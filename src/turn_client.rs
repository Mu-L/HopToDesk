use hbb_common::{
    bail, log,
    tcp::FramedStream,
    tokio::{
        self,
        net::TcpStream,
        sync::{mpsc},
    },
    tokio_util::compat::Compat,
    ResultType,
};
use std::{net::SocketAddr, sync::Arc};
use turn::client::{tcp::TcpSplit, ClientConfig};
use webrtc_util::conn::Conn;

use crate::rendezvous_messages::{self, ToJson};

#[derive(Debug)]
pub struct TurnConfig {
    addr: String,
    username: String,
    password: String,
}

async fn get_turn_servers() -> Option<Vec<TurnConfig>> {
    let map = hbb_common::api::call_api().await.ok()?;
    let mut servers = Vec::new();
    for server in map["turnservers"].as_array()? {
        if server["protocol"].as_str()? == "turn" {
            servers.push(TurnConfig {
                addr: format!("{}:{}", server["host"].as_str()?, server["port"].as_str()?),
                username: server["username"].as_str()?.to_string(),
                password: server["password"].as_str()?.to_string(),
            });
        }
    }
    Some(servers)
}

pub async fn connect_over_turn_servers(
    peer_id: &str,
    peer_addr: SocketAddr,
    mut sender: soketto::Sender<Compat<TcpStream>>,
) -> ResultType<(Arc<impl Conn>, FramedStream)> {
    if let Some(turn_servers) = get_turn_servers().await {
        let srv_len = turn_servers.len();
        let sender = Arc::new(tokio::sync::Mutex::new(sender));
        let (tx, mut rx) = mpsc::channel(srv_len);
        for config in turn_servers {
            let sender = sender.clone();
            let peer_id = peer_id.to_owned();
            let tx = tx.clone();
            tokio::spawn(async move {
                let turn_server = config.addr.clone();
                log::info!(
                    "[turn] start establishing over TURN server: {}",
                    turn_server
                );
                if let Ok(turn_client) = TurnClient::new(config).await {
                    match turn_client.create_relay_connection(peer_addr).await {
                        Ok(relay) => {
                            let conn = relay.0;
                            let relay_addr = relay.1;
                            match establish_over_relay(&peer_id, turn_client, relay_addr, sender)
                                .await
                            {
                                Ok(stream) => {
                                    tx.send(Some((conn, stream))).await;
                                    log::info!(
                                        "[turn] connection has been established by TURN server {}",
                                        turn_server
                                    );
                                    return;
                                }
                                Err(err) => log::warn!("{}", err),
                            };
                        }
                        Err(err) => log::warn!("create relay conn failed {err}"),
                    };
                }

                tx.send(None).await;
            });
        }
        for _ in 0..srv_len {
            if let Some(ret) = rx.recv().await {
                if let Some(ret) = ret {
                    return Ok(ret);
                }
            }
        }
        bail!("Failed to connect via relay server: all condidates are failed!") // all tasks have done without luck.
    }
    bail!("empty turn servers!")
}

async fn establish_over_relay(
    peer_id: &str,
    turn_client: TurnClient,
    relay_addr: SocketAddr,
    sender: Arc<tokio::sync::Mutex<soketto::Sender<Compat<TcpStream>>>>,
) -> ResultType<FramedStream> {
    let mut sender = sender.lock().await;
    sender
        .send_text(&rendezvous_messages::RelayConnection::new(peer_id, relay_addr).to_json())
        .await?;
    match turn_client.wait_new_connection().await {
        Ok(stream) => {
            sender
                .send_text(&rendezvous_messages::RelayReady::new(peer_id).to_json())
                .await?;
            return Ok(stream);
        }
        Err(e) => bail!("Failed to connect via relay server: {}", e),
    }
}

pub async fn get_public_ip() -> Option<SocketAddr> {
    let servers = get_turn_servers().await?;
    let len = servers.len();
    let (tx, mut rx) = tokio::sync::mpsc::channel(len);
    for config in servers {
        let tx = tx.clone();
        tokio::spawn(async move {
            log::info!("start retrieve public ip via: {}", config.addr);
            let turn_addr = config.addr.clone();
            if let Ok(turn_client) = TurnClient::new(config).await {
                if let Ok(addr) = turn_client.get_public_ip().await {
                    tx.send(Some(addr)).await;
                    log::info!("got public ip: {} via {}", addr, turn_addr);
                    return;
                }
            }
            tx.send(None).await;
        });
    }
    for _ in 0..len {
        if let Some(addr) = rx.recv().await {
            if addr.is_some() {
                return addr;
            }
        }
    }
    return None;
}

pub struct TurnClient {
    client: turn::client::Client,
}

impl TurnClient {
    pub async fn new(config: TurnConfig) -> ResultType<Self> {
        let tcp_split = TcpSplit::from(TcpStream::connect(&config.addr).await?);
        let mut client = turn::client::Client::new(ClientConfig {
            stun_serv_addr: config.addr.clone(),
            turn_serv_addr: config.addr,
            username: config.username,
            password: config.password,
            realm: String::new(),
            software: String::new(),
            rto_in_ms: 0,
            conn: Arc::new(tcp_split),
            vnet: None,
        })
        .await?;
        client.listen().await?;
        Ok(Self { client })
    }

    pub async fn get_public_ip(&self) -> ResultType<SocketAddr> {
        Ok(self.client.send_binding_request().await?)
    }

    pub async fn create_relay_connection(
        &self,
        peer_addr: SocketAddr,
    ) -> ResultType<(Arc<impl Conn>, SocketAddr)> {
        let relay_connection = self.client.allocate().await?;
        relay_connection.send_to(b"init", peer_addr).await?;
        let local_addr = relay_connection.local_addr().await?;

        Ok((
            // Avoid the conn to be dropped, otherwise the timer in it will be
            // stopped. That will stop to send refresh transaction periodically.
            // More detail to check:
            //
            //   https://datatracker.ietf.org/doc/html/rfc5766#page-31
            Arc::new(relay_connection),
            local_addr,
        ))
    }

    pub async fn wait_new_connection(&self) -> ResultType<FramedStream> {
        let tcp_stream = self.client.wait_new_connection().await.unwrap();
        let addr = tcp_stream.local_addr()?;
        Ok(FramedStream::from(tcp_stream, addr))
    }
}
