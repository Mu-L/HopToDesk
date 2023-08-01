use std::{
    collections::HashMap,
    net::SocketAddr,
    ops::Deref,
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Mutex, RwLock,
    },
    time::UNIX_EPOCH,
};

pub use async_trait::async_trait;
use bytes::Bytes;
#[cfg(not(any(target_os = "android", target_os = "linux")))]
use cpal::{
    traits::{DeviceTrait, HostTrait, StreamTrait},
    Device, Host, StreamConfig,
};
use crossbeam_queue::ArrayQueue;
use futures::{stream::SplitSink, SinkExt, StreamExt};
use tokio_tungstenite::{tungstenite::Message as WsMessage, MaybeTlsStream, WebSocketStream};
use magnum_opus::{Channels::*, Decoder as AudioDecoder};
#[cfg(not(any(target_os = "android", target_os = "linux")))]
use ringbuf::{ring_buffer::RbBase, Rb};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub use file_trait::FileManager;
#[cfg(not(feature = "flutter"))]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::tokio::sync::mpsc::UnboundedSender;
use hbb_common::{
    allow_err,
    anyhow::{anyhow, Context},
    bail,
    config::{Config, PeerConfig, PeerInfoSerde, Resolution, CONNECT_TIMEOUT, RENDEZVOUS_TIMEOUT},
    get_version_number, log,
    message_proto::{option_message::BoolOption, *},
    protobuf::Message as _,
    rand,
    rendezvous_proto::*,
    socket_client,
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::FramedStream,
    timeout,
    tokio::time::Duration,
    tokio::{self, net::TcpStream},
    //AddrMangle, 
    ResultType, Stream,
};
pub use helper::*;
use scrap::{
    codec::Decoder,
    record::{Recorder, RecorderContext},
    ImageFormat, ImageRgb,
};

use crate::is_keyboard_mode_supported;

#[cfg(not(feature = "flutter"))]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::ui_session_interface::SessionPermissionConfig;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::{check_clipboard, ClipboardContext, CLIPBOARD_INTERVAL};

pub use super::lang::*;

pub mod file_trait;
pub mod helper;
pub mod io_loop;

pub const MILLI1: Duration = Duration::from_millis(1);
pub const SEC30: Duration = Duration::from_secs(30);
pub const VIDEO_QUEUE_SIZE: usize = 120;

#[cfg(all(target_os = "linux", feature = "linux_headless"))]
#[cfg(not(any(feature = "flatpak", feature = "appimage")))]
pub const LOGIN_MSG_DESKTOP_NOT_INITED: &str = "Desktop env is not inited";
pub const LOGIN_MSG_DESKTOP_SESSION_NOT_READY: &str = "Desktop session not ready";
pub const LOGIN_MSG_DESKTOP_XSESSION_FAILED: &str = "Desktop xsession failed";
pub const LOGIN_MSG_DESKTOP_SESSION_ANOTHER_USER: &str = "Desktop session another user login";
pub const LOGIN_MSG_DESKTOP_XORG_NOT_FOUND: &str = "Desktop xorg not found";
// ls /usr/share/xsessions/
pub const LOGIN_MSG_DESKTOP_NO_DESKTOP: &str = "Desktop none";
pub const LOGIN_MSG_DESKTOP_SESSION_NOT_READY_PASSWORD_EMPTY: &str =
    "Desktop session not ready, password empty";
pub const LOGIN_MSG_DESKTOP_SESSION_NOT_READY_PASSWORD_WRONG: &str =
    "Desktop session not ready, password wrong";
pub const LOGIN_MSG_PASSWORD_EMPTY: &str = "Empty Password";
pub const LOGIN_MSG_PASSWORD_WRONG: &str = "Wrong Password";
pub const LOGIN_MSG_NO_PASSWORD_ACCESS: &str = "No Password Access";
pub const LOGIN_MSG_OFFLINE: &str = "Offline";
#[cfg(target_os = "linux")]
pub const SCRAP_UBUNTU_HIGHER_REQUIRED: &str = "Wayland requires Ubuntu 21.04 or higher version.";
#[cfg(target_os = "linux")]
pub const SCRAP_OTHER_VERSION_OR_X11_REQUIRED: &str =
    "Wayland requires higher version of linux distro. Please try X11 desktop or change your OS.";
pub const SCRAP_X11_REQUIRED: &str = "x11 expected";
pub const SCRAP_X11_REF_URL: &str = "";

#[cfg(feature = "flutter")]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) struct ClientClipboardContext;

#[cfg(not(feature = "flutter"))]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) struct ClientClipboardContext {
    pub cfg: SessionPermissionConfig,
    pub tx: UnboundedSender<Data>,
}

/// Client of the remote desktop.
pub struct Client;

pub type WsSender = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, WsMessage>;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct TextClipboardState {
    is_required: bool,
    running: bool,
}

use crate::{
    rendezvous_messages::{self, ToJson},
    turn_client,
};

#[cfg(not(any(target_os = "android", target_os = "linux")))]
lazy_static::lazy_static! {
static ref AUDIO_HOST: Host = cpal::default_host();
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
lazy_static::lazy_static! {
    static ref ENIGO: Arc<Mutex<enigo::Enigo>> = Arc::new(Mutex::new(enigo::Enigo::new()));
    static ref OLD_CLIPBOARD_TEXT: Arc<Mutex<String>> = Default::default();
    static ref TEXT_CLIPBOARD_STATE: Arc<Mutex<TextClipboardState>> = Arc::new(Mutex::new(TextClipboardState::new()));
}

#[inline]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn get_old_clipboard_text() -> &'static Arc<Mutex<String>> {
    &OLD_CLIPBOARD_TEXT
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn get_key_state(key: enigo::Key) -> bool {
    use enigo::KeyboardControllable;
    #[cfg(target_os = "macos")]
    if key == enigo::Key::NumLock {
        return true;
    }
    ENIGO.lock().unwrap().get_key_state(key)
}

cfg_if::cfg_if! {
    if #[cfg(target_os = "android")] {

use hbb_common::libc::{c_float, c_int, c_void};
use std::cell::RefCell;
type Oboe = *mut c_void;
extern "C" {
    fn create_oboe_player(channels: c_int, sample_rate: c_int) -> Oboe;
    fn push_oboe_data(oboe: Oboe, d: *const c_float, n: c_int);
    fn destroy_oboe_player(oboe: Oboe);
}

struct OboePlayer {
    raw: Oboe,
}

impl Default for OboePlayer {
    fn default() -> Self {
        Self {
            raw: std::ptr::null_mut(),
        }
    }
}

impl OboePlayer {
    fn new(channels: i32, sample_rate: i32) -> Self {
        unsafe {
            Self {
                raw: create_oboe_player(channels, sample_rate),
            }
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn is_null(&self) -> bool {
        self.raw.is_null()
    }

    fn push(&mut self, d: &[f32]) {
        if self.raw.is_null() {
            return;
        }
        unsafe {
            push_oboe_data(self.raw, d.as_ptr(), d.len() as _);
        }
    }
}

impl Drop for OboePlayer {
    fn drop(&mut self) {
        unsafe {
            if !self.raw.is_null() {
                destroy_oboe_player(self.raw);
            }
        }
    }
}

}
}

#[derive(Clone)]
struct Peer {
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    peer_public_addr: SocketAddr,
    peer_nat_type: NatType,
    my_nat_type: i32,
    id_pk: Vec<u8>,
    listening_time_used: u64,
}

impl Peer {
    fn from_peer_id(peer_id: &str) -> ResultType<Self> {
        let local_addr = turn_client::get_local_ip()?;
        let id_pk = Vec::new();
        let mut peer_addr = Config::get_any_listen_addr(true);
        let peer_public_addr = peer_addr;
        let peer_nat_type = NatType::UNKNOWN_NAT;
        if peer_addr.port() == 0 {
            if let Ok(pa) = peer_id.parse() {
                peer_addr = pa;
            } else {
                let peer_sock_addr = format!("{}:21118", peer_id);
                if let Ok(pa) = peer_sock_addr.parse() {
                    peer_addr = pa
                } else {
                    log::info!("cant connect to {} with addr {}", peer_id, peer_addr);
                    bail!("Unable to connect to the remote partner.");
                }
            }
        }

        Ok(Self {
            local_addr: SocketAddr::new(local_addr, 0),
            peer_addr,
            peer_public_addr,
            peer_nat_type,
            my_nat_type: NatType::UNKNOWN_NAT as i32,
            id_pk,
            listening_time_used: 0,
        })
    }

    async fn connect_timeout(&self, peer_id: &str) -> u64 {
        let direct_failures = PeerConfig::load(peer_id).direct_failures;
        let mut connect_timeout = 0;
        const MIN: u64 = 1000;
        if self.peer_nat_type == NatType::SYMMETRIC {
            connect_timeout = MIN;
        } else {
            if self.peer_nat_type == NatType::ASYMMETRIC {
                let mut my_nat_type = self.my_nat_type;
                if my_nat_type == NatType::UNKNOWN_NAT as i32 {
                    my_nat_type = crate::get_nat_type(100).await;
                }
                if my_nat_type == NatType::ASYMMETRIC as i32 {
                    connect_timeout = CONNECT_TIMEOUT;
                    if direct_failures > 0 {
                        connect_timeout = self.listening_time_used * 6;
                    }
                } else if my_nat_type == NatType::SYMMETRIC as i32 {
                    connect_timeout = MIN;
                }
            }
            if connect_timeout == 0 {
                let n = if direct_failures > 0 { 3 } else { 6 };
                connect_timeout = self.listening_time_used * (n as u64);
            }
            if connect_timeout < MIN {
                connect_timeout = MIN;
            }
        }
        log::info!("peer address: {}, timeout: {}", peer_id, connect_timeout);

        connect_timeout
    }
}

impl Client {
    pub async fn start(
        peer: &str,
        conn_type: ConnType,
    ) -> ResultType<(
        Stream,
        Option<Arc<impl webrtc_util::Conn>>,
        bool,
        String,
        String,
    )> {
        match Self::_start(peer, conn_type).await {
            Err(err) => {
                // Refresh API
                hbb_common::api::erase_api().await;
                let err_str = err.to_string();
                if err_str.starts_with("Failed") {
                    bail!(err_str + ": Please try later");
                } else {
                    return Err(err);
                }
            }
            Ok(x) => Ok(x),
        }
    }

    /// Start a new connection.
    async fn _start(
        peer_id: &str,
//        key: &str,
//        token: &str,
        conn_type: ConnType,
    ) -> ResultType<(
        Stream,
        Option<Arc<impl webrtc_util::Conn>>,
        bool,
        String,
        String,
    )> {
        match Self::get_peer_info(peer_id).await {
            Ok((peer, sender)) => {
                let (mut conn, relay, direct) =
                    Self::_connect_both(peer_id, &peer, sender, conn_type).await?;
                let (security_numbers, avatar_image) =
                    Self::secure_connection(peer_id, peer.id_pk, &mut conn).await?;

                Ok((conn, relay, direct, security_numbers, avatar_image))
            }
            Err(err) => {
                log::info!("get peer info failed with error {}, may be no internet access, try access directly.",err);
                let peer = Peer::from_peer_id(peer_id)?;
                let mut conn = Self::connect_directly(peer_id, &peer).await?;
                let (security_numbers, avatar_image) =
                    Self::secure_connection(peer_id, peer.id_pk, &mut conn).await?;
                Ok((conn, None, true, security_numbers, avatar_image))
            }
        }
    }

    async fn _connect_both(
        peer_id: &str,
        peer: &Peer,
        sender: WsSender,
        _conn_type: ConnType,
    ) -> ResultType<(FramedStream, Option<Arc<impl webrtc_util::Conn>>, bool)> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);

        {
            let tx = tx.clone();
            let peer_id = peer_id.to_owned();
            let peer = peer.clone();
            tokio::spawn(async move {
                match Self::connect_directly(&peer_id, &peer).await {
                    Ok(stream) => {
                        match tx.send(Ok((stream, None, true))).await {
                            Ok(()) => {}
                            Err(e) => log::info!("Error while connecting to TURN server {e}"),
                        }
                        //tx.send(Ok((stream, None, true))).await;
                    }
                    Err(err) => {
                        tx.send(Err(err)).await.unwrap_or_else(|e| {
                            log::info!("Error while connecting to TURN server {e}");
                        });

                        //tx.send(Err(err)).await;
                    }
                }
            });
        }

        {
            let tx = tx.clone();
            let peer_id = peer_id.to_owned();
            let peer = peer.clone();
            tokio::spawn(async move {
                match Self::connect_over_turn(&peer_id, sender, peer.peer_public_addr).await {
                    Ok((stream, relay)) => {
                        tx.send(Ok((stream, Some(relay), true)))
                            .await
                            .unwrap_or_else(|e| {
                                log::info!("Error while connecting to TURN server {e}");
                            });

                        //tx.send(Ok((stream, Some(relay), true))).await;
                    }
                    Err(err) => {
                        //tx.send(Err(err)).await;
                        match tx.send(Err(err)).await {
                            Ok(_) => {}
                            Err(_err) => {} //Err(e) => {  }
                        }
                    }
                };
            });
        }
        for i in 0..2 {
            if let Some(ret) = rx.recv().await {
                match ret {
                    Ok(ret) => return Ok(ret),
                    Err(err) => {
                        if i == 1 {
                            return Err(err);
                        }
                    }
                }
            }
        }
        unreachable!()
    }

    async fn get_peer_info(peer: &str) -> ResultType<(Peer, WsSender)> {
        let rendezvous_server = match crate::get_rendezvous_server(1_000).await {
            Some(server) => server,
            None => bail!("Failed to retrieve rendez-vous server address"),
        };

        let my_peer_id = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let start = std::time::Instant::now();
        log::info!("get peer info via signal {}", rendezvous_server);
        let (my_addr, _, websocket_client) =
            crate::rendezvous_ws::create_websocket_with_peer_id(&rendezvous_server, &my_peer_id)
                .await?;
        let (mut sender, mut receiver) = websocket_client.split();

        let mut id_pk = Vec::new();
        let mut peer_addr = Config::get_any_listen_addr(true);
        let mut peer_public_addr = peer_addr;
        let mut peer_nat_type = NatType::UNKNOWN_NAT;
        let my_nat_type = crate::get_nat_type(100).await;
        for i in 1..=3 {
            log::info!("#{} punch attempt with {}, id: {}", i, my_addr, peer);
            sender
                .send(WsMessage::Text(
                    rendezvous_messages::ConnectRequest::new(peer, &my_peer_id).to_json(),
                ))
                .await?;
            use hbb_common::protobuf::Enum;
            match timeout(RENDEZVOUS_TIMEOUT, receiver.next()).await? {
                Some(r) => {
                    let msg = r?;
                    if let WsMessage::Text(m) = msg {
                        if let Ok(listening) =
                            serde_json::from_str::<rendezvous_messages::Listening>(&m)
                        {
                            if let Ok(raw_pk) = crate::decode64(listening.pk) {
                                id_pk = raw_pk;
                                peer_addr = listening.addr;
                                peer_public_addr = listening.public_addr;
                                peer_nat_type =
                                    NatType::from_i32(listening.nat_type).unwrap_or(peer_nat_type);
                                break;
                            }
                        }
                    }
                }
                None => log::info!("timed out connection to signal server"),
            }
        }
        if peer_addr.port() == 0 {
            if let Ok(pa) = peer.parse() {
                peer_addr = pa;
            } else {
                let peer_sock_addr = format!("{}:21118", peer);
                if let Ok(pa) = peer_sock_addr.parse() {
                    peer_addr = pa
                } else {
                    log::info!("cant connect to {} with addr {}", peer, peer_addr);
                    bail!("Unable to connect to the remote partner.");
                }
            }
        }
        let time_used = start.elapsed().as_millis() as u64;
        log::info!(
            "{} ms used for listening, id_pk size: {}",
            time_used,
            id_pk.len()
        );

        Ok((
            Peer {
                local_addr: SocketAddr::new(my_addr, 0),
                peer_addr,
                peer_public_addr,
                peer_nat_type,
                my_nat_type,
                id_pk,
                listening_time_used: time_used,
            },
            sender,
        ))
    }

    async fn connect_over_turn(
        peer_id: &str,
        sender: WsSender,
        peer_public_addr: SocketAddr,
    ) -> ResultType<(FramedStream, Arc<impl webrtc_util::Conn>)> {
        let start = std::time::Instant::now();
        log::info!("start connecting peer via turn servers");

        let (relay, conn) = match turn_client::connect_over_turn_servers(
            &peer_id,
            peer_public_addr,
            sender,
        )
        .await
        {
            Ok((relay_conn, stream)) => {
                log::info!("connect successfully to peer via TURN servers!");
                (relay_conn, stream)
            }
            Err(err) => {
                log::warn!("attempt to connect via turn servers failed: {}", err);
                return Err(err.into());
            }
        };

        let time_used = start.elapsed().as_millis() as u64;
        log::info!("{}ms used to establish connection", time_used);

        //Self::secure_connection(peer_id, id_pk, &mut conn).await?;
        Ok((conn, relay))
    }

    async fn connect_directly(peer_id: &str, peer: &Peer) -> ResultType<FramedStream> {
        let connect_timeout = peer.connect_timeout(peer_id).await;
        log::info!("start connecting peer directly: {}", peer.local_addr);
        match socket_client::connect_tcp(peer.peer_addr, peer.local_addr, connect_timeout).await {
            Ok(conn) => {
                log::info!("connect successfully to {} directly!", peer.local_addr);
                Ok(conn)
            }
            Err(err) => {
                log::warn!(
                    "attempt to connect to {} directly failed: {}",
                    peer.local_addr,
                    err
                );

                let any_addr = Config::get_any_listen_addr(true);
                log::info!("start connecting peer directly: {}", any_addr);
                match socket_client::connect_tcp(peer.peer_addr, any_addr, connect_timeout).await {
                    Ok(stream) => {
                        log::info!("connect successfully to {} directly!", any_addr);
                        Ok(stream)
                    }
                    Err(err) => {
                        log::warn!(
                            "attempt to connect to {} directly failed: {}",
                            any_addr,
                            err
                        );
                        Err(err)
                    }
                }
            }
        }
    }

    pub async fn secure_connection(
        peer_id: &str,
        id_pk: Vec<u8>,
        conn: &mut Stream,
    ) -> ResultType<(String, String)> {
        let mut security_numbers = String::new();
        let avatar_image = String::new();
        let mut sign_pk = None;
        if !id_pk.is_empty() {
            let t = get_pk(&id_pk);
            if let Some(pk) = t {
                sign_pk = Some(sign::PublicKey(pk));
            }

            if sign_pk.is_none() {
                log::error!("Handshake failed: invalid public key from rendezvous server");
            }
        }
        let sign_pk = match sign_pk {
            Some(v) => v,
            None => {
                // send an empty message out in case server is setting up secure and waiting for first message
                conn.send(&Message::new()).await?;
                return Ok((security_numbers, avatar_image));
            }
        };
        log::info!("Start secure connecton");
        match timeout(CONNECT_TIMEOUT, conn.next()).await? {
            Some(res) => {
                let bytes = res?;
                if let Ok(msg_in) = Message::parse_from_bytes(&bytes) {
                    if let Some(message::Union::SignedId(si)) = msg_in.union {
                        if let Ok((id, their_pk_b)) = decode_id_pk(&si.id, &sign_pk) {
                            if id == peer_id {
                                let their_pk_b = box_::PublicKey(their_pk_b);
                                let (our_pk_b, out_sk_b) = box_::gen_keypair();
                                let key = secretbox::gen_key();
                                let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
                                let sealed_key = box_::seal(&key.0, &nonce, &their_pk_b, &out_sk_b);
                                let mut msg_out = Message::new();
                                msg_out.set_public_key(PublicKey {
                                    asymmetric_value: Vec::from(our_pk_b.0).into(),
                                    symmetric_value: sealed_key.into(),
                                    ..Default::default()
                                });
                                timeout(CONNECT_TIMEOUT, conn.send(&msg_out)).await??;
                                conn.set_key(key);
								security_numbers =
                                    hbb_common::password_security::compute_security_code(
                                        &out_sk_b,
                                        &their_pk_b,
                                    );
                                log::info!(
                                    "Connection is secured: {}, and Security Code is: {}",
                                    conn.is_secured(),
                                    security_numbers
                                );
                            } else {
                                log::error!("Handshake failed: sign failure");
                                conn.send(&Message::new()).await?;
                            }
                        } else {
                            // fall back to non-secure connection in case pk mismatch
                            log::info!("pk mismatch, fall back to non-secure");
                            let mut msg_out = Message::new();
                            msg_out.set_public_key(PublicKey::new());
                            timeout(CONNECT_TIMEOUT, conn.send(&msg_out)).await??;
                        }
                    } else {
                        log::error!("Handshake failed: invalid message type");
                        conn.send(&Message::new()).await?;
                    }
                } else {
                    log::error!("Handshake failed: invalid message format");
                    conn.send(&Message::new()).await?;
                }
            }
            None => {
                bail!("Connection lost");
            }
        }
        Ok((security_numbers, avatar_image))
    }

    #[inline]
    #[cfg(feature = "flutter")]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub fn set_is_text_clipboard_required(b: bool) {
        TEXT_CLIPBOARD_STATE.lock().unwrap().is_required = b;
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn try_stop_clipboard(_self_uuid: &uuid::Uuid) {
        #[cfg(feature = "flutter")]
        if crate::flutter::other_sessions_running(_self_uuid) {
            return;
        }
        TEXT_CLIPBOARD_STATE.lock().unwrap().running = false;
    }

    // `try_start_clipboard` is called by all session when connection is established. (When handling peer info).
    // This function only create one thread with a loop, the loop is shared by all sessions.
    // After all sessions are end, the loop exists.
    //
    // If clipboard update is detected, the text will be sent to all sessions by `send_text_clipboard_msg`.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn try_start_clipboard(_ctx: Option<ClientClipboardContext>) {
        let mut clipboard_lock = TEXT_CLIPBOARD_STATE.lock().unwrap();
        if clipboard_lock.running {
            return;
        }

        match ClipboardContext::new() {
            Ok(mut ctx) => {
                clipboard_lock.running = true;
                // ignore clipboard update before service start
                check_clipboard(&mut ctx, Some(&OLD_CLIPBOARD_TEXT));
                std::thread::spawn(move || {
                    log::info!("Start text clipboard loop");
                    loop {
                        std::thread::sleep(Duration::from_millis(CLIPBOARD_INTERVAL));
                        if !TEXT_CLIPBOARD_STATE.lock().unwrap().running {
                            break;
                        }

                        if !TEXT_CLIPBOARD_STATE.lock().unwrap().is_required {
                            continue;
                        }

                        if let Some(msg) = check_clipboard(&mut ctx, Some(&OLD_CLIPBOARD_TEXT)) {
                            #[cfg(feature = "flutter")]
                            crate::flutter::send_text_clipboard_msg(msg);
                            #[cfg(not(feature = "flutter"))]
                            if let Some(ctx) = &_ctx {
                                if ctx.cfg.is_text_clipboard_required() {
                                    let _ = ctx.tx.send(Data::Message(msg));
                                }
                            }
                        }
                    }
                    log::info!("Stop text clipboard loop");
                });
            }
            Err(err) => {
                log::error!("Failed to start clipboard service of client: {}", err);
            }
        }
    }

    #[inline]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn get_current_text_clipboard_msg() -> Option<Message> {
        let txt = &*OLD_CLIPBOARD_TEXT.lock().unwrap();
        if txt.is_empty() {
            None
        } else {
            Some(crate::create_clipboard_msg(txt.clone()))
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl TextClipboardState {
    fn new() -> Self {
        Self {
            is_required: true,
            running: false,
        }
    }
}

/// Audio handler for the [`Client`].
#[derive(Default)]
pub struct AudioHandler {
    audio_decoder: Option<(AudioDecoder, Vec<f32>)>,
    #[cfg(target_os = "android")]
    oboe: Option<OboePlayer>,
    #[cfg(target_os = "linux")]
    simple: Option<psimple::Simple>,
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    audio_buffer: AudioBuffer,
    sample_rate: (u32, u32),
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    audio_stream: Option<Box<dyn StreamTrait>>,
    channels: u16,
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    device_channel: u16,
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    ready: Arc<std::sync::Mutex<bool>>,
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
struct AudioBuffer(pub Arc<std::sync::Mutex<ringbuf::HeapRb<f32>>>);

#[cfg(not(any(target_os = "android", target_os = "linux")))]
impl Default for AudioBuffer {
    fn default() -> Self {
        Self(Arc::new(std::sync::Mutex::new(
            ringbuf::HeapRb::<f32>::new(48000 * 2), // 48000hz, 2 channel, 1 second
        )))
    }
}

impl AudioHandler {
    /// Start the audio playback.
    #[cfg(target_os = "linux")]
    fn start_audio(&mut self, format0: AudioFormat) -> ResultType<()> {
        use psimple::Simple;
        use pulse::sample::{Format, Spec};
        use pulse::stream::Direction;

        let spec = Spec {
            format: Format::F32le,
            channels: format0.channels as _,
            rate: format0.sample_rate as _,
        };
        if !spec.is_valid() {
            bail!("Invalid audio format");
        }

        self.simple = Some(Simple::new(
            None,                   // Use the default server
            &crate::get_app_name(), // Our application’s name
            Direction::Playback,    // We want a playback stream
            None,                   // Use the default device
            "playback",             // Description of our stream
            &spec,                  // Our sample format
            None,                   // Use default channel map
            None,                   // Use default buffering attributes
        )?);
        self.sample_rate = (format0.sample_rate, format0.sample_rate);
        Ok(())
    }

    /// Start the audio playback.
    #[cfg(target_os = "android")]
    fn start_audio(&mut self, format0: AudioFormat) -> ResultType<()> {
        self.oboe = Some(OboePlayer::new(
            format0.channels as _,
            format0.sample_rate as _,
        ));
        self.sample_rate = (format0.sample_rate, format0.sample_rate);
        Ok(())
    }

    /// Start the audio playback.
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    fn start_audio(&mut self, format0: AudioFormat) -> ResultType<()> {
        let device = AUDIO_HOST
            .default_output_device()
            .with_context(|| "Failed to get default output device")?;
        log::info!(
            "Using default output device: \"{}\"",
            device.name().unwrap_or("".to_owned())
        );
        let config = device.default_output_config().map_err(|e| anyhow!(e))?;
        let sample_format = config.sample_format();
        log::info!("Default output format: {:?}", config);
        log::info!("Remote input format: {:?}", format0);
        let config: StreamConfig = config.into();
        self.sample_rate = (format0.sample_rate, config.sample_rate.0);
        let mut build_output_stream = |config: StreamConfig| match sample_format {
            cpal::SampleFormat::I8 => self.build_output_stream::<i8>(&config, &device),
            cpal::SampleFormat::I16 => self.build_output_stream::<i16>(&config, &device),
            cpal::SampleFormat::I32 => self.build_output_stream::<i32>(&config, &device),
            cpal::SampleFormat::I64 => self.build_output_stream::<i64>(&config, &device),
            cpal::SampleFormat::U8 => self.build_output_stream::<u8>(&config, &device),
            cpal::SampleFormat::U16 => self.build_output_stream::<u16>(&config, &device),
            cpal::SampleFormat::U32 => self.build_output_stream::<u32>(&config, &device),
            cpal::SampleFormat::U64 => self.build_output_stream::<u64>(&config, &device),
            cpal::SampleFormat::F32 => self.build_output_stream::<f32>(&config, &device),
            cpal::SampleFormat::F64 => self.build_output_stream::<f64>(&config, &device),
            f => bail!("unsupported audio format: {:?}", f),
        };
        if config.channels > format0.channels as _ {
            let no_rechannel_config = StreamConfig {
                channels: format0.channels as _,
                ..config.clone()
            };
            if let Err(_) = build_output_stream(no_rechannel_config) {
                build_output_stream(config)?;
            }
        } else {
            build_output_stream(config)?;
        }

        Ok(())
    }

    /// Handle audio format and create an audio decoder.
    pub fn handle_format(&mut self, f: AudioFormat) {
        match AudioDecoder::new(f.sample_rate, if f.channels > 1 { Stereo } else { Mono }) {
            Ok(d) => {
                let buffer = vec![0.; f.sample_rate as usize * f.channels as usize];
                self.audio_decoder = Some((d, buffer));
                self.channels = f.channels as _;
                allow_err!(self.start_audio(f));
            }
            Err(err) => {
                log::error!("Failed to create audio decoder: {}", err);
            }
        }
    }

    /// Handle audio frame and play it.
    #[inline]
    pub fn handle_frame(&mut self, frame: AudioFrame) {
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        if self.audio_stream.is_none() || !self.ready.lock().unwrap().clone() {
            return;
        }
        #[cfg(target_os = "linux")]
        if self.simple.is_none() {
            log::debug!("PulseAudio simple binding does not exists");
            return;
        }
        #[cfg(target_os = "android")]
        if self.oboe.is_none() {
            return;
        }
        self.audio_decoder.as_mut().map(|(d, buffer)| {
            if let Ok(n) = d.decode_float(&frame.data, buffer, false) {
                let channels = self.channels;
                let n = n * (channels as usize);
                #[cfg(not(any(target_os = "android", target_os = "linux")))]
                {
                    let sample_rate0 = self.sample_rate.0;
                    let sample_rate = self.sample_rate.1;
                    let audio_buffer = self.audio_buffer.0.clone();
                    let mut buffer = buffer[0..n].to_owned();
                    if sample_rate != sample_rate0 {
                        buffer = crate::audio_resample(
                            &buffer[0..n],
                            sample_rate0,
                            sample_rate,
                            channels,
                        );
                    }
                    if self.channels != self.device_channel {
                        buffer = crate::audio_rechannel(
                            buffer,
                            sample_rate,
                            sample_rate,
                            self.channels,
                            self.device_channel,
                        );
                    }
                    audio_buffer.lock().unwrap().push_slice_overwrite(&buffer);
                }
                #[cfg(target_os = "android")]
                {
                    self.oboe.as_mut().map(|x| x.push(&buffer[0..n]));
                }
                #[cfg(target_os = "linux")]
                {
                    let data_u8 =
                        unsafe { std::slice::from_raw_parts::<u8>(buffer.as_ptr() as _, n * 4) };
                    self.simple.as_mut().map(|x| x.write(data_u8));
                }
            }
        });
    }

    /// Build audio output stream for current device.
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    fn build_output_stream<T: cpal::Sample + cpal::SizedSample + cpal::FromSample<f32>>(
        &mut self,
        config: &StreamConfig,
        device: &Device,
    ) -> ResultType<()> {
        self.device_channel = config.channels;
        let err_fn = move |err| {
            // too many errors, will improve later
            log::trace!("an error occurred on stream: {}", err);
        };
        let audio_buffer = self.audio_buffer.0.clone();
        let ready = self.ready.clone();
        let timeout = None;
        let stream = device.build_output_stream(
            config,
            move |data: &mut [T], _: &_| {
                if !*ready.lock().unwrap() {
                    *ready.lock().unwrap() = true;
                }
                let mut lock = audio_buffer.lock().unwrap();
                let mut n = data.len();
                if lock.occupied_len() < n {
                    n = lock.occupied_len();
                }
                let mut elems = vec![0.0f32; n];
                lock.pop_slice(&mut elems);
                drop(lock);
                let mut input = elems.into_iter();
                for sample in data.iter_mut() {
                    *sample = match input.next() {
                        Some(x) => T::from_sample(x),
                        _ => T::from_sample(0.),
                    };
                }
            },
            err_fn,
            timeout,
        )?;
        stream.play()?;
        self.audio_stream = Some(Box::new(stream));
        Ok(())
    }
}

/// Video handler for the [`Client`].
pub struct VideoHandler {
    decoder: Decoder,
    pub rgb: ImageRgb,
    recorder: Arc<Mutex<Option<Recorder>>>,
    record: bool,
}

impl VideoHandler {
    /// Create a new video handler.
    pub fn new() -> Self {
        VideoHandler {
            decoder: Decoder::new(),
            rgb: ImageRgb::new(ImageFormat::ARGB, crate::DST_STRIDE_RGBA),
            recorder: Default::default(),
            record: false,
        }
    }

    /// Handle a new video frame.
    #[inline]
    pub fn handle_frame(&mut self, vf: VideoFrame) -> ResultType<bool> {
        match &vf.union {
            Some(frame) => {
                let res = self.decoder.handle_video_frame(frame, &mut self.rgb);
                if self.record {
                    self.recorder
                        .lock()
                        .unwrap()
                        .as_mut()
                        .map(|r| r.write_frame(frame));
                }
                res
            }
            _ => Ok(false),
        }
    }

    /// Reset the decoder.
    pub fn reset(&mut self) {
        self.decoder = Decoder::new();
    }

    /// Start or stop screen record.
    pub fn record_screen(&mut self, start: bool, w: i32, h: i32, id: String) {
        self.record = false;
        if start {
            self.recorder = Recorder::new(RecorderContext {
                server: false,
                id,
                default_dir: crate::ui_interface::default_video_save_directory(),
                filename: "".to_owned(),
                width: w as _,
                height: h as _,
                format: scrap::CodecFormat::VP9,
                tx: None,
            })
            .map_or(Default::default(), |r| Arc::new(Mutex::new(Some(r))));
        } else {
            self.recorder = Default::default();
        }

        self.record = start;
    }
}

/// Login config handler for [`Client`].
#[derive(Default)]
pub struct LoginConfigHandler {
    id: String,
    pub conn_type: ConnType,
    hash: Hash,
    password: Vec<u8>, // remember password for reconnect
    tokenex: String,
	pub remember: bool,
    config: PeerConfig,
    pub port_forward: (String, i32),
    pub version: i64,
    features: Option<Features>,
    pub session_id: u64, // used for local <-> server communication
    pub supported_encoding: SupportedEncoding,
    pub restarting_remote_device: bool,
    pub force_relay: bool,
    switch_uuid: Option<String>,
    pub success_time: Option<hbb_common::tokio::time::Instant>,
    pub direct_error_counter: usize,
}

impl Deref for LoginConfigHandler {
    type Target = PeerConfig;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

/// Load [`PeerConfig`] from id.
///
/// # Arguments
///
/// * `id` - id of peer
#[inline]
pub fn load_config(id: &str) -> PeerConfig {
    PeerConfig::load(id)
}

impl LoginConfigHandler {
    /// Initialize the login config handler.
    ///
    /// # Arguments
    ///
    /// * `id` - id of peer
    /// * `conn_type` - Connection type enum.
    pub fn initialize(
        &mut self,
        id: String,
        conn_type: ConnType,
        switch_uuid: Option<String>,
        force_relay: bool,
		tokenex: String,
    ) {
        self.id = id;
        self.conn_type = conn_type;
		self.tokenex = tokenex;
        let config = self.load_config();
        self.remember = !config.password.is_empty();
        self.config = config;
        self.session_id = rand::random();
        self.supported_encoding = Default::default();
        self.restarting_remote_device = false;
        self.force_relay = !self.get_option("force-always-relay").is_empty() || force_relay;
        self.switch_uuid = switch_uuid;
        self.success_time = None;
        self.direct_error_counter = 0;
    }
/*
    // XXX: fix conflicts between with config that introduces by Deref.
    pub fn set_reconnect_password(&mut self, password: Vec<u8>) {
        self.password = password
    }

    // XXX: fix conflicts between with config that introduces by Deref.
    pub fn get_reconnect_password(&self) -> Vec<u8> {
        return self.password.clone();
    }
*/
    pub fn should_auto_login(&self) -> String {
        let l = self.lock_after_session_end.v;
        let a = !self.get_option("auto-login").is_empty();
        let p = self.get_option("os-password");
        if !p.is_empty() && l && a {
            p
        } else {
            "".to_owned()
        }
    }

    /// Load [`PeerConfig`].
    fn load_config(&self) -> PeerConfig {
        load_config(&self.id)
    }

    /// Save a [`PeerConfig`] into the handler.
    ///
    /// # Arguments
    ///
    /// * `config` - [`PeerConfig`] to save.
    pub fn save_config(&mut self, config: PeerConfig) {
        config.store(&self.id);
        self.config = config;
    }

    /// Set an option for handler's [`PeerConfig`].
    ///
    /// # Arguments
    ///
    /// * `k` - key of option
    /// * `v` - value of option
    pub fn set_option(&mut self, k: String, v: String) {
        let mut config = self.load_config();
        config.options.insert(k, v);
        self.save_config(config);
    }

    //to-do: too many dup code below.
    
    /// Save view style to the current config.
    ///
    /// # Arguments
    ///
    /// * `value` - The view style to be saved.
    pub fn save_view_style(&mut self, value: String) {
        let mut config = self.load_config();
        config.view_style = value;
        self.save_config(config);
    }

    /// Save keyboard mode to the current config.
    ///
    /// # Arguments
    ///
    /// * `value` - The view style to be saved.
    pub fn save_keyboard_mode(&mut self, value: String) {
        let mut config = self.load_config();
        config.keyboard_mode = value;
        self.save_config(config);
    }

    /// Save scroll style to the current config.
    ///
    /// # Arguments
    ///
    /// * `value` - The view style to be saved.
    pub fn save_scroll_style(&mut self, value: String) {
        let mut config = self.load_config();
        config.scroll_style = value;
        self.save_config(config);
    }

    /// Set a ui config of flutter for handler's [`PeerConfig`].
    ///
    /// # Arguments
    ///
    /// * `k` - key of option
    /// * `v` - value of option
    pub fn save_ui_flutter(&mut self, k: String, v: String) {
        let mut config = self.load_config();
        config.ui_flutter.insert(k, v);
        self.save_config(config);
    }

    /// Get a ui config of flutter for handler's [`PeerConfig`].
    /// Return String if the option is found, otherwise return "".
    ///
    /// # Arguments
    ///
    /// * `k` - key of option
    pub fn get_ui_flutter(&self, k: &str) -> String {
        if let Some(v) = self.config.ui_flutter.get(k) {
            v.clone()
        } else {
            "".to_owned()
        }
    }

    /// Toggle an option in the handler.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the option to toggle.
    pub fn toggle_option(&mut self, name: String) -> Option<Message> {
        let mut option = OptionMessage::default();
        let mut config = self.load_config();
        if name == "show-remote-cursor" {
            config.show_remote_cursor.v = !config.show_remote_cursor.v;
            option.show_remote_cursor = (if config.show_remote_cursor.v {
                BoolOption::Yes
            } else {
                BoolOption::No
            })
            .into();
        } else if name == "disable-audio" {
            config.disable_audio.v = !config.disable_audio.v;
            option.disable_audio = (if config.disable_audio.v {
                BoolOption::Yes
            } else {
                BoolOption::No
            })
            .into();
        } else if name == "disable-clipboard" {
            config.disable_clipboard.v = !config.disable_clipboard.v;
            option.disable_clipboard = (if config.disable_clipboard.v {
                BoolOption::Yes
            } else {
                BoolOption::No
            })
            .into();
        } else if name == "lock-after-session-end" {
            config.lock_after_session_end.v = !config.lock_after_session_end.v;
            option.lock_after_session_end = (if config.lock_after_session_end.v {
                BoolOption::Yes
            } else {
                BoolOption::No
            })
            .into();
        } else if name == "privacy-mode" {
            // try toggle privacy mode
            option.privacy_mode = (if config.privacy_mode.v {
                BoolOption::No
            } else {
                BoolOption::Yes
            })
            .into();
        } else if name == "enable-file-transfer" {
            config.enable_file_transfer.v = !config.enable_file_transfer.v;
            option.enable_file_transfer = (if config.enable_file_transfer.v {
                BoolOption::Yes
            } else {
                BoolOption::No
            })
            .into();
        } else if name == "block-input" {
            option.block_input = BoolOption::Yes.into();
        } else if name == "unblock-input" {
            option.block_input = BoolOption::No.into();
        } else if name == "show-quality-monitor" {
            config.show_quality_monitor.v = !config.show_quality_monitor.v;
        } else if name == "allow_swap_key" {
            config.allow_swap_key.v = !config.allow_swap_key.v;
        } else if name == "view-only" {
            config.view_only.v = !config.view_only.v;
            let f = |b: bool| {
                if b {
                    BoolOption::Yes.into()
                } else {
                    BoolOption::No.into()
                }
            };
            if config.view_only.v {
                option.disable_keyboard = f(true);
                option.disable_clipboard = f(true);
                option.show_remote_cursor = f(true);
            } else {
                option.disable_keyboard = f(false);
                option.disable_clipboard = f(self.get_toggle_option("disable-clipboard"));
                option.show_remote_cursor = f(self.get_toggle_option("show-remote-cursor"));
            }
        } else {
            let is_set = self
                .options
                .get(&name)
                .map(|o| !o.is_empty())
                .unwrap_or(false);
            if is_set {
                if name == "zoom-cursor" {
                    self.config.options.insert(name, "".to_owned());
                } else {
                    // Notice: When PeerConfig loads, the default value is taken when the option key does not exist.
                    self.config.options.remove(&name);
                }
            } else {
                self.config.options.insert(name, "Y".to_owned());
            }
            self.config.store(&self.id);
            return None;
        }
        if !name.contains("block-input") {
            self.save_config(config);
        }
        let mut misc = Misc::new();
        misc.set_option(option);
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        Some(msg_out)
    }

    /// Get [`PeerConfig`] of the current [`LoginConfigHandler`].
    ///
    /// # Arguments
    pub fn get_config(&mut self) -> &mut PeerConfig {
        &mut self.config
    }

    /// Get [`OptionMessage`] of the current [`LoginConfigHandler`].
    /// Return `None` if there's no option, for example, when the session is only for file transfer.
    ///
    /// # Arguments
    ///
    /// * `ignore_default` - If `true`, ignore the default value of the option.
    fn get_option_message(&self, ignore_default: bool) -> Option<OptionMessage> {
        if self.conn_type.eq(&ConnType::FILE_TRANSFER)
            || self.conn_type.eq(&ConnType::PORT_FORWARD)
            || self.conn_type.eq(&ConnType::RDP)
        {
            return None;
        }
        let mut n = 0;
        let mut msg = OptionMessage::new();
        let q = self.image_quality.clone();
        if let Some(q) = self.get_image_quality_enum(&q, ignore_default) {
            msg.image_quality = q.into();
            n += 1;
        } else if q == "custom" {
            let config = PeerConfig::load(&self.id);
            let quality = if config.custom_image_quality.is_empty() {
                50
            } else {
                config.custom_image_quality[0]
            };
            msg.custom_image_quality = quality << 8;
            #[cfg(feature = "flutter")]
            if let Some(custom_fps) = self.options.get("custom-fps") {
                msg.custom_fps = custom_fps.parse().unwrap_or(30);
            }
            n += 1;
        }
        let view_only = self.get_toggle_option("view-only");
        if view_only {
            msg.disable_keyboard = BoolOption::Yes.into();
            n += 1;
        }
        if view_only || self.get_toggle_option("show-remote-cursor") {
            msg.show_remote_cursor = BoolOption::Yes.into();
            n += 1;
        }
        if self.get_toggle_option("lock-after-session-end") {
            msg.lock_after_session_end = BoolOption::Yes.into();
            n += 1;
        }
        if self.get_toggle_option("disable-audio") {
            msg.disable_audio = BoolOption::Yes.into();
            n += 1;
        }
        if self.get_toggle_option("enable-file-transfer") {
            msg.enable_file_transfer = BoolOption::Yes.into();
            n += 1;
        }
        if view_only || self.get_toggle_option("disable-clipboard") {
            msg.disable_clipboard = BoolOption::Yes.into();
            n += 1;
        }
        msg.supported_decoding =
            hbb_common::protobuf::MessageField::some(Decoder::supported_decodings(Some(&self.id)));
        n += 1;

        if n > 0 {
            Some(msg)
        } else {
            None
        }
    }

    pub fn get_option_message_after_login(&self) -> Option<OptionMessage> {
        if self.conn_type.eq(&ConnType::FILE_TRANSFER)
            || self.conn_type.eq(&ConnType::PORT_FORWARD)
            || self.conn_type.eq(&ConnType::RDP)
        {
            return None;
        }
        let mut n = 0;
        let mut msg = OptionMessage::new();
        if self.get_toggle_option("privacy-mode") {
            msg.privacy_mode = BoolOption::Yes.into();
            n += 1;
        }
        if n > 0 {
            Some(msg)
        } else {
            None
        }
    }

    /// Parse the image quality option.
    /// Return [`ImageQuality`] if the option is valid, otherwise return `None`.
    ///
    /// # Arguments
    ///
    /// * `q` - The image quality option.
    /// * `ignore_default` - Ignore the default value.
    fn get_image_quality_enum(&self, q: &str, ignore_default: bool) -> Option<ImageQuality> {
        if q == "low" {
            Some(ImageQuality::Low)
        } else if q == "best" {
            Some(ImageQuality::Best)
        } else if q == "balanced" {
            if ignore_default {
                None
            } else {
                Some(ImageQuality::Balanced)
            }
        } else {
            None
        }
    }

    /// Get the status of a toggle option.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the toggle option.
    pub fn get_toggle_option(&self, name: &str) -> bool {
        if name == "show-remote-cursor" {
            self.config.show_remote_cursor.v
        } else if name == "lock-after-session-end" {
            self.config.lock_after_session_end.v
        } else if name == "privacy-mode" {
            self.config.privacy_mode.v
        } else if name == "enable-file-transfer" {
            self.config.enable_file_transfer.v
        } else if name == "disable-audio" {
            self.config.disable_audio.v
        } else if name == "disable-clipboard" {
            self.config.disable_clipboard.v
        } else if name == "show-quality-monitor" {
            self.config.show_quality_monitor.v
        } else if name == "allow_swap_key" {
            self.config.allow_swap_key.v
        } else if name == "view-only" {
            self.config.view_only.v
        } else {
            !self.get_option(name).is_empty()
        }
    }

    pub fn is_privacy_mode_supported(&self) -> bool {
        if let Some(features) = &self.features {
            features.privacy_mode
        } else {
            false
        }
    }

    pub fn refresh() -> Message {
        let mut misc = Misc::new();
        misc.set_refresh_video(true);
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        msg_out
    }

    /// Create a [`Message`] for saving custom image quality.
    ///
    /// # Arguments
    ///
    /// * `bitrate` - The given bitrate.
    /// * `quantizer` - The given quantizer.
    pub fn save_custom_image_quality(&mut self, image_quality: i32) -> Message {
        let mut misc = Misc::new();
        misc.set_option(OptionMessage {
            custom_image_quality: image_quality << 8,
            ..Default::default()
        });
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        let mut config = self.load_config();
        config.image_quality = "custom".to_owned();
        config.custom_image_quality = vec![image_quality as _];
        self.save_config(config);
        msg_out
    }

    /// Save the given image quality to the config.
    /// Return a [`Message`] that contains image quality, or `None` if the image quality is not valid.
    /// # Arguments
    ///
    /// * `value` - The image quality.
    pub fn save_image_quality(&mut self, value: String) -> Option<Message> {
        let mut res = None;
        if let Some(q) = self.get_image_quality_enum(&value, false) {
            let mut misc = Misc::new();
            misc.set_option(OptionMessage {
                image_quality: q.into(),
                ..Default::default()
            });
            let mut msg_out = Message::new();
            msg_out.set_misc(misc);
            res = Some(msg_out);
        }
        let mut config = self.load_config();
        config.image_quality = value;
        self.save_config(config);
        res
    }

    /// Create a [`Message`] for saving custom fps.
    ///
    /// # Arguments
    ///
    /// * `fps` - The given fps.
    pub fn set_custom_fps(&mut self, fps: i32) -> Message {
        let mut misc = Misc::new();
        misc.set_option(OptionMessage {
            custom_fps: fps,
            ..Default::default()
        });
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        let mut config = self.load_config();
        config
            .options
            .insert("custom-fps".to_owned(), fps.to_string());
        self.save_config(config);
        msg_out
    }

    pub fn get_option(&self, k: &str) -> String {
        if let Some(v) = self.config.options.get(k) {
            v.clone()
        } else {
            "".to_owned()
        }
    }

    #[inline]
    pub fn get_custom_resolution(&self, display: i32) -> Option<(i32, i32)> {
        self.config
            .custom_resolutions
            .get(&display.to_string())
            .map(|r| (r.w, r.h))
    }

    #[inline]
    pub fn set_custom_resolution(&mut self, display: i32, wh: Option<(i32, i32)>) {
        let display = display.to_string();
        let mut config = self.load_config();
        match wh {
            Some((w, h)) => {
                config
                    .custom_resolutions
                    .insert(display, Resolution { w, h });
            }
            None => {
                config.custom_resolutions.remove(&display);
            }
        }
        self.save_config(config);
    }
    
    pub fn handle_login_error(&mut self, err: &str, interface: &impl Interface) -> bool {
        if err == "Wrong Password" {
            self.password = Default::default();
            interface.msgbox("re-input-password", err, "Do you want to enter again?", "");
            true
        } else if err == "2FA Not Authorized" {
            self.password = Default::default();
            interface.msgbox(
                "re-input-password-2fa",
                "Login Error",
                err,
                "Do you want to enter again and accept 2fa?",
            );
            true
        } else if err == "No Password Access" {
            self.password = Default::default();
            interface.msgbox(
                "wait-remote-accept-nook",
                "Prompt",
                "Please wait for the remote side to accept your session request...",
                "",
            );
            true
        } else {
            if err.contains(SCRAP_X11_REQUIRED) {
                interface.msgbox("error", "Login Error", err, SCRAP_X11_REF_URL);
            } else {
                interface.msgbox("error", "Login Error", err, "");
            }
            false
        }
    }

    /// Get user name.
    /// Return the name of the given peer. If the peer has no name, return the name in the config.
    ///
    /// # Arguments
    ///
    /// * `pi` - peer info.
    pub fn get_username(&self, pi: &PeerInfo) -> String {
        return if pi.username.is_empty() {
            self.info.username.clone()
        } else {
            pi.username.clone()
        };
    }

    /// Handle peer info.
    ///
    /// # Arguments
    ///
    /// * `username` - The name of the peer.
    /// * `pi` - The peer info.
    pub fn handle_peer_info(&mut self, pi: &PeerInfo) {
        if !pi.version.is_empty() {
            self.version = hbb_common::get_version_number(&pi.version);
        }
        self.features = pi.features.clone().into_option();
        let serde = PeerInfoSerde {
            username: pi.username.clone(),
            hostname: pi.hostname.clone(),
            platform: pi.platform.clone(),
        };
        let mut config = self.load_config();
        config.info = serde;
        let password = self.password.clone();
        let password0 = config.password.clone();
		
        let remember = self.remember;
        if remember {
            if !password.is_empty() && password != password0 {
                config.password = password;
                log::debug!("remember password of {}", self.id);
            }
        } else {
            if !password0.is_empty() {
                config.password = Default::default();
                log::debug!("remove password of {}", self.id);
            }
        }
        if config.keyboard_mode.is_empty() {
            if is_keyboard_mode_supported(&KeyboardMode::Map, get_version_number(&pi.version)) {
                config.keyboard_mode = KeyboardMode::Map.to_string();
            } else {
                config.keyboard_mode = KeyboardMode::Legacy.to_string();
            }
        } else {
            let keyboard_modes =
                crate::get_supported_keyboard_modes(get_version_number(&pi.version));
            let current_mode = &KeyboardMode::from_str(&config.keyboard_mode).unwrap_or_default();
            if !keyboard_modes.contains(current_mode) {
                config.keyboard_mode = KeyboardMode::Legacy.to_string();
            }
        }
        //self.conn_id = pi.conn_id;
        // no matter if change, for update file time
        self.save_config(config);
		self.supported_encoding = pi.encoding.clone().unwrap_or_default();
    }

    pub fn get_remote_dir(&self) -> String {
        serde_json::from_str::<HashMap<String, String>>(&self.get_option("remote_dir"))
            .unwrap_or_default()
            .remove(&self.info.username)
            .unwrap_or_default()
    }

    pub fn get_all_remote_dir(&self, path: String) -> String {
        let d = self.get_option("remote_dir");
        let user = self.info.username.clone();
        let mut x = serde_json::from_str::<HashMap<String, String>>(&d).unwrap_or_default();
        if path.is_empty() {
            x.remove(&user);
        } else {
            x.insert(user, path);
        }
        serde_json::to_string::<HashMap<String, String>>(&x).unwrap_or_default()
    }

    /// Create a [`Message`] for login.
    fn create_login_msg(
        &self,
        os_username: String,
        os_password: String,
        password: Vec<u8>,
    ) -> Message {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        let my_id = Config::get_id_or(crate::common::DEVICE_ID.lock().unwrap().clone());
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let my_id = Config::get_id();
		let avatar = Config::get_option("avatar");
		//let mut tokenex = "NOTOKEN".to_string();

		#[cfg(not(any(target_os = "android", target_os = "ios")))]
        let tokenex = std::fs::read_to_string(Config::path("LastToken.toml")).unwrap_or_else(|err| {
                eprintln!("Error reading file: {}", err);
                String::new()
            });

		#[cfg(any(target_os = "android", target_os = "ios"))]
		let tokenex = "".to_string();
		
		
        let mut lr = LoginRequest {
            username: self.id.clone(),
            password: password.into(),
			tokenex: tokenex,
            my_id,
            my_name: crate::username(),
            option: self.get_option_message(true).into(),
            session_id: self.session_id,
            version: crate::VERSION.to_string(),
            os_login: Some(OSLogin {
                username: os_username,
                password: os_password,
                ..Default::default()
            })
            .into(),
			avatar_image: avatar,
            ..Default::default()
        };
		match self.conn_type {
            ConnType::FILE_TRANSFER => lr.set_file_transfer(FileTransfer {
                dir: self.get_remote_dir(),
                show_hidden: !self.get_option("remote_show_hidden").is_empty(),
                ..Default::default()
            }),
            ConnType::PORT_FORWARD | ConnType::RDP => lr.set_port_forward(PortForward {
                host: self.port_forward.0.clone(),
                port: self.port_forward.1,
                ..Default::default()
            }),
            _ => {}
        }

        let mut msg_out = Message::new();
        msg_out.set_login_request(lr);
        msg_out
    }

    pub fn change_prefer_codec(&self) -> Message {
        let decoding = scrap::codec::Decoder::supported_decodings(Some(&self.id));
        let mut misc = Misc::new();
        misc.set_option(OptionMessage {
            supported_decoding: hbb_common::protobuf::MessageField::some(decoding),
            ..Default::default()
        });
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        msg_out
    }

    pub fn restart_remote_device(&self) -> Message {
        let mut misc = Misc::new();
        misc.set_restart_remote_device(true);
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        msg_out
    }
    /*

    pub fn set_force_relay(&mut self, direct: bool, received: bool, err: String) {
        self.force_relay = false;
        if direct && !received {
            let errno = errno::errno().0;
            // TODO: check mac and ios
            if cfg!(windows) && (errno == 10054 || err.contains("10054"))
                || !cfg!(windows) && (errno == 104 || err.contains("104"))
            {
                self.force_relay = true;
                self.set_option("force-always-relay".to_owned(), "Y".to_owned());
            }
        }
    }
    */
}

/// Media data.
pub enum MediaData {
    VideoQueue,
    VideoFrame(Box<VideoFrame>),
    AudioFrame(Box<AudioFrame>),
    AudioFormat(AudioFormat),
    Reset,
    RecordScreen(bool, i32, i32, String),
}

pub type MediaSender = mpsc::Sender<MediaData>;

/// Start video and audio thread.
/// Return two [`MediaSender`], they should be given to the media producer.
///
/// # Arguments
///
/// * `video_callback` - The callback for video frame. Being called when a video frame is ready.
pub fn start_video_audio_threads<F>(
    video_callback: F,
) -> (
    MediaSender,
    MediaSender,
    Arc<ArrayQueue<VideoFrame>>,
    Arc<AtomicUsize>,
)
where
    F: 'static + FnMut(&mut scrap::ImageRgb) + Send,
{
    let (video_sender, video_receiver) = mpsc::channel::<MediaData>();
    let video_queue = Arc::new(ArrayQueue::<VideoFrame>::new(VIDEO_QUEUE_SIZE));
    let video_queue_cloned = video_queue.clone();
    let mut video_callback = video_callback;
    let mut duration = std::time::Duration::ZERO;
    let mut count = 0;
    let fps = Arc::new(AtomicUsize::new(0));
    let decode_fps = fps.clone();
    let mut skip_beginning = 0;

    std::thread::spawn(move || {
        let mut video_handler = VideoHandler::new();
        loop {
            if let Ok(data) = video_receiver.recv() {
                match data {
                    MediaData::VideoFrame(_) | MediaData::VideoQueue => {
                        let vf = if let MediaData::VideoFrame(vf) = data {
                            *vf
                        } else {
                            if let Some(vf) = video_queue.pop() {
                                vf
                            } else {
                                continue;
                            }
                        };
                        let start = std::time::Instant::now();
                        if let Ok(true) = video_handler.handle_frame(vf) {
                            video_callback(&mut video_handler.rgb);
                            // fps calculation
                            // The first frame will be very slow
                            if skip_beginning < 5 {
                                skip_beginning += 1;
                                continue;
                            }
                            duration += start.elapsed();
                            count += 1;
                            if count % 10 == 0 {
                                fps.store(
                                    (count * 1000 / duration.as_millis()) as usize,
                                    Ordering::Relaxed,
                                );
                            }
                            // Clear to get real-time fps
                            if count > 300 {
                                count = 0;
                                duration = Duration::ZERO;
                            }
                        }
                    }
                    MediaData::Reset => {
                        video_handler.reset();
                    }
                    MediaData::RecordScreen(start, w, h, id) => {
                        video_handler.record_screen(start, w, h, id)
                    }
                    _ => {}
                }
            } else {
                break;
            }
        }
        log::info!("Video decoder loop exits");
    });
    let audio_sender = start_audio_thread();
    return (video_sender, audio_sender, video_queue_cloned, decode_fps);
}

/// Start an audio thread
/// Return a audio [`MediaSender`]
pub fn start_audio_thread() -> MediaSender {
    let (audio_sender, audio_receiver) = mpsc::channel::<MediaData>();
    std::thread::spawn(move || {
        let mut audio_handler = AudioHandler::default();
        loop {
            if let Ok(data) = audio_receiver.recv() {
                match data {
                    MediaData::AudioFrame(af) => {
                        audio_handler.handle_frame(*af);
                    }
                    MediaData::AudioFormat(f) => {
                        log::debug!("recved audio format, sample rate={}", f.sample_rate);
                        audio_handler.handle_format(f);
                    }
                    _ => {}
                }
            } else {
                break;
            }
        }
        log::info!("Audio decoder loop exits");
    });
    audio_sender
}

/// Handle latency test.
///
/// # Arguments
///
/// * `t` - The latency test message.
/// * `peer` - The peer.
pub async fn handle_test_delay(t: TestDelay, peer: &mut Stream) {
    if !t.from_client {
        let mut msg_out = Message::new();
        msg_out.set_test_delay(t);
        allow_err!(peer.send(&msg_out).await);
    }
}

/// Whether is track pad scrolling.
#[inline]
#[cfg(all(target_os = "macos", not(feature = "flutter")))]
fn check_scroll_on_mac(mask: i32, x: i32, y: i32) -> bool {
    // flutter version we set mask type bit to 4 when track pad scrolling.
    if mask & 7 == crate::input::MOUSE_TYPE_TRACKPAD {
        return true;
    }
    if mask & 3 != crate::input::MOUSE_TYPE_WHEEL {
        return false;
    }
    let btn = mask >> 3;
    if y == -1 {
        btn != 0xff88 && btn != -0x780000
    } else if y == 1 {
        btn != 0x78 && btn != 0x780000
    } else if x != 0 {
        // No mouse support horizontal scrolling.
        true
    } else {
        false
    }
}

/// Send mouse data.
///
/// # Arguments
///
/// * `mask` - Mouse event.
///     * mask = buttons << 3 | type
///     * type, 1: down, 2: up, 3: wheel
///     * buttons, 1: left, 2: right, 4: middle
/// * `x` - X coordinate.
/// * `y` - Y coordinate.
/// * `alt` - Whether the alt key is pressed.
/// * `ctrl` - Whether the ctrl key is pressed.
/// * `shift` - Whether the shift key is pressed.
/// * `command` - Whether the command key is pressed.
/// * `interface` - The interface for sending data.
#[inline]
pub fn send_mouse(
    mask: i32,
    x: i32,
    y: i32,
    alt: bool,
    ctrl: bool,
    shift: bool,
    command: bool,
    interface: &impl Interface,
) {
    let mut msg_out = Message::new();
    let mut mouse_event = MouseEvent {
        mask,
        x,
        y,
        ..Default::default()
    };
    if alt {
        mouse_event.modifiers.push(ControlKey::Alt.into());
    }
    if shift {
        mouse_event.modifiers.push(ControlKey::Shift.into());
    }
    if ctrl {
        mouse_event.modifiers.push(ControlKey::Control.into());
    }
    if command {
        mouse_event.modifiers.push(ControlKey::Meta.into());
    }
    #[cfg(all(target_os = "macos", not(feature = "flutter")))]
    if check_scroll_on_mac(mask, x, y) {
        let factor = 3;
        mouse_event.mask = crate::input::MOUSE_TYPE_TRACKPAD;
        mouse_event.x *= factor;
        mouse_event.y *= factor;
    }
    interface.swap_modifier_mouse(&mut mouse_event);
    msg_out.set_mouse_event(mouse_event);
    interface.send(Data::Message(msg_out));
}

#[inline]
pub fn send_pointer_device_event(
    mut evt: PointerDeviceEvent,
    alt: bool,
    ctrl: bool,
    shift: bool,
    command: bool,
    interface: &impl Interface,
) {
    let mut msg_out = Message::new();
    if alt {
        evt.modifiers.push(ControlKey::Alt.into());
    }
    if shift {
        evt.modifiers.push(ControlKey::Shift.into());
    }
    if ctrl {
        evt.modifiers.push(ControlKey::Control.into());
    }
    if command {
        evt.modifiers.push(ControlKey::Meta.into());
    }
    msg_out.set_pointer_device_event(evt);
    interface.send(Data::Message(msg_out));
}


/// Activate OS by sending mouse movement.
///
/// # Arguments
///
/// * `interface` - The interface for sending data.
fn activate_os(interface: &impl Interface) {
    send_mouse(0, 0, 0, false, false, false, false, interface);
    std::thread::sleep(Duration::from_millis(50));
    send_mouse(0, 3, 3, false, false, false, false, interface);
    std::thread::sleep(Duration::from_millis(50));
    send_mouse(1 | 1 << 3, 0, 0, false, false, false, false, interface);
    send_mouse(2 | 1 << 3, 0, 0, false, false, false, false, interface);
    /*
    let mut key_event = KeyEvent::new();
    // do not use Esc, which has problem with Linux
    key_event.set_control_key(ControlKey::RightArrow);
    key_event.press = true;
    let mut msg_out = Message::new();
    msg_out.set_key_event(key_event.clone());
    interface.send(Data::Message(msg_out.clone()));
    */
}

/// Input the OS's password.
///
/// # Arguments
///
/// * `p` - The password.
/// * `avtivate` - Whether to activate OS.
/// * `interface` - The interface for sending data.
pub fn input_os_password(p: String, activate: bool, interface: impl Interface) {
    std::thread::spawn(move || {
        _input_os_password(p, activate, interface);
    });
}

/// Input the OS's password.
///
/// # Arguments
///
/// * `p` - The password.
/// * `avtivate` - Whether to activate OS.
/// * `interface` - The interface for sending data.
fn _input_os_password(p: String, activate: bool, interface: impl Interface) {
    if activate {
        activate_os(&interface);
        std::thread::sleep(Duration::from_millis(1200));
    }
    let mut key_event = KeyEvent::new();
    key_event.press = true;
    let mut msg_out = Message::new();
    key_event.set_seq(p);
    msg_out.set_key_event(key_event.clone());
    interface.send(Data::Message(msg_out.clone()));
    key_event.set_control_key(ControlKey::Return);
    msg_out.set_key_event(key_event);
    interface.send(Data::Message(msg_out));
}

#[derive(Copy, Clone)]
struct LoginErrorMsgBox {
    msgtype: &'static str,
    title: &'static str,
    text: &'static str,
    link: &'static str,
    try_again: bool,
}

lazy_static::lazy_static! {
    static ref LOGIN_ERROR_MAP: Arc<HashMap<&'static str, LoginErrorMsgBox>> = {
        use hbb_common::config::LINK_HEADLESS_LINUX_SUPPORT;
        let map = HashMap::from([(LOGIN_MSG_DESKTOP_SESSION_NOT_READY, LoginErrorMsgBox{
            msgtype: "session-login",
            title: "",
            text: "",
            link: "",
            try_again: true,
        }), (LOGIN_MSG_DESKTOP_XSESSION_FAILED, LoginErrorMsgBox{
            msgtype: "session-re-login",
            title: "",
            text: "",
            link: "",
            try_again: true,
        }), (LOGIN_MSG_DESKTOP_SESSION_ANOTHER_USER, LoginErrorMsgBox{
            msgtype: "info-nocancel",
            title: "another_user_login_title_tip",
            text: "another_user_login_text_tip",
            link: "",
            try_again: false,
        }), (LOGIN_MSG_DESKTOP_XORG_NOT_FOUND, LoginErrorMsgBox{
            msgtype: "info-nocancel",
            title: "xorg_not_found_title_tip",
            text: "xorg_not_found_text_tip",
            link: LINK_HEADLESS_LINUX_SUPPORT,
            try_again: true,
        }), (LOGIN_MSG_DESKTOP_NO_DESKTOP, LoginErrorMsgBox{
            msgtype: "info-nocancel",
            title: "no_desktop_title_tip",
            text: "no_desktop_text_tip",
            link: LINK_HEADLESS_LINUX_SUPPORT,
            try_again: true,
        }), (LOGIN_MSG_DESKTOP_SESSION_NOT_READY_PASSWORD_EMPTY, LoginErrorMsgBox{
            msgtype: "session-login-password",
            title: "",
            text: "",
            link: "",
            try_again: true,
        }), (LOGIN_MSG_DESKTOP_SESSION_NOT_READY_PASSWORD_WRONG, LoginErrorMsgBox{
            msgtype: "session-login-re-password",
            title: "",
            text: "",
            link: "",
            try_again: true,
        }), (LOGIN_MSG_NO_PASSWORD_ACCESS, LoginErrorMsgBox{
            msgtype: "wait-remote-accept-nook",
            title: "Prompt",
            text: "Please wait for the remote side to accept your session request...",
            link: "",
            try_again: true,
        })]);
        Arc::new(map)
    };
}

/// Handle login error.
/// Return true if the password is wrong, return false if there's an actual error.
pub fn handle_login_error(
    lc: Arc<RwLock<LoginConfigHandler>>,
    err: &str,
    interface: &impl Interface,
) -> bool {
    if err == LOGIN_MSG_PASSWORD_EMPTY {
        lc.write().unwrap().password = Default::default();
        interface.msgbox("input-password", "Password Required", "", "");
        true
    } else if err == LOGIN_MSG_PASSWORD_WRONG {
        lc.write().unwrap().password = Default::default();
        interface.msgbox("re-input-password", err, "Do you want to enter again?", "");
        true
    } else if LOGIN_ERROR_MAP.contains_key(err) {
        if let Some(msgbox_info) = LOGIN_ERROR_MAP.get(err) {
            interface.msgbox(
                msgbox_info.msgtype,
                msgbox_info.title,
                msgbox_info.text,
                msgbox_info.link,
            );
            msgbox_info.try_again
        } else {
            // unreachable!
            false
        }
    } else {
        if err.contains(SCRAP_X11_REQUIRED) {
            interface.msgbox("error", "Login Error", err, SCRAP_X11_REF_URL);
        } else {
            interface.msgbox("error", "Login Error", err, "");
        }
        false
    }
}

/// Handle hash message sent by peer.
/// Hash will be used for login.
///
/// # Arguments
///
/// * `lc` - Login config.
/// * `hash` - Hash sent by peer.
/// * `interface` - [`Interface`] for sending data.
/// * `peer` - [`Stream`] for communicating with peer.
pub async fn handle_hash(
    lc: Arc<RwLock<LoginConfigHandler>>,
    password_preset: &str,
    hash: Hash,
    interface: &impl Interface,
    peer: &mut Stream,
) {
    lc.write().unwrap().hash = hash.clone();
    let uuid = lc.read().unwrap().switch_uuid.clone();
    if let Some(uuid) = uuid {
        if let Ok(uuid) = uuid::Uuid::from_str(&uuid) {
            send_switch_login_request(lc.clone(), peer, uuid).await;
            return;
        }
    }
    //let mut password = lc.read().unwrap().get_reconnect_password();
    let mut password = lc.read().unwrap().password.clone();
    if password.is_empty() {
        if !password_preset.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(password_preset);
            hasher.update(&hash.salt);
            let res = hasher.finalize();
            password = res[..].into();
        }
    }
    if password.is_empty() {
        password = lc.read().unwrap().config.password.clone();
    }
    let password = if password.is_empty() {
        // login without password, the remote side can click accept
        interface.msgbox("input-password", "Password Required", "", "");
        Vec::new()
    } else {
        let mut hasher = Sha256::new();
        hasher.update(&password);
        hasher.update(&hash.challenge);
        hasher.finalize()[..].into()
    };

    let os_username = lc.read().unwrap().get_option("os-username");
    let os_password = lc.read().unwrap().get_option("os-password");

    send_login(lc.clone(), os_username, os_password, password, peer).await;
    lc.write().unwrap().hash = hash;
}

/// Send login message to peer.
///
/// # Arguments
///
/// * `lc` - Login config.
/// * `os_username` - OS username.
/// * `os_password` - OS password.
/// * `password` - Password.
/// * `peer` - [`Stream`] for communicating with peer.
async fn send_login(
    lc: Arc<RwLock<LoginConfigHandler>>,
    os_username: String,
    os_password: String,
    password: Vec<u8>,
    peer: &mut Stream,
) {
    let msg_out = lc
        .read()
        .unwrap()
        .create_login_msg(os_username, os_password, password);
    allow_err!(peer.send(&msg_out).await);
}

/// Handle login request made from ui.
///
/// # Arguments
///
/// * `lc` - Login config.
/// * `os_username` - OS username.
/// * `os_password` - OS password.
/// * `password` - Password.
/// * `remember` - Whether to remember password.
/// * `peer` - [`Stream`] for communicating with peer.
pub async fn handle_login_from_ui(
    lc: Arc<RwLock<LoginConfigHandler>>,
    os_username: String,
    os_password: String,
    password: String,
    remember: bool,
    peer: &mut Stream,
) {
    let mut hash_password = if password.is_empty() {
        let mut password2 = lc.read().unwrap().password.clone();
        if password2.is_empty() {
            password2 = lc.read().unwrap().config.password.clone();
        }
        password2
    } else {
	    let mut hasher = Sha256::new();
	    hasher.update(password);
	    hasher.update(&lc.read().unwrap().hash.salt);
	    let res = hasher.finalize();
	    lc.write().unwrap().remember = remember;
	    //lc.write().unwrap().set_reconnect_password(res[..].into());
	    lc.write().unwrap().password = res[..].into();
        res[..].into()
    };
    let mut hasher2 = Sha256::new();
    hasher2.update(&hash_password[..]);
    hasher2.update(&lc.read().unwrap().hash.challenge);
    hash_password = hasher2.finalize()[..].to_vec();

    send_login(lc.clone(), os_username, os_password, hash_password, peer).await;
}

async fn send_switch_login_request(
    lc: Arc<RwLock<LoginConfigHandler>>,
    peer: &mut Stream,
    uuid: Uuid,
) {
    let mut msg_out = Message::new();
    msg_out.set_switch_sides_response(SwitchSidesResponse {
        uuid: Bytes::from(uuid.as_bytes().to_vec()),
        lr: hbb_common::protobuf::MessageField::some(
            lc.read()
                .unwrap()
                .create_login_msg("".to_owned(), "".to_owned(), vec![])
                .login_request()
                .to_owned(),
        ),
        ..Default::default()
    });
    allow_err!(peer.send(&msg_out).await);
}

/// Interface for client to send data and commands.
#[async_trait]
pub trait Interface: Send + Clone + 'static + Sized {
    /// Send message data to remote peer.
    fn send(&self, data: Data);
    fn msgbox(&self, msgtype: &str, title: &str, text: &str, link: &str);
    fn handle_login_error(&mut self, err: &str) -> bool;
    fn handle_peer_info(&mut self, pi: PeerInfo);
    fn set_force_relay(&mut self, direct: bool, received: bool);
    fn on_error(&self, err: &str) {
        self.msgbox("error", "Error", err, "");
    }
    fn is_force_relay(&self) -> bool;
    async fn handle_hash(&mut self, pass: &str, hash: Hash, peer: &mut Stream);
    async fn handle_login_from_ui(
        &mut self,
        os_username: String,
        os_password: String,
        password: String,
        remember: bool,
        peer: &mut Stream,
    );
    async fn handle_test_delay(&mut self, t: TestDelay, peer: &mut Stream);

    fn get_login_config_handler(&self) -> Arc<RwLock<LoginConfigHandler>>;

    fn swap_modifier_mouse(&self, _msg: &mut hbb_common::protos::message::MouseEvent) {}
}

/// Data used by the client interface.
#[derive(Clone)]
pub enum Data {
    Close,
    CloseID(String),
    Login((String, String, String, bool)),
    Message(Message),
    SendFiles((i32, String, String, i32, bool, bool)),
    RemoveDirAll((i32, String, bool, bool)),
    ConfirmDeleteFiles((i32, i32)),
    SetNoConfirm(i32),
    RemoveDir((i32, String)),
    RemoveFile((i32, String, i32, bool)),
    CreateDir((i32, String, bool)),
    CancelJob(i32),
    RemovePortForward(i32),
    AddPortForward((i32, String, i32)),
    #[cfg(not(feature = "flutter"))]
    ToggleClipboardFile,
    NewRDP,
    SetConfirmOverrideFile((i32, i32, bool, bool, bool)),
    AddJob((i32, String, String, i32, bool, bool)),
    ResumeJob((i32, bool)),
    RecordScreen(bool, i32, i32, String),
    ElevateDirect,
    ElevateWithLogon(String, String),
    NewVoiceCall,
    CloseVoiceCall,
}

/// Keycode for key events.
#[derive(Clone, Debug)]
pub enum Key {
    ControlKey(ControlKey),
    Chr(u32),
    _Raw(u32),
}

lazy_static::lazy_static! {
    pub static ref KEY_MAP: HashMap<&'static str, Key> =
    [
        ("VK_A", Key::Chr('a' as _)),
        ("VK_B", Key::Chr('b' as _)),
        ("VK_C", Key::Chr('c' as _)),
        ("VK_D", Key::Chr('d' as _)),
        ("VK_E", Key::Chr('e' as _)),
        ("VK_F", Key::Chr('f' as _)),
        ("VK_G", Key::Chr('g' as _)),
        ("VK_H", Key::Chr('h' as _)),
        ("VK_I", Key::Chr('i' as _)),
        ("VK_J", Key::Chr('j' as _)),
        ("VK_K", Key::Chr('k' as _)),
        ("VK_L", Key::Chr('l' as _)),
        ("VK_M", Key::Chr('m' as _)),
        ("VK_N", Key::Chr('n' as _)),
        ("VK_O", Key::Chr('o' as _)),
        ("VK_P", Key::Chr('p' as _)),
        ("VK_Q", Key::Chr('q' as _)),
        ("VK_R", Key::Chr('r' as _)),
        ("VK_S", Key::Chr('s' as _)),
        ("VK_T", Key::Chr('t' as _)),
        ("VK_U", Key::Chr('u' as _)),
        ("VK_V", Key::Chr('v' as _)),
        ("VK_W", Key::Chr('w' as _)),
        ("VK_X", Key::Chr('x' as _)),
        ("VK_Y", Key::Chr('y' as _)),
        ("VK_Z", Key::Chr('z' as _)),
        ("VK_0", Key::Chr('0' as _)),
        ("VK_1", Key::Chr('1' as _)),
        ("VK_2", Key::Chr('2' as _)),
        ("VK_3", Key::Chr('3' as _)),
        ("VK_4", Key::Chr('4' as _)),
        ("VK_5", Key::Chr('5' as _)),
        ("VK_6", Key::Chr('6' as _)),
        ("VK_7", Key::Chr('7' as _)),
        ("VK_8", Key::Chr('8' as _)),
        ("VK_9", Key::Chr('9' as _)),
        ("VK_COMMA", Key::Chr(',' as _)),
        ("VK_SLASH", Key::Chr('/' as _)),
        ("VK_SEMICOLON", Key::Chr(';' as _)),
        ("VK_QUOTE", Key::Chr('\'' as _)),
        ("VK_LBRACKET", Key::Chr('[' as _)),
        ("VK_RBRACKET", Key::Chr(']' as _)),
        ("VK_BACKSLASH", Key::Chr('\\' as _)),
        ("VK_MINUS", Key::Chr('-' as _)),
        ("VK_PLUS", Key::Chr('=' as _)), // it is =, but sciter return VK_PLUS
        ("VK_DIVIDE", Key::ControlKey(ControlKey::Divide)), // numpad
        ("VK_MULTIPLY", Key::ControlKey(ControlKey::Multiply)), // numpad
        ("VK_SUBTRACT", Key::ControlKey(ControlKey::Subtract)), // numpad
        ("VK_ADD", Key::ControlKey(ControlKey::Add)), // numpad
        ("VK_DECIMAL", Key::ControlKey(ControlKey::Decimal)), // numpad
        ("VK_F1", Key::ControlKey(ControlKey::F1)),
        ("VK_F2", Key::ControlKey(ControlKey::F2)),
        ("VK_F3", Key::ControlKey(ControlKey::F3)),
        ("VK_F4", Key::ControlKey(ControlKey::F4)),
        ("VK_F5", Key::ControlKey(ControlKey::F5)),
        ("VK_F6", Key::ControlKey(ControlKey::F6)),
        ("VK_F7", Key::ControlKey(ControlKey::F7)),
        ("VK_F8", Key::ControlKey(ControlKey::F8)),
        ("VK_F9", Key::ControlKey(ControlKey::F9)),
        ("VK_F10", Key::ControlKey(ControlKey::F10)),
        ("VK_F11", Key::ControlKey(ControlKey::F11)),
        ("VK_F12", Key::ControlKey(ControlKey::F12)),
        ("VK_ENTER", Key::ControlKey(ControlKey::Return)),
        ("VK_CANCEL", Key::ControlKey(ControlKey::Cancel)),
        ("VK_BACK", Key::ControlKey(ControlKey::Backspace)),
        ("VK_TAB", Key::ControlKey(ControlKey::Tab)),
        ("VK_CLEAR", Key::ControlKey(ControlKey::Clear)),
        ("VK_RETURN", Key::ControlKey(ControlKey::Return)),
        ("VK_SHIFT", Key::ControlKey(ControlKey::Shift)),
        ("VK_CONTROL", Key::ControlKey(ControlKey::Control)),
        ("VK_MENU", Key::ControlKey(ControlKey::Alt)),
        ("VK_PAUSE", Key::ControlKey(ControlKey::Pause)),
        ("VK_CAPITAL", Key::ControlKey(ControlKey::CapsLock)),
        ("VK_KANA", Key::ControlKey(ControlKey::Kana)),
        ("VK_HANGUL", Key::ControlKey(ControlKey::Hangul)),
        ("VK_JUNJA", Key::ControlKey(ControlKey::Junja)),
        ("VK_FINAL", Key::ControlKey(ControlKey::Final)),
        ("VK_HANJA", Key::ControlKey(ControlKey::Hanja)),
        ("VK_KANJI", Key::ControlKey(ControlKey::Kanji)),
        ("VK_ESCAPE", Key::ControlKey(ControlKey::Escape)),
        ("VK_CONVERT", Key::ControlKey(ControlKey::Convert)),
        ("VK_SPACE", Key::ControlKey(ControlKey::Space)),
        ("VK_PRIOR", Key::ControlKey(ControlKey::PageUp)),
        ("VK_NEXT", Key::ControlKey(ControlKey::PageDown)),
        ("VK_END", Key::ControlKey(ControlKey::End)),
        ("VK_HOME", Key::ControlKey(ControlKey::Home)),
        ("VK_LEFT", Key::ControlKey(ControlKey::LeftArrow)),
        ("VK_UP", Key::ControlKey(ControlKey::UpArrow)),
        ("VK_RIGHT", Key::ControlKey(ControlKey::RightArrow)),
        ("VK_DOWN", Key::ControlKey(ControlKey::DownArrow)),
        ("VK_SELECT", Key::ControlKey(ControlKey::Select)),
        ("VK_PRINT", Key::ControlKey(ControlKey::Print)),
        ("VK_EXECUTE", Key::ControlKey(ControlKey::Execute)),
        ("VK_SNAPSHOT", Key::ControlKey(ControlKey::Snapshot)),
        ("VK_INSERT", Key::ControlKey(ControlKey::Insert)),
        ("VK_DELETE", Key::ControlKey(ControlKey::Delete)),
        ("VK_HELP", Key::ControlKey(ControlKey::Help)),
        ("VK_SLEEP", Key::ControlKey(ControlKey::Sleep)),
        ("VK_SEPARATOR", Key::ControlKey(ControlKey::Separator)),
        ("VK_NUMPAD0", Key::ControlKey(ControlKey::Numpad0)),
        ("VK_NUMPAD1", Key::ControlKey(ControlKey::Numpad1)),
        ("VK_NUMPAD2", Key::ControlKey(ControlKey::Numpad2)),
        ("VK_NUMPAD3", Key::ControlKey(ControlKey::Numpad3)),
        ("VK_NUMPAD4", Key::ControlKey(ControlKey::Numpad4)),
        ("VK_NUMPAD5", Key::ControlKey(ControlKey::Numpad5)),
        ("VK_NUMPAD6", Key::ControlKey(ControlKey::Numpad6)),
        ("VK_NUMPAD7", Key::ControlKey(ControlKey::Numpad7)),
        ("VK_NUMPAD8", Key::ControlKey(ControlKey::Numpad8)),
        ("VK_NUMPAD9", Key::ControlKey(ControlKey::Numpad9)),
        ("Apps", Key::ControlKey(ControlKey::Apps)),
        ("Meta", Key::ControlKey(ControlKey::Meta)),
        ("RAlt", Key::ControlKey(ControlKey::RAlt)),
        ("RWin", Key::ControlKey(ControlKey::RWin)),
        ("RControl", Key::ControlKey(ControlKey::RControl)),
        ("RShift", Key::ControlKey(ControlKey::RShift)),
        ("CTRL_ALT_DEL", Key::ControlKey(ControlKey::CtrlAltDel)),
        ("LOCK_SCREEN", Key::ControlKey(ControlKey::LockScreen)),
    ].iter().cloned().collect();
}

/// Check if the given message is an error and can be retried.
///
/// # Arguments
///
/// * `msgtype` - The message type.
/// * `title` - The title of the message.
/// * `text` - The text of the message.
#[inline]
pub fn check_if_retry(msgtype: &str, title: &str, text: &str) -> bool {
    msgtype == "error"
        && title == "Connection Error"
        && (text.contains("10054") || text.contains("104")
            || (!text.to_lowercase().contains("offline")
                && !text.to_lowercase().contains("exist")
                && !text.to_lowercase().contains("handshake")
                && !text.to_lowercase().contains("failed")
                && !text.to_lowercase().contains("resolve")
                && !text.to_lowercase().contains("mismatch")
                && !text.to_lowercase().contains("manually")
                && !text.to_lowercase().contains("as expected")
                && !text.to_lowercase().contains("closed the session")
                && !text.to_lowercase().contains("not allowed")))
}

#[inline]
fn get_pk(pk: &[u8]) -> Option<[u8; 32]> {
    if pk.len() == 32 {
        let mut tmp = [0u8; 32];
        tmp[..].copy_from_slice(&pk);
        Some(tmp)
    } else {
        None
    }
}
/*
#[inline]
fn get_rs_pk(str_base64: &str) -> Option<sign::PublicKey> {
    if let Ok(pk) = crate::decode64(str_base64) {
        get_pk(&pk).map(|x| sign::PublicKey(x))
    } else {
        None
    }
}
*/

fn decode_id_pk(signed: &[u8], key: &sign::PublicKey) -> ResultType<(String, [u8; 32])> {
    let res = IdPk::parse_from_bytes(
        &sign::verify(signed, key).map_err(|_| anyhow!("Signature mismatch"))?,
    )?;
    if let Some(pk) = get_pk(&res.pk) {
        Ok((res.id, pk))
    } else {
        bail!("Wrong public length");
    }
}


