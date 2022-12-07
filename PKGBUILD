pkgname=hoptodesk
pkgver=1.2.4
pkgrel=0
epoch=
pkgdesc=""
arch=('x86_64')
url=""
license=('GPL-3.0')
groups=()
depends=('gtk3' 'xdotool' 'libxcb' 'libxfixes' 'alsa-lib' 'pulseaudio' 'ttf-arphic-uming' 'python-pip' 'curl')
makedepends=()
checkdepends=()
optdepends=()
provides=()
conflicts=()
replaces=()
backup=()
options=()
install=pacman_install
changelog=
noextract=()
md5sums=() #generate with 'makepkg -g'

package() {
	install -Dm 755 ${HBB}/target/release/${pkgname} -t "${pkgdir}/usr/bin"
	install -Dm 644 ${HBB}/libsciter-gtk.so -t "${pkgdir}/usr/lib/hoptodesk"
  install -Dm 644 $HBB/hoptodesk.service -t "${pkgdir}/usr/share/hoptodesk/files"
  install -Dm 644 $HBB/hoptodesk.desktop -t "${pkgdir}/usr/share/hoptodesk/files"
  install -Dm 644 $HBB/256-no-margin.png "${pkgdir}/usr/share/hoptodesk/files/hoptodesk.png"
}
