pkgname=chainrecon
pkgver=1.0.0
pkgrel=1
pkgdesc="IoT network security analysis framework"
arch=('any')
url="https://github.com/Immortal-ibr/ChainRecon"

depends=('python' 'python-jinja' 'python-requests' 'python-defusedxml'
         'python-cryptography' 'python-yaml' 'python-rich'
         'python-openpyxl' 'wireshark-cli' 'nmap' 'python-textual')
optdepends=('python-pyshark' 'scapy' 'python-shodan'
            'python-weasyprint' 'python-nmap' 'frida-tools'
            'tcpdump' 'android-tools' 'jadx' 'apktool')
makedepends=('git')

source=("$pkgname::git+$url.git")
sha256sums=('SKIP')

package() {
    cd "$srcdir/$pkgname"

    install -d "$pkgdir/usr/share/$pkgname" "$pkgdir/usr/bin"

    cp -r analysis chainrecon.py community_plugins config interactive.py \
          models plugins profiles runners scripts tui utils workflows \
          "$pkgdir/usr/share/$pkgname/"

    sed -i '1i #!/usr/bin/env python3' "$pkgdir/usr/share/$pkgname/chainrecon.py"

    # mark the entry point executable
    chmod 755 "$pkgdir/usr/share/$pkgname/chainrecon.py"

    # expose it on PATH as /usr/bin/chainrecon
    ln -s "/usr/share/$pkgname/chainrecon.py" "$pkgdir/usr/bin/$pkgname"
}
