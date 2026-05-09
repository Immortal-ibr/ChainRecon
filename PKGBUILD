pkgname=chainrecon
pkgver=1.0.0
pkgrel=1
pkgdesc="IoT network security analysis framework"
arch=('any')
url="https://github.com/Immortal-ibr/ChainRecon"

depends=('python'
         'python-jinja'
         'python-requests'
         'python-defusedxml'
         'python-cryptography'
         'python-yaml'
         'python-rich'
         'python-openpyxl'
         'wireshark-cli'
         'nmap')

optdepends=('python-pyshark'
            'scapy'
            'python-shodan'
            'python-weasyprint'
            'python-nmap'
            'python-textual'
            'frida-tools'
            'tcpdump'
            'android-tools'
            'jadx'
            'apktool')

makedepends=('git'
             'python-build'
             'python-installer'
             'python-setuptools'
             'python-wheel')

source=("$pkgname::git+$url.git")
sha256sums=('SKIP')

build() {
    cd "$srcdir/$pkgname"
    python -m build --wheel --no-isolation
}

package() {
    cd "$srcdir/$pkgname"
    python -m installer --destdir="$pkgdir" dist/*.whl
}
