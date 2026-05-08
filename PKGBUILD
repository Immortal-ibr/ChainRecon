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

prepare() {
    cd "$srcdir/$pkgname"

    mkdir -p chainrecon
    mv analysis plugins runners utils models tui chainrecon/
    mv chainrecon.py chainrecon/__init__.py
    mv interactive.py chainrecon/interactive.py
    sed -i 's/include.*/include = ["chainrecon*"]/' pyproject.toml

    # replace imports for updated naming
    find chainrecon -name '*.py' -exec sed -i \
        -e 's/from analysis\./from chainrecon.analysis./g' \
        -e 's/from utils\./from chainrecon.utils./g' \
        -e 's/from runners\./from chainrecon.runners./g' \
        -e 's/from models\./from chainrecon.models./g' \
        -e 's/from tui\./from chainrecon.tui./g' \
        -e 's/from plugins\./from chainrecon.plugins./g' \
        -e 's/from analysis import/from chainrecon.analysis import/g' \
        -e 's/from utils import/from chainrecon.utils import/g' \
        -e 's/from runners import/from chainrecon.runners import/g' \
        -e 's/from models import/from chainrecon.models import/g' \
        -e 's/from tui import/from chainrecon.tui import/g' \
        -e 's/from plugins import/from chainrecon.plugins import/g' \
        {} \;
}

build() {
    cd "$srcdir/$pkgname"
    python -m build --wheel --no-isolation
}

package() {
    cd "$srcdir/$pkgname"
    python -m installer --destdir="$pkgdir" dist/*.whl
}
