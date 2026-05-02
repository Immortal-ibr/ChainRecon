pkgname=chainrecon
pkgver=1.0.0
pkgrel=1
pkgdesc="IoT network security analysis framework"
arch=('any')
url="https://github.com/Immortal-ibr/ChainRecon"
license=('MIT')

depends=('python' 'wireshark-cli' 'nmap')
makedepends=('git' 'python-pip')

#source=("git+https://github.com/Immortal-ibr/ChainRecon.git")
#sha256sums=('SKIP')
#replace $startdir with $srcdir/ChainRecon if you decide to have it fetch from git

build() {
    cd "$startdir"
    # create python venv
    python -m venv venv

    # install deps to venv
    ./venv/bin/pip install --isolated --no-cache-dir -r requirements.txt
}

package() {
    cd "$startdir"

    install -d "$pkgdir/opt/chainrecon"
    install -d "$pkgdir/usr/bin"

    # copy src code to venv
    cp -a . "$pkgdir/opt/chainrecon/"
    rm -rf "$pkgdir/opt/chainrecon/.git" "$pkgdir/opt/chainrecon/.github"

    # global executable wrapper script
    cat > "$pkgdir/usr/bin/chainrecon" << 'EOF'
#!/bin/bash
export PYTHONPATH="/opt/chainrecon"
exec /opt/chainrecon/venv/bin/python /opt/chainrecon/chainrecon.py "$@"
EOF
    chmod 755 "$pkgdir/usr/bin/chainrecon"
}