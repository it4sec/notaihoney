#!/usr/bin/env bash
set -e

DATE=$(date +%Y-%m-%d)
PACKAGE_DIR="../package"
ARCHIVE="${PACKAGE_DIR}/notaihoney-${DATE}.tar.gz"

mkdir -p "$PACKAGE_DIR"

tar -czf "$ARCHIVE" -C .. \
    dist/notaihoney \
    config/honeypot.yaml \
    deploy/systemd/notaihoney.service \
    deploy/systemd/notaihoney-capture.service \
    deploy/nftables/base.nft \
    scripts

echo "Created: $ARCHIVE"