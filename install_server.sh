#!/bin/bash
set -eu

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now otxc.service 2>/dev/null || true
  rm -f /etc/systemd/system/otxc.service /usr/local/bin/otxc_server
  systemctl daemon-reload
  # /usr/share/otxc is shared with the client; only remove it if the client is gone
  if [ -L /usr/local/bin/otxc ]; then
    echo "otxc client is still installed, keeping /usr/share/otxc"
  else
    rm -rf /usr/share/otxc
  fi
  echo "left the otxc user and /var/lib/otxc in place; remove them manually if unwanted"
  exit 0
fi

if ! [ -d /usr/share/otxc ]; then
  git clone https://git.tarxz.zip/odd/otxc /usr/share/otxc
fi
ln -s /usr/share/otxc/otxc_server.py /usr/local/bin/otxc_server
ln -s /usr/share/otxc/otxc.service /etc/systemd/system/otxc.service
adduser otxc
