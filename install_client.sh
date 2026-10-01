#!/bin/bash
set -eu

if [ "${1:-}" = "--uninstall" ]; then
  rm -f /usr/local/bin/otxc
  # /usr/share/otxc is shared with the server; only remove it if the server is gone
  if [ -L /usr/local/bin/otxc_server ] || [ -L /etc/systemd/system/otxc.service ]; then
    echo "otxc server is still installed, keeping /usr/share/otxc"
  else
    rm -rf /usr/share/otxc
  fi
  exit 0
fi

if ! [ -d /usr/share/otxc ]; then
  git clone https://git.tarxz.zip/odd/otxc /usr/share/otxc
fi
ln -s /usr/share/otxc/otxc /usr/local/bin/otxc
