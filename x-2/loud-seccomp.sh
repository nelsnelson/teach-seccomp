#! /usr/bin/env bash

cat << EOF > /tmp/config
lxc.seccomp = /tmp/whitelist
EOF

cat << EOF > /tmp/whitelist
1
whitelist
0
1
EOF

echo
echo "Config contents:"
cat /tmp/config

echo
echo "Whitelist contents:"
cat /tmp/whitelist

cmd="sudo lxc-execute -n echo-test -f /tmp/config -l DEBUG -o /tmp/lxc.log -- cat /etc/hostname"
echo
echo "Executing command: ${cmd}"
echo `${cmd}`

echo
echo "Debug output:"
cat /tmp/lxc.log

sudo rm -f /tmp/lxc.log
rm -f /tmp/config
rm -f /tmp/whitelist

