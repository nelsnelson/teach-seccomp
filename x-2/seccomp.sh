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
echo "Executing lxc instance:"
sudo lxc-execute -n echo-test -f /tmp/config -l DEBUG -o /tmp/lxc.log -- cat /etc/hostname
echo "Debug output:"
cat /tmp/lxc.log
rm /tmp/config
rm /tmp/whitelist
sudo rm /tmp/lxc.log

