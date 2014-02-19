#! /usr/bin/env bash

rm -f /tmp/config
cat << EOF > /tmp/config
lxc.seccomp = /tmp/whitelist
EOF

# Example Version 2 seccomp whitelist:
# 2
# whitelist trap
# # 'whitelist' would normally mean kill a task doing any syscall which is not
# # whitelisted below.  By appending 'trap' to the line, we will cause a SIGSYS
# # to be sent to the task instead.  'errno 0' would  mean don't allow the system
# # call but immediately return 0.  'errno 22' would mean return EINVAL immediately.
# [x86_64]
# open
# close
# read
# write
# mount
# umount2
# # Since we are listing system calls by name, we can also ask to have them resolved
# # for another arch, i.e. for 32/64-bit versions.
# [x86]
# open
# close
# read
# write
# mount
# umount2
# # Do note that this policy does not whitelist enough system calls to allow a
# # system container to boot.

rm -f /tmp/whitelist
cat << EOF > /tmp/whitelist
2
whitelist trap
[x86_64]
exit
[x86]
exit
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
#rm -f /tmp/config
#rm -f /tmp/whitelist

