#!/bin/sh
stty intr ^]
exec qemu-system-x86_64 -m 64M -kernel bzImage -initrd rootfs.cpio -append "loglevel=3 console=ttyS0 oops=panic panic=1 nokaslr" -nographic -net user -net nic -device e1000 -smp cores=2,threads=2 -cpu kvm64,+smep,+smap -monitor /dev/null 2>/dev/null -s -S