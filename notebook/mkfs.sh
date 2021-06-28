#/bin/bash
cd ./core && musl-gcc --static -Os go1.c -o exp && find . -print0 | cpio --null -o --format=newc | gzip -9 > ../rootfs.cpio