gdb \
    -ex "file vmlinux" \
    -ex "add-symbol-file notebook.ko 0xffffffffc0002000" \
    -ex "target remote :1234" \
    -ex "continue" \