#!/usr/bin/env python3

import re
import sys

from poshc2 import Colours
from poshc2.server.Core import decrypt
from poshc2.server.database.Helpers import select_first
from poshc2.server.database.Model import C2Server


def decrypt_and_print(key, encrypted):
    try:
        decrypted = decrypt(key, encrypted)
        print(f"{Colours.GREEN}[+] Success with key {key}\n\t{decrypted}")
        sys.exit(0)
    except Exception:
        print(f"{Colours.RED}[-] Failed decrypt with key: {key}{Colours.END}")


def main():
    if len(sys.argv) != 2:
        print("Usage: From pipenv shell in PoshC2 directory -> python3 cookie-decrypter.py <path/to/sec.log>")
        print("Usage: From pipenv shell in PoshC2 directory -> python3 cookie-decrypter.py <cookie value>")
        sys.exit(0)

    key = select_first(C2Server.encryption_key)

    if not key:
        print(f"{Colours.RED}[-] Could not get key from database{Colours.END}")
        sys.exit(1)

    arg = sys.argv[1]

    try:
        log_file = open(arg, "r")
        print(f"[*] Checking file {arg}")

        for line in log_file:
            if re.search("SessionID", line):
                encrypted = line.split("SessionID=")[1]
                decrypt_and_print(key, encrypted)

        print(f"{Colours.RED}[-] Failed to find and decrypt cookie{Colours.END}")
    except Exception:
        print(f"[*] Decrypting cookie value {arg}")
        decrypt_and_print(key, arg)
        print(f"{Colours.RED}[-] Failed to decrypt cookie value{Colours.END}")


if __name__ == "__main__":
    main()
