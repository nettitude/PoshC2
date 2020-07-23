#!/usr/bin/env python3

import sys


def start():
    from poshc2.server.C2Server import main
    args = sys.argv
    args.remove("--server")
    args.remove("start.py")
    main(args)
