#! /usr/bin/env python3

import sys

VERSION = "v5.1"

def run():
    if sys.argv[1] == '--client':
        import poshc2.client as client
        client.start()
    elif sys.argv[1] == '--server':
        import poshc2.server as server
        server.start()
    else:
        print("Unrecognised startup arguments, expected --server/--client as first arg: %s" % str(sys.argv))
