#!/usr/bin/env python3
import sys 

def start():
    from poshc2.client.command_handlers.ImplantHandler import main
    args = sys.argv
    args.remove("--client")
    args.remove("start.py")
    main(args)