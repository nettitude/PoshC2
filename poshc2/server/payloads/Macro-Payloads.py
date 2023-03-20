from poshc2 import Colours
from poshc2.Utils import format_macro
from poshc2.server.Config import PayloadTemplatesDirectory


def create_payloads(payloads, name):
    payloads.quickstart_log(Colours.END)
    payloads.quickstart_log(f"Macro Payload written to: {payloads.output_directory}{name}macro.txt")

    strmacro = format_macro("str", str(payloads.create_raw_base()))
    with open(f"{PayloadTemplatesDirectory}dropper.macro", 'r') as f:
        content = f.read()
    content = str(content).replace("#REPLACEME#", strmacro)

    with open(f"{payloads.output_directory}{name}macro.txt", 'w') as f:
        f.write(content)
