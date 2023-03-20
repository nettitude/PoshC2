from poshc2 import Colours
from poshc2.server.Config import PayloadTemplatesDirectory


# TODO this doesn't appear to actually edit the payload at all?
def create_payloads(payloads, name):
    payloads.quickstart_log(Colours.END)
    payloads.quickstart_log("JS files:")

    with open(f"{PayloadTemplatesDirectory}dropper.js", 'r') as f:
        dropper = f.read()

    payloads.quickstart_log(f"JS Payload written to: {payloads.output_directory}{name}Launcher.js")
    filename = f"{payloads.output_directory}Launcher.js"
    output_file = open(filename, 'w')
    output_file.write(dropper)
    output_file.close()
