from enum import Enum


class ImplantType(Enum):
    PowerShellHttp = "PS"
    PowerShellHttpProxy = "PS;P"
    PowerShellHttpDaisy = "PS;D"
    SharpHttp = "C#"
    SharpHttpProxy = "C#;P"
    SharpHttpDaisy = "C#;D"
    SharpPBind = "C#;PB"
    SharpFComm = "C#;FC"
    JXAHttp = "JXA"
    LinuxHttp = "NL"
    LinuxHttpProxy = "NL;P"
    PythonHttp = "PY"
    PythonHttpProxy = "PY;P"
    PythonHttpDaisy = "PY;D"
    UnmanagedHttp = "C"
    UnmanagedHttpProxy = "C;P"

    @classmethod
    def get(cls, value):
        for k, v in cls.__members__.items():
            if k == value:
                return v
        else:
            raise ValueError(f"'{cls.__name__}' enum not found for '{value}'")

    @staticmethod
    def get_all_implants_list():
        return [ImplantType.PowerShellHttp, ImplantType.PowerShellHttpProxy, ImplantType.PowerShellHttpDaisy, ImplantType.SharpHttp,
                ImplantType.SharpHttpProxy, ImplantType.SharpHttpDaisy, ImplantType.SharpPBind, ImplantType.SharpFComm, ImplantType.JXAHttp,
                ImplantType.GoHttp, ImplantType.LinuxHttp, ImplantType.LinuxHttpProxy, ImplantType.PythonHttp, ImplantType.PythonHttpProxy,
                ImplantType.PythonHttpDaisy, ImplantType.UnmanagedHttp, ImplantType.UnmanagedHttpProxy]

    @staticmethod
    def get_sharp_implants_list():
        return [ImplantType.SharpHttp, ImplantType.SharpHttpProxy, ImplantType.SharpHttpDaisy, ImplantType.SharpPBind, ImplantType.SharpFComm]

    def is_sharp_implant(self):
        return self in [ImplantType.SharpHttp, ImplantType.SharpHttpProxy, ImplantType.SharpHttpDaisy, ImplantType.SharpPBind, ImplantType.SharpFComm]

    def is_python_implant(self):
        return self in [ImplantType.PythonHttp, ImplantType.PythonHttpProxy, ImplantType.PythonHttpDaisy]

    def is_jxa_implant(self):
        return self in [ImplantType.JXAHttp]

    def is_linux_implant(self):
        return self in [ImplantType.LinuxHttp, ImplantType.LinuxHttpProxy]

    def is_unmanaged_implant(self):
        return self in [ImplantType.UnmanagedHttp, ImplantType.UnmanagedHttpProxy]

    def is_powershell_implant(self):
        return self in [ImplantType.PowerShellHttp, ImplantType.PowerShellHttpDaisy, ImplantType.PowerShellHttpProxy]

    def is_pbind_implant(self):
        return self in [ImplantType.SharpPBind]

    def is_fcomm_implant(self):
        return self in [ImplantType.SharpFComm]

    def is_proxy_implant(self):
        return self in [ImplantType.SharpHttpProxy, ImplantType.PowerShellHttpProxy, ImplantType.UnmanagedHttpProxy, ImplantType.LinuxHttpProxy, ImplantType.PythonHttpProxy]

    def is_daisy_implant(self):
        return self in [ImplantType.SharpHttpDaisy, ImplantType.PythonHttpDaisy, ImplantType.PowerShellHttpDaisy]

    def get_history_file(self):
        if self.is_sharp_implant():
            return ".sharp-history"
        if self.is_unmanaged_implant():
            return ".unmanaged-history"
        if self.is_powershell_implant():
            return ".ps-history"
        if self.is_jxa_implant():
            return ".jxa-history"
        if self.is_linux_implant():
            return ".linux-history"
        if self.is_python_implant():
            return ".python-history"
        raise f"Error: unrecognised implant type: {self}"

    def supports_module(self, module_name):
        if self.is_sharp_implant():
            return (".exe" in module_name) or (".dll" in module_name)
        if self.is_unmanaged_implant():
            return (".exe" in module_name) or (".dll" in module_name)
        if self.is_powershell_implant():
            return ".ps1" in module_name
        if self.is_jxa_implant():
            return ".js" in module_name
        if self.is_linux_implant():
            return ".py" in module_name
        if self.is_python_implant():
            return ".py" in module_name
