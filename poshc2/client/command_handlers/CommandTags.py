from enum import Enum


class Tag(Enum):
    Filesystem = 0,
    Injection = 1
    Lateral_Movement = 1,
    Util = 2,
    SOCKS = 3,
    Data_Gathering = 4,
    Credential_Harvesting = 5,
    Comms = 6,
    Help = 7,
    Opsec = 8,
    Privilege_Escalation = 8,
    Process_Manipulation = 9,
    Memory_Manipulation = 10,
    RDP = 11,
    WMI = 12,
    Enumeration = 13,
    SQL = 14,
    Collection = 15,
    Azure_AD = 16,
    Registry = 17,
    Web = 18,
    Core = 19,
    PBind = 20

    def get_friendly_name(self):
        return self.name.replace("_", " ")
