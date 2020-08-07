from poshc2.server.database.DB import get_powerstatusbyrandomuri, insert_blankpowerstatus, update_screenlocked, update_monitoron
from poshc2.server.database.DB import update_powerstatus, update_acstatus, update_apmstatus


def create_if_no_status_for_uri(RandomURI):
    result = get_powerstatusbyrandomuri(RandomURI)
    if result is None:
        insert_blankpowerstatus(RandomURI)


def translate_power_status(status, RandomURI):
    if "Power Status Monitoring:" in status:
        print(status)
    elif ":" in status:
        create_if_no_status_for_uri(RandomURI)
        splt = status.split(":")
        if splt[0] == "WM_QUERYENDSESSION":
            print("[!] SHUTDOWN may be imminent. Query End Session has been called:")
        elif splt[0] == "WM_WTSSESSION_CHANGE":
            if splt[1] == "CONSOLE_CONNECT":
                print("[+] Console session has been connected to")
            elif splt[1] == "CONSOLE_DISCONNECT":
                print("[-]Console session has been disconnected from ")
            elif splt[1] == "REMOTE_CONNECT":
                print("[+] Remote connection has been made to the machine (RDP)")
            elif splt[1] == "REMOTE_DISCONNECT":
                print("[-] Remote connection has been dropped (RDP)")
            elif splt[1] == "SESSION_LOGON":
                print("[+] A user has logged on")
            elif splt[1] == "SESSION_LOGOFF":
                print("[!] A user has logged off")
            elif splt[1] == "SESSION_LOCK":
                print("[!] Session has been locked")
                update_screenlocked(RandomURI, 1)
            elif splt[1] == "SESSION_UNLOCK":
                print("[+] Session has been unlocked")
                update_screenlocked(RandomURI, 0)
            elif splt[1] == "SESSION_REMOTE_CONTROL":
                print("[-] Session remote control status has changed")
        elif splt[0] == "WM_POWERBROADCAST":
            if splt[1] == "GUID_MONITOR_POWER_ON":
                if splt[2] == "On":
                    update_monitoron(RandomURI, 1)
                    print("[+] Monitor(screen) has been switched ON")
                else:
                    update_monitoron(RandomURI, 0)
                    print("[!] Monitor(screen) has been switched OFF")
            elif splt[1] == "GUID_BATTERY_PERCENTAGE_REMAINING":
                result = get_powerstatusbyrandomuri(RandomURI)
                if (splt[2].isdigit()):
                    battperc = int(splt[2])
                    if (battperc <= 100 and battperc >= 0):
                        if (battperc > 50):
                            print("[+] Battery has %s%% charge" % battperc)
                        elif battperc > 15:
                            print("[!] WARNING: Battery has only %s%% charge" % battperc)
                        elif battperc < 15:
                            print("[!] CRITICAL BATTERY: %s%% charge left" % battperc)
                    update_powerstatus(RandomURI, result[3], result[4], result[5], ("%s%%" % battperc))
                else:
                    print("[-] Battery status: UNKNOWN")
                    update_powerstatus(RandomURI, result[3], result[4], result[5], "UNKNOWN")
            elif splt[1] == "GUID_ACDC_POWER_SOURCE":
                if splt[2] == "Unplugged":
                    update_acstatus(RandomURI, 0)
                    print("[!] DISCHARGING the battery now. AC has been unplugged.")
                else:
                    if splt[2] == "UPS":
                        print("[!] UPS powered now. Machine may turn off at any time")
                    update_acstatus(RandomURI, 0)
            elif splt[1] == "PBT_APMBATTERYLOW":
                print("[!] Low battery reported")
                result = get_powerstatusbyrandomuri(RandomURI)
                update_powerstatus(RandomURI, result[3], result[4], "LOW", result[6])
            elif splt[1] == "PBT_APMQUERYSUSPEND":
                print("[!] SUSPEND may be imminent. QuerySuspend has been called:")
                update_apmstatus(RandomURI, "QUERYSUSPEND")
            elif splt[1] == "PBT_APMSUSPEND":
                print("[!] SUSPEND/SLEEP, machine has been hibernated")
                update_apmstatus(RandomURI, "SUSPEND")
            elif splt[1] == "PBT_APMRESUMESUSPEND":
                print("[+] Resume from suspend.")
                update_apmstatus(RandomURI, "RESUME")
            elif splt[1] == "PBT_APMPOWERSTATUSCHANGE":
                lns = status.splitlines(False)
                result = get_powerstatusbyrandomuri(RandomURI)
                acpower = result[3]
                chrging = result[4]
                stus = result[5]
                percent = result[6]
                for i in lns:
                    if i.startswith("GUID_ACDC_POWER_SOURCE:"):
                        if(i[23:] == "Plugged"):
                            print("[+] AC is plugged in")
                            acpower = 1
                        elif (i[23:] == "Unplugged"):
                            print("[!] AC has been unplugged")
                            acpower = 0
                        elif (i[23:] == "UPS"):
                            print("[!] Computer is on a UPS")
                            acpower = 0
                    elif i.startswith("CHRG:"):
                        chrging = (i[5:] == "CHARGING")
                        print("[+] Battery is charging: %s" % chrging)
                    elif i.startswith("PERCENT:"):
                        prcnt = i[8:]
                        if prcnt != "UNKNOWN" and prcnt.isdigit():
                            percent = ("%s%%" % prcnt)
                            print("[+] Battery Percent: %s" % percent)
                        else:
                            percent = "UNKNOWN"
                            print("[-] Battery Percent: UNKNOWN")
                    elif i.startswith("BATTERY:"):
                        stus = i[8:]
                        if stus is None or status == "":
                            stus = "UNKNOWN"
                            print("[-] Battery Status: UNKNOWN")
                        else:
                            print("[+] Battery Status: %s" % stus)
                update_powerstatus(RandomURI, acpower, chrging, stus, percent)


def getpowerstatus(randomuri):
    pwrStatus = get_powerstatusbyrandomuri(randomuri)
    if (pwrStatus is not None):
        if (pwrStatus[9] is not None and pwrStatus[9] != ""):
            print("[+] Power status @ %s" % pwrStatus[9])
        else:
            print("[+] Power status")
        if (pwrStatus[2] is not None and pwrStatus[2] != ""):
            print("apmstatus: %s" % pwrStatus[2])
        if (pwrStatus[3]):
            if (not pwrStatus[4]):
                print("BATTERY: Not Charging")
            else:
                print("BATTERY: Charging")
        else:
            print("BATTERY: Discharging %s%%" % pwrStatus["BatteryPercentLeft"])

        if (pwrStatus[5] is not None and pwrStatus[5] != ""):
            print("BATTERY FLAG: %s" % pwrStatus[5])

        if (pwrStatus[7] > 0):
            print("SCREEN: LOCKED")
        else:
            print("SCREEN: UNLOCKED")

        if (pwrStatus[8]):
            print("MONITOR: ON")
        else:
            print("MONITOR: OFF")
    else:
        print("[X] No power status has been recorded for this implant")
