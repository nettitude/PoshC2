from datetime import datetime, timezone

from poshc2.server.database.Model import PowerStatus
from poshc2.server.database.Helpers import insert_object, update_object, get_power_status


def create_if_no_status_for_id(implant_id):
    power_status = get_power_status(implant_id)

    if power_status is None:
        power_status = PowerStatus(
            implant_id = implant_id,
            apm_status = None,
            on_ac_power = 255,
            charging = 255,
            battery_status = None,
            battery_percent_left = None,
            screen_locked = 0,
            monitor_on = 1,
            last_update = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        )

        insert_object(power_status)


def translate_power_status(status, implant_id):
    if "Power Status Monitoring:" in status:
        print(status)
    elif ":" in status:
        create_if_no_status_for_id(implant_id)
        splt = status.split(":")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

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
                update_object(PowerStatus, {PowerStatus.screen_locked: 1, PowerStatus.last_update: now}, {PowerStatus.implant_id: implant_id})
            elif splt[1] == "SESSION_UNLOCK":
                print("[+] Session has been unlocked")
                update_object(PowerStatus, {PowerStatus.screen_locked: 0, PowerStatus.last_update: now}, {PowerStatus.implant_id: implant_id})
            elif splt[1] == "SESSION_REMOTE_CONTROL":
                print("[-] Session remote control status has changed")
        elif splt[0] == "WM_POWERBROADCAST":
            if splt[1] == "GUID_MONITOR_POWER_ON":
                if splt[2] == "On":
                    update_object(PowerStatus, {PowerStatus.monitor_on: 1, PowerStatus.last_update: now}, {PowerStatus.implant_id: implant_id})
                    print("[+] Monitor(screen) has been switched ON")
                else:
                    update_object(PowerStatus, {PowerStatus.monitor_on: 0, PowerStatus.last_update: now}, {PowerStatus.implant_id: implant_id})
                    print("[!] Monitor(screen) has been switched OFF")
            elif splt[1] == "GUID_BATTERY_PERCENTAGE_REMAINING":
                power_status = get_power_status(implant_id)

                if splt[2].isdigit():
                    battery_percentage = int(splt[2])

                    if 100 >= battery_percentage >= 0:
                        if battery_percentage > 50:
                            print(f"[+] Battery has {battery_percentage}% charge")
                        elif battery_percentage > 15:
                            print(f"[!] WARNING: Battery has only {battery_percentage}% charge")
                        elif battery_percentage < 15:
                            print(f"[!] CRITICAL BATTERY: {battery_percentage}% charge left")

                    update_object(PowerStatus, {PowerStatus.battery_percent_left: battery_percentage, PowerStatus.last_update: now}, {PowerStatus.id: power_status.id})
                else:
                    print("[-] Battery status: UNKNOWN")
                    update_object(PowerStatus, {PowerStatus.battery_percent_left: "UNKNOWN", PowerStatus.last_update: now}, {PowerStatus.id: power_status.id})
            elif splt[1] == "GUID_ACDC_POWER_SOURCE":
                if splt[2] == "Unplugged":
                    update_object(PowerStatus, {PowerStatus.on_ac_power: 0, PowerStatus.last_update: now}, {PowerStatus.implant_id: implant_id})
                    print("[!] DISCHARGING the battery now. AC has been unplugged.")
                else:
                    if splt[2] == "UPS":
                        print("[!] UPS powered now. Machine may turn off at any time")

                    update_object(PowerStatus, {PowerStatus.on_ac_power: 0, PowerStatus.last_update: now}, {PowerStatus.implant_id: implant_id})
            elif splt[1] == "PBT_APMBATTERYLOW":
                print("[!] Low battery reported")
                power_status = get_power_status(implant_id)
                update_object(PowerStatus, {PowerStatus.battery_status: "LOW", PowerStatus.last_update: now}, {PowerStatus.id: power_status.id})
            elif splt[1] == "PBT_APMQUERYSUSPEND":
                print("[!] SUSPEND may be imminent. QuerySuspend has been called:")
                update_object(PowerStatus, {PowerStatus.apm_status: "QUERYSUSPEND", PowerStatus.last_update: now}, {PowerStatus.implant_id: implant_id})
            elif splt[1] == "PBT_APMSUSPEND":
                print("[!] SUSPEND/SLEEP, machine has been hibernated")
                update_object(PowerStatus, {PowerStatus.apm_status: "SUSPEND", PowerStatus.last_update: now}, {PowerStatus.implant_id: implant_id})
            elif splt[1] == "PBT_APMRESUMESUSPEND":
                print("[+] Resume from suspend.")
                update_object(PowerStatus, {PowerStatus.apm_status: "RESUME", PowerStatus.last_update: now}, {PowerStatus.implant_id: implant_id})
            elif splt[1] == "PBT_APMPOWERSTATUSCHANGE":
                lns = status.splitlines(False)
                power_status = get_power_status(implant_id)

                for i in lns:
                    if i.startswith("GUID_ACDC_POWER_SOURCE:"):
                        if i[23:] == "Plugged":
                            print("[+] AC is plugged in")
                            on_ac_power = 1
                        elif i[23:] == "Unplugged":
                            print("[!] AC has been unplugged")
                            on_ac_power = 0
                        elif i[23:] == "UPS":
                            print("[!] Computer is on a UPS")
                            on_ac_power = 0
                    elif i.startswith("CHRG:"):
                        charging = (i[5:] == "CHARGING")
                        print(f"[+] Battery is charging: {charging}")
                    elif i.startswith("PERCENT:"):
                        battery_percent_left = i[8:]

                        if battery_percent_left != "UNKNOWN" and battery_percent_left.isdigit():
                            print(f"[+] Battery Percent: {battery_percent_left}%")
                        else:
                            print("[-] Battery Percent: UNKNOWN")
                            battery_percent_left = "UNKNOWN"
                    elif i.startswith("BATTERY:"):
                        battery_status = i[8:]

                        if battery_status is None or battery_status == "":
                            print("[-] Battery Status: UNKNOWN")
                            battery_status = "UNKNOWN"
                        else:
                            print(f"[+] Battery Status: {status}")

                update_object(PowerStatus, {PowerStatus.on_ac_power: on_ac_power, PowerStatus.charging: charging, PowerStatus.battery_percent_left: battery_percent_left, PowerStatus.battery_status: battery_status, PowerStatus.last_update: now}, {PowerStatus.id: power_status.id})


def get_powerstatus(implant_id):
    pwrStatus = get_power_status(implant_id)

    if pwrStatus is not None:
        if pwrStatus.last_update is not None and pwrStatus.last_update != "":
            print(f"[+] Power status @ {pwrStatus.last_update}")
        else:
            print("[+] Power status")

        if pwrStatus.apm_status is not None and pwrStatus.apm_status != "":
            print(f"apmstatus: {pwrStatus.apm_status}")

        if pwrStatus.on_ac_power:
            if not pwrStatus.charging:
                print("BATTERY: Not Charging")
            else:
                print("BATTERY: Charging")
        else:
            print(f"BATTERY: Discharging {pwrStatus.battery_percent_left}%")

        if pwrStatus.battery_status is not None and pwrStatus.battery_status != "":
            print(f"BATTERY FLAG: {pwrStatus.battery_status}")

        if pwrStatus.screen_locked > 0:
            print("SCREEN: LOCKED")
        else:
            print("SCREEN: UNLOCKED")

        if pwrStatus.monitor_on:
            print("MONITOR: ON")
        else:
            print("MONITOR: OFF")
    else:
        print("[X] No power status has been recorded for this implant")


def get_powerstatus_label(implant):
    implant_label = ""
    powerstatus_label = False
    power_status_details = get_power_status(implant.id)

    if power_status_details is not None:
        if implant_label is not None:
            implant_label += " "
        else:
            implant_label = ""

        apmstatus = power_status_details.apm_status.lower()

        if apmstatus == "shutdown":
            implant_label += "SHTDWN "
            powerstatus_label = True
        elif apmstatus == "suspend" or apmstatus == "querysuspend":
            implant_label += "SUSPND "
            powerstatus_label = True

        if not powerstatus_label:
            if power_status_details.screen_locked:
                implant_label += "LOCKED "

            if not power_status_details.monitor_on:
                implant_label += "SCRN OFF "

            if not power_status_details.on_ac_power:
                if power_status_details.battery_percent_left is not None and power_status_details.battery_percent_left.isdigit():
                    implant_label += f"DSCHRG: {power_status_details.battery_percent_left}% "
                else:
                    implant_label += "DSCHRG "

    return implant_label
