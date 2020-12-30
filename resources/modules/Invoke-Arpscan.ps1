<#
.Synopsis
    ArpScanner

    PortScan / EgressBuster 2017
    Ben Turner @benpturner 
    Rob Maslen @rbmaslen 

.DESCRIPTION
    Powershell ArpScanner using C# AssemblyLoad. This uses [DllImport("iphlpapi.dll", ExactSpelling=true)] to Export 'SendARP'

    Uses [DllImport("ws2_32.dll", SetLastError = true)] for Resolution 

    By default it will loop through all interfaces and perform an arpscan of the local network based on the IP Address and Subnet mask provided by the network adaptor. 

    The C# Code has been included but for OpSec purposes it uses AssemblyLoad and not AddType

.EXAMPLE
    PS C:\> Invoke-Arpscan
.EXAMPLE
    PS C:\> Invoke-Arpscan -Resolve
.EXAMPLE
    PS C:\> ArpScan -Resolve
.EXAMPLE
    PS C:\> Invoke-Arpscan -IPCidr 10.0.0.1/24
.EXAMPLE
    PS C:\> Invoke-Arpscan -IPCidr 10.0.0.1/24 -AddType -Resolve

#>
$arploaded = $null
function Invoke-Arpscan {

param (
    [Parameter(Mandatory = $False)]
    [string]$IPCidr,
    [Parameter(Mandatory=$False)]
    [switch]$Resolve,
    [Parameter(Mandatory=$False)]
    [switch]$AddType
)  

if ($AddType.IsPresent) {

echo "[+] Loading Assembly using AddType"
echo ""

Add-Type -TypeDefinition @"
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Net.Sockets;

public class ArpScanner
{
    public class MacState
    {
        public Int32 Counter = 0;
        public AutoResetEvent DoneEvent = new AutoResetEvent(false);
        public Dictionary<String, String> Results
        {
            get { return _results; }
            set { _results = value; }
        }
        Dictionary<String, String> _results;
    }
    public class IPQueryState
    {
        public IPQueryState(MacState state)
        {
            CurrentState = state;
        }
        public MacState CurrentState { get { return _currentState; } private set { _currentState = value; } }
        MacState _currentState;

        public string Query { get { return _query; } set { _query = value; } }
        String _query;
    }

    public Dictionary<String, String> DoScan(String ipString)
    {
        return DoScan(ipString, 100);
    }


    public Dictionary<String, String> DoScan(String ipString, ushort maxThreads)
    {
        ThreadPool.SetMaxThreads(maxThreads, maxThreads);
        Dictionary<String, String> Results = new Dictionary<String, String>();
        if ((!ipString.StartsWith("127.0.0.1")) && !ipString.StartsWith("169"))
        {
            MacState state = new MacState();
            state.Results = Results;
            if (ArpScanner.IPv4Tools.IsIPRangeFormat(ipString))
            {
                ArpScanner.IPv4Tools.IPRange iprange = IPv4Tools.IPEnumerator[ipString];

                foreach (string n in iprange)
                {
                    state.Counter++;
                }

                foreach (string ip in iprange)
                {
                    IPQueryState ipq = new IPQueryState(state);
                    ipq.Query = ip;
                    ThreadPool.QueueUserWorkItem(GetMAC, ipq);
                }
                state.DoneEvent.WaitOne();
            }
            else
            {
                IPQueryState ipq = new IPQueryState(state);
                ipq.Query = ipString;
                GetMAC(ipq);
            }


        }
        return Results;
    }
    public static String gethostbyaddrNetBIOS(String ipaddress)
    {
        try
        {
            IPAddress src = IPAddress.Parse(ipaddress);
            uint intAddress = BitConverter.ToUInt32(src.GetAddressBytes(), 0);
            IntPtr nameInt = Kernel32Imports.gethostbyaddr(ref intAddress, 4, ProtocolFamily.NetBios);
            IntPtr name = Marshal.ReadIntPtr(nameInt);
            String NetbiosName = Marshal.PtrToStringAnsi(name);
            return NetbiosName;
        }
        catch
        {
            return "N/A";
        }

    }
    static void GetMAC(object state)
    {
        IPQueryState queryState = state as IPQueryState;
        try
        {
            IPAddress dst = null;
            if (!IPAddress.TryParse(queryState.Query, out dst))
            {
                Console.WriteLine(String.Format("IP Address {0} is invalid ", queryState.Query));
                return;
            }

            uint uintAddress = BitConverter.ToUInt32(dst.GetAddressBytes(), 0);
            byte[] macAddr = new byte[6];
            int macAddrLen = macAddr.Length;
            int retValue = Kernel32Imports.SendARP(uintAddress, 0, macAddr, ref macAddrLen);
            if (retValue != 0)
            {
                return;
            }
            string[] str = new string[(int)macAddrLen];
            for (int i = 0; i < macAddrLen; i++)
                str[i] = macAddr[i].ToString("x2");
            string mac = string.Join(":", str);

            if (queryState.Query != null && mac != null)
                queryState.CurrentState.Results.Add(queryState.Query, mac);

        }
        finally
        {
            int temp = 0;
            if ((temp = Interlocked.Decrement(ref queryState.CurrentState.Counter)) == 0)
                queryState.CurrentState.DoneEvent.Set();
        }
    }

    static class Kernel32Imports
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(uint DestIP, uint SrcIP, byte[] pMacAddr, ref int PhyAddrLen);
        [DllImport("ws2_32.dll", SetLastError = true)]
        internal static extern IntPtr gethostbyaddr(
          [In] ref uint addr,
          [In] int len,
          [In] ProtocolFamily type
          );
    }

    class IPv4Tools
    {
        private static readonly Regex _ipCidrRegex = new Regex(@"^(?<ip>(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(\/(?<cidr>(\d|[1-2]\d|3[0-2])))$");
        private static readonly Regex _ipRegex = new Regex(@"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$");
        private static readonly Regex _ipRangeRegex = new Regex(@"^(?<ip>(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?<from>([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])))(\-(?<to>([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])))$");

        public static IPv4Tools IPEnumerator
        {
            get
            {
                return new IPv4Tools();
            }
        }

        public IPRange this[string value]
        {
            get
            {
                return new IPRange(value);
            }
        }

        public static bool IsIPRangeFormat(string IpRange)
        {
            return (_ipCidrRegex.Match(IpRange).Success || _ipRangeRegex.Match(IpRange).Success);
        }

        public static bool IsIPCidr(string ip_cidr)
        {
            return _ipCidrRegex.Match(ip_cidr).Success;
        }

        public static bool IsIPRange(string IpRange)
        {
            return _ipRangeRegex.Match(IpRange).Success;
        }

        public static bool IsIP(string ip)
        {
            return _ipRegex.Match(ip).Success;
        }

        public static Match IpCidrMatch(string ip_cidr)
        {
            return _ipCidrRegex.Match(ip_cidr);
        }

        public static Match IpRangeMatch(string IpRange)
        {
            return _ipRangeRegex.Match(IpRange);
        }

        public class IPRange : IEnumerable<string>
        {
            string _ip_cidr;
            public IPRange(string ip_cidr)
            {
                _ip_cidr = ip_cidr;
            }

            public IEnumerator<string> GetEnumerator()
            {
                return new IPRangeEnumerator(_ip_cidr);
            }

            private IEnumerator GetEnumerator1()
            {
                return this.GetEnumerator();
            }
            IEnumerator IEnumerable.GetEnumerator()
            {
                return GetEnumerator1();
            }
        }

        class IPRangeEnumerator : IEnumerator<string>
        {
            string _ipcidr = null;
            UInt32 _loAddr;
            UInt32 _hiAddr;
            UInt32? _current = null;

            public IPRangeEnumerator(string ip_cidr)
            {
                _ipcidr = ip_cidr;
                Match cidrmch = IPv4Tools.IpCidrMatch(ip_cidr);
                Match rangeMch = IPv4Tools.IpRangeMatch(ip_cidr);
                if (cidrmch.Success)
                    ProcessCidrRange(cidrmch);
                else if (rangeMch.Success)
                    ProcessIPRange(rangeMch);

                if (!cidrmch.Success && !rangeMch.Success)
                    throw new Exception("IP Range must either be in IP/CIDR or IP to-from format");
            }
            public void ProcessIPRange(Match rangeMch)
            {
                System.Net.IPAddress startIp = IPAddress.Parse(rangeMch.Groups["ip"].Value);
                ushort fromRange = ushort.Parse(rangeMch.Groups["from"].Value);
                ushort toRange = ushort.Parse(rangeMch.Groups["to"].Value);

                if (fromRange > toRange)
                    throw new Exception("IP Range the from must be less than the to");
                else if (toRange > 254)
                    throw new Exception("IP Range the to must be less than 254");
                else
                {
                    byte[] arrIpBytes = startIp.GetAddressBytes();
                    Array.Reverse(arrIpBytes);
                    uint ipuint = System.BitConverter.ToUInt32(arrIpBytes, 0);
                    _loAddr = ipuint;
                    _hiAddr = ipuint + ((uint)(toRange - fromRange)) + 1;
                }
            }

            public void ProcessCidrRange(Match cidrmch)
            {
                System.Net.IPAddress ip = IPAddress.Parse(cidrmch.Groups["ip"].Value);
                Int32 cidr = Int32.Parse(cidrmch.Groups["cidr"].Value);

                if (cidr <= 0)
                    throw new Exception("CIDR can't be negative");
                else if (cidr > 32)
                    throw new Exception("CIDR can't be more 32");
                else if (cidr == 32)
                {
                    byte[] arrIpBytes = ip.GetAddressBytes();
                    Array.Reverse(arrIpBytes);
                    UInt32 ipuint = System.BitConverter.ToUInt32(arrIpBytes, 0);
                    _loAddr = ipuint;
                    _hiAddr = ipuint;
                }
                else
                {
                    byte[] arrIpBytes = ip.GetAddressBytes();
                    Array.Reverse(arrIpBytes);
                    UInt32 ipuint = System.BitConverter.ToUInt32(arrIpBytes, 0);
                    uint umsk = uint.MaxValue >> cidr;
                    uint lmsk = (umsk ^ uint.MaxValue);
                    _loAddr = ipuint & lmsk;
                    _hiAddr = ipuint | umsk;
                }
            }

            UInt32 HostToNetwork(UInt32 host)
            {
                byte[] hostBytes = System.BitConverter.GetBytes(host);
                Array.Reverse(hostBytes);
                return System.BitConverter.ToUInt32(hostBytes, 0);
            }

            public string Current
            {
                get
                {
                    if (String.IsNullOrEmpty(_ipcidr) || !_current.HasValue)
                        throw new InvalidOperationException();

                    return IPv4Tools.UIntToIpString(HostToNetwork(_current.Value));
                }
            }

            public bool MoveNext()
            {
                if (!_current.HasValue)
                {
                    _current = _loAddr;
                    if (_current == _hiAddr) //handles if /32 used
                        return true;
                }
                else
                    _current++;

                if ((0xFF & _current) == 0 || (0xFF & _current) == 255)
                    _current++;

                if (_current < _hiAddr)
                    return true;
                else
                    return false;
            }

            public void Reset()
            {
                _current = _loAddr;
                if ((0xFF & _current) == 0 || (0xFF & _current) == 255)
                    _current++;
            }

            object Current1
            {
                get { return this.Current; }
            }

            object IEnumerator.Current
            {
                get { return Current1; }
            }

            public void Dispose()
            { }
        }
        static string UIntToIpString(UInt32 address)
        {
            int num1 = 15;
            char[] chPtr = new char[15];
            int num2 = (int)(address >> 24 & (long)byte.MaxValue);
            do
            {
                chPtr[--num1] = (char)(48 + num2 % 10);
                num2 /= 10;
            }
            while (num2 > 0);
            int num3;
            chPtr[num3 = num1 - 1] = '.';
            int num4 = (int)(address >> 16 & (long)byte.MaxValue);
            do
            {
                chPtr[--num3] = (char)(48 + num4 % 10);
                num4 /= 10;
            }
            while (num4 > 0);
            int num5;
            chPtr[num5 = num3 - 1] = '.';
            int num6 = (int)(address >> 8 & (long)byte.MaxValue);
            do
            {
                chPtr[--num5] = (char)(48 + num6 % 10);
                num6 /= 10;
            }
            while (num6 > 0);

            int startIndex;
            chPtr[startIndex = num5 - 1] = '.';
            int num7 = (int)(address & (long)byte.MaxValue);
            do
            {
                chPtr[--startIndex] = (char)(48 + num7 % 10);
                num7 /= 10;
            }
            while (num7 > 0);

            return new string(chPtr, startIndex, 15 - startIndex);
        }
    }
}
"@
} else {
    if ($arploaded -ne "TRUE") {
        $script:arploaded = "TRUE"
        echo "[+] Loading Assembly using System.Reflection"
        echo ""
        $ps = "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b2xlAFdhaXRPbmUAV3JpdGVMaW5lAHR5cGUAQ2FwdHVyZQBEaXNwb3NlAFRyeVBhcnNlAFJldmVyc2UATWFjU3RhdGUAZ2V0X0N1cnJlbnRTdGF0ZQBzZXRfQ3VycmVudFN0YXRlAF9jdXJyZW50U3RhdGUASVBRdWVyeVN0YXRlAHN0YXRlAEd1aWRBdHRyaWJ1dGUARGVidWdnYWJsZUF0dHJpYnV0ZQBDb21WaXNpYmxlQXR0cmlidXRlAEFzc2VtYmx5VGl0bGVBdHRyaWJ1dGUAQXNzZW1ibHlUcmFkZW1hcmtBdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBEZWZhdWx0TWVtYmVyQXR0cmlidXRlAENvbXBpbGF0aW9uUmVsYXhhdGlvbnNBdHRyaWJ1dGUAQXNzZW1ibHlQcm9kdWN0QXR0cmlidXRlAEFzc2VtYmx5Q29weXJpZ2h0QXR0cmlidXRlAEFzc2VtYmx5Q29tcGFueUF0dHJpYnV0ZQBSdW50aW1lQ29tcGF0aWJpbGl0eUF0dHJpYnV0ZQBCeXRlAGdldF9WYWx1ZQBnZXRfSGFzVmFsdWUAdmFsdWUAU3lzdGVtLlRocmVhZGluZwBUb1N0cmluZwBVSW50VG9JcFN0cmluZwBpcFN0cmluZwByYW5nZU1jaABjaWRybWNoAElwUmFuZ2VNYXRjaABJcENpZHJNYXRjaABTdGFydHNXaXRoAFB0clRvU3RyaW5nQW5zaQBXYWl0Q2FsbGJhY2sASG9zdFRvTmV0d29yawBNYXJzaGFsAHdzMl8zMi5kbGwAQXJwU2Nhbm5lckRMTC5kbGwAaXBobHBhcGkuZGxsAFRocmVhZFBvb2wAZ2V0X0l0ZW0AUXVldWVVc2VyV29ya0l0ZW0AU3lzdGVtAERvU2NhbgBQaHlBZGRyTGVuAGxlbgBKb2luAFN5c3RlbS5SZWZsZWN0aW9uAEdyb3VwQ29sbGVjdGlvbgBJbnZhbGlkT3BlcmF0aW9uRXhjZXB0aW9uAGlwAEdyb3VwAENoYXIAcE1hY0FkZHIAX2hpQWRkcgBfbG9BZGRyAGdldGhvc3RieWFkZHIASXNJUENpZHIAX2lwX2NpZHIAX2lwY2lkcgBBcnBTY2FubmVyAENvdW50ZXIAQml0Q29udmVydGVyAElFbnVtZXJhdG9yAGdldF9JUEVudW1lcmF0b3IASVBSYW5nZUVudW1lcmF0b3IAU3lzdGVtLkNvbGxlY3Rpb25zLklFbnVtZXJhYmxlLkdldEVudW1lcmF0b3IALmN0b3IALmNjdG9yAFJlYWRJbnRQdHIAU3lzdGVtLkRpYWdub3N0aWNzAFNldE1heFRocmVhZHMAbWF4VGhyZWFkcwBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMAU3lzdGVtLlJ1bnRpbWUuQ29tcGlsZXJTZXJ2aWNlcwBEZWJ1Z2dpbmdNb2RlcwBHZXRBZGRyZXNzQnl0ZXMAR2V0Qnl0ZXMASVB2NFRvb2xzAFN5c3RlbS5UZXh0LlJlZ3VsYXJFeHByZXNzaW9ucwBTeXN0ZW0uQ29sbGVjdGlvbnMAZ2V0X0dyb3VwcwBnZXRfU3VjY2VzcwBJUEFkZHJlc3MAaXBhZGRyZXNzAFN5c3RlbS5OZXQuU29ja2V0cwBnZXRfUmVzdWx0cwBzZXRfUmVzdWx0cwBfcmVzdWx0cwBLZXJuZWwzMkltcG9ydHMASXNJUFJhbmdlRm9ybWF0AE9iamVjdABTeXN0ZW0uTmV0AFNldABSZXNldABHZXRWYWx1ZU9yRGVmYXVsdABEZWNyZW1lbnQAU3lzdGVtLkNvbGxlY3Rpb25zLklFbnVtZXJhdG9yLkN1cnJlbnQAU3lzdGVtLkNvbGxlY3Rpb25zLklFbnVtZXJhdG9yLmdldF9DdXJyZW50AF9jdXJyZW50AERvbmVFdmVudABBdXRvUmVzZXRFdmVudABob3N0AE1vdmVOZXh0AF9pcFJhbmdlUmVnZXgAX2lwUmVnZXgAX2lwQ2lkclJlZ2V4AEFycmF5AFByb3RvY29sRmFtaWx5AGdldF9RdWVyeQBzZXRfUXVlcnkAX3F1ZXJ5AElzTnVsbE9yRW1wdHkAAAAAEzEAMgA3AC4AMAAuADAALgAxAAAHMQA2ADkAAAdOAC8AQQAANUkAUAAgAEEAZABkAHIAZQBzAHMAIAB7ADAAfQAgAGkAcwAgAGkAbgB2AGEAbABpAGQAIAAABXgAMgAAAzoAAIEhXgAoAD8APABpAHAAPgAoACgAWwAwAC0AOQBdAHwAWwAxAC0AOQBdAFsAMAAtADkAXQB8ADEAWwAwAC0AOQBdAHsAMgB9AHwAMgBbADAALQA0AF0AWwAwAC0AOQBdAHwAMgA1AFsAMAAtADUAXQApAFwALgApAHsAMwB9ACgAWwAwAC0AOQBdAHwAWwAxAC0AOQBdAFsAMAAtADkAXQB8ADEAWwAwAC0AOQBdAHsAMgB9AHwAMgBbADAALQA0AF0AWwAwAC0AOQBdAHwAMgA1AFsAMAAtADUAXQApACkAKABcAC8AKAA/ADwAYwBpAGQAcgA+ACgAXABkAHwAWwAxAC0AMgBdAFwAZAB8ADMAWwAwAC0AMgBdACkAKQApACQAAYDTXgAoACgAWwAwAC0AOQBdAHwAWwAxAC0AOQBdAFsAMAAtADkAXQB8ADEAWwAwAC0AOQBdAHsAMgB9AHwAMgBbADAALQA0AF0AWwAwAC0AOQBdAHwAMgA1AFsAMAAtADUAXQApAFwALgApAHsAMwB9ACgAWwAwAC0AOQBdAHwAWwAxAC0AOQBdAFsAMAAtADkAXQB8ADEAWwAwAC0AOQBdAHsAMgB9AHwAMgBbADAALQA0AF0AWwAwAC0AOQBdAHwAMgA1AFsAMAAtADUAXQApACQAAYFpXgAoAD8APABpAHAAPgAoACgAWwAwAC0AOQBdAHwAWwAxAC0AOQBdAFsAMAAtADkAXQB8ADEAWwAwAC0AOQBdAHsAMgB9AHwAMgBbADAALQA0AF0AWwAwAC0AOQBdAHwAMgA1AFsAMAAtADUAXQApAFwALgApAHsAMwB9ACgAPwA8AGYAcgBvAG0APgAoAFsAMAAtADkAXQB8AFsAMQAtADkAXQBbADAALQA5AF0AfAAxAFsAMAAtADkAXQB7ADIAfQB8ADIAWwAwAC0ANABdAFsAMAAtADkAXQB8ADIANQBbADAALQA1AF0AKQApACkAKABcAC0AKAA/ADwAdABvAD4AKABbADAALQA5AF0AfABbADEALQA5AF0AWwAwAC0AOQBdAHwAMQBbADAALQA5AF0AewAyAH0AfAAyAFsAMAAtADQAXQBbADAALQA5AF0AfAAyADUAWwAwAC0ANQBdACkAKQApACQAAW9JAFAAIABSAGEAbgBnAGUAIABtAHUAcwB0ACAAZQBp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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        $dllbytes  = [System.Convert]::FromBase64String($ps)
        $assembly = [System.Reflection.Assembly]::Load($dllbytes)
    }
}

if ($IPCidr) {

    try {
        echo "[+] Arpscan against: $IPCidr"
        $ArpScanner = New-Object ArpScanner
        $r = $ArpScanner.DoScan($ipcidr)
        $r
        echo ""

        if ($Resolve.IsPresent){
            echo "IP Resolution"
            echo "================="
        }

        foreach ($y in $r){
            [string]$t = $y.Keys
            foreach ($ip in $y.Keys){
            if ($Resolve.IsPresent){
                $nbtname = [ArpScanner]::gethostbyaddrNetBIOS($ip)
                echo "$ip - $nbtname"  
            }             
            }
            
            echo $y.Value
        }


    } catch {
        echo "[-] Error against network $IPCidr"
    }

} else {

    $Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -EA Stop | ? {$_.IPEnabled}

    foreach ($Network in $Networks) {

    $ip  = $Network.IpAddress[0]
    $mask  = $Network.IPSubnet[0]
    $DefaultGateway = $Network.DefaultIPGateway
    $DNSServers  = $Network.DNSServerSearchOrder

    $val = 0; $mask -split "\." | % {$val = $val * 256 + [Convert]::ToInt64($_)}
    $ipcidr = $ip + "/" + [Convert]::ToString($val,2).IndexOf('0')

    try {
        echo "[+] Arpscan against: $ipcidr"
        $ArpScanner = New-Object ArpScanner
        $r = $ArpScanner.DoScan($ipcidr)
        $r
        echo ""

        if ($Resolve.IsPresent){
            echo "IP Resolution"
            echo "================="
        }

        foreach ($y in $r){
            [string]$t = $y.Keys
            foreach ($ip in $y.Keys){
            if ($Resolve.IsPresent){
                $nbtname = [ArpScanner]::gethostbyaddrNetBIOS($ip)
                echo "$ip - $nbtname"  
            }             
            }
            
            echo $y.Value
        }

    } catch {
        echo "[-] Error against network $ipcidr"
    }

    }

}

}
New-Alias ArpScan Invoke-Arpscan
