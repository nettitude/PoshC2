using System;

internal interface IComms : IDisposable
{
    string GetCommands();
    void SendTaskOutputString(string taskId, string data);
    void SendTaskOutputBytes(string taskId, byte[] data);
    string Stage(string environmentalInfo);
}