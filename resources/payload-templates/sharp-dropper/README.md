# Sharp Dropper

This project is the C# Dropper. It can be opened as a solution for ease of dev but note that Posh will not build the
solution only using `mingw` to build `Program.cs`, so changes to the project/solution files only affect development.

## Error codes

The project uses error codes instead of messages, these are stored in ERROR_CODES.txt.

## Config

The config has the format:

```
RetriesEnabled;RetryLimit;StageWaitTime;DomainCheck;ProxyUrl;ProxyUser;ProxyPass;UserAgent;HttpReferrer;KillDate;UrlId;FailoverDomain1,FailoverHostHeader1:FailoverDomain2,FailoverHostHeader2;BeaconDomain1,BeaconHostHeader1:BeaconDomain2,BeaconHostHeader2;/url/1:/url/2;RandomUri;StageUrl;Images;Sleep;Jitter;Key
```

E.g.:

```
true;10;30;BLOREBANK;;;;Base64EncodedUserAgent;;2022-10-10;1;https://blorebank.com:8080,asdf.azureedge.net-https://test.blorebank.com,asdf2.azureedge.net;http://beacon.blorebank.com,;/test1:/test2:/test3;image1,image2;randomuri;/stage;30;0.6;key
```