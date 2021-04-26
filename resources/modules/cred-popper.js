function prompter(title, text, icon){
	let app = Application.currentApplication()
	app.includeStandardAdditions = true
	let prompt = app.displayDialog(text, {defaultAnswer: "", buttons: ["OK", "Cancel"], defaultButton: "OK", cancelButton: "Cancel", withTitle: title, withIcon: Path(icon), hiddenAnswer: true });
	let pass = prompt.textReturned;
    // If running BigSur, testing the pass is not yet working...
    let osVer = ObjC.deepUnwrap($.NSProcessInfo.processInfo.operatingSystemVersionString.js);
    if (osVer.includes("11.")){
        return pass;
    }else{
        testPass(pass);
    }
}
function testPass(pass){
    ObjC.import('Collaboration');
    ObjC.import('CoreServices');
    let cu = ObjC.deepUnwrap($.NSProcessInfo.processInfo.userName);
    let authority = $.CBIdentityAuthority.defaultIdentityAuthority;
    let username = cu;
    let password = pass;
    let user = $.CBIdentity.identityWithNameAuthority(username, authority);
    if(user.js !== undefined){
        if(user.authenticateWithPassword(password)){
            console.log("Successful authentication");
            return password;
        }
        else{
            prompter(title, text, icon);
        }
    }
    else{
        console.log("User does not exist");
    }
}

var title = "%s";
var text = "%s";
var icon = "%s";
prompter(title, text, icon)
