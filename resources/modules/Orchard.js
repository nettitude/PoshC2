//Author Cody Thomas, @its_a_feature_
ObjC.import("Foundation");
ObjC.import("stdio");
ObjC.import('OpenDirectory');
//for all of these, there is a switch to use ObjC calls vs terminal calls
currApp = Application.currentApplication();
currApp.includeStandardAdditions = true;
// Lookup tables for doing OpenDirectory queries via LDAP
var object_class = {
	"AttributeTypes": 			"dsRecTypeStandard:AttributeTypes",
	"AFPServer": 				"dsRecTypeStandard:AFPServer",
	"Aliases": 					"dsRecTypeStandard:Aliases",
	"Augments": 				"dsRecTypeStandard:Augments",
	"Automount": 				"dsRecTypeStandard:Automount",
	"AutomountMap": 			"dsRecTypeStandard:AutomountMap",
	"AutoServerSetup": 			"dsRecTypeStandard:AutoServerSetup",
	"Bootp": 					"dsRecTypeStandard:Bootp",
	"CertificateAuthorities": 	"dsRecTypeStandard:CertificateAuthorities",
	"ComputerLists": 			"dsRecTypeStandard:ComputerLists",
	"ComputerGroups": 			"dsRecTypeStandard:ComputerGroups",
	"Computers": 				"dsRecTypeStandard:Computers",
	"Configuration": 			"dsRecTypeStandard:Config",
	"Ethernets": 				"dsRecTypeStandard:Ethernets",
	"FileMakerServers": 		"dsRecTypeStandard:FileMakerServers",
	"FTPServer": 				"dsRecTypeStandard:FTPServer",
	"Groups": 					"dsRecTypeStandard:Groups",
	"HostServices": 			"dsRecTypeStandard:HostServices",
	"Hosts": 					"dsRecTypeStandard:Hosts",
	"LDAPServer": 				"dsRecTypeStandard:LDAPServer",
	"Locations": 				"dsRecTypeStandard:Locations",
	"Mounts": 					"dsRecTypeStandard:Mounts",
	"NFS": 						"dsRecTypeStandard:NFS",
	"NetDomains": 				"dsRecTypeStandard:NetDomains",
	"NetGroups": 				"dsRecTypeStandard:NetGroups",
	"Networks": 				"dsRecTypeStandard:Networks",
	"PasswordServer": 			"dsRecTypeStandard:PasswordServer",
	"People": 					"dsRecTypeStandard:People",
	"Plugins": 					"dsRecTypeStandard:Plugins",
	"PresetComputers": 			"dsRecTypeStandard:PresetComputers",
	"PresetComputerGroups": 	"dsRecTypeStandard:PresetComputerGroups",
	"PresetComputerLists": 		"dsRecTypeStandard:PresetComputerLists",
	"PresetGroups": 			"dsRecTypeStandard:PresetGroups",
	"PresetUsers": 				"dsRecTypeStandard:PresetUsers",
	"PrintService": 			"dsRecTypeStandard:PrintService",
	"PrintServiceUser": 		"dsRecTypeStandard:PrintServiceUser",
	"Printers": 				"dsRecTypeStandard:Printers",
	"Protocols": 				"dsRecTypeStandard:Protocols",
	"QTSServer": 				"dsRecTypeStandard:QTSServer",
	"RecordTypes": 				"dsRecTypeStandard:RecordTypes",
	"Resources": 				"dsRecTypeStandard:Resources",
	"RPC": 						"dsRecTypeStandard:RPC",
	"SMBServer": 				"dsRecTypeStandard:SMBServer",
	"Server": 					"dsRecTypeStandard:Server",
	"Services": 				"dsRecTypeStandard:Services",
	"SharePoints": 				"dsRecTypeStandard:SharePoints",
	"UserAuthenticationData": 	"dsRecTypeStandard:UserAuthenticationData",
	"Users": 					"dsRecTypeStandard:Users",
	"WebServer": 				"dsRecTypeStandard:WebServer",	
}
var match_type = {
	"Any": 			0x01,//$.kODMatchAny,
	"BeginsWith": 	0x2002,//$.kODMatchInsensitiveBeginsWith,
	"EndsWith": 	0x2003,//$.kODMatchInsensitiveEndsWith,
	"Contains": 	0x2004,//$.kODMatchInsensitiveContains,
	"EqualTo": 		0x2001,//$.kODMatchInsensitiveEqualTo,
	"LessThan": 	0x2007,//$.kODMatchLessThan,
	"GreaterThan": 	0x2006,//$.kODMatchGreaterThan
}
var attributes_list = {
	"all": 							["",								"dsAttributesAll"],
	"*": 							["",								"dsAttributesAll"],
	"accountpolicydata": 			["accountPolicyData",				"dsAttrTypeNative:"],
	"accountexpires": 				["accountExpires",				 	"dsAttrTypeNative:"],
	"admincount": 					["adminCount",						"dsAttrTypeNative:"],
	"adminlimits": 					["AdminLimits", 					"dsAttrTypeStandard:"],
	"altsecurityidentities": 		["AltSecurityIdentities",			"dsAttrTypeStandard:"], //x509
	"afp_guestaccess": 				["afp_guestaccess",					"dsAttrTypeNative:"],
	"afp_name": 					["afp_name",					 	"dsAttrTypeNative:"],
	"afp_shared":  					["afp_shared",						"dsAttrTypeNative:"],
	"authenticationhint": 			["AuthenticationHint", 				"dsAttrtypeStandard:"],
	"badpasswordtime": 				["badPasswordTime",					"dsAttrTypeNative:"],
	"badpwdcount": 					["badPwdCount",						"dsAttrTypeNative:"],
	"bootfile": 					["BootFile", 						"dsAttrTypeStandard:"],
	"bootparams": 					["BootParams", 						"dsAttrTypeStandard:"],
	"cacertificiate": 				["CACertificate", 					"dsAttrTypeStandard:"],
	"capacity": 					["Capacity", 						"dsAttrTypeStandard:"],
	"category": 					["Category", 						"dsAttrtypeStandard:"],
	"certificaterevocationlist": 	["CertificateRevocationList", 		"dsAttrTypeStandard:"],
	"codepage": 					["codePage",						"dsAttrTypeNative:"],
	"comment": 						["Comment",							"dsAttrTypeStandard:"],
	"contactguid": 					["ContactGUID",						"dsAttrtypeStandard:"],
	"countrycode": 					["countryCode",						"dsAttrTypeNative:"],
	"creationtimestamp": 			["CreationTimestamp",				"dsAttrTypeStandard:"],
	"crosscertificatepair": 		["CrossCertificatePair", 			"dsAttrTypeStandard:"],
	"cn": 							["cn",								"dsAttrTypeNative:"],
	"fullname": 					["FullName",						""], //have to use realname
	"displayname": 					["displayName",						"dsAttrTypeNative:"],
	"distinguishedname": 			["distinguishedName",				"dsAttrTypeNative:"],
	"directory_path": 				["directory_path",					"dsAttrTypeNative:"],
	"dnsdomain": 					["DNSDomain",						"dsAttrTypeStandard:"],
	"dnsnameserver": 				["DNSNameServer",					"dsAttrTypeStandard:"],
	"dscorepropagationdata": 		["dsCorePropagationData",			"dsAttrTypeNative:"],
	"emailaddress": 				["EMailAddress", 					"dsAttrTypeStandard:"],
	"enetaddress": 					["ENetAddress", 					"dsAttrTypeNative:"],
	"expire": 						["Expire", 							"dsAttrTypeStandard:"],
	"firstname": 					["FirstName",						"dsAttrTypeStandard:"],
	"ftp_name": 					["ftp_name",						"dsAttrTypeNative:"],
	"generateduid": 				["GeneratedUID",					"dsAttrTypeStandard:"],
	"grouptype": 					["groupType",						"dsAttrTypeNative:"],
	"hardwareuuid": 				["HardwareUUID", 					"dsAttrTypeStandard:"],
	"heimdalsrpkey": 				["HeimdalSRPKey", 					"dsAttrTypeNative:"],
	"ishidden": 					["IsHidden",						"dsAttrTypeNative:"],
	"instancetype": 				["instanceType",					"dsAttrTypeNative:"],
	"iscriticalsystemobject": 		["isCriticalSystemObject",			"dsAttrTypeNative:"],
	"jobtitle": 					["JobTitle", 						"dsAttrTypeStandard:"],
	"kerberoskeys": 				["KerberosKeys", 					"dsAttrTypeNative:"],
	"kerberosservices": 			["KerberosServices",				"dsAttrTypeStandard:"], //host, afpserver, cifs, vnc, etc
	"lastname": 					["LastName",						"dsAttrTypeStandard:"],
	"lastlogoff": 					["lastLogoff",						"dsAttrTypeNative:"],
	"lastlogon": 					["lastLogon",					 	"dsAttrTypeNative:"],
	"lastlogontimestamp": 			["lastLogonTimestamp",				"dsAttrTypeNative:"],
	"localpolicyglags": 			["localPolicyFlags",				"dsAttrTypeNative:"],
	"logoncount": 					["logonCount",						"dsAttrTypeNative:"],
	"logonhours": 					["logonHours",					 	"dsAttrTypeNative:"],
	"ldapsearchbasesuffix": 		["LDAPSearchBaseSuffix",			"dsAttrtypeStandard:"],
	"automountmap": 				["AutomountMap",					"dsAttrTypeStandard:"],
	"applemetanodelocation":  		["AppleMetaNodeLocation",			"dsAttrTypeStandard:"],
	"applemetarecordname": 			["AppleMetaRecordName",				"dsAttrTypeStandard:"],
	"machineserves": 				["MachineServes", 					"dsAttrTypeStandard:"],
	"mcxflags": 					["MCXFlags",						"dsAttrTypeStandard:"],
	"mcxsettings": 					["MCXSettings",						"dsAttrTypeStandard:"],
	"middlename": 					["MiddleName",						"dsAttrTypeStandard:"],
	"member": 						["member",							"dsAttrTypeNative:"],
	"memberof": 					["memberOf",						"dsAttrTypeNative:"],
	"members": 						["members",							"dsAttrTypeNative:"],
	"msdfsr-computerreferencebl": 	["msDFSR-ComputerReferenceBL",	 	"dsAttrTypeNative:"],
	"msds-generationid": 			["msDS-GenerationId",				"dsAttrTypeNative:"],
	"msds-supportedencryptiontypes":["msDS-SupportedEncryptionTypes",	"dsAttrTypeNative:"],
	"modificationtimestamp": 		["ModificationTimestamp",			"dsAttrTypeStandard:"],
	"name": 						["name",						 	"dsAttrTypeNative:"],
	"networkaddress": 				["networkAddress",				 	"dsAttrTypeNative:"],
	"networkview": 					["NetworkView", 					"dsAttrTypeStandard:"],
	"nfshomedirectory": 			["NFSHomeDirectory",				"dsAttrTypeStandard:"],
	"nodesaslrealm": 				["NodeSASLRealm", 					"dsAttrTypeStandard:"],
	"note": 						["Note",							"dsAttrTypeStandard:"],//says this is for last name attribute???
	"objectclass": 					["objectClass",						"dsAttrTypeNative:"],
	"objectcategory": 				["objectCategory",					"dsAttrTypeNative:"],
	"objectguid": 					["objectGUID",						"dsAttrTypeNative:"],
	"objectsid": 					["objectSid",						"dsAttrTypeNative:"], 
	"olcdatabase": 					["OLCDatabase", 					"dsAttrTypeStandard:"],
	"olcdatabaseindex": 			["OLCDatabaseIndex", 				"dsAttrTypeStandard:"],
	"olcsyncrepl": 					["OLCSyncRepl", 					"dsAttrTypeStandard:"],
	"operatingsystem": 				["operatingSystem",					"dsAttrTypeNative:"],
	"operatingsystemversion": 		["operatingSystemVersion",			"dsAttrTypeNative:"],
	"owner": 						["Owner",							"dsAttrTypeStandard:"],
	"ownerguid": 					["OwnerGUID",						"dsAttrTypeStandard:"],
	"password": 					["Password",						"dsAttrTypeStandard:"],
	"passwordplus": 				["PasswordPlus",					"dsAttrTypeStandard:"],//indicates authentication redirection
	"passwordpolicyoptions": 		["PasswordPolicyOptions",			"dsAttrTypeStandard:"],
	"passwordserverlist": 			["PasswordServerList",				"dsAttrTypeStandard:"],
	"passwordserverlocation": 		["PasswordServerLocation",			"dsAttrTypeStandard:"],
	"port": 						["Port",							"dsAttrTypeStandard:"],//which port a service is on
	"presetuserisadmin": 			["PresetUserIsAdmin", 				"dsAttrTypeStandard:"],
	"primarycomputerguid": 			["PrimaryComputerGUID",				"dsAttrTypeStandard:"],
	"primarycomputerlist": 			["PrimaryComputerList", 			"dsAttrTypeStandard:"],
	"primarygroupid": 				["PrimaryGroupID",					"dsAttrTypeStandard:"],
	"profiles": 					["Profiles", 						"dsAttrTypeStandard:"],
	"profilestimestamp": 			["ProfilesTimestamp", 				"dsAttrTypeStandard:"],
	"realname": 					["RealName",						"dsAttrTypeStandard:"], //Yes, fullname maps to realname because... apple
	"realuserid": 					["RealUserID",						"dsAttrTypeStandard:"],
	"relativednprefix": 			["RelativeDNPrefix",				"dsAttrTypeStandard:"],//relative distinguished name,
	"ridsetreferences": 			["rIDSetReferences",				"dsAttrTypeNative:"],
	"samaccountname": 				["sAMAccountName",					"dsAttrTypeNative:"],
	"samaccounttype": 				["sAMAccountType",					"dsAttrTypeNative:"],
	"serverreferencebl": 			["serverReferenceBL",				"dsAttrTypeNative:"],
	"serviceprincipalname": 		["servicePrincipalName",			"dsAttrTypeNative:"],
	"shadowhashdata": 				["ShadowHashData", 					"dsAttrTypeNative:"],
	"smbacctflags": 				["SMBAccountFlags",					"dsAttrTypeStandard:"],//account control flag
	"smbgrouprid": 					["SMBGroupRID",						"dsAttrTypeStandard:"], //define PDC SMB interaction with DirectoryService
	"smbhome": 						["SMBHome",							"dsAttrTypeStandard:"],//UNC address of a windows home directory mount point
	"smbhomedrive": 				["SMBHomeDrive",					"dsAttrTypeStandard:"],
	"smbprimarygroupsid": 			["SMBPrimaryGroupSID",				"dsAttrTypeStandard:"],
	"smbpasswordlastset": 			["SMBPasswordLastSet",				"dsAttrTypeStandard:"],// used in SMB interaction
	"smbprofilepath": 				["SMBProfilePath",					"dsAttrTypeStandard:"],//defines desktop management info
	"smbrid": 						["SMBRID",							"dsAttrTypeStandard:"], //used in SMB interaction
	"smbscriptpath": 				["SMBScriptPath",					"dsAttrTypeStandard:"],//define SMB login script path
	"smbsid": 						["SMBSID",							"dsAttrTypeStandard:"], //define SMB Security ID
	"smbuserworkstations": 			["SMBUserWorkstations",				"dsAttrTypeStandard:"],//list of workstations a user can log in from
	"smblogofftime": 				["SMBLogoffTime",					"dsAttrTypeStandard:"],
	"smblogontime": 				["SMBLogonTime",					"dsAttrTypeStandard:"],
	"smb_createmask": 				["smb_createmask",					"dsAttrTypeNative:"],
	"smb_directorymask": 			["smb_directorymask",				"dsAttrTypeNative:"],
	"smb_guestaccess": 				["smb_guestaccess",					"dsAttrTypeNative:"],
	"smb_name": 					["smb_name",						"dsAttrTypeNative:"],
	"smb_shared":  					["smb_shared",						"dsAttrTypeNative:"],
	"servicetype": 					["ServiceType",						"dsAttrTypeStandard:"],//define SMB login script path
	"serviceslocator": 				["ServicesLocator", 				"dsAttrTypeStandard:"],
	"setupadvertising": 			["SetupAssistantAdvertising",		"dsAttrTypeStandard:"],//raw service type of a service, ex: http or https for kODRecordTypeWebServer
	"sharepoint_account_uuid": 		["sharepoint_account_uuid",			"dsAttrTypeNative:"],
	"sharepoint_group_id": 			["sharepoint_group_id",				"dsAttrTypeNative:"],
	"showinadvancedviewonly": 		["showInAdvancedViewOnly",			"dsAttrTypeNative:"],
	"uniqueid": 					["UniqueID",						"dsAttrTypeStandard:"], //user's 32bit ID in legacy manner
	"unlockoptions": 				["unlockOptions",					"dsAttrTypeNative:"],
	"url": 							["URL", 							"dsAttrTypeStandard:"],
	"users": 						["users",						 	"dsAttrTypeNative:"],
	"usnchanged": 					["uSNChanged",						"dsAttrTypeNative:"],
	"usncreated": 					["uSNCreated",						"dsAttrTypeNative:"], 
	"useraccountcontrol": 			["userAccountControl",				"dsAttrTypeNative:"],
	"usercertificate": 				["UserCertificate",					"dsAttrTypeStandard:"],
	"userpkcs12data": 				["UserPKCS12Data",					"dsAttrTypeStandard:"],
	"usershell": 					["UserShell",						"dsAttrTypeStandard:"],
	"usersmimecertificate": 		["UserSMIMECertificate",			"dsAttrTypeStandard:"],
	"webloguri": 					["WeblogURI",						"dsAttrTypeStandard:"],//URI of a user's weblog
	"whenchanged": 					["whenChanged",						"dsAttrTypeNative:"],
	"whencreated": 					["whenCreated",						"dsAttrTypeNative:"],
	"_writers_usercertificate": 	["_writers_UserCertificate",		"dsAttrTypeNative:"],
	"_writers_hint": 				["_writers_hint",					"dsAttrTypeNative:"],
	"_writers_passwd": 				["_writers_passwd",				 	"dsAttrTypeNative:"],
	"_writers_unlockoptions": 		["_writers_unlockOptions",			"dsAttrTypeNative:"],
	"_writers_usercertificate": 	["_writers_UserCertificate",		"dsAttrTypeNative:"],
	"xmlplist": 					["XMLPlist",						"dsAttrTypeStandard:"],//specify an XML Property List
	"protocolnumber": 				["ProtocolNumber",					"dsAttrTypeStandard:"],
	"rpcnumber": 					["RPCNumber",						"dsAttrTypeStandard:"],
	"networknumber": 				["NetworkNumber",					"dsAttrTypeStandard:"],
	"accesscontrolentry": 			["AccessControlEntry",				"dsAttrTypeStandard:"],
	"authenticationauthority": 		["AuthenticationAuthority",			"dsAttrTypeStandard:"], //specify mechanism used to verify or set a user's password
	"authorityrevocationlist": 		["AuthorityRevocationList", 		"dsAttrTypeStandard:"],
	"automountinformation": 		["AutomountInformation",			"dsAttrTypeStandard:"],
	"computers": 					["Computers",						"dsAttrTypeStandard:"],
	"dnsname": 						["DNSName",							"dsAttrTypeStandard:"],
	"group": 						["Group",							"dsAttrTypeStandard:"],//store a list of groups
	"groupmembers": 				["GroupMembers",					"dsAttrTypeStandard:"], //specify GUID values of members of a group that are not groups
	"groupmembership": 				["GroupMembership",					"dsAttrTypeStandard:"], //specify list of users that belong to a given group
	"groupservices": 				["GroupServices",					"dsAttrTypeStandard:"],//XML plist to define group's services,
	"homedirectory": 				["HomeDirectory",					"dsAttrTypeStandard:"],
	"imhandle": 					["IMHandle",						"dsAttrTypeStandard:"],//user's instant messaging handles
	"ipaddress": 					["IPAddress",						"dsAttrTypeStandard:"],
	"ipv6address": 					["IPv6Address",						"dsAttrTypeStandard:"],
	"kdcauthkey": 					["KDCAuthKey",						"dsAttrTypeStandard:"],//store a KDC master key
	"kdcconfigdata": 				["KDCConfigData", 					"dsAttrTypeStandard:"],
	"keywords": 					["Keywords", 						"dsAttrTypeStandard:"],
	"ldapreadreplicas": 			["LDAPReadReplicas",				"dsAttrTypeStandard:"],//list of LDAP server URLs that can be used to read directory data
	"ldapwritereplicas": 			["LDAPWriteReplicas",				"dsAttrTypeStandard:"],
	"linkedidentity": 				["LinkedIdentity",					"dsAttrTypeNative:"],
	"localerelay": 					["LocaleRelay", 					"dsAttrTypeStandard:"],
	"localesubnets": 				["LocaleSubnets", 					"dsAttrTypeStandard:"],
	"nestedgroups": 				["NestedGroups",					"dsAttrTypeStandard:"], //specify list of nested group GUID values in a group attribute
	"netgroups": 					["NetGroups",						"dsAttrTypeStandard:"],//specify a list of net groups that a user or host record is a member of
	"nickname": 					["NickName",						"dsAttrTypeStandard:"],
	"organizationinfo": 			["OrganizationInfo",				"dsAttrTypeStandard:"],
	"organizationname": 			["OrganizationName",				"dsAttrTypeStandard:"],
	"pgppublickey": 				["PGPPublicKey",					"dsAttrTypeStandard:"],
	"protocols": 					["Protocols",						"dsAttrTypeStandard:"],
	"recordname": 					["RecordName",						"dsAttrTypeStandard:"],
	"record_daemon_version": 		["record_daemon_version",			"dsAttrTypeNative:"],
	"relationships": 				["Relationships",					"dsAttrTypeStandard:"],
	"resourceinfo": 				["ResourceInfo",					"dsAttrTypeStandard:"],
	"resourcetype": 				["ResourceType",					"dsAttrTypeStandard:"],
	"authcredential": 				["AuthCredential",					"dsAttrTypeStandard:"],//stores an authentication credential used to authenticate to a directory
	"daterecordcreated": 			["DateRecordCreated",				"dsAttrTypeStandard:"],
	"kerberosflags": 				["KerberosFlags",					"dsAttrTypeNative:"],
	"kerberosrealm": 				["KerberosRealm",					"dsAttrTypeStandard:"],
	"ntdomaincomputeraccount": 		["NTDomainComputerAccount",			"dsAttrTypeStandard:"],//support kerberos SMB server services
	"primaryntdomain": 				["PrimaryNTDomain",					"dsAttrTypeStandard:"],
	"pwdagingpolicy": 				["PwdAgingPolicy",					"dsAttrTypeStandard:"],//record's password aging policy
	"readonlynode": 				["ReadOnlyNode",					"dsAttrTypeStandard:"],
	"authmethod": 					["AuthMethod",						"dsAttrTypeStandard:"],//specify a record's authentication method
	"recordtype": 					["RecordType",						"dsAttrTypeStandard:"], //specify type of a record or directory node
	"advertisedservices": 			["AdvertisedServices",				"dsAttrTypeStandard:"],//specify (Bounjour) advertised services
	"networkinterfaces": 			["NetworkInterfaces",				"dsAttrTypeStandard:"],
	"primarylocale": 				["PrimaryLocale",					"dsAttrTypeStandard:"]
}
var node_list = {
	"network": 			0x2205,//$.kODNodeTypeNetwork,
	"local": 			0x2200,//$.kODNodeTypeLocalNodes,
	"config": 			0x2202,//$.kODNodeTypeConfigure,
	"contacts": 		0x2204,//$.kODNodeTypeContacts
}
// helper functions to actually do the OD queries and return results
function Get_OD_ObjectClass({objectclass="Users", match="Any", value=null, max_results=0, query_attributes="All", return_attributes=[null], nodetype='network'} = {}){
	//gets all attributes for all local users
	var session = Ref();
	var node = Ref();
	var query = Ref();
	session = $.ODSession.defaultSession;
	//console.log(session);
	var fixed_return_attributes = [];
	for(var i in return_attributes){
		if(return_attributes[i] != null){
			ret_attr_lower = return_attributes[i].toLowerCase();
			if(attributes_list.hasOwnProperty(ret_attr_lower)){
				fixed_return_attributes.push(attributes_list[ret_attr_lower][1] + attributes_list[ret_attr_lower][0]);
			}
		}else{
			fixed_return_attributes.push(null);
		}
	}
	if(fixed_return_attributes.length == 1){
		fixed_return_attributes = fixed_return_attributes[0];
	}
	if(attributes_list.hasOwnProperty(query_attributes.toLowerCase())){
		query_attr_lower = query_attributes.toLowerCase();
		query_attributes = attributes_list[query_attr_lower][1] + attributes_list[query_attr_lower][0];
	}
	else{
		console.log("query attribute " + query_attributes + " not found");
		return;
	}
	//console.log(fixed_return_attributes);
	node = $.ODNode.nodeWithSessionTypeError(session, node_list[nodetype], null);
	//console.log("about to print subnode names\n");
	//console.log(ObjC.deepUnwrap($.ODNodeCopySubnodeNames(node, $())));
	//console.log("about to print supported attributes\n");
	//console.log(JSON.stringify([ObjC.deepUnwrap($.ODNodeCopySupportedAttributes(node, object_class[objectclass], $()))], null, 2));
	//https://developer.apple.com/documentation/opendirectory/odquery/1391709-querywithnode?language=objc
	//console.log("about to print supported record types\n");
	//console.log(JSON.stringify([ObjC.deepUnwrap($.ODNodeCopySupportedRecordTypes(node, $()))], null, 2));
	query = $.ODQuery.queryWithNodeForRecordTypesAttributeMatchTypeQueryValuesReturnAttributesMaximumResultsError(
	node, 
	object_class[objectclass], //(objectclass) https://developer.apple.com/documentation/opendirectory/opendirectory_functions/record_types?language=objc
	query_attributes, //set to recordname that we're looking to match
	match_type[match], //( equals, beginsWith, contains, etc) https://developer.apple.com/documentation/opendirectory/opendirectory_functions/match_types?language=objc
	value, // input query (like admin)
	fixed_return_attributes,
	max_results, //maximum number of results, 0=all
	$()); //error
	var results = query.resultsAllowingPartialError(false, null);
	//results;
	//console.log(results);
	var output = {};
	output[objectclass] = {};
	for(var i = 0; i < results.count; i++){
		var error = Ref();
		var attributes = results.objectAtIndex(i).recordDetailsForAttributesError($(),error);
		var keys = attributes.allKeys;
		output[objectclass][i] = {};
		for(var j = 0; j < keys.count; j++){
			var key = ObjC.unwrap(keys.objectAtIndex(j));
			var array = attributes.valueForKey(keys.objectAtIndex(j));
			var array_length = parseInt($.CFArrayGetCount(array));
			var val = [];
			for(var k = 0; k < array_length; k++){
				if(!array.objectAtIndex(k).isKindOfClass($.NSString.class)){
					//console.log(array.objectAtIndex(k).base64EncodedStringWithOptions(null).js);
					val.push(array.objectAtIndex(k).base64EncodedStringWithOptions(null).js);
				}else{
					//console.log(array.objectAtIndex(k));
					val.push(array.objectAtIndex(k).js);
				}
			}
			//var val = ObjC.deepUnwrap(attributes.valueForKey(keys.objectAtIndex(j)));
			output[objectclass][i][key] = val;
		}
	}
	return output;
}
function Get_OD_Node_Configuration({node="all"} = {}){
	let session = $.ODSession.defaultSession;
	let names = session.nodeNamesAndReturnError($());
	//console.log(names);
	names = ObjC.deepUnwrap(names);
	let configuration = {};
	for(let i in names){
		//console.log(names[i]);
		let config = session.configurationForNodename(names[i]);
		configuration[names[i]] = {};
		if(config.nodeName.js !== undefined){
			configuration[names[i]]['nodeName'] = config.nodeName.js;
		}
		configuration[names[i]]['trustAccount'] = ObjC.deepUnwrap(config.trustAccount);
		configuration[names[i]]['trustKerberosPrincipal'] = ObjC.deepUnwrap(config.trustKerberosPrincipal);
		configuration[names[i]]['trustMetaAccount'] = ObjC.deepUnwrap(config.trustMetaAccount);
		configuration[names[i]]['trustType'] = ObjC.deepUnwrap(config.trustType);
		configuration[names[i]]['trustUsesKerberosKeytab'] = config.trustUsesKerberosKeytab;
		configuration[names[i]]['trustUsesMutualAuthentication'] = ObjC.deepUnwrap(config.trustUsesMutualAuthentication);
		configuration[names[i]]['trustUsesSystemKeychain'] = ObjC.deepUnwrap(config.trustUsesSystemKeychain);
		if(config.defaultModuleEntries !== undefined){
			configuration[names[i]]['defaultMappings'] = ObjC.deepUnwrap(config.defaultModuleEntries);
		}
		if(config.authenticationModuleEntries !== undefined){
			configuration[names[i]]['authenticationModuleEntries'] = config.authenticationModuleEntries;
		}
		configuration[names[i]]['virtualSubnodes'] = ObjC.deepUnwrap(config.virtualSubnodes);
		configuration[names[i]]['templateName'] = ObjC.deepUnwrap(config.templateName);
		configuration[names[i]]['preferredDestinationHostName'] = ObjC.deepUnwrap(config.preferredDestinationHostName);
		configuration[names[i]]['preferredDestinationHostPort'] = ObjC.deepUnwrap(config.preferredDestinationHostPort);
		if(config.discoveryModuleEntries !== undefined){
			configuration[names[i]]['discoveryModuleEntries'] = ObjC.deepUnwrap(config.discoveryModuleEntries);
		}
	}
	//node = $.ODNode.nodeWithSessionTypeError(session, $.kODNodeTypeLocalNodes, null);
	node = $.ODNode.nodeWithSessionTypeError(session, 0x2200, null);
	//var policies = $.ODNodeCopyAccountPolicies(node, $());
	let policies = node.accountPoliciesAndReturnError($());
	if(policies.js !== undefined){
		configuration['Local_policies'] = ObjC.deepUnwrap(policies);
	}
	//node = $.ODNode.nodeWithSessionTypeError(session, $.kODNodeTypeNetwork, null);
	node = $.ODNode.nodeWithSessionTypeError(session, 0x2205, null);
	//var policies = $.ODNodeCopyAccountPolicies(node, $());
	policies = node.accountPoliciesAndReturnError($());
	if(policies.js !== undefined){
		configuration['Network_policies'] = ObjC.deepUnwrap(policies);
	}
	return JSON.stringify(configuration, null, 2);
}
// main functions
function ConvertTo_SID({API=true, object=".\\root", type="Users",help=false} = {}){
	//goes from "Domain\User" or "Domain\Group" or "Domain\Computer" to SID
	//type should be: Users, Groups, or Computers
	if(help){
	    var output = "";
		output += "\\nConvert Users, Groups, Or Computers to domain or local SIDs.";
		output += "\\n\"object\" should be either \".\\\\localthing\" or \"NETBIOSDOMAIN\\\\thing\"";
		output += "\\n\"type\" should be \"Users\", \"Groups\", or \"Computers\"";
		output += "\\ncalled: ConvertTo_SID({object:\".\\\\root\",type:\"Users\"});";
		return output;
	}
	command = "";
	splitObject = object.split('\\');
	if (splitObject.length != 2)
	{
		return "Invalid format for the object. Should be DOMAIN\\object\n";
	}
	if (API == true) {
		//Use ObjC calls
		if(object.includes(".")){
			//we need to do a local query instead
			var fixed_query = object.split("\\").slice(1);
			var query = Get_OD_ObjectClass({objectclass:type, max_results:1, value:fixed_query, match:"EqualTo", query_attributes:"RecordName", return_attributes:["SMBSID"], nodetype:"local"});
		}else{
			var query = Get_OD_ObjectClass({objectclass:type, max_results:1, value:object, match:"EqualTo", query_attributes:"RecordName", return_attributes:["SMBSID"]});
		}
		try{
	        var sid = query[type][0]["dsAttrTypeStandard:SMBSID"][0];
	        return sid;
	    }catch(err){
	    	return "No such object";
	    }
	}
	else{
		//use command-line functionality
		if (splitObject[0] == ".")
		{ //do a local query
			command = "dscl . read \"/" + type + "/" + splitObject[1] + "\" SMBSID";
		}
		else{
			command = "dscl \"/Active Directory/" + splitObject[0] + 
				"/All Domains\" read \"/" + type + "/" + splitObject[1] + "\" SMBSID";
		}
		//output will either have SMBSID: S-1-5... or No Such Key: SMBSID if user exists
		try{
			output = currApp.doShellScript(command);
			if (output.indexOf("SMBSID: S-") != -1)
				return output.split(" ")[1].trim();
			else
				return "No such key";
		}
		catch(err){
			//<dscl_cmd> DS Error: -14136 (eDSRecordNotFound) if object doesn't exist
			return err.toString();
		}
	}
}
function ConvertFrom_SID({API=true, sid="S-1-5-21-3278496235-3004902057-1244587532-512", type="Users",help=false} = {}){
	//goes from S-1-5-21-... to "Domain\User", "Domain\Group", or "Domain\Computer"
	if(help){
	    var output = "";
		output += "\\nConvert Users, Groups, or Computers from SIDs to names";
		output += "\\n\"sid\" should be a full SID value in quotes for either a User, Group, or Computer. No other type is currently supported.";
		output += "\\n\"type\" should be \"Users\",\"Groups\", or \"Computers\"";
		output += "\\ncalled: ConvertFrom_SID({sid:\"S-1-5-21-3278496235-3004902057-1244587532-512\",type:\"Users\"})";
		return output;
	}
	command = "";
	domain = Get_CurrentNETBIOSDomain(API);
	if (!domain){
		return "Failed to get domain.";
	}
	if (API == true){
		var query = Get_OD_ObjectClass({objectclass:type, max_results:1, value:sid, match:"EqualTo", query_attributes:"SMBSID", return_attributes:["RecordName"]});
        try{
	        var name = query[type][0]["dsAttrTypeStandard:RecordName"][0];
	        return name;
	    }catch(err){
	    	return "No such object";
	    }
	}
	else{
		command = "dscl \"/Active Directory/" + domain + "/All Domains\"" +
		" search /" + type + " SMBSID " + sid;
		try{
			output = currApp.doShellScript(command);
			//example output:
			//root		SMBSID = (
    		//"S-1-5-18"
			//)
			//check to make sure we actually got a result
			if (output){
				user = output.split("\n")[0].split("\t")[0].trim();
				return user;
			}
			return "Command executed returned no output: " + command;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_DomainUser({API=true, user, attribute, requested_domain,limit=0, help=false} = {}){
	//returns all users or specific user objects in AD
	//can specify different properties they want returned
	if(help){
	    var output = "";
		output += "\\nList all domain users or get information on a specific user. If no user is specified, list all users.";
		output += "\\n\"user\" should be a domain name.";
		output += "\\n\"attribute\" should be a comma separated list of attributes to select from the returned user. This only works in conjunction with a specific user, not when listing out all users.";
		output += "\\n\"requested_domain\" should be the NETBIOS domain name to query. Most often this will be left blank and auto filled by the function.";
		output += "\\ncalled: Get_DomainUser() <--- list out all domain users";
		output += "\\ncalled: Get_DomainUser({user:\"bob\",attribute:\"name, SMBSID\"});";
		output += "\\nNote: cannot currently query outside of the current forest";
		return output;
	}
	if (API == true){
		if(user){
			if(attribute){
				var query = Get_OD_ObjectClass({value:user, match:"Contains", query_attributes:"recordname", return_attributes:attribute.split(", "), max_results:limit});
			}else{
				var query = Get_OD_ObjectClass({value:user, match:"Contains", query_attributes:"recordname", max_results:limit});
			}
			return JSON.stringify(query, null, 2);
		}
		if(attribute){
			var query = Get_OD_ObjectClass({return_attributes:attribute.split(", "), max_results:limit});
			return JSON.stringify(query, null, 2);
		}
		return JSON.stringify(Get_OD_ObjectClass({max_results:limit}), null, 2);
	}
	else{
		domain = requested_domain ? requested_domain : Get_CurrentNETBIOSDomain(API);
		if(user){
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" read /Users/" + user;
			if(attribute){
				command += " " + attribute;
			}
		}
		else{
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" ls /Users";
			if(attribute){
			    command += " " + attribute;
			}
		}
		try{
		    //console.log(command);
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_DomainUserViaAttribute({API=true, value, attribute, return_attributes_list=[null],limit=0, help=false} = {}){
	if(help){
		return "Queries Users for the `attribute` which contains `value` and returns all matching object's attributes specified in `return_attributes_list`."
	}
	if (API == true){
		let query = Get_OD_ObjectClass({value:value, match:"Contains", query_attributes:attribute, max_results:limit, return_attributes:return_attributes_list});
		return JSON.stringify(query, null, 2);
	} else{
		return "Only API supported";
	}
}
function Get_LocalUser({API=true, user, attribute, limit=0, help=false} = {}){
	//returns all users or specific user objects in AD
	//can specify different properties they want returned
	if(help){
	    var output = "";
		output += "\\nList all local users or get information on a specific user. If no user is specified, list all users.";
		output += "\\n\"user\" should be a local user's name.";
		output += "\\n\"attributes\" should be a comma separated list of attributes to select from the returned user. This only works in conjunction with a specific user, not when listing out all users.";
		output += "\\ncalled: Get_LocalUser() <--- list out all local users";
		output += "\\ncalled: Get_LocalUser({user:\"bob\",attribute:\"name, SMBSID\"});";
		return output;
	}
	if (API == true){
		if(user){
			if(attribute){
				var query = Get_OD_ObjectClass({value:user, match:"Contains", query_attributes:"recordname", return_attributes:attribute.split(","), max_results:limit, nodetype:"local"});
			}else{
				var query = Get_OD_ObjectClass({value:user, match:"Contains", query_attributes:"recordname", max_results:limit, nodetype:"local"});
			}
			return JSON.stringify(query, null, 2);
		}
		if(attribute){
			var query = Get_OD_ObjectClass({return_attributes:attribute.split(","), max_results:limit, nodetype:"local"});
			return JSON.stringify(query, null, 2);
		}
		return JSON.stringify(Get_OD_ObjectClass({max_results:limit, nodetype:"local"}), null, 2);
	}
	else{
		if(user){
			command = "dscl . read /Users/" + user;
			if(attribute){
				command += " " + attribute;
			}
		}
		else{
			command = "dscl . ls /Users";
			if(attribute){
			    command += " " + attribute;
			}
		}
		try{
		    //console.log(command);
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_DomainComputer({API=true, computer, attribute, limit=0, requested_domain,help=false} = {}){
	//returns all computers or specific computer objects in AD
	if(help){
	    var output = "";
		output += "\\nList all domain computers or get information on a specific computer. If no computer is specified, list all computer.";
		output += "\\n\"computer\" should be a domain computer name.";
		output += "\\n\"attributes\" should be a comma separated list of attributes to select from the returned computer. This only works in conjunction with a specific computer, not when listing out all computers.";
		output += "\\n\"requested_domain\" should be the NETBIOS domain name to query. Most often this will be left blank and auto filled by the function.";
		output += "\\ncalled: Get_DomainComputer() <--- list out all domain computers";
		output += "\\ncalled: Get_DomainComputer({computer:\"testmac$\",attribute:\"name\"});";
		return output;
	}
	if (API == true){
		if(computer){
			if(attribute){
				var query = Get_OD_ObjectClass({objectclass:"Computers", value:computer, match:"Contains", query_attributes:"recordname", return_attributes:attribute.split(","), max_results:limit});
			}else{
				var query = Get_OD_ObjectClass({objectclass:"Computers", value:computer, match:"Contains", query_attributes:"recordname", max_results:limit});
			}
			return JSON.stringify(query, null, 2);
		}
		if(attribute){
			var query = Get_OD_ObjectClass({objectclass:"Computers", return_attributes:attribute.split(","), max_results:limit});
			return JSON.stringify(query, null, 2);
		}
		return JSON.stringify(Get_OD_ObjectClass({objectclass:"Computers", max_results:limit}), null, 2);
	}
	else{
		domain = requested_domain ? requested_domain : Get_CurrentNETBIOSDomain(API);
		if(computer){
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" read \"/Computers/" + computer + "\"";
			if(attribute){
				command += " " + attribute;
			}
		}
		else{
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" ls /Computers";
			if(attribute){
			    command += " " + attribute;
			}
		}
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_DomainComputerViaAttribute({API=true, value, attribute, limit=0, return_attributes_list=[null],help=false} = {}){
	//returns all computers or specific computer objects in AD
	if(help){
		return "Queries Computers for the `attribute` which contains `value` and returns all matching object's attributes specified in `return_attributes_list`."
	}
	if (API == true){
		let query = Get_OD_ObjectClass({objectclass:"Computers", value:value, match:"Contains", query_attributes:attribute, max_results:limit, return_attributes:return_attributes_list});
		return JSON.stringify(query, null, 2);
	} else{
		return "Only API supported";
	}

}
function Get_LDAPSearch({API=false, currDomain, remoteDomain, numResults=0, query="", attribute,help=false} = {}){
	if(help){
	    var output = "";
		output += "\\nExecute a customized LDAP search query";
		output += "\\n\"currDomain\" should be the domain to query. Ex: in ldap://currDomain.";
		output += "\\n\"remoteDomain\" should be the search base, typically the same as the currDomain, so it can be left out.";
		output += "\\n\"numResults\" specifies how many results to return where 0 indicates all results.";
		output += "\\n\"query\" is the LDAP query.";
		output += "\\n\"attributes\" is a comma separated list of attributes to selet from the query results.";
		output += "\\ncalled: Get_LDAPSearch({query=\"(objectclass=user)\"})";
		return output;
	}
	if(API == true){
        return "API method not implemented yet";
	}
	else{
		domain = currDomain ? currDomain : Get_CurrentDomain(API);
		adjust = remoteDomain ? remoteDomain.split(".") : domain.split(".");
		rdomain = "";
		for(var i = 0; i < adjust.length; i++){
			rdomain += "DC=" + adjust[i];
			if(i+1 < adjust.length){
				rdomain += ","
			}
		}
		command = "ldapsearch -H ldap://" + domain + " -b " + rdomain + " -z " + numResults + " \"" + query + "\" ";
		if(attribute){
			command += attribute;
		}
		//console.log(command);
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_DomainOU({API=false, OU, attribute, requested_domain,help=false} = {}){
	//search for all OUs or specific OU objects in AD
	if(help){
	    var output = "";
		output += "\\nList all domain OUs or get information on a specific OU. If no OU is specified, list all OUs.";
		output += "\\n\"OU\" should be a domain OU name.";
		output += "\\n\"attributes\" should be a comma separated list of attributes to select from the returned OU. This only works in conjunction with a specific OU, not when listing out all OUs.";
		output += "\\n\"requested_domain\" should be the NETBIOS domain name to query. Most often this will be left blank and auto filled by the function.";
		output += "\\ncalled: Get_DomainOU() <--- list out all domain computers";
		output += "\\ncalled: Get_DomainOU({OU:\"Domain Controllers\"});";
		return output;
	}
	if (API == true){
        return "API method not implemented yet";
	}
	else{
		domain = requested_domain ? requested_domain : Get_CurrentNETBIOSDomain(API);
		if(OU){
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" read \"/OrganizationalUnit/" + OU + "\"";
			if(attribute){
				command += " " + attribute;
			}
		}
		else{
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" ls /OrganizationalUnit";
			if(attribute){
			    command += " " + attribute;
			}
		}
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_DomainSID({API=true,help=false} = {}){
	//returns SID for current domain or specified domain
	if(help){
	    var output = "";
		output += "\\nGets the SID of the domain by truncating the SID for the \"Domain Admins\" group.";
		output += "\\ncalled: Get_DomainSID()";
		return output;
	}
	if(API == true){
		var domain = Get_CurrentNETBIOSDomain(API);
		var search_value = domain + "\\Domain Computers";
		var domain_computers = Get_OD_ObjectClass({objectclass:"Groups", max_results:1, value:search_value, match:"Contains", query_attributes:"RecordName", return_attributes:["SMBSID"]});
        var sid = domain_computers["Groups"][0]["dsAttrTypeStandard:SMBSID"][0];
        var sid_array = sid.split("-");
        return sid_array.slice(0, sid_array.length-1).join("-");
	}
	else{
		command = "dsmemberutil getsid -G \"Domain Admins\"";
		try{
			output = currApp.doShellScript(command);
			return output.slice(0,-4); //take off the last -512 on the SID that's specific to Domain Admins group
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_DomainGroup({API=true, group, attribute, requested_domain,help=false,verbose=false, limit=0} = {}){
	//returns all groups or specific groups in an AD
	if(help){
	    var output = "";
		output += "\\nList all domain groups or get information on a specific group. If no group is specified, list all groups.";
		output += "\\n\"group\" should be a domain group name.";
		output += "\\n\"attributes\" should be a comma separated list of attributes to select from the returned group. This only works in conjunction with a specific group, not when listing out all group.";
		output += "\\n\"requested_domain\" should be the NETBIOS domain name to query. Most often this will be left blank and auto filled by the function.";
		output += "\\ncalled: Get_DomainGroup() <--- list out all domain groups";
		output += "\\ncalled: Get_DomainGroup({group:\"Domain Admins\",attribute:\"GroupMembership\"});";
		return output;
	}
	if(API == true){
        if(group){
			if(attribute){
				var query = Get_OD_ObjectClass({objectclass:"Groups", value:group, match:"Contains", query_attributes:"recordname", return_attributes:attribute.split(","), max_results:limit});
			}else{
				var query = Get_OD_ObjectClass({objectclass:"Groups", value:group, match:"Contains", query_attributes:"recordname", max_results:limit});
			}
			return JSON.stringify(query, null, 2);
		}
		if(attribute){
			var query = Get_OD_ObjectClass({objectclass:"Groups", return_attributes:attribute.split(","), max_results:limit});
			return JSON.stringify(query, null, 2);
		}
		return JSON.stringify(Get_OD_ObjectClass({objectclass:"Groups", max_results:limit}), null, 2);
	}
	else{
		domain = requested_domain ? requested_domain : Get_CurrentNETBIOSDomain(API);
		if(group){
		    if(verbose){
                command = "dscl \"/Active Directory/" + domain + "/All Domains\" read \"/Groups/" + group + "\"";
                if(attribute){
                    command += " " + attribute;
                }
            }else{
                command = "dscacheutil -q group -a name \"" + group + "\"";
            }
		}
		else{
			command = "dscl \"/Active Directory/" + domain + "/All Domains\" ls /Groups";
			if(attribute){
			    command += " " + attribute;
			}
		}
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_LocalGroup({API=true, group, attribute,help=false, verbose=false, limit=0} = {}){
	//returns all groups or specific groups in an AD
	if(help){
	    var output = "";
		output += "\\nList all local groups or get information on a specific group. If no group is specified, list all groups.";
		output += "\\n\"group\" should be a local group name.";
		output += "\\n\"verbose\" get more verbose output with dscl instead of dscacheutil"
		output += "\\n\"attributes\" should be a comma separated list of attributes to select from the returned group. This only works in conjunction with a specific group, not when listing out all groups, and only when verbose is true.";
		output += "\\ncalled: Get_LocalGroup() <--- list out all domain groups";
		output += "\\ncalled: Get_LocalGroup({group:\"admin\",attributes:\"GroupMembership\"});";
		output += "\\ncalled: Get_LocalGroup({attribute:\"GroupMembership\", verbose:true}); <--- get a mapping of all groups and their GroupMembership";
		return output;
	}
	if(API == true){
        if(group){
			if(attribute){
				var query = Get_OD_ObjectClass({objectclass:"Groups", value:group, match:"Contains", query_attributes:"recordname", return_attributes:attribute.split(","), max_results:limit, nodetype:"local"});
			}else{
				var query = Get_OD_ObjectClass({objectclass:"Groups", value:group, match:"Contains", query_attributes:"recordname", max_results:limit, nodetype:"local"});
			}
			return JSON.stringify(query, null, 2);
		}
		if(attribute){
			var query = Get_OD_ObjectClass({objectclass:"Groups", return_attributes:attribute.split(","), max_results:limit, nodetype:"local"});
			return JSON.stringify(query, null, 2);
		}
		return JSON.stringify(Get_OD_ObjectClass({objectclass:"Groups", max_results:limit, nodetype:"local"}), null, 2);
	}
	else{
		if(group){
		    if(verbose){
                command = "dscl . read \"/Groups/" + group + "\"";
                if(attribute){
                    command += " " + attribute;
                }
            }
            else{
                command = "dscacheutil -q group -a name " + group;
            }
		}
		else{
		    if(verbose){
		        command = "dscl . ls /Groups";
		        if(attribute){
		            command += " " + attribute;
		        }
			}
			else{
			    command = "dscacheutil -q group";
			}
		}
		try{
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_DomainGroupMember({API=true, group="Domain Admins", domain,help=false, limit=0} = {}){
	if(help){
	    var output = "";
		output += "\\nGet all the members of a specific domain group";
		output += "\\n\"group\" should be a specific domain group to query.";
		output += "\\n\"domain\" is the NETBIOS domain name to query, but if not specified, the function will figure it out.";
		output += "\\ncalled: Get_DomainGroupMember({group:\"Domain Admins\"});";
		return output;
	}
	//return members of a specific domain group
	if(!domain){
		domain = Get_CurrentNETBIOSDomain(API);
	}
	if (API == true){
        return Get_DomainGroup({group:group, attribute:"distinguishedName,member,memberOf,nestedgroups,groupmembership", limit:limit});
	}
	else{
		try{
            if(group){
                command = "dscl \"/Active Directory/" + domain + "/All Domains\" read \"/Groups/" + group + "\" GroupMembership";
            }
			else{
			    command = "dscl \"/Active Directory/" + domain + "/All Domains\" ls /Groups GroupMembership";
			}
			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_LocalGroupMember({API=true, group,help=false, limit=0} = {}){
	if(help){
	    var output = "";
		output += "\\nGet all the members of a specific local group";
		output += "\\n\"group\" should be a specific local group to query.";
		output += "\\ncalled: Get_LocalGroupMember({group:\"admin\"});";
		return output;
	}
	if (API == true){
        return Get_LocalGroup({group:group, attribute:"GroupMembership,nestedGroups,member,memberOf,nestedgroups",limit:limit});
	}
	else{
		try{
            if(group){
                command = "dscl . read \"/Groups/" + group + "\" GroupMembership";
            }
            else{
                command = "dscl . ls /Groups GroupMembership"
            }

			output = currApp.doShellScript(command);
			return output;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Search_LocalGroup({API=false, attribute="GroupMembership", value="", help=false} = {}){
    if(help){
        var output = "";
        output += "\\nSearch a specific group attribute for a specific value";
        output += "\\n\"attribute\" is a specific group attribute to search through, default is \"GroupMembership\"";
        output += "\\n\"value\" is the value to search for";
        output += "\\ncalled: Search_LocalGroups({attribute:\"GroupMembership\", value:\"username\"});";
        return output;
    }
    if (API == true){
        return "API method not implemented yet";
    }
    else{
        try{
            command = "dscl . -search /Groups " + attribute + " " + value;
            output = currApp.doShellScript(command);
            return output;
        }catch(err){
            return err.toString();
        }
    }
}
function Search_DomainGroup({API=false, attribute="GroupMembership", value="", help=false, domain} = {}){
    if(help){
        var output = "";
        output += "\\nSearch a specific group attribute for a specific value";
        output += "\\n\"attribute\" is a specific group attribute to search through, default is \"GroupMembership\"";
        output += "\\n\"value\" is the value to search for";
        output += "\\ncalled: Search_DomainGroups({attribute:\"GroupMembership\", value:\"username\"});";
        return output;
    }
    if(!domain){
		domain = Get_CurrentNETBIOSDomain(API);
	}
    if (API == true){
        return "API method not implemented yet";
    }
    else{
        command = "dscl \"/Active Directory/" + domain + "/All Domains\" -search /Groups " + attribute + " " + value;
        try{
            output = currApp.doShellScript(command);
            return output;
        }
        catch(error){
            return error.toString();
        }
    }
}
function Search_LocalUser({API=false, attribute="UserShell", value="/bin/bash", help=false} = {}){
    if(help){
        var output = "";
        output += "\\nSearch local users attribute for a specific value";
        output += "\\n\"attribute\" is a specific user attribute to search through, default is \"UserShell\"";
        output += "\\n\"value\" is the value to search for, default is \"/bin/bash\"";
        output += "\\ncalled: Search_LocalUsers({attribute:\"UserShell\", value:\"/bin/bash\"});";
        return output;
    }
    if (API == true){
        return "API method not implemented yet";
    }
    else{
        try{
            command = "dscl . -search /Users " + attribute + " " + value;
            output = currApp.doShellScript(command);
            return output;
        }catch(err){
            return err.toString();
        }
    }
}
function Search_DomainUser({API=false, attribute="", value="", help=false, domain} = {}){
    if(help){
        var output = "";
        output += "\\nSearch a specific group attribute for a specific value";
        output += "\\n\"attribute\" is a specific user attribute to search through, default is \"\"";
        output += "\\n\"value\" is the value to search for";
        output += "\\ncalled: Search_DomainUsers({attribute:\"\", value:\"username\"});";
        return output;
    }
    if(!domain){
		domain = Get_CurrentNETBIOSDomain(API);
	}
    if (API == true){
        return "API method not implemented yet";
    }
    else{
        command = "dscl \"/Active Directory/" + domain + "/All Domains\" -search /Users " + attribute + " " + value;
        try{
            output = currApp.doShellScript(command);
            return output;
        }
        catch(error){
            return error.toString();
        }
    }
}
////////////////////////////////////////////////
///////// HELPER FUNCTIONS /////////////////////
////////////////////////////////////////////////
function Get_CurrentDomain(API=true,help=false){
	if(help){
	    var output = "";
		output += "\\nGet the fully qualified current domain";
		output += "\\ncalled: Get_CurrentDomain();";
		return output;
	}
	if(API == true){
		var config = Get_OD_Node_Configuration();
		var keys = Object.keys(config);
		for(var i in keys){
			if(config[keys[i]]['nodeName'] != "Contacts" && config[keys[i]]['nodeName'] != "Search" && config[keys[i]]['nodeName']){
				return config[keys[i]]['trustKerberosPrincipal'].split("@")[1];
			}
		}
		return "No domain found";
	}
	else{
		try{
			output = currApp.doShellScript("dsconfigad -show");
			//Active Directory Forest 		= forest.tld
			//Active Directory Domain 		= domain.tld
			//Computer Account 				= computer-name
			//a bunch of others with (something = something) format
			//Look into Advanced Options - Administrative
			//	preferred domain controller, allowed admin group
			components = output.split("\r");
			domain = components[1].split("=")[1].trim();
			return domain;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_CurrentNETBIOSDomain(API=true,help=false){
	if(help){
	    let output = "";
		output += "\\nGet the NETBIOS name of the current domain";
		output += "\\ncalled: Get_CurrentNETBIOSDomain();";
		return output;
	}
	if(API == true){
        let config = Get_OD_Node_Configuration();
		let keys = Object.keys(config);
		for(let i in keys){
			if(config[keys[i]].hasOwnProperty('nodeName') && config[keys[i]]['nodeName'] != "Contacts" && config[keys[i]]['nodeName'] != "Search"){
				return config[keys[i]]['nodeName'];
			}
		}
		return "No Domain Found";
	}
	else{
		try{
			let output = currApp.doShellScript("echo show com.apple.opendirectoryd.ActiveDirectory | scutil");
			//<dictionary>{
			//DomainForestName : test.local
			//DomainGuid : 01FDCACC-C89D-45B8-8829-3BAB54490F6C
			//DomainNameDns : test.local
			//DomainNameFlat : TEST
			//MachineRole : 3
			//NodeName: /Active Directory/TEST
			//TrustAccount : testmac$
			//}
			components = output.split("\r");
			domain = components[4].split(":")[1].trim();
			return domain;
		}
		catch(err){
			return err.toString();
		}
	}
}
function Get_Forest(API=false,help=false){
	if(help){
	    var output = "";
		output += "\\nGet the fully qualified forest name";
		output += "\\ncalled: Get_Forest();";
		return output;
	}
	if(API == true){
        return "API method not implemented yet";
	}
	else{
		try{
			output = currApp.doShellScript("dsconfigad -show");
			//Active Directory Forest 		= forest.tld
			//Active Directory Domain 		= domain.tld
			//Computer Account 				= computer-name
			//a bunch of others with (something = something) format
			//Look into Advanced Options - Administrative
			//	preferred domain controller, allowed admin group
			components = output.split("\r");
			forest = components[0].split("=")[1].trim();
			return forest;
		}
		catch(err){
			return err.toString();
		}
	}
}
