	Function Test-ADCredential
	{
		Param($username, $password, $domain)
		Add-Type -AssemblyName System.DirectoryServices.AccountManagement
		$ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
		$pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($ct, $domain)
		$object = New-Object PSObject | Select Username, Password, IsValid
		$object.Username = $username;
		$object.Password = $password;
		$object.IsValid = $pc.ValidateCredentials($username, $password).ToString();
		return $object
	}
