<#
.SYNOPSIS
	Create a new or update an existing Let's Encrypt certificate for one or more domains and add it to a store then update the SSL bindings for a NetScaler
.DESCRIPTION
	The script will use ACMESharp to create a new or update an existing certificate for one or more domains. If generated successfully the script will add the certificate to the NetScaler and update the SSL binding for a web site. This script is for use with a Citrix NetScaler (v11.x and up). The script will validate the dns records provided. For example, the domain(s) listed must be configured with the same IP Address that is configured (via NAT) to a Content Switch.
.PARAMETER Help
	Display the detailed information about this script
.PARAMETER CleanNS
	Cleanup the NetScaler configuration made within this script, for when somewhere it gone wrong
.PARAMETER NSManagementURL
	Management URL, used to connect to the NetScaler
.PARAMETER NSUserName
	NetScaler username with enough access to configure it
.PARAMETER NSPassword
	NetScaler username password
.PARAMETER NSCredential
	Use a PSCredential object instead of a username or password. Use "Get-Credential" to generate a credential object
	C:\PS> $Credential = Get-Credential
.PARAMETER NSCsVipName
	Name of the HTTP NetScaler Content Switch used for the domain validation
	.PARAMETER NSCsVipBinding
	NetScaler Content Switch binding used for the validation
.PARAMETER NSSvcName
	NetScaler Load Balance service name
.PARAMETER NSSvcDestination
	IP Address used for the NetScaler Service (leave default 1.2.3.4, only change when already used
.PARAMETER NSLbName
	NetScaler Load Balance VIP name
.PARAMETER NSRspName
	NetScaler Responder Policy name
.PARAMETER NSRsaName
	NetScaler Responder Action name
.PARAMETER NSCspName
	NetScaler Content Switch Policy name
.PARAMETER NSCertNameToUpdate
	NetScaler SSL Certkey name currently in use, that needs to be renewd
.PARAMETER CertDir
	Directory where to store the certificates
.PARAMETER PfxPassword
	Password for the PFX certificate, generated at the end
.PARAMETER EmailAddress
	The email address used to request the certificates and receive a notification when the certificates (almost) expires
.PARAMETER cn
	(Common Name) The Primary (first) dns record for the certificaten
.PARAMETER san
	(Subject Alternate Name) every following domain listed in this certificate. sepatated via an comma , and between quotes "".
	E.g.: "sts.domain.com","www.domain.com","vpn.domain.com"
.PARAMETER Production
	Use the production Let's encryt server
.PARAMETER DisableIPCheck
	If you want to skip the IP Address verification, specify this parameter
.PARAMETER CleanVault
	Force initialization of the vault before use
.PARAMETER SaveNSConfig
	Save the NetScaler config after all the changes.
.PARAMETER ns10x
	When using v10x, some nitro functions will not work propperly, run the script with this parameter.
.EXAMPLE
	.\GenLeCertForNS.ps1 -CN "domain.com" -EmailAddress "hostmaster@domain.com" -SAN "sts.domain.com","www.domain.com","vpn.domain.com" -PfxPassword "P@ssw0rd" -CertDir "C:\Certificates" -NSManagementURL "http://192.168.100.1" -NSCsVipName "cs_domain.com_http" -NSPassword "nsroot" -NSUserName "P@ssw0rd" -NSCertNameToUpdate "san_domain_com" -Production -CleanVault -Verbose
	Generate a (Production)certificate for hostname "domain.com" with alternate names : "sts.domain.com, www.domain.com, vpn.domain.com". Using the emailaddress "hostmaster@domain.com". At the end storing the certificates  in "C:\Certificates" and uploading them to the NetScaler. Also Cleaning the vault on the NetScaler the content Switch "cs_domain.com_http" will be used to validate the certificates.
.EXAMPLE
	.\GenLeCertForNS.ps1 -CleanNS -NSManagementURL "http://192.168.100.1" -NSCsVipName "cs_domain.com_http" -NSPassword "nsroot" -NSUserName "P@ssw0rd" -Verbose
	Cleaning left over configuration from this schript when something went wrong during a previous attempt to generate new certificates and generating Verbose output.
.NOTES
	File Name : GenLeCertForNS.ps1
	Version   : v0.8.1
	Author    : John Billekens
	Requires  : PowerShell v3 and up
	            NetScaler 11.x and up
	            Run As Administrator
	            ACMESharp (can be installed via this script)
.LINK
	https://blog.j81.nl
#>

[cmdletbinding(DefaultParametersetName="ConfigNetScaler")]
param(
		[Parameter(ParameterSetName="Help",Mandatory=$false)]
		[alias("h")]
		[switch]$Help,
		
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$true)]
		[switch]$CleanNS,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$true)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[alias("URL")]
		[string]$NSManagementURL,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$false)]
		[alias("User", "Username")]
		[string]$NSUserName,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$false)]
		[alias("Password")]
		[string]$NSPassword,

		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$false)]
		[ValidateScript({
			if ($_ -is [System.Management.Automation.PSCredential]) {
				$true
			} elseif ($_ -is [string]) {
				$Script:Credential=Get-Credential -Credential $_
				$true
			} else {
				Write-Error "You passed an unexpected object type for the credential (-NSCredential)"
			}
		})][alias("Credential")]
		[object]$NSCredential,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$true)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$NSCsVipName,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$false)]
		[string]$NSCsVipBinding = 11,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$false)]
		[string]$NSSvcName = "svc_letsencrypt_cert_dummy",
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$false)]
		[string]$NSSvcDestination = "1.2.3.4",
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$false)]
		[string]$NSLbName = "lb_letsencrypt_cert",
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$false)]
		[string]$NSRspName = "rsp_letsencrypt",
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$false)]
		[string]$NSRsaName = "rsa_letsencrypt",
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$false)]
		[string]$NSCspName = "csp_NSCertCsp",
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[string]$NSCertNameToUpdate,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$CertDir,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[string]$PfxPassword = $null,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]$CN,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$true)]
		[string]$EmailAddress,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[string[]]$SAN=@(),
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[switch]$Production,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[switch]$DisableIPCheck,

		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[switch]$CleanVault,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$false)]
		[switch]$SaveNSConfig,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$false)]
		[switch]$ns10x
)

#requires -version 3.0
#requires -runasadministrator

#region Functions

function InvokeNSRestApi {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$true)]
		[PSObject]$Session,

		[Parameter(Mandatory=$true)]
		[ValidateSet('DELETE', 'GET', 'POST', 'PUT')]
		[string]$Method,

		[Parameter(Mandatory=$true)]
		[string]$Type,

		[string]$Resource,

		[string]$Action,

		[hashtable]$Arguments = @{},

		[switch]$Stat = $false,

		[ValidateScript({$Method -eq 'GET'})]
		[hashtable]$Filters = @{},

		[ValidateScript({$Method -ne 'GET'})]
		[hashtable]$Payload = @{},

		[switch]$GetWarning = $false,

		[ValidateSet('EXIT', 'CONTINUE', 'ROLLBACK')]
		[string]$OnErrorAction = 'EXIT'
	)
	# https://github.com/devblackops/NetScaler
	if ([string]::IsNullOrEmpty($($Session.ManagementURL))) {
		throw "ERROR. Probably not logged into the NetScaler"
	}
	if ($Stat) {
		$uri = "$($Session.ManagementURL)/nitro/v1/stat/$Type"
	} else {
		$uri = "$($Session.ManagementURL)/nitro/v1/config/$Type"
	}
	if (-not ([string]::IsNullOrEmpty($Resource))) {
		$uri += "/$Resource"
	}
	if ($Method -ne 'GET') {
		if (-not ([string]::IsNullOrEmpty($Action))) {
			$uri += "?action=$Action"
		}

		if ($Arguments.Count -gt 0) {
			$queryPresent = $true
			if ($uri -like '*?action*') {
				$uri += '&args='
			} else {
				$uri += '?args='
			}
			$argsList = @()
			foreach ($arg in $Arguments.GetEnumerator()) {
				$argsList += "$($arg.Name):$([System.Uri]::EscapeDataString($arg.Value))"
			}
			$uri += $argsList -join ','
		}
	} else {
		$queryPresent = $false
		if ($Arguments.Count -gt 0) {
			$queryPresent = $true
			$uri += '?args='
			$argsList = @()
			foreach ($arg in $Arguments.GetEnumerator()) {
				$argsList += "$($arg.Name):$([System.Uri]::EscapeDataString($arg.Value))"
			}
			$uri += $argsList -join ','
		}
		if ($Filters.Count -gt 0) {
			$uri += if ($queryPresent) { '&filter=' } else { '?filter=' }
			$filterList = @()
			foreach ($filter in $Filters.GetEnumerator()) {
				$filterList += "$($filter.Name):$([System.Uri]::EscapeDataString($filter.Value))"
			}
			$uri += $filterList -join ','
		}
	}
	Write-Verbose -Message "URI: $uri"

	$jsonPayload = $null
	if ($Method -ne 'GET') {
		$warning = if ($GetWarning) { 'YES' } else { 'NO' }
		$hashtablePayload = @{}
		$hashtablePayload.'params' = @{'warning' = $warning; 'onerror' = $OnErrorAction; <#"action"=$Action#>}
		$hashtablePayload.$Type = $Payload
		$jsonPayload = ConvertTo-Json -InputObject $hashtablePayload -Depth 100
		Write-Verbose -Message "JSON Payload:`n$jsonPayload"
	}

	$response = $null
	$restError = $null
	try {
		$restError = @()
		$restParams = @{
			Uri = $uri
			ContentType = 'application/json'
			Method = $Method
			WebSession = $Session.WebSession
			ErrorVariable = 'restError'
			Verbose = $false
		}

		if ($Method -ne 'GET') {
			$restParams.Add('Body', $jsonPayload)
		}

		$response = Invoke-RestMethod @restParams

		if ($response) {
			if ($response.severity -eq 'ERROR') {
				throw "Error. See response: `n$($response | Format-List -Property * | Out-String)"
			} else {
				Write-Verbose -Message "Response:`n$(ConvertTo-Json -InputObject $response | Out-String)"
				if ($Method -eq "GET") { return $response }
			}
		}
	}
	catch [Exception] {
		if ($Type -eq 'reboot' -and $restError[0].Message -eq 'The underlying connection was closed: The connection was closed unexpectedly.') {
			Write-Verbose -Message 'Connection closed due to reboot'
		} else {
			throw $_
		}
	}
}

function Connect-NetScaler {
	[cmdletbinding()]
	param(
		[parameter(Mandatory)]
		[string]$ManagementURL,

		[parameter(Mandatory)]
		[pscredential]$Credential = (Get-Credential -Message 'NetScaler credential'),

		[int]$Timeout = 3600,

		[switch]$PassThru
	)
	# https://github.com/devblackops/NetScaler
	Write-Verbose -Message "Connecting to $ManagementURL..."
	try {
		if ($script:ns10x) {
			$login = @{
				login = @{
					username = $Credential.UserName;
					password = $Credential.GetNetworkCredential().Password
				}
			}
		} else {
			$login = @{
				login = @{
					username = $Credential.UserName;
					password = $Credential.GetNetworkCredential().Password
					timeout = $Timeout
				}
			}
		}
		$loginJson = ConvertTo-Json -InputObject $login
		Write-Verbose "JSON Data:`n$($loginJson | Out-String)"
		$saveSession = @{}
		$params = @{
			Uri = "$ManagementURL/nitro/v1/config/login"
			Method = 'POST'
			Body = $loginJson
			SessionVariable = 'saveSession'
			ContentType = 'application/json'
			ErrorVariable = 'restError'
			Verbose = $false
		}
		$response = Invoke-RestMethod @params

		if ($response.severity -eq 'ERROR') {
			throw "Error. See response: `n$($response | Format-List -Property * | Out-String)"
		} else {
			Write-Verbose -Message "Response:`n$(ConvertTo-Json -InputObject $response | Out-String)"
		}
	} catch [Exception] {
		throw $_
	}

	$session = [PSObject]@{
		ManagementURL=[string]$ManagementURL;
		WebSession=[Microsoft.PowerShell.Commands.WebRequestSession]$saveSession;
	}

	$Script:NSSession = $session
	
	if($PassThru){
			return $session
	}
}

#endregion Functions

#region Help

if($Help){
	Write-Verbose "Generating help for `"$ScriptFilename`""
	Get-Help "$ScriptFilename" -Full
	Exit(0)
}

#endregion Help

#region Script variables

if ($ns10x){
	Write-Verbose "ns10x parameter userd, some options are now disabled."
}
Write-Verbose "Generating Session GUID"
[string]$SessionGUID = [guid]::NewGuid()
Write-Verbose "Setting session DATE/TIME variable"
[string]$SessionDateTime = (Get-Date).ToString("yyyyMMddHHmm")
if (-not([string]::IsNullOrWhiteSpace($NSCredential))) {
	Write-Verbose "Using NSCredential"
} elseif ((-not([string]::IsNullOrWhiteSpace($NSUserName))) -and (-not([string]::IsNullOrWhiteSpace($NSPassword)))){
	Write-Verbose "Using NSUsername / NSPassword"
	[pscredential]$NSCredential = new-object -typename System.Management.Automation.PSCredential -argumentlist $NSUserName, $(ConvertTo-SecureString -String $NSPassword -AsPlainText -Force)
} else {
	Write-Verbose "No valid username/password or credential specified. Enter a username and password, e.g. `"nsroot`""
	[pscredential]$NSCredential = Get-Credential -Message "NetScaler username and password:"
}
Write-Verbose "Starting new session ($SessionGUID)"
if(-not ([string]::IsNullOrWhiteSpace($SAN))){
	[string[]]$SAN = @($SAN.Split(","))
}

#endregion Script variables

#region Load Module
if (-not ($CleanNS)) {
	Write-Verbose "Load ACMESharp Modules"
	if (-not(Get-Module ACMESharp)){
		try {
			$ACMEVersions = (get-Module -Name ACMESharp -ListAvailable).Version
			$ACMEUpdateRequired = $false
			ForEach ($ACMEVersion in $ACMEVersions) {
				if (($ACMEVersion.Minor -eq 8) -and ($ACMEVersion.Build -eq 1) -and (-not $ACMEUpdateRequired)) {
					Write-Verbose "v0.8.1 of ACMESharp is installed, continuing"
				} else {
					Write-Verbose "v0.8.1 of ACMESharp is NOT installed, update/downgrade required"
					$ACMEUpdateRequired = $true
				}
			}
			if ($ACMEUpdateRequired) {
				Write-Verbose "Trying to update the ACMESharp modules"
				Install-Module -Name ACMESharp -Scope AllUsers -RequiredVersion 0.8.1 -Force -ErrorAction SilentlyContinue
			}
			Write-Verbose "Try loading module ACMESharp"
			Import-Module ACMESharp -ErrorAction Stop
		} catch [System.IO.FileNotFoundException] {
			Write-Verbose "Checking for PackageManagement"
			if ([string]::IsNullOrWhiteSpace($(Get-Module -ListAvailable -Name PackageManagement))) {
				Write-Warning "PackageManagement is not available please install this first or manually install ACMESharp"
				Write-Warning "Visit `"https://www.microsoft.com/en-us/download/details.aspx?id=51451`" to download Package Management"
				Write-Warning "ACMESharp: https://github.com/ebekker/ACMESharp"
				Start "https://www.microsoft.com/en-us/download/details.aspx?id=49186"
				Exit (1)
			} else {
				try {
					if (-not ((Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue).Version -ge [System.Version]"2.8.5.208")) {
						Write-Verbose "Installing Nuget"
						Get-PackageProvider -Name NuGet -Force -ErrorAction SilentlyContinue | Out-Null
					}
					$installationPolicy = (Get-PSRepository -Name PSGallery).InstallationPolicy
					if (-not ($installationPolicy.ToLower() -eq "trusted")){
						Write-Verbose "Defining PSGallery PSRepository as trusted"
						Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
					}
					Write-Verbose "Installing ACMESharp"
					try {
						Install-Module -Name ACMESharp -Scope AllUsers -RequiredVersion 0.8.1 -Force -AllowClobber
					} catch {
						Write-Verbose "Installing ACMESharp again but without the -AllowClobber option"
						Install-Module -Name ACMESharp -Scope AllUsers -RequiredVersion 0.8.1 -Force
					}
					if (-not ((Get-PSRepository -Name PSGallery).InstallationPolicy -eq $installationPolicy)){
						Write-Verbose "Returning the PSGallery PSRepository InstallationPolicy to previous value"
						Set-PSRepository -Name "PSGallery" -InstallationPolicy $installationPolicy | Out-Null
					}
					Write-Verbose "Try loading module ACMESharp"
					Import-Module ACMESharp -ErrorAction Stop
				} catch {
					Write-Verbose "Error Details: $($_.Exception.Message)"
					Write-Error "Error while loading and/or installing module"
					Exit (1)
				}
			}
		
		}
	}
}
#endregion Load Module

#region Vault
if (-not ($CleanNS)) {
	if ($Production) {
		$VaultName = ":sys"
		$BaseService = "LetsEncrypt"
		Write-Verbose "Using the vault `"$VaultName`" for production certificates"
	} else {
		$VaultName = ":user"	
		$BaseService = "LetsEncrypt-STAGING"
		Write-Verbose "Using the vault `"$VaultName`" for test/staging purposes"
	}
	try {
		Write-Verbose "Get ACMEVault `"$VaultName`"" 
		$VaultData = Get-ACMEVault -VaultProfile $VaultName
	} catch {
		Write-Verbose "`"$VaultName`" Vault not available, initialize"
		$CleanVault = $true
	}
	if ($CleanVault) {
		Write-Verbose "Initializing Vault"
		Initialize-ACMEVault -VaultProfile $VaultName -Force
		Write-Verbose "Finished initializing"
		$VaultData = Get-ACMEVault -VaultProfile $VaultName
	}
	Write-Verbose "Configure vault `"$VaultName`" for `"$BaseService`""
	Set-ACMEVault -VaultProfile $VaultName -BaseService $BaseService
}
#endregion Vault

#region Registration
if (-not ($CleanNS)) {
	try {
		Write-Verbose "Retreive existing Registration"
		$Registration = Get-ACMERegistration -VaultProfile $VaultName
		if ($Registration.Contacts -contains "mailto:$EmailAddress"){
			Write-Verbose "Existing registration found, no changes necessary"
		} else {
			Write-Verbose "Current registration `"$($Registration.Contacts)`" is not equal to `"$EmailAddress`", setting new registration"
			$Registration = New-ACMERegistration -VaultProfile $VaultName -Contacts mailto:$EmailAddress -AcceptTos
		}
	} catch {
		Write-Verbose "Setting new registration to `"$EmailAddress`""
		$Registration = New-ACMERegistration -VaultProfile $VaultName -Contacts mailto:$EmailAddress -AcceptTos
	}
}
#endregion Registration

#region DNS

#region Primary DNS
if (-not ($CleanNS)) {
	Write-Verbose "Validating DNS record(s)"
	$DNSObjects = @()
	
	Write-Verbose "Checking `"$CN`""
	try {
		if ($DisableIPCheck){
			Write-Warning "Skipping IP check, validation might fail"
			$PrimaryIP = "NoIPCheck"
		} else {
			$PublicDnsServer = "208.67.222.222"
			Write-Verbose "Using public DNS server (OpenDNS, 208.67.222.222) to verify dns records"
			Write-Verbose "Trying to get IP Address"
			$PrimaryIP = (Resolve-DnsName -Server $PublicDnsServer -Name $CN -DnsOnly -Type A -ErrorAction SilentlyContinue).IPAddress
			if ([string]::IsNullOrWhiteSpace($PrimaryIP)) {
				throw "ERROR: No valid entry found for DNSName:`"$CN`""
			}
			if ($PrimaryIP -is [system.array]){
				Write-Warning "More than one ip address found`n$($PrimaryIP | Format-Table | Out-String)"
				$PrimaryIP = $PrimaryIP[0]
				Write-Warning "using the first one`"$PrimaryIP`""
			}
		}
	} catch {
		Write-Verbose "Error Details: $($_.Exception.Message)"
		Write-Verbose "Error while retreiving IP Address"
		throw "Error while retreiving IP Address, does not exists?"
	}
	
	
	try {
		Write-Verbose "Start validation process for `"$CN`""
		$IdentifierAlias = "$($CN)-$($SessionGUID)"
		$Identifier = New-ACMEIdentifier -Dns $CN -Alias $IdentifierAlias -VaultProfile $VaultName
	} catch {
		try {
			Write-Verbose "Posibly it already exists, retreiving data"
			$Identifier = Get-ACMEIdentifier -IdentifierRef $CN -VaultProfile $VaultName
		} catch {
			Write-Verbose "Record is invalid"
			$Identifier = [PSCustomObject]@{
				Status = "invalid"
				Expires = $null
			}
		}
	}
	try {
		Write-Verbose "Extracting data, checking validation"
		$response = Invoke-RestMethod -Uri $Identifier.Uri -Method Get
		$result = $response  | Select-Object status,expires
		$Identifier = [PSCustomObject]@{
			Status = $result.status
			Expires = $result.expires
		}
	}catch{
		Write-Verbose "Someting went wrong with the validation: $($result | Format-Table | Out-String)"
	}
	Write-Verbose "Checking if current validation is still valid"
	if (($Identifier.status -eq "valid") -and ($([datetime]$Identifier.Expires - $(Get-Date)).TotalDays -gt 0.3)) {
		Write-Verbose "`"$CN`" is valid"
		$Validation = $true
	} else {
		Write-Verbose "`"$CN`" is NOT valid"
		$Validation = $false
	}
	Write-Verbose "Validation response: $($result | Format-Table | Out-String)"
	Write-Verbose "Storing values"
	$DNSObjects += [PSCustomObject]@{
		DNSName = $CN
		IPAddress = $PrimaryIP
		Status = $(if ([string]::IsNullOrWhiteSpace($PrimaryIP)) {$false} else {$true})
		Match = $null
		SAN = $false
		DNSValid = $Validation
		Alias = $IdentifierAlias
	}
}
Write-Verbose "$($DNSObjects | Format-Table | Out-String)"

#endregion Primary DNS

#region SAN
if (-not ($CleanNS)) {
	Write-Verbose "Checking if SAN entries are available"
	if ([string]::IsNullOrWhiteSpace($SAN)) {
		Write-Verbose "No SAN entries found"
	} elseif (($($SAN.Count) -eq 1) -and ($SAN[0] -eq $CN)) {
		Write-Verbose "Skipping SAN, CN:`"$CN`" is equal to SAN:`"$($SAN[0])`""
	} else {
		Write-Verbose "$($SAN.Count) found, checking each one"
		foreach ($DNSRecord in $SAN) {
			try {
				if ($DisableIPCheck) {
					Write-Verbose "Skipping IP check"
					$SANIP = "NoIPCheck"
				} else {
					Write-Verbose "Start basic IP Check for `"$DNSRecord`", trying to get IP Address"
					$SANIP = (Resolve-DnsName -Server $PublicDnsServer -Name $DNSRecord -DnsOnly -Type A -ErrorAction SilentlyContinue).IPAddress
					if ($SANIP -is [system.array]){
						Write-Warning "More than one ip address found`n$($SANIP | Format-Table | Out-String)"
						$SANIP = $SANIP[0]
						Write-Warning "using the first one`"$SANIP`""
					}
					Write-Verbose "Finished, Result: $SANIP"
				}
				
			} catch {
				Write-Verbose "Error while retreiving IP Address"
				Write-Host -ForeGroundColor Red "Error while retreiving IP Address, does not exists?"
				$SANIP = $null
			}
			if ([string]::IsNullOrWhiteSpace($SANIP)) {
				Write-Verbose "No valid entry found for DNSName:`"$DNSRecord`""
				$SANMatch = $false
				$SANStatus = $false
			} else {
				Write-Verbose "Valid entry found"
				$SANStatus = $true
				if ($DisableIPCheck) {
					Write-Verbose "IP address checking was disabled"
					$SANMatch = $true
				} else {
					Write-Verbose "All IP Adressess must match, checking"
					if ($SANIP -match $($DNSObjects[0].IPAddress)) {
						Write-Verbose "`"$SANIP ($DNSRecord)`" matches to `"$($DNSObjects[0].IPAddress) ($($DNSObjects[0].DNSName))`""
						$SANMatch = $true
					} else {
						Write-Verbose "`"$SANIP`" ($DNSRecord) NOT matches to `"$($DNSObjects[0].IPAddress)`" ($($DNSObjects[0].DNSName))"
						$SANMatch = $false
					}
				}
			}
			try {
				Write-Verbose "Start validation process for `"$DNSRecord`""
				$IdentifierAlias = "$($DNSRecord)-$($SessionGUID)"
				$Identifier = New-ACMEIdentifier -Dns $DNSRecord -Alias $IdentifierAlias -VaultProfile $VaultName
			} catch {
				try {
					Write-Verbose "Posibly it already exists, retreiving data"
					$Identifier = Get-ACMEIdentifier -IdentifierRef $DNSRecord -VaultProfile $VaultName
				} catch {
					Write-Verbose "Record is invalid"
					$Identifier = [PSCustomObject]@{
						Status = "invalid"
						Expires = $null
					}
				}
			}
			try {
				if ($Identifier.Uri) {
					Write-Verbose "Extracting data, checking validation"
					$response = Invoke-RestMethod -Uri $Identifier.Uri -Method Get
					$result = $response  | Select-Object status,expires
					$Identifier = [PSCustomObject]@{
						Status = $result.status
						Expires = $result.expires
					}
				} else {
					Write-Verbose "Nothing to extract, probably a new request"
				}
			}catch{
				Write-Verbose "Someting went wrong with the validation: $($result | Format-Table | Out-String)"
			}
			Write-Verbose "Checking if current validation is still valid"
			if (($Identifier.status -eq "valid") -and ($([datetime]$Identifier.Expires - $(Get-Date)).TotalDays -gt 0.3)) {
				Write-Verbose "`"$DNSRecord`" is valid"
				$Validation = $true
			} else {
				Write-Verbose "`"$DNSRecord`" is NOT valid"
				$Validation = $false
			}
			Write-Verbose "Validation response: $($result | Format-Table | Out-String)"
			$DNSObjects += [PSCustomObject]@{
				DNSName = $DNSRecord
				IPAddress = $SANIP
				Status = $SANStatus
				Match = $SANMatch
				SAN = $true
				DNSValid = $Validation
				Alias = $IdentifierAlias
			}
		}
	}
}
Write-Verbose "$($DNSObjects | Format-Table | Out-String)"

#endregion SAN

if (-not ($CleanNS)) {
	Write-Verbose "Checking for invalid DNS Records"
	$InvalidDNS = $DNSObjects | Where-Object {$_.Status -eq $false}
	if ($InvalidDNS) {
		Write-Verbose "$($InvalidDNS | Select-Object DNSName,Status | Format-Table | Out-String)"
		$DNSObjects[0] | Select-Object DNSName,IPAddress | Format-Table | Out-String | Foreach {Write-Host -ForeGroundColor Green "$_"}
		$InvalidDNS | Select-Object DNSName,IPAddress | Format-Table | Out-String | Foreach {Write-Host -ForeGroundColor Red "$_"}
		throw "ERROR, invalid (not registered?) DNS Record(s) found:`r`n"
	} else {
		Write-Verbose "None found, continuing"
	}
	Write-Verbose "Checking non matching DNS Records"
	$DNSNoMatch = $DNSObjects | Where-Object {$_.Match -eq $false}
	if ($DNSNoMatch -and (-not $DisableIPCheck)) {
		Write-Verbose "$($DNSNoMatch | Select-Object DNSName,Match | Format-Table | Out-String)"
		$DNSObjects[0] | Select-Object DNSName,IPAddress | Format-Table | Out-String | Foreach {Write-Host -ForeGroundColor Green "$_"}
		$DNSNoMatch | Select-Object DNSName,IPAddress | Format-Table | Out-String | Foreach {Write-Host -ForeGroundColor Red "$_"}
		throw "ERROR: Non-matching records found, must match to `"$($DNSObjects[0].DNSName)`" ($($DNSObjects[0].IPAddress))"
	} else {
		Write-Verbose "All IP Adressess match"
	}
}
#region ACME DNS Verification

#region NetScaler pre dns
	
if (-not ($CleanNS)) {
	Write-Verbose "Checking if validation is required"
	$DNSValidationRequired = $DNSObjects | Where-Object {$_.DNSValid -eq $false}
	try {
		Write-Verbose "Login to NetScaler and save session to global variable"
		$NSSession = Connect-NetScaler -ManagementURL $NSManagementURL -Credential $NSCredential -PassThru
		if ($DNSValidationRequired) {
			Write-Verbose "$($DNSValidationRequired | Select-Object DNSName,DNSValid | Format-Table | Out-String)"
			Write-Verbose "$($DNSValidationRequired.Count) items need validation"
			Write-Verbose "Enable required NetScaler Features, Load Balancer, Responder and Content Switch"
			$payload = @{"feature"="LB RESPONDER CS APPFLOW"}
			$response = InvokeNSRestApi -Session $NSSession -Method POST -Type nsfeature -Payload $payload -Action enable
			try {
				Write-Verbose "Verifying Content Switch"
				$response = InvokeNSRestApi -Session $NSSession -Method GET -Type csvserver -Resource $NSCsVipName
			} catch {
				$ExcepMessage = $_.Exception.Message
				Write-Verbose "Error Details: $ExcepMessage"
				throw "Could not find/read out the content switch `"$NSCsVipName`" not available?"
			} finally {
				if ($ExcepMessage -like "*(404) Not Found*") {
					Write-Host -ForeGroundColor Red "`nThe Content Switch `"$NSCsVipName`" does NOT exists!"
					Exit (1)
				} elseif ($ExcepMessage -like "*The remote server returned an error*") {
					Write-Host -ForeGroundColor Red "`nUnknown error found while checking the Content Switch: `"$NSCsVipName`""
					Write-Host -ForeGroundColor Red "Error message: `"$ExcepMessage`""
					Exit (1)
				} elseif (($response.errorcode -eq "0") -and (-not ($response.csvserver.servicetype -eq "HTTP"))) {
					Write-Host -ForeGroundColor Red "`nThe Content Switch is $($response.csvserver.servicetype) and NOT HTTP"
					Write-Host -ForeGroundColor Red "Please use a HTTP (Port 80) Content Switch this is required for the validation. Exiting now`n"
					Exit (1)
				}
			}
			try { 
				Write-Verbose "Configuring NetScaler: Check if Load Balancer Service exists"
				$response = InvokeNSRestApi -Session $NSSession -Method GET -Type service -Resource $NSSvcName
				Write-Verbose "Yep it exists, continuing"
			} catch {
				Write-Verbose "It does not exist, continuing"
				Write-Verbose "Configuring NetScaler: Create Load Balance Service `"$NSSvcName`""
				$payload = @{"name"="$NSSvcName";"ip"="$NSSvcDestination";"servicetype"="HTTP";"port"="80";"healthmonitor"="NO";} 
				$response = InvokeNSRestApi -Session $NSSession -Method POST -Type service -Payload $payload -Action add
			}
			try { 
				Write-Verbose "Configuring NetScaler: Check if Load Balancer exists"
				$response = InvokeNSRestApi -Session $NSSession -Method GET -Type lbvserver -Resource $NSLbName
				Write-Verbose "Yep it exists, continuing"
			} catch {
				Write-Verbose "Nope, continuing"
				Write-Verbose "Configuring NetScaler: Create Load Balance Vip `"$NSLbName`""
				$payload = @{"name"="$NSLbName";"servicetype"="HTTP";"ipv46"="0.0.0.0";"Port"="0";}
				$response = InvokeNSRestApi -Session $NSSession -Method POST -Type lbvserver -Payload $payload -Action add
			} finally {
				Write-Verbose "Configuring NetScaler: Bind Service `"$NSSvcName`" to Load Balance Vip `"$NSLbName`""
				$payload = @{"name"="$NSLbName";"servicename"="$NSSvcName";}
				$response = InvokeNSRestApi -Session $NSSession -Method PUT -Type lbvserver_service_binding -Payload $payload
			}
			try { 
				Write-Verbose "Configuring NetScaler: Check if Responder Policy exists"
				$response = InvokeNSRestApi -Session $NSSession -Method GET -Type responderpolicy -Resource $NSRspName
				try {
					Write-Verbose "Yep it exists, continuing"
					Write-Verbose "Configuring NetScaler: Change Responder Policy to default values"
					$payload = @{"name"="$NSRspName";"action"="rsa_letsencrypt";"rule"='HTTP.REQ.URL.CONTAINS("well-known/acme-challenge/XXXXXX")';}
					$response = InvokeNSRestApi -Session $NSSession -Method POST -Type responderpolicy -Payload $payload -Action set
				} catch {
					throw "Something went wrong with reconfiguring the existing policy `"$NSRspName`", exiting now..."
				}	
			} catch {
				$payload = @{"name"="$NSRsaName";"type"="respondwith";"target"='"HTTP/1.0 200 OK" +"\r\n\r\n" + "XXXX"';}
				$response = InvokeNSRestApi -Session $NSSession -Method POST -Type responderaction -Payload $payload -Action add
				$payload = @{"name"="$NSRspName";"action"="$NSRsaName";"rule"='HTTP.REQ.URL.CONTAINS("well-known/acme-challenge/XXXX")';}
				$response = InvokeNSRestApi -Session $NSSession -Method POST -Type responderpolicy -Payload $payload -Action add
			} finally {
				$payload = @{"name"="$NSLbName";"policyname"="$NSRspName";"priority"=100;}
				$response = InvokeNSRestApi -Session $NSSession -Method PUT -Type lbvserver_responderpolicy_binding -Payload $payload -Resource $NSLbName
			}
			try { 
				Write-Verbose "Configuring NetScaler: Check if Content Switch Policy exists"
				$response = InvokeNSRestApi -Session $NSSession -Method GET -Type cspolicy -Resource $NSCspName
				Write-Verbose "It does, continuing"
				if (-not($response.cspolicy.rule -eq "HTTP.REQ.URL.CONTAINS(`"well-known/acme-challenge/`")")) {
					$payload = @{"policyname"="$NSCspName";"rule"="HTTP.REQ.URL.CONTAINS(`"well-known/acme-challenge/`")";}
					$response = InvokeNSRestApi -Session $NSSession -Method PUT -Type cspolicy -Payload $payload
				}
			} catch {
				Write-Verbose "Configuring NetScaler: Create Content Switch Policy"
				$payload = @{"policyname"="$NSCspName";"rule"='HTTP.REQ.URL.CONTAINS("well-known/acme-challenge/")';}
				$response = InvokeNSRestApi -Session $NSSession -Method POST -Type cspolicy -Payload $payload -Action add
				
				
			}
			Write-Verbose "Configuring NetScaler: Bind Load Balancer `"$NSLbName`" to Content Switch `"$NSCsVipName`" with prio: $NSCsVipBinding"
			$payload = @{"name"="$NSCsVipName";"policyname"="$NSCspName";"priority"="$NSCsVipBinding";"targetlbvserver"="$NSLbName";"gotopriorityexpression"="END";}
			$response = InvokeNSRestApi -Session $NSSession -Method PUT -Type csvserver_cspolicy_binding -Payload $payload
			Write-Verbose "Finished configuring the NetScaler"
		}
	} catch {
		Write-Verbose "Error Details: $($_.Exception.Message)"
		throw "ERROR: Could not configure the NetScaler, exiting now"
	}
}

#endregion NetScaler pre dns

#region DNS Check

if (-not ($CleanNS)) {
	Write-Verbose "Check if DNS Records need to be validated"
	foreach ($DNSObject in $DNSObjects) {
		Write-Verbose "Checking validation for `"$($DNSObject.DNSName)`""
		if ($DNSObject.DNSValid){
			Write-Verbose "Still valid"
		} else {
			Write-Verbose "New validation required, Start verifying"
			try {
				try {
					$Challenge = ((Complete-ACMEChallenge $($DNSObject.Alias) -ChallengeType http-01 -Handler manual -VaultProfile $VaultName).Challenges | Where-Object { $_.Type -eq "http-01" }).Challenge
				} catch {
					$Challenge = ((Complete-ACMEChallenge $($DNSObject.DNSName) -ChallengeType http-01 -Handler manual -VaultProfile $VaultName).Challenges | Where-Object { $_.Type -eq "http-01" }).Challenge
				}
				Write-Verbose "Configuring NetScaler: Change Responder Policy `"$NSRspName`" to: `"HTTP.REQ.URL.CONTAINS(`"$($Challenge.FilePath)`")`""
				$payload = @{"name"="$NSRspName";"action"="$NSRsaName";"rule"="HTTP.REQ.URL.CONTAINS(`"$($Challenge.FilePath)`")";}
				$response = InvokeNSRestApi -Session $NSSession -Method POST -Type responderpolicy -Payload $payload -Action set
				
				Write-Verbose "Configuring NetScaler: Change Responder Action `"$NSRsaName`" to return "
				Write-Verbose "`"HTTP/1.0 200 OK\r\n\r\n$($Challenge.FileContent)`""
				$payload = @{"name"="$NSRsaName";"target"="`"HTTP/1.0 200 OK\r\n\r\n$($Challenge.FileContent)`"";}
				$response = InvokeNSRestApi -Session $NSSession -Method POST -Type responderaction -Payload $payload -Action set
				
				Write-Verbose "Wait 1 second"
				Start-Sleep -Seconds 1
				Write-Verbose "Start Submitting Challenge"
				try {
					$SubmittedChallenge = Submit-ACMEChallenge $($DNSObject.Alias) -ChallengeType http-01 -VaultProfile $VaultName
				} catch {
					$SubmittedChallenge = Submit-ACMEChallenge $($DNSObject.DNSName) -ChallengeType http-01 -VaultProfile $VaultName
				}
				Write-Verbose "Retreiving validation status"
				try {
					$UpdateIdentifier = (Update-ACMEIdentifier $($DNSObject.Alias) -ChallengeType http-01 -VaultProfile $VaultName -Alias $($DNSObject.DNSName)).Challenges | Where-Object {$_.Type -eq "http-01"}
				} catch {
					$UpdateIdentifier = (Update-ACMEIdentifier $($DNSObject.DNSName) -ChallengeType http-01 -VaultProfile $VaultName -Alias $($DNSObject.DNSName)).Challenges | Where-Object {$_.Type -eq "http-01"}
				}
				$i = 0
				while(-NOT ($UpdateIdentifier.Status.ToLower() -eq "valid")) {
					$i++
					Write-Verbose "($($i.ToString())) $($DNSObject.DNSName) is not (yet) validated, Wait 2 second"
					Start-Sleep -Seconds 2
					Write-Verbose "Retreiving validation status"
					try {
						$UpdateIdentifier = (Update-ACMEIdentifier $($DNSObject.Alias) -ChallengeType http-01 -VaultProfile $VaultName -Alias $($DNSObject.DNSName)).Challenges | Where-Object {$_.Type -eq "http-01"}
					} catch {
						$UpdateIdentifier = (Update-ACMEIdentifier $($DNSObject.DNSName) -ChallengeType http-01 -VaultProfile $VaultName -Alias $($DNSObject.DNSName)).Challenges | Where-Object {$_.Type -eq "http-01"}
					}
					if (($i -ge 60) -or ($UpdateIdentifier.Status.ToLower() -eq "invalid")) {break}
				}
				switch ($UpdateIdentifier.Status.ToLower()) {
					"pending" {
						throw "ERROR. It took to long for the validation ($($DNSObject.DNSName)) to complete, exiting now."
					}
					"invalid" {
						throw "ERROR. Validation for `"$($DNSObject.DNSName)`" is invalid! Exiting now."
					}
					"valid" {
						Write-Host -ForeGroundColor Green "Verification for `"$($DNSObject.DNSName)`" was valid, continuing"
					}
					default {
						throw "ERROR. Unexpected status for `"$($DNSObject.DNSName)`" is `"$($UpdateIdentifier.Status)`", exiting now."
					}
				}
			} catch {
				Write-Verbose "Error Details: $($_.Exception.Message)"
				throw "Error while verifying `"$($DNSObject.DNSName)`", exiting now"
			}
		}
	}
}

#endregion DNS Check

#region NetScaler post DNS

if (($DNSValidationRequired) -or ($CleanNS)) {
	Write-Verbose "Login to NetScaler and save session to global variable"
	Connect-NetScaler -ManagementURL $NSManagementURL -Credential $NSCredential
	try {
		Write-Verbose "Checking if a binding exists for `"$NSCspName`""
		$Filters = @{"policyname"="$NSCspName"}
		$response = InvokeNSRestApi -Session $NSSession -Method GET -Type csvserver_cspolicy_binding -Resource "$NSCsVipName" -Filters $Filters
		if ($response.csvserver_cspolicy_binding.policyname -eq $NSCspName) {
			Write-Verbose "Removing Content Switch Loadbalance Binding"
			$Arguments = @{"name"="$NSCsVipName";"policyname"="$NSCspName";"priority"="$NSCsVipBinding";}
			$response = InvokeNSRestApi -Session $NSSession -Method DELETE -Type csvserver_cspolicy_binding -Arguments $Arguments
		} else {
			Write-Verbose "No binding found"
		}
	} catch { 
		Write-Verbose "Error Details: $($_.Exception.Message)"
		Write-Warning "Not able to remove the Content Switch Loadbalance Binding"
	}
	try {
		Write-Verbose "Checking if Content Switch Policy `"$NSCspName`" exists"
		try { 
			$response = InvokeNSRestApi -Session $NSSession -Method GET -Type cspolicy -Resource "$NSCspName"
		} catch{}
		if ($response.cspolicy.policyname -eq $NSCspName) {
			Write-Verbose "Removing Content Switch Policy"
			$response = InvokeNSRestApi -Session $NSSession -Method DELETE -Type cspolicy -Resource "$NSCspName"
		} else {
			Write-Verbose "Content Switch Policy not found"
		}
	} catch { 
		Write-Verbose "Error Details: $($_.Exception.Message)"
		Write-Warning "Not able to remove the Content Switch Policy" 
	}
	try {
		Write-Verbose "Checking if Load Balance vServer `"$NSLbName`" exists"
		try { 
			$response = InvokeNSRestApi -Session $NSSession -Method GET -Type lbvserver -Resource "$NSLbName"
		} catch{}
		if ($response.lbvserver.name -eq $NSLbName) {
			Write-Verbose "Removing the Load Balance vServer"
			$response = InvokeNSRestApi -Session $NSSession -Method DELETE -Type lbvserver -Resource "$NSLbName"
		} else {
			Write-Verbose "Load Balance vServer not found"
		}
	} catch { 
		Write-Verbose "Error Details: $($_.Exception.Message)"
		Write-Warning "Not able to remove the Load Balance vserver" 
	}
	try {
		Write-Verbose "Checking if Service `"$NSSvcName`" exists"
		try { 
			$response = InvokeNSRestApi -Session $NSSession -Method GET -Type service -Resource "$NSSvcName"
		} catch{}
		if ($response.service.name -eq $NSSvcName) {
			Write-Verbose "Removing Service `"$NSSvcName`""
			$response = InvokeNSRestApi -Session $NSSession -Method DELETE -Type service -Resource "$NSSvcName"
		} else {
			Write-Verbose "Service not found"
		}
	} catch { 
		Write-Verbose "Error Details: $($_.Exception.Message)"
		Write-Warning "Not able to remove the Service" 
	}
	try {
		Write-Verbose "Checking if server `"$NSSvcDestination`" exists"
		try { 
			$response = InvokeNSRestApi -Session $NSSession -Method GET -Type server -Resource "$NSSvcDestination"
		} catch{}
		if ($response.server.name -eq $NSSvcDestination) {
			Write-Verbose "Removing Server `"$NSSvcDestination`""
			$response = InvokeNSRestApi -Session $NSSession -Method DELETE -Type server -Resource "$NSSvcDestination"
		} else {
			Write-Verbose "Server not found"
		}
	} catch { 
		Write-Verbose "Error Details: $($_.Exception.Message)"
		Write-Warning "Not able to remove the Server" 
	}
	try {
		Write-Verbose "Checking if Responder Policy `"$NSRspName`" exists"
		try { 
			$response = InvokeNSRestApi -Session $NSSession -Method GET -Type responderpolicy -Resource "$NSRspName"
		} catch{}
		if ($response.responderpolicy.name -eq $NSRspName) {
			Write-Verbose "Removing Responder Policy `"$NSRspName`""
			$response = InvokeNSRestApi -Session $NSSession -Method DELETE -Type responderpolicy -Resource "$NSRspName" 
		} else {
			Write-Verbose "Responder Policy not found"
		}
	} catch { 
		Write-Verbose "Error Details: $($_.Exception.Message)"
		Write-Warning "Not able to remove the Responder Policy" 
	}
	try {
		Write-Verbose "Checking if Responder Action `"$NSRsaName`" exists"
		try { 
			$response = InvokeNSRestApi -Session $NSSession -Method GET -Type responderaction -Resource "$NSRsaName"
		} catch{}
		if ($response.responderaction.name -eq $NSRsaName) {
			Write-Verbose "Removing Responder Action `"$NSRsaName`""
			$response = InvokeNSRestApi -Session $NSSession -Method DELETE -Type responderaction -Resource $NSRsaName
		} else {
			Write-Verbose "Responder Action not found"
		}
	} catch { 
		Write-Verbose "Error Details: $($_.Exception.Message)"
		Write-Warning "Not able to remove the Responder Action" 
	}
}	

#endregion NetScaler Post DNS

#endregion ACME DNS Verification

#endregion DNS

#region Certificates
	
if (-not ($CleanNS)) {
	$SANs = $DNSObjects | Where-Object {$_.SAN -eq $true}
	try {
		if ($SANs) {
			Write-Verbose "Get certificate with SANs (ID: $SessionGUID)"
			Write-Verbose "Domain:`n$($DNSObjects[0] | Select-Object DNSName,Alias | Format-Table | Out-String)"
			Write-Verbose "Subject Alternative Names:`n$(@($SANs) | Select-Object DNSName,Alias | Format-Table | Out-String)"
			$NewCertificate = New-ACMECertificate $DNSObjects[0].Alias `
				-AlternativeIdentifierRefs @($SANs.Alias) `
				-Alias $DNSObjects[0].Alias `
				-Generate `
				-VaultProfile $VaultName | Out-Null
		} else {
			Write-Verbose "Get single DNS Name certificate (ID: SessionGUID)"
			Write-Verbose "Domain:`r`n$($($DNSObjects[0].DNSName) | fl * | Out-String)"
			$NewCertificate = New-ACMECertificate $DNSObjects[0].Alias `
				-Alias $DNSObjects[0].Alias `
				-Generate `
				-VaultProfile $VaultName | Out-Null
		}
		Write-Verbose "Submit Certificate request"
		Submit-ACMECertificate $DNSObjects[0].Alias -VaultProfile $VaultName | Out-Null
	} catch {
		throw "ERROR. Certificate completion failed, details: $($_.Exception.Message | Out-String)"
	}
	$i = 0
	while (-not (Update-ACMECertificate $DNSObjects[0].Alias -VaultProfile $VaultName | select IssuerSerialNumber)) {
		if ($i -ge 120) {
			throw "Error: Retreiving certificate failed, took to long to complete"
		}
		Write-Host "Waiting for certificate to come available..."
		Start-Sleep -seconds 2
	}
	
	$CertificateDirectory = Join-Path -Path $CertDir -ChildPath "$($SessionDateTime)-$($SessionGUID)"
	Write-Verbose "Create directory `"$CertificateDirectory`" for storing the new certificates"
	$output = New-Item $CertificateDirectory -ItemType directory -force
	if (Test-Path $CertificateDirectory){
		if ($Production){
			Write-Verbose "Writing production certificates"
			$IntermediateCACertKeyName = "Lets Encrypt Authority X3-int"
			$IntermediateCAFileName = "$($IntermediateCACertKeyName).crt"
			$IntermediateCAFullPath = Join-Path -Path $CertificateDirectory -ChildPath $IntermediateCAFileName
			$IntermediateCASerial = "0a0141420000015385736a0b85eca708"
		} else {
			Write-Verbose "Writing test/staging certificates"
			$IntermediateCACertKeyName = "Fake LE Intermediate X1-int"
			$IntermediateCAFileName = "$($IntermediateCACertKeyName).crt"
			$IntermediateCAFullPath = Join-Path -Path $CertificateDirectory -ChildPath $IntermediateCAFileName
			$IntermediateCASerial = "8be12a0e5944ed3c546431f097614fe5"

		}
		Write-Verbose "Intermediate: `"$IntermediateCAFileName`""
		Get-ACMECertificate $DNSObjects[0].Alias -ExportIssuerPEM $IntermediateCAFullPath -VaultProfile $VaultName | Out-Null
		
		
		$CertificateCertKeyName = "$($SessionDateTime )_$($DNSObjects[0].DNSName)"
		
		if ($Production){
			$CertificateFileName = "$CertificateCertKeyName.crt"
			$CertificateKeyFileName = "$CertificateCertKeyName.crt.key"
			$CertificatePfxFileName = "$CertificateCertKeyName.pfx"
		} else {
			$CertificateFileName = "TST-$CertificateCertKeyName.crt"
			$CertificateKeyFileName = "TST-$CertificateCertKeyName.crt.key"
			$CertificatePfxFileName = "TST-$CertificateCertKeyName.pfx"
		}
		$CertificateFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificateFileName
		Write-Verbose "Certificate: `"$CertificateFileName`""
		Get-ACMECertificate $DNSObjects[0].Alias -ExportCertificatePEM $CertificateFullPath -VaultProfile $VaultName | Out-Null
		$CertificateKeyFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificateKeyFileName
		Write-Verbose "Key: `"$CertificateKeyFileName`""
		Get-ACMECertificate $DNSObjects[0].Alias -ExportKeyPEM $CertificateKeyFullPath -VaultProfile $VaultName | Out-Null
		$CertificatePfxFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificatePfxFileName 
		if ($PfxPassword){
			Write-Verbose "PFX: `"$CertificatePfxFileName`""
			Get-ACMECertificate $DNSObjects[0].Alias -ExportPkcs12 "$CertificatePfxFullPath" -CertificatePassword "$PfxPassword" -VaultProfile $VaultName | Out-Null
		} else {
			Write-Warning "No Password was specified, so a PFX certificate was not generated. If you want one run the following command:`n `
				Get-ACMECertificate $($DNSObjects[0].Alias) -ExportPkcs12 `"$CertificatePfxFullPath`" -CertificatePassword `"P@ssw0rd`" -VaultProfile `"$VaultName`"`n`n"
		}
	}
}

#endregion Certificates

#region Upload certificates to NetScaler

if (-not ($CleanNS)) {
	try {
		Write-Verbose "Retreiving existing certificates"
		$CertDetails = InvokeNSRestApi -Session $NSSession -Method GET -Type sslcertkey
		Write-Verbose "Checking if IntermediateCA `"$IntermediateCACertKeyName`" already exists"
		$IntermediateCADetails = $CertDetails.sslcertkey | Where-Object {$_.serial -eq $IntermediateCASerial}
		if (-not ($IntermediateCADetails)) {
			Write-Verbose "Uploading `"$IntermediateCAFileName`" to the NetScaler"
			$IntermediateCABase64 = [System.Convert]::ToBase64String($(Get-Content $IntermediateCAFullPath -Encoding "Byte"))
			$payload = @{"filename"="$IntermediateCAFileName";"filecontent"="$IntermediateCABase64";"filelocation"="/nsconfig/ssl/";"fileencoding"="BASE64";}
			$response = InvokeNSRestApi -Session $NSSession -Method POST -Type systemfile -Payload $payload
			Write-Verbose "Succeeded"
			Write-Verbose "Add the certificate to the NetScaler config"
			$payload = @{"certkey"="$IntermediateCACertKeyName";"cert"="/nsconfig/ssl/$($IntermediateCAFileName)";}
			$response = InvokeNSRestApi -Session $NSSession -Method POST -Type sslcertkey -Payload $payload
			Write-Verbose "Succeeded"
		} else {
			$IntermediateCACertKeyName = $IntermediateCADetails.certkey
			Write-Verbose "Saving existing name `"$IntermediateCACertKeyName`" for later use"
		}
		$ExistingCertificateDetails = $CertDetails.sslcertkey | Where-Object {$_.certkey -eq $NSCertNameToUpdate}
		if (($NSCertNameToUpdate) -and ($ExistingCertificateDetails)) {
			$CertificateCertKeyName = $($ExistingCertificateDetails.certkey)
			Write-Verbose "Existing certificate `"$($ExistingCertificateDetails.certkey)`" found on the netscaler, start updating"
			try {
				Write-Verbose "Unlinking certificate"
				$payload = @{"certkey"="$($ExistingCertificateDetails.certkey)";}
				$response = InvokeNSRestApi -Session $NSSession -Method POST -Type sslcertkey -Payload $payload -Action unlink
				
			} catch {
				Write-Verbose "Certificate was not linked"
			}
			$NSUpdating = $true
		} elseif ($NSCertNameToUpdate) {
			Write-Verbose " `"$NSCertNameToUpdate`" is $($NSCertNameToUpdate.Length) long"
			if ($NSCertNameToUpdate.Length -gt 30) {
				Write-Verbose "Name is to long, only using the first 31 characters"
				$CertificateCertKeyName = $NSCertNameToUpdate.subString(0,31)
			} else {
				Write-Verbose "CertkeyName is not too long, continuing"
				$CertificateCertKeyName = $NSCertNameToUpdate
			}
			Write-Verbose "No existing certificate found, using predefined name `"$NSCertNameToUpdate`". Start configuring the certificate"
			$NSUpdating = $false
		} else {
			Write-Verbose "Start configuring the certificaten"
			$NSUpdating = $false
		}
		$CertificateCrtBase64 = [System.Convert]::ToBase64String($(Get-Content $CertificateFullPath -Encoding "Byte"))
		$CertificateKeyBase64 = [System.Convert]::ToBase64String($(Get-Content $CertificateKeyFullPath -Encoding "Byte"))
		Write-Verbose "Uploading the certificate"
		$payload = @{"filename"="$CertificateFileName";"filecontent"="$CertificateCrtBase64";"filelocation"="/nsconfig/ssl/";"fileencoding"="BASE64";}
		$response = InvokeNSRestApi -Session $NSSession -Method POST -Type systemfile -Payload $payload
		
		Write-Verbose "Uploading the certificate key"
		$payload = @{"filename"="$CertificateKeyFileName";"filecontent"="$CertificateKeyBase64";"filelocation"="/nsconfig/ssl/";"fileencoding"="BASE64";}
		$response = InvokeNSRestApi -Session $NSSession -Method POST -Type systemfile -Payload $payload
		Write-Verbose "Finished uploading"
		if ($NSUpdating) {
			Write-Verbose "Update the certificate and key to the NetScaler config"
			$payload = @{"certkey"="$CertificateCertKeyName";"cert"="/nsconfig/ssl/$($CertificateFileName)";"key"="/nsconfig/ssl/$($CertificateKeyFileName)"}
			$response = InvokeNSRestApi -Session $NSSession -Method POST -Type sslcertkey -Payload $payload -Action update
			Write-Verbose "Succeeded"
	
		} else {
			Write-Verbose "Add the certificate and key to the NetScaler config"
			$payload = @{"certkey"="$CertificateCertKeyName";"cert"="/nsconfig/ssl/$($CertificateFileName)";"key"="/nsconfig/ssl/$($CertificateKeyFileName)"}
			$response = InvokeNSRestApi -Session $NSSession -Method POST -Type sslcertkey -Payload $payload
			Write-Verbose "Succeeded"
		}
		Write-Verbose "Link `"$CertificateCertKeyName`" to `"$IntermediateCACertKeyName`""
		$payload = @{"certkey"="$CertificateCertKeyName";"linkcertkeyname"="$IntermediateCACertKeyName";}
		$response = InvokeNSRestApi -Session $NSSession -Method POST -Type sslcertkey -Payload $payload -Action link
		Write-Verbose "Succeeded"
		if ($SaveNSConfig) {
			Write-Verbose "Saving NetScaler configuration"
			InvokeNSRestApi -Session $NSSession -Method POST -Type nsconfig -Action save
		}
		""
		Write-Host -ForeGroundColor Green "Finished with the certificates!"
		if (-not $Production){
			Write-Host -ForeGroundColor Green "You are now ready for the Production version!"
			Write-Host -ForeGroundColor Green "Add the `"-Production`" parameter and rerun the same script."
		}
	} catch {
		throw "ERROR. Certificate completion failed, details: $($_.Exception.Message | Out-String)"
	}
}
#endregion Upload certificates to NetScaler
