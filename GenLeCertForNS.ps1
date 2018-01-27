<#
.SYNOPSIS
	Create a new or update an existing Let's Encrypt certificate for one or more domains and add it to a store then update the SSL bindings for a NetScaler
.DESCRIPTION
	The script will use ACMESharp to create a new or update an existing certificate for one or more domains. If generated successfully the script will add the certificate to the NetScaler and update the SSL binding for a web site. This script is for use with a Citrix NetScaler (v11.x and up). The script will validate the dns records provided. For example, the domain(s) listed must be configured with the same IP Address that is configured (via NAT) to a Content Switch.
.PARAMETER Help
	Display the detailed information about this script
.PARAMETER CleanNS
	Cleanup the NetScaler configuration made within this script, for when somewhere it gone wrong
.PARAMETER RemoveTestCertificates
	Tries to remove all the Test certificates signed by the "Fake LE Intermediate X1" staging intermediate
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
	IP Address used for the NetScaler Service (leave default 1.2.3.4), only change when already used
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
	.\GenLeCertForNS.ps1 -CN "domain.com" -EmailAddress "hostmaster@domain.com" -SAN "sts.domain.com","www.domain.com","vpn.domain.com" -PfxPassword "P@ssw0rd" -CertDir "C:\Certificates" -NSManagementURL "http://192.168.100.1" -NSCsVipName "cs_domain.com_http" -NSPassword "P@ssw0rd" -NSUserName "nsroot" -NSCertNameToUpdate "san_domain_com" -Production -CleanVault -Verbose
	Generate a (Production)certificate for hostname "domain.com" with alternate names : "sts.domain.com, www.domain.com, vpn.domain.com". Using the emailaddress "hostmaster@domain.com". At the end storing the certificates  in "C:\Certificates" and uploading them to the NetScaler. Also Cleaning the vault on the NetScaler the content Switch "cs_domain.com_http" will be used to validate the certificates.
.EXAMPLE
	.\GenLeCertForNS.ps1 -CleanNS -NSManagementURL "http://192.168.100.1" -NSCsVipName "cs_domain.com_http" -NSPassword "P@ssw0rd" -NSUserName "nsroot" -Verbose
	Cleaning left over configuration from this schript when something went wrong during a previous attempt to generate new certificates and generating Verbose output.
.EXAMPLE
	.\GenLeCertForNS.ps1 -RemoveTestCertificates -NSManagementURL "http://192.168.100.1" -NSPassword "P@ssw0rd" -NSUserName "nsroot" -Verbose
	Remob=ving ALL the test certificates from your NetScaler.
.NOTES
	File Name : GenLeCertForNS.ps1
	Version   : v0.9.2
	Author    : John Billekens
	Requires  : PowerShell v3 and up
	            NetScaler 11.x and up
	            Run As Administrator
	            ACMESharp 0.9.1.326 (can be installed via this script)
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

		[Parameter(ParameterSetName="CleanTestCertificate",Mandatory=$false)]
		[alias("RemTestCert")]
		[switch]$RemoveTestCertificates,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$true)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$true)]
		[Parameter(ParameterSetName="CleanTestCertificate",Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[alias("URL")]
		[string]$NSManagementURL,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanTestCertificate",Mandatory=$false)]
		[alias("User", "Username")]
		[string]$NSUserName,
		
		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanTestCertificate",Mandatory=$false)]
		[alias("Password")]
		[string]$NSPassword,

		[Parameter(ParameterSetName="ConfigNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanNetScaler",Mandatory=$false)]
		[Parameter(ParameterSetName="CleanTestCertificate",Mandatory=$false)]
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
$ScriptVersion = "v0.9.2"

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
		Username=$Credential.UserName;
		Version="UNKNOWN";
	}

	try {
		Write-Verbose -Message "Trying to retreive the NetScaler version"
		$params = @{
			Uri = "$ManagementURL/nitro/v1/config/nsversion"
			Method = 'GET'
			WebSession = $Session.WebSession
			ContentType = 'application/json'
			ErrorVariable = 'restError'
			Verbose = $false
		}
		$response = Invoke-RestMethod @params
		Write-Verbose -Message "Response:`n$(ConvertTo-Json -InputObject $response | Out-String)"
		$version = $response.nsversion.version.Split(",")[0]
		if (-not ([string]::IsNullOrWhiteSpace($version))) {
			$session.version = $version
		}
	} catch {
		Write-Verbose -Message "Error. See response: `n$($response | Format-List -Property * | Out-String)"
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

Write-Verbose "Script version: $ScriptVersion"
if ($ns10x){
	Write-Verbose "ns10x parameter used, some options are now disabled."
}
Write-Verbose "Setting session DATE/TIME variable"
[datetime]$ScriptDateTime = Get-Date
[string]$SessionDateTime = $ScriptDateTime.ToString("yyyyMMdd-HHmmss")
[string]$IdentifierDate = $ScriptDateTime.ToString("yyyyMMdd")
Write-Verbose "Session DATE/TIME variable value: `"$SessionDateTime`""

if (-not([string]::IsNullOrWhiteSpace($NSCredential))) {
	Write-Verbose "Using NSCredential"
} elseif ((-not([string]::IsNullOrWhiteSpace($NSUserName))) -and (-not([string]::IsNullOrWhiteSpace($NSPassword)))){
	Write-Verbose "Using NSUsername / NSPassword"
	[pscredential]$NSCredential = new-object -typename System.Management.Automation.PSCredential -argumentlist $NSUserName, $(ConvertTo-SecureString -String $NSPassword -AsPlainText -Force)
} else {
	Write-Verbose "No valid username/password or credential specified. Enter a username and password, e.g. `"nsroot`""
	[pscredential]$NSCredential = Get-Credential -Message "NetScaler username and password:"
}
Write-Verbose "Starting new session"
if(-not ([string]::IsNullOrWhiteSpace($SAN))){
	[string[]]$SAN = @($SAN.Split(","))
}

#endregion Script variables

#region Load Module

if ((-not ($CleanNS)) -and (-not ($RemoveTestCertificates))) {
	Write-Verbose "Load ACMESharp Modules"
	if (-not(Get-Module ACMESharp)){
		try {
			$ACMEVersions = (get-Module -Name ACMESharp -ListAvailable).Version
			$ACMEUpdateRequired = $false
			ForEach ($ACMEVersion in $ACMEVersions) {
				if (($ACMEVersion.Minor -eq 9) -and ($ACMEVersion.Build -eq 1) -and (-not $ACMEUpdateRequired)) {
					Write-Verbose "v0.9.1 of ACMESharp is installed, continuing"
				} else {
					Write-Verbose "v0.9.1 of ACMESharp is NOT installed, update/downgrade required"
					$ACMEUpdateRequired = $true
				}
			}
			if ($ACMEUpdateRequired) {
				Write-Verbose "Trying to update the ACMESharp modules"
				Install-Module -Name ACMESharp -Scope AllUsers -RequiredVersion 0.9.1 -Force -ErrorAction SilentlyContinue
			}
			Write-Verbose "Try loading module ACMESharp"
			Import-Module ACMESharp -ErrorAction Stop
		} catch [System.IO.FileNotFoundException] {
			Write-Verbose "Checking for PackageManagement"
			if ([string]::IsNullOrWhiteSpace($(Get-Module -ListAvailable -Name PackageManagement))) {
				Write-Warning "PackageManagement is not available please install this first or manually install ACMESharp"
				Write-Warning "Visit `"https://docs.microsoft.com/en-us/powershell/gallery/psget/get_psget_module`" to download Package Management"
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
						Install-Module -Name ACMESharp -Scope AllUsers -RequiredVersion 0.9.1.326 -Force -AllowClobber
					} catch {
						Write-Verbose "Installing ACMESharp again but without the -AllowClobber option"
						Install-Module -Name ACMESharp -Scope AllUsers -RequiredVersion 0.9.1.326 -Force
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
					Write-Warning "PackageManagement is not available please install this first or manually install ACMESharp"
					Write-Warning "Visit `"https://docs.microsoft.com/en-us/powershell/gallery/psget/get_psget_module`" to download Package Management"
					Write-Warning "ACMESharp: https://github.com/ebekker/ACMESharp"
					Start "https://www.microsoft.com/en-us/download/details.aspx?id=49186"
					Exit (1)
				}
			}
		}
	}
}

#endregion Load Module

#region NetScaler Check

if ((-not ($CleanNS)) -and (-not ($RemoveTestCertificates))) {
	Write-Verbose "Login to NetScaler and save session to global variable"
	Write-Host -ForeGroundColor White "`r`nNetScaler:"
	$NSSession = Connect-NetScaler -ManagementURL $NSManagementURL -Credential $NSCredential -PassThru
	Write-Host -ForeGroundColor White -NoNewLine "- URL: "
	Write-Host -ForeGroundColor Green "$NSManagementURL"
	Write-Host -ForeGroundColor White -NoNewLine "- Username: "
	Write-Host -ForeGroundColor Green "$($NSSession.Username)"
	Write-Host -ForeGroundColor White -NoNewLine "- Version: "
	Write-Host -ForeGroundColor Green "$($NSSession.Version)"
	try {
		Write-Verbose "Verifying Content Switch"
		$response = InvokeNSRestApi -Session $NSSession -Method GET -Type csvserver -Resource $NSCsVipName
	} catch {
		$ExcepMessage = $_.Exception.Message
		Write-Verbose "Error Details: $ExcepMessage"
	} finally {
		if (($response.errorcode -eq "0") -and `
				($response.csvserver.type -eq "CONTENT") -and `
				($response.csvserver.curstate -eq "UP") -and `
				($response.csvserver.servicetype -eq "HTTP") -and `
				($response.csvserver.port -eq "80") ) {
			Write-Host -ForeGroundColor White -NoNewLine "- Content Switch: "
			Write-Host -ForeGroundColor Green "`"$NSCsVipName`" -> Found"
			Write-Host -ForeGroundColor White -NoNewLine "- Connection: "
			Write-Host -ForeGroundColor Green "OK`r`n"
		} elseif ($ExcepMessage -like "*(404) Not Found*") {
			Write-Host -ForeGroundColor White -NoNewLine "- Content Switch: "
			Write-Host -ForeGroundColor Red "ERROR: The Content Switch `"$NSCsVipName`" does NOT exist!`r`n"
			Write-Host -ForeGroundColor White -NoNewLine "- Error message: "
			Write-Host -ForeGroundColor Red "`"$ExcepMessage`"`r`n"
			Write-Host -ForeGroundColor Yellow "  IMPORTANT: Please make sure a HTTP Content Switch is available`r`n"
			Write-Host -ForeGroundColor White -NoNewLine "- Connection: "
			Write-Host -ForeGroundColor Red "FAILED!`r`n"
			Write-Host -ForeGroundColor Red "  Exiting now`r`n"
			Exit (1)
		}  elseif ($ExcepMessage -like "*The remote server returned an error*") {
			Write-Host -ForeGroundColor White -NoNewLine "- Content Switch: "
			Write-Host -ForeGroundColor Red "ERROR: Unknown error found while checking the Content Switch"
			Write-Host -ForeGroundColor White -NoNewLine "- Error message: "
			Write-Host -ForeGroundColor Red "`"$ExcepMessage`"`r`n"
			Write-Host -ForeGroundColor White -NoNewLine "- Connection: "
			Write-Host -ForeGroundColor Red "FAILED!`r`n"
			Write-Host -ForeGroundColor Red "  Exiting now`r`n"
			Exit (1)
		} elseif (($response.errorcode -eq "0") -and (-not ($response.csvserver.servicetype -eq "HTTP"))) {
			Write-Host -ForeGroundColor White -NoNewLine "- Content Switch: "
			Write-Host -ForeGroundColor Red "ERROR: Content Switch is $($response.csvserver.servicetype) and NOT HTTP`r`n"
			if (-not ([string]::IsNullOrWhiteSpace($ExcepMessage))){
				Write-Host -ForeGroundColor White -NoNewLine "- Error message: "
				Write-Host -ForeGroundColor Red "`"$ExcepMessage`"`r`n"
			}
			Write-Host -ForeGroundColor Yellow "  IMPORTANT: Please use a HTTP (Port 80) Content Switch!`r`n  This is required for the validation.`r`n"
			Write-Host -ForeGroundColor White -NoNewLine "- Connection: "
			Write-Host -ForeGroundColor Red "FAILED!`r`n"
			Write-Host -ForeGroundColor Red "  Exiting now`r`n"
			Exit (1)
		} else {
			Write-Host -ForeGroundColor White -NoNewLine "- Content Switch: "
			Write-Host -ForeGroundColor Green "Found"
			Write-Host -ForeGroundColor White -NoNewLine "- Content Switch state: "
			if ($response.csvserver.curstate -eq "UP") {
				Write-Host -ForeGroundColor Green "UP"
			} else {
				Write-Host -ForeGroundColor RED "$($response.csvserver.curstate)"
			}
			Write-Host -ForeGroundColor White -NoNewLine "- Content Switch type: "
			if ($response.csvserver.type -eq "CONTENT") {
				Write-Host -ForeGroundColor Green "CONTENT"
			} else {
				Write-Host -ForeGroundColor RED "$($response.csvserver.type)"
			}
			if (-not ([string]::IsNullOrWhiteSpace($ExcepMessage))){
				Write-Host -ForeGroundColor White -NoNewLine "`r`n- Error message: "
				Write-Host -ForeGroundColor Red "`"$ExcepMessage`"`r`n"
			}
			Write-Host -ForeGroundColor White -NoNewLine "- Data: "
			$response.csvserver  | Format-List -Property * | Out-String
			Write-Host -ForeGroundColor White -NoNewLine "- Connection: "
			Write-Host -ForeGroundColor Red "FAILED!`r`n"
			Write-Host -ForeGroundColor Red "  Exiting now`r`n"
			Exit (1)
		}
	}
}

#endregion NetScaler Check

#region Vault

if ((-not ($CleanNS)) -and (-not ($RemoveTestCertificates))) {
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
		$VaultData = ACMESharp\Get-ACMEVault -VaultProfile $VaultName
	} catch {
		Write-Verbose "`"$VaultName`" Vault not available, initialize"
		$CleanVault = $true
	}
	if ($CleanVault) {
		Write-Verbose "Initializing Vault"
		ACMESharp\Initialize-ACMEVault -VaultProfile $VaultName -Force
		Write-Verbose "Finished initializing"
		$VaultData = ACMESharp\Get-ACMEVault -VaultProfile $VaultName
	}
	Write-Verbose "Configure vault `"$VaultName`" for `"$BaseService`""
	ACMESharp\Set-ACMEVault -VaultProfile $VaultName -BaseService $BaseService
}

#endregion Vault

#region Registration

if ((-not ($CleanNS)) -and (-not ($RemoveTestCertificates))) {
	Write-Host -NoNewLine -ForeGroundColor Yellow "`n`nIMPORTANT: "
	Write-Host -ForeGroundColor White "By running this script you agree with the terms specified by Let's Encrypt."
	try {
		Write-Verbose "Retreive existing Registration"
		$Registration = ACMESharp\Get-ACMERegistration -VaultProfile $VaultName
		if ($Registration.Contacts -contains "mailto:$($EmailAddress)"){
			Write-Verbose "Existing registration found, no changes necessary"
		} else {
			Write-Verbose "Current registration `"$($Registration.Contacts)`" is not equal to `"$EmailAddress`", setting new registration"
			$Registration = ACMESharp\New-ACMERegistration -VaultProfile $VaultName -Contacts "mailto:$($EmailAddress)" -AcceptTos
		}
	} catch {
		Write-Verbose "Setting new registration to `"$EmailAddress`""
		
		$Registration = ACMESharp\New-ACMERegistration -VaultProfile $VaultName -Contacts "mailto:$($EmailAddress)" -AcceptTos
	}
	Write-Host -ForeGroundColor Yellow "`n`n`nTerms of Agreement:`n$($Registration.TosLinkUri)`n`n`n"
}

#endregion Registration

#region DNS

#region Primary DNS

if ((-not ($CleanNS)) -and (-not ($RemoveTestCertificates))) {
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
				Write-Warning "More than one ip address found`n$($PrimaryIP | Format-List | Out-String)"
				$PrimaryIP = $PrimaryIP[0]
				Write-Warning "using the first one`"$PrimaryIP`""
			}
		}
	} catch {
		Write-Verbose "Error Details: $($_.Exception.Message)"
		Write-Host -ForeGroundColor Red "`nError while retreiving IP Address,"
		Write-Host -ForeGroundColor Red "you can try to re-run the script with the -DisableIPCheck parameter.`n"
		throw "Error while retreiving IP Address, does not exist?"
	}
	
	$Identifier = $null
	$IdentifierAlias = $null
	try {
		Write-Verbose "Find pre-existing registration for `"$CN`""
		$IdentifierAlias = "DNS-$($CN)-$IdentifierDate"
		$Identifier = ACMESharp\Get-ACMEIdentifier -IdentifierRef $IdentifierAlias -VaultProfile $VaultName
	} catch {
		try {
			Write-Verbose "Registration does not exist, registering `"$CN`""
			$Identifier = ACMESharp\New-ACMEIdentifier -Dns $CN -Alias $IdentifierAlias -VaultProfile $VaultName
		} catch {
			Write-Verbose "Registration is invalid"
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
			#$result = $response  | Select-Object status,expires
			if ((-not([string]::IsNullOrWhiteSpace($response.status))) -and (-not([string]::IsNullOrWhiteSpace($response.expires)))) {
				$httpIdentifier = ($response | select -expand Challenges | Where-Object {$_.type -eq "http-01"})
			}
		} else {
			Write-Verbose "No URI available to check..."
		}
	}catch{
		Write-Verbose "Someting went wrong with the validation:`n$($response | Format-List | Out-String)"
	}
	Write-Verbose "Checking if current validation is still valid"
	if (($response.status -eq "valid") -and ($([datetime]$response.Expires - $(Get-Date)).TotalDays -gt 1)) {
		Write-Verbose "Registration for `"$CN`" is still valid"
		$Validation = $true
		Write-Verbose "Validation response:`n$($($response | Select-Object Identifier,Status,Expires) | Format-List | Out-String)"
	} else {
		Write-Verbose "Registration for `"$CN`" is NOT valid, validation required"
		$Validation = $false
		Write-Verbose "Validation response:`n$($($Identifier | Select-Object Identifier,Status,Expires) | Format-List | Out-String)"
	}
	Write-Verbose "Storing values for reference"
	$DNSObjects += [PSCustomObject]@{
		DNSName = $CN
		IPAddress = $PrimaryIP
		Status = $(if ([string]::IsNullOrWhiteSpace($PrimaryIP)) {$false} else {$true})
		Match = $null
		SAN = $false
		DNSValid = $Validation
		Alias = $IdentifierAlias
	}
	Write-Verbose "SAN Objects:`n$($DNSObjects | Format-List | Out-String)"
}

#endregion Primary DNS

#region SAN

if ((-not ($CleanNS)) -and (-not ($RemoveTestCertificates))) {
	$DNSRecord = $null
	Write-Verbose "Checking if SAN entries are available"
	if ([string]::IsNullOrWhiteSpace($SAN)) {
		Write-Verbose "No SAN entries found"
	} else {
		Write-Verbose "$($SAN.Count) found, checking each one"
		foreach ($DNSRecord in $SAN) {
			Write-Verbose "Start with SAN: `"$DNSRecord`""
			try {
				if ($DisableIPCheck) {
					Write-Verbose "Skipping IP check"
					$SANIP = "NoIPCheck"
				} else {
					Write-Verbose "Start basic IP Check for `"$DNSRecord`", trying to get IP Address"
					$SANIP = (Resolve-DnsName -Server $PublicDnsServer -Name $DNSRecord -DnsOnly -Type A -ErrorAction SilentlyContinue).IPAddress
					if ($SANIP -is [system.array]){
						Write-Warning "More than one ip address found`n$($SANIP | Format-List | Out-String)"
						$SANIP = $SANIP[0]
						Write-Warning "using the first one`"$SANIP`""
					}
					Write-Verbose "Finished, Result: $SANIP"
				}
				
			} catch {
				Write-Verbose "Error Details: $($_.Exception.Message)"
				Write-Host -ForeGroundColor Red "`nError while retreiving IP Address,"
				Write-Host -ForeGroundColor Red "you can try to re-run the script with the -DisableIPCheck parameter."
				Write-Host -ForeGroundColor Red "The script will continue but `"$DNSRecord`" will be skipped`n"
				$SANIP = "Skipped"
			}
			if ([string]::IsNullOrWhiteSpace($SANIP)) {
				Write-Verbose "No valid entry found for DNSName:`"$DNSRecord`""
				$SANMatch = $false
				$SANStatus = $false
			} else {
				Write-Verbose "Valid entry found"
				$SANStatus = $true
				if ($SANIP -eq "NoIPCheck") {
					Write-Verbose "IP address checking was disabled"
					$SANMatch = $true
				} elseif ($SANIP -eq "Skipped") {
					Write-Verbose "IP address checking failed, `"$DNSRecord`" will be skipped"
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
			if (-not($SANIP -eq "Skipped")) {
				$Identifier = $null
				$IdentifierAlias = $null
				try {
					Write-Verbose "Find pre-existing registration for `"$DNSRecord`""
					$IdentifierAlias = "DNS-$($DNSRecord)-$IdentifierDate"
					$Identifier = ACMESharp\Get-ACMEIdentifier -IdentifierRef $IdentifierAlias -VaultProfile $VaultName
				} catch {
					try {
						Write-Verbose "Registration does not exist, registering `"$DNSRecord`""
						$Identifier = ACMESharp\New-ACMEIdentifier -Dns $DNSRecord -Alias $IdentifierAlias -VaultProfile $VaultName
					} catch {
						Write-Verbose "Registration is invalid"
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
						#$result = $response  | Select-Object status,expires
						if ((-not([string]::IsNullOrWhiteSpace($response.status))) -and (-not([string]::IsNullOrWhiteSpace($response.expires)))) {
							$httpIdentifier = ($response | select -expand Challenges | Where-Object {$_.type -eq "http-01"})
						}
					} else {
						Write-Verbose "No URI available to check..."
					}
				}catch{
					Write-Verbose "Someting went wrong with the validation:`n$($response | Format-Table | Out-String)"
				}
				
				Write-Verbose "Checking if current validation is still valid"
				if (($response.status -eq "valid") -and ($([datetime]$response.Expires - $(Get-Date)).TotalDays -gt 1)) {
					Write-Verbose "Registration for `"$DNSRecord`" is still valid"
					$Validation = $true
					Write-Verbose "Validation response:`n$($($response | Select-Object Identifier,Status,Expires) | Format-Table | Out-String)"
				} else {
					Write-Verbose "Registration for `"$DNSRecord`" is NOT valid, validation required"
					$Validation = $false
					Write-Verbose "Validation response:`n$($($Identifier | Select-Object Identifier,Status,Expires) | Format-Table | Out-String)"
				}
				Write-Verbose "Storing values for reference"
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
			Write-Verbose "Finished with SAN: `"$DNSRecord`""
		}
	}
	Write-Verbose "SAN Objects:`n$($DNSObjects | Format-List | Out-String)"
}

#endregion SAN

if ((-not ($CleanNS)) -and (-not ($RemoveTestCertificates))) {
	Write-Verbose "Checking for invalid DNS Records"
	$InvalidDNS = $DNSObjects | Where-Object {$_.Status -eq $false}
	$SkippedDNS = $DNSObjects | Where-Object {$_.IPAddress -eq "Skipped"}
	if ($InvalidDNS) {
		Write-Verbose "Invalid DNS object(s):`n$($InvalidDNS | Select-Object DNSName,Status | Format-List | Out-String)"
		$DNSObjects[0] | Select-Object DNSName,IPAddress | Format-List | Out-String | Foreach {Write-Host -ForeGroundColor Green "$_"}
		$InvalidDNS | Select-Object DNSName,IPAddress | Format-List | Out-String | Foreach {Write-Host -ForeGroundColor Red "$_"}
		throw "ERROR, invalid (not registered?) DNS Record(s) found!"
	} else {
		Write-Verbose "None found, continuing"
	}
	if ($SkippedDNS) {
		Write-Warning "The following DNS object(s) will be skipped:`n$($SkippedDNS | Select-Object DNSName | Format-List | Out-String)"
	} 
	Write-Verbose "Checking non matching DNS Records"
	$DNSNoMatch = $DNSObjects | Where-Object {$_.Match -eq $false}
	if ($DNSNoMatch -and (-not $DisableIPCheck)) {
		Write-Verbose "$($DNSNoMatch | Select-Object DNSName,Match | Format-List | Out-String)"
		$DNSObjects[0] | Select-Object DNSName,IPAddress | Format-List | Out-String | Foreach {Write-Host -ForeGroundColor Green "$_"}
		$DNSNoMatch | Select-Object DNSName,IPAddress | Format-List | Out-String | Foreach {Write-Host -ForeGroundColor Red "$_"}
		throw "ERROR: Non-matching records found, must match to `"$($DNSObjects[0].DNSName)`" ($($DNSObjects[0].IPAddress))"
	} elseif ($DisableIPCheck) {
		Write-Verbose "IP Adressess checking was skipped"
	} else {
		Write-Verbose "All IP Adressess match"
	}
}


#region ACME DNS Verification

if ((-not ($CleanNS)) -and (-not ($RemoveTestCertificates))) {
	Write-Verbose "Checking if validation is required"
	$DNSValidationRequired = $DNSObjects | Where-Object {$_.DNSValid -eq $false}
	if ($DNSValidationRequired) {
		Write-Verbose "Validation NOT required"
		$NetScalerActionsRequired = $true
	} else {
		Write-Verbose "Validation required for the following objects:`n$($DNSValidationRequired | Select-Object DNSName | Format-List | Out-String)"
		$NetScalerActionsRequired = $false
	
	}
}

#region NetScaler pre dns
	
if ((-not ($CleanNS)) -and ($NetScalerActionsRequired) -and (-not ($RemoveTestCertificates))) {
	try {
		Write-Verbose "Login to NetScaler and save session to global variable"
		$NSSession = Connect-NetScaler -ManagementURL $NSManagementURL -Credential $NSCredential -PassThru
		Write-Verbose "Enable required NetScaler Features, Load Balancer, Responder, Content Switch and SSL"
		$payload = @{"feature"="LB RESPONDER CS SSL"}
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
				Write-Host -ForeGroundColor Red "`nThe Content Switch `"$NSCsVipName`" does NOT exist!"
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
			Write-Verbose "Checking LB Service binding"
			$response = InvokeNSRestApi -Session $NSSession -Method GET -Type lbvserver_service_binding -Resource $NSLbName
			if ($response.lbvserver_service_binding.servicename -eq $NSSvcName) {
				Write-Verbose "LB Service binding is ok"
				$SvcConfigure = $True
			} else {
				$payload = @{"name"="$NSLbName";"servicename"="$NSSvcName";}
				$response = InvokeNSRestApi -Session $NSSession -Method PUT -Type lbvserver_service_binding -Payload $payload
			}
		}
		try {
			Write-Verbose "Configuring NetScaler: Check if Responder Action exists"
			$response = InvokeNSRestApi -Session $NSSession -Method GET -Type responderaction -Resource $NSRsaName
			try {
				Write-Verbose "Yep it exists, continuing"
				Write-Verbose "Configuring NetScaler: Change Responder Action to default values"
				$payload = @{"name"="$NSRsaName";"target"='"HTTP/1.0 200 OK" +"\r\n\r\n" + "XXXX"';}
				$response = InvokeNSRestApi -Session $NSSession -Method POST -Type responderaction -Payload $payload -Action set
			} catch {
				throw "Something went wrong with reconfiguring the existing action `"$NSRsaName`", exiting now..."
			}	
		} catch {
			$payload = @{"name"="$NSRsaName";"type"="respondwith";"target"='"HTTP/1.0 200 OK" +"\r\n\r\n" + "XXXX"';}
			$response = InvokeNSRestApi -Session $NSSession -Method POST -Type responderaction -Payload $payload -Action add
		}
		try { 
			Write-Verbose "Configuring NetScaler: Check if Responder Policy exists"
			$response = InvokeNSRestApi -Session $NSSession -Method GET -Type responderpolicy -Resource $NSRspName
			try {
				Write-Verbose "Yep it exists, continuing"
				Write-Verbose "Configuring NetScaler: Change Responder Policy to default values"
				$payload = @{"name"="$NSRspName";"action"="rsa_letsencrypt";"rule"='HTTP.REQ.URL.CONTAINS(".well-known/acme-challenge/XXXX")';}
				$response = InvokeNSRestApi -Session $NSSession -Method POST -Type responderpolicy -Payload $payload -Action set

			} catch {
				throw "Something went wrong with reconfiguring the existing policy `"$NSRspName`", exiting now..."
			}	
		} catch {
			$payload = @{"name"="$NSRspName";"action"="$NSRsaName";"rule"='HTTP.REQ.URL.CONTAINS(".well-known/acme-challenge/XXXX")';}
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
	} catch {
		Write-Verbose "Error Details: $($_.Exception.Message)"
		throw "ERROR: Could not configure the NetScaler, exiting now"
	}
	Start-Sleep -Seconds 2
}

#endregion NetScaler pre dns

#region Test NS CS

if ((-not ($CleanNS)) -and ($NetScalerActionsRequired) -and (-not ($RemoveTestCertificates))) {
	Write-Host -ForeGroundColor White "Executing some tests, can take a couple of seconds/minutes..."
	Write-Host -ForeGroundColor Yellow "`r`nPlease note that if a test fails, the script still tries to continue!`r`n"
	ForEach ($DNSObject in $DNSObjects ) {
		Write-Host -ForeGroundColor White -NoNewLine " -Checking: => "
		Write-Host -ForeGroundColor Yellow "`"$($DNSObject.DNSName)`" ($($DNSObject.IPAddress))"
		$TestURL = "http://$($DNSObject.DNSName)/.well-known/acme-challenge/XXXX"
		Write-Verbose "Testing if the Content Switch is available on `"$TestURL`" (via internal DNS)"
		try {
			Write-Verbose "Retreiving data"
			$Result = Invoke-WebRequest -URI $TestURL -TimeoutSec 2
			Write-Verbose "Success, output: $($Result| Out-String)"
		} catch {
			$Result = $null
			Write-Verbose "Internal check failed, error Details: $($_.Exception.Message)"
		}
		if ($Result.RawContent -eq "HTTP/1.0 200 OK" + "`r`n`r`n" + "XXXX") {
			Write-Host -ForeGroundColor White -NoNewLine " -Test (Int. DNS): "
			Write-Host -ForeGroundColor Green "OK"
		} else {
			Write-Host -ForeGroundColor White -NoNewLine " -Test (Int. DNS): "
			Write-Host -ForeGroundColor Yellow "Not successfull, maybe not resolvable internally?"
			Write-Verbose "Output: $($Result| Out-String)"
		}
		
		try {
			Write-Verbose "Checking if Public IP is available for external DNS testing"
			[ref]$ValidIP = [ipaddress]::None
			if (([ipaddress]::TryParse("$($DNSObject.IPAddress)",$ValidIP)) -and (-not ($DisableIPCheck))) {
				Write-Verbose "Testing if the Content Switch is available on `"$TestURL`" (via external DNS)"
				$TestURL = "http://$($DNSObject.IPAddress)/.well-known/acme-challenge/XXXX"
				$Headers = @{"Host"="$($DNSObject.DNSName)"}
				Write-Verbose "Retreiving data"
				$Result = Invoke-WebRequest -URI $TestURL -Headers $Headers -TimeoutSec 2
				Write-Verbose "Success, output: $($Result| Out-String)"
			} else {
				Write-Verbose "Public IP is not available for external DNS testing"
			}
		} catch {
			$Result = $null
			Write-Verbose "External check failed, error Details: $($_.Exception.Message)"
		}
		[ref]$ValidIP = [ipaddress]::None
		if (([ipaddress]::TryParse("$($DNSObject.IPAddress)",$ValidIP)) -and (-not ($DisableIPCheck))) {
			if ($Result.RawContent -eq "HTTP/1.0 200 OK" + "`r`n`r`n" + "XXXX") {
				Write-Host -ForeGroundColor White -NoNewLine " -Test (Ext. DNS): "
				Write-Host -ForeGroundColor Green "OK"
			} else {
				Write-Host -ForeGroundColor White -NoNewLine " -Test (Ext. DNS): "
				Write-Host -ForeGroundColor Yellow "Not successfull, maybe not resolvable externally?"
				Write-Verbose "Output: $($Result| Out-String)"
			}
		}
	}
	Write-Host -ForeGroundColor White "`r`nFinished the tests, script will continue again."
}

#endregion Test NS CS

#region DNS Check

if ((-not ($CleanNS)) -and (-not ($RemoveTestCertificates))) {
	Write-Verbose "Check if DNS Records need to be validated"
	Write-Host -ForeGroundColor White "Verification:"
	foreach ($DNSObject in $DNSObjects) {
		$DNSRecord = $DNSObject.DNSName
		$Challenge = $null
		$UpdateIdentifier = $null
		Write-Verbose "Checking validation for `"$DNSRecord`""
		if ($DNSObject.DNSValid){
			Write-Host -ForeGroundColor White -NoNewLine " -DNS: "
			Write-Host -ForeGroundColor Green "`"$DNSRecord`""
			Write-Host -ForeGroundColor White -NoNewLine " -Status: "
			Write-Host -ForeGroundColor Green "=> Still valid"
		} else {
			Write-Verbose "New validation required, Start verifying"
			$IdentifierAlias = $DNSObject.Alias
			try {
				try {
					$CompletedChallenge = ACMESharp\Complete-ACMEChallenge -IdentifierRef $IdentifierAlias -ChallengeType http-01 -Handler manual -VaultProfile $VaultName -Force
					if ($([datetime]$CompletedChallenge.Expires - $(Get-Date)).TotalDays -gt 1) {
						$Challenge = ($CompletedChallenge.Challenges | Where-Object { $_.Type -eq "http-01" }).Challenge
					} else {
						
					}
				} catch {
					Write-Verbose "Error Details: $($_.Exception.Message)"
					throw "Error while creating the Challenge"
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
					$SubmittedChallenge = ACMESharp\Submit-ACMEChallenge -IdentifierRef $IdentifierAlias -ChallengeType http-01 -VaultProfile $VaultName
				} catch {
					Write-Verbose "Error Details: $($_.Exception.Message)"
					throw "Error while submitting the Challenge"
				}
				Write-Verbose "Retreiving validation status"
				try {
					$UpdateIdentifier = (ACMESharp\Update-ACMEIdentifier -IdentifierRef $IdentifierAlias -ChallengeType http-01 -VaultProfile $VaultName).Challenges | Where-Object {$_.Type -eq "http-01"}
				} catch {
					Write-Verbose "Error Details: $($_.Exception.Message)"
					throw "Error while retreiving validation status"
				}
				$i = 0
				Write-Host -ForeGroundColor White -NoNewLine " -DNS: "
				Write-Host -ForeGroundColor Green "`"$DNSRecord`""
				Write-Host -ForeGroundColor White -NoNewLine " -Status: "
				while(-NOT ($UpdateIdentifier.Status.ToLower() -eq "valid")) {
					Write-Host -ForeGroundColor Yellow -NoNewLine "="
					$i++
					Write-Verbose "($($i.ToString())) $DNSRecord is not (yet) validated, Wait 2 second"
					Start-Sleep -Seconds 2
					Write-Verbose "Retreiving validation status"
					try {
						$UpdateIdentifier = (ACMESharp\Update-ACMEIdentifier -IdentifierRef $IdentifierAlias -ChallengeType http-01 -VaultProfile $VaultName).Challenges | Where-Object {$_.Type -eq "http-01"}
					} catch {
						Write-Verbose "Error Details: $($_.Exception.Message)"
						throw "Error while retreiving validation status"
					}
					if (($i -ge 60) -or ($UpdateIdentifier.Status.ToLower() -eq "invalid")) {break}
				}
				switch ($UpdateIdentifier.Status.ToLower()) {
					"pending" {
						Write-Host -ForeGroundColor Red "ERROR"
						throw "It took to long for the validation ($DNSRecord) to complete, exiting now."
					}
					"invalid" {
						Write-Host -ForeGroundColor Red "ERROR"
						throw "Validation for `"$DNSRecord`" is invalid! Exiting now."
					}
					"valid" {
						Write-Host -ForeGroundColor Green "> validated successfully"
					}
					default {
						Write-Host -ForeGroundColor Red "ERROR"
						throw "Unexpected status for `"$DNSRecord`" is `"$($UpdateIdentifier.Status)`", exiting now."
					}
				}
			} catch {
				Write-Verbose "Error Details: $($_.Exception.Message)"
				throw "Error while verifying `"$DNSRecord`", exiting now"
			}
		}
	}
	"`r`n"
}

#endregion DNS Check

#region NetScaler post DNS

if (($NetScalerActionsRequired) -or ($CleanNS) -and (-not ($RemoveTestCertificates))) {
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
	
if ((-not ($CleanNS)) -and (-not ($RemoveTestCertificates))) {
	$SANs = $DNSObjects | Where-Object {$_.SAN -eq $true}
	$IdentifierAlias = $DNSObjects[0].Alias
	try {
		$CertificateAlias = "CRT-SAN-$SessionDateTime-$CN"
		if ($SANs) {
			Write-Verbose "Get certificate with SANs"
			Write-Verbose "Domain:`n$($DNSObjects[0] | Select-Object DNSName,Alias | Format-List | Out-String)"
			Write-Verbose "Subject Alternative Names:`n$(@($SANs) | Select-Object DNSName,Alias | Format-List | Out-String)"
			$NewCertificate = ACMESharp\New-ACMECertificate $IdentifierAlias `
				-AlternativeIdentifierRefs @($SANs.Alias) `
				-Alias $CertificateAlias `
				-Generate `
				-VaultProfile $VaultName
		} else {
			Write-Verbose "Get single DNS Name certificate"
			Write-Verbose "Domain:`n$($($DNSObjects[0].DNSName) | fl * | Out-String)"
			$NewCertificate = ACMESharp\New-ACMECertificate $IdentifierAlias `
				-Alias $CertificateAlias `
				-Generate `
				-VaultProfile $VaultName
		}
		Write-Verbose "Submit Certificate request"
		$SubmittedCertificate = ACMESharp\Submit-ACMECertificate $CertificateAlias -VaultProfile $VaultName
	} catch {
		throw "ERROR. Certificate completion failed, details: $($_.Exception.Message | Out-String)"
	}
	$i = 0
	while (-not (ACMESharp\Update-ACMECertificate $CertificateAlias -VaultProfile $VaultName | select IssuerSerialNumber)) {
		$i++
		$imax = 120
		if ($i -ge $imax) {
			throw "Error: Retreiving certificate failed, took to long to complete"
		}
		Write-Host "Will continue $(($imax-$i)*2) more seconds for the certificate to come available..."
		Start-Sleep -seconds 2
	}
	
	$CertificateDirectory = Join-Path -Path $CertDir -ChildPath $CertificateAlias
	Write-Verbose "Create directory `"$CertificateDirectory`" for storing the new certificates"
	$output = New-Item $CertificateDirectory -ItemType directory -force
	if (Test-Path $CertificateDirectory){
		if ($Production){
			$CertificateName = "$($ScriptDateTime.ToString("yyyyMMdd"))-$cn"
			Write-Verbose "Writing production certificates"
			$IntermediateCACertKeyName = "Lets Encrypt Authority X3-int"
			$IntermediateCAFileName = "$($IntermediateCACertKeyName).crt"
			$IntermediateCAFullPath = Join-Path -Path $CertificateDirectory -ChildPath $IntermediateCAFileName
			$IntermediateCASerial = "0a0141420000015385736a0b85eca708"
		} else {
			$CertificateName = "$($ScriptDateTime.ToString("yyyyMMddHHmm"))-$cn"
			Write-Verbose "Writing test/staging certificates"
			$IntermediateCACertKeyName = "Fake LE Intermediate X1-int"
			$IntermediateCAFileName = "$($IntermediateCACertKeyName).crt"
			$IntermediateCAFullPath = Join-Path -Path $CertificateDirectory -ChildPath $IntermediateCAFileName
			$IntermediateCASerial = "8be12a0e5944ed3c546431f097614fe5"
		}
		Write-Verbose "Intermediate: `"$IntermediateCAFileName`""
		ACMESharp\Get-ACMECertificate $CertificateAlias -ExportIssuerPEM $IntermediateCAFullPath -VaultProfile $VaultName | Out-Null
		
		if ($Production){
			$CertificateName = "$($CertificateName.subString(0,31))"
			$CertificateFileName = "$($CertificateAlias.subString(0,59)).crt"
			$CertificateKeyFileName = "$($CertificateAlias.subString(0,59)).key"
			$CertificatePfxFileName = "$CertificateAlias.pfx"
		} else {
			$CertificateName = "TST-$($CertificateName.subString(0,27))"
			$CertificateFileName = "TST-$($CertificateAlias.subString(0,55)).crt"
			$CertificateKeyFileName = "TST-$($CertificateAlias.subString(0,55)).key"
			$CertificatePfxFileName = "TST-$CertificateAlias.pfx"
		}
		Write-Verbose "CertificateName: `"$CertificateName`" ($($CertificateName.length) max 31)"
		
		$CertificateFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificateFileName
		Write-Verbose "Certificate: `"$CertificateFileName`" ($($CertificateFileName.length) max 63)"
		ACMESharp\Get-ACMECertificate $CertificateAlias -ExportCertificatePEM $CertificateFullPath -VaultProfile $VaultName | Out-Null
		$CertificateKeyFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificateKeyFileName
		Write-Verbose "Key: `"$CertificateKeyFileName`"($($CertificateFileName.length) max 63)"
		ACMESharp\Get-ACMECertificate $CertificateAlias -ExportKeyPEM $CertificateKeyFullPath -VaultProfile $VaultName | Out-Null
		$CertificatePfxFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificatePfxFileName 
		if ($PfxPassword){
			Write-Verbose "PFX: `"$CertificatePfxFileName`" ($($CertificatePfxFileName.length))"
			ACMESharp\Get-ACMECertificate $CertificateAlias -ExportPkcs12 "$CertificatePfxFullPath" -CertificatePassword "$PfxPassword" -VaultProfile $VaultName | Out-Null
		} else {
			try {
				$length=15
				$Assembly = Add-Type -AssemblyName System.Web
				$PfxPassword = [System.Web.Security.Membership]::GeneratePassword($length,2)
				Write-Warning "No Password was specified, so a random password was generated!"
				
				Write-Host -ForeGroundColor Yellow "`n***********************"
				Write-Host -ForeGroundColor Yellow "*   PFX Password:     *"
				Write-Host -ForeGroundColor Yellow "*                     *"
				Write-Host -ForeGroundColor Yellow "*   $PfxPassword   *"
				Write-Host -ForeGroundColor Yellow "*                     *"
				Write-Host -ForeGroundColor Yellow "***********************`n"
				ACMESharp\Get-ACMECertificate $CertificateAlias -ExportPkcs12 "$CertificatePfxFullPath" -CertificatePassword "$PfxPassword" -VaultProfile $VaultName | Out-Null
			} catch {
				Write-Verbose "An error occured while generating a Password."
			}
		}
	}
}

#endregion Certificates

#region Upload certificates to NetScaler

if ((-not ($CleanNS)) -and (-not ($RemoveTestCertificates))) {
	try {
		Write-Verbose "Retreiving existing certificates"
		$CertDetails = InvokeNSRestApi -Session $NSSession -Method GET -Type sslcertkey
		Write-Verbose "Checking if IntermediateCA `"$IntermediateCACertKeyName`" already exists"
		if ($ns10x) {
			$IntermediateCADetails = $CertDetails.sslcertkey | Where-Object {$_.cert -match $IntermediateCAFileName}
		} else {
			$IntermediateCADetails = $CertDetails.sslcertkey | Where-Object {$_.serial -eq $IntermediateCASerial}
		}
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
		} else {
			$CertificateCertKeyName = $CertificateName
			$ExistingCertificateDetails = $CertDetails.sslcertkey | Where-Object {$_.certkey -eq $CertificateCertKeyName}
			if ($ExistingCertificateDetails) {
				Write-Warning "Certificate `"$CertificateCertKeyName`" already exists, please update manually"
				exit(1)
			}
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
			$payload = @{"certkey"="$CertificateCertKeyName";"cert"="$($CertificateFileName)";"key"="$($CertificateKeyFileName)"}
			$response = InvokeNSRestApi -Session $NSSession -Method POST -Type sslcertkey -Payload $payload -Action update
			Write-Verbose "Succeeded"
	
		} else {
			Write-Verbose "Add the certificate and key to the NetScaler config"
			$payload = @{"certkey"="$CertificateCertKeyName";"cert"="$($CertificateFileName)";"key"="$($CertificateKeyFileName)"}
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

#region Remove Test Certificates

if ((-not ($CleanNS)) -and $RemoveTestCertificates) {
	Write-Verbose "Login to NetScaler and save session to global variable"
	$NSSession = Connect-NetScaler -ManagementURL $NSManagementURL -Credential $NSCredential -PassThru
	$IntermediateCACertKeyName = "Fake LE Intermediate X1"
	$IntermediateCASerial = "8be12a0e5944ed3c546431f097614fe5"
	Write-Verbose "Retreiving existing certificates"
	$CertDetails = InvokeNSRestApi -Session $NSSession -Method GET -Type sslcertkey
	Write-Verbose "Checking if IntermediateCA `"$IntermediateCACertKeyName`" already exists"
	if ($ns10x) {
		$IntermediateCADetails = $CertDetails.sslcertkey | Where-Object {$_.cert -match $IntermediateCAFileName}
	} else {
		$IntermediateCADetails = $CertDetails.sslcertkey | Where-Object {$_.serial -eq $IntermediateCASerial}
	}
	$LinkedCertificates = $CertDetails.sslcertkey | Where-Object {$_.linkcertkeyname -eq $IntermediateCADetails.certkey}
	Write-Verbose "The following certificates were found:`n$($LinkedCertificates | Select-Object certkey,linkcertkeyname,serial | Format-List | Out-String)"
	ForEach ($LinkedCertificate in $LinkedCertificates) {
		$payload = @{"certkey"="$($LinkedCertificate.certkey)";}
		try {
			$response = InvokeNSRestApi -Session $NSSession -Method POST -Type sslcertkey -Payload $payload -Action unlink
			Write-Host -NoNewLine "NetScaler, unlinked: "
			Write-Host -ForeGroundColor Green "$($LinkedCertificate.certkey)"
		} catch {
			Write-Warning "Could not unlink certkey `"$($LinkedCertificate.certkey)`""
		}
	}
	$FakeCerts = $CertDetails.sslcertkey | Where-Object {$_.issuer -match $IntermediateCACertKeyName}
	ForEach ($FakeCert in $FakeCerts) {
		try {
			$response = InvokeNSRestApi -Session $NSSession -Method DELETE -Type sslcertkey -Resource $($FakeCert.certkey)
			Write-Host -NoNewLine "NetScaler, removing: "
			Write-Host -ForeGroundColor Green "$($FakeCert.certkey)"
		} catch {
			Write-Warning "Could not delete certkey `"$($FakeCert.certkey)`" from the netscaler"
		}
		$CertFilePath = (split-path $($FakeCert.cert) -Parent).Replace("\","/")
		if ([string]::IsNullOrEmpty($CertFilePath)) {
			$CertFilePath = "/nsconfig/ssl/"
		}
		$CertFileName = split-path $($FakeCert.cert) -Leaf
		Write-Host -NoNewLine "NetScaler, deleted: "
		Write-Host -ForeGroundColor Green "$(Join-Path -Path $CertFilePath -ChildPath $CertFileName)"
		$KeyFilePath = (split-path $($FakeCert.key) -Parent).Replace("\","/")
		if ([string]::IsNullOrEmpty($KeyFilePath)) {
			$KeyFilePath = "/nsconfig/ssl/"
		}
		$KeyFileName = split-path $($FakeCert.key) -Leaf
		Write-Host -NoNewLine "NetScaler, deleted: "
		Write-Host -ForeGroundColor Green "$(Join-Path -Path $KeyFilePath -ChildPath $KeyFileName)"
		$Arguments = @{"filelocation"="$CertFilePath";}
		try {
			$response = InvokeNSRestApi -Session $NSSession -Method DELETE -Type systemfile -Resource $CertFileName -Arguments $Arguments
		} catch {
			Write-Warning "Could not delete file: `"$CertFileName`" from location: `"$CertFilePath`""
		}
		$Arguments = @{"filelocation"="$KeyFilePath";}
		try {
			$response = InvokeNSRestApi -Session $NSSession -Method DELETE -Type systemfile -Resource $KeyFileName -Arguments $Arguments
		} catch {
			Write-Warning "Could not delete file: `"$KeyFileName`" from location: `"$KeyFilePath`""
		}
		
	}
	$Arguments = @{"filelocation"="/nsconfig/ssl";}
	$CertFiles = InvokeNSRestApi -Session $NSSession -Method Get -Type systemfile -Arguments $Arguments
	$CertFilesToRemove = $CertFiles.systemfile | Where-Object {$_.filename -match "TST-"}
	ForEach ($CertFileToRemove in $CertFilesToRemove) {
		$Arguments = @{"filelocation"="$($CertFileToRemove.filelocation)";}
		try {
		Write-Host -NoNewLine "File deleted: "
		$response = InvokeNSRestApi -Session $NSSession -Method DELETE -Type systemfile -Resource $($CertFileToRemove.filename) -Arguments $Arguments
		Write-Host -ForeGroundColor Green "$($CertFileToRemove.filename)"
		} catch {
			Write-Host -ForeGroundColor Red "$($CertFileToRemove.filename) (Error, not removed)"
			Write-Warning "Could not delete file: `"$($CertFileToRemove.filename)`" from location: `"$($CertFileToRemove.filelocation)`""
		}
	}
}

#endregion Remove Test Certificates
