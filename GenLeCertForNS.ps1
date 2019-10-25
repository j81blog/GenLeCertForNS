<#
.SYNOPSIS
    Create a new or update an existing Let's Encrypt certificate for one or more domains and add it to a store then update the SSL bindings for a ADC
.DESCRIPTION
    The script will utilize Posh-ACME to create a new or update an existing certificate for one or more domains. If generated successfully the script will add the certificate to the ADC and update the SSL binding for a web site. This script is for use with a Citrix ADC (v11.x and up). The script will validate the dns records provided. For example, the domain(s) listed must be configured with the same IP Address that is configured (via NAT) to a Content Switch. Or Use DNS verification if a WildCard domain was specified.
.PARAMETER Help
    Display the detailed information about this script
.PARAMETER CleanADC
    Clean-up the ADC configuration made within this script, for when somewhere it gone wrong
.PARAMETER RemoveTestCertificates
    Remove all the Test/Staging certificates signed by the "Fake LE Intermediate X1" staging intermediate
.PARAMETER ManagementURL
    Management URL, used to connect to the ADC
.PARAMETER Username
    ADC Username with enough access to configure it
.PARAMETER Password
    ADC Username password
.PARAMETER Credential
    Use a PSCredential object instead of a Username or password. Use "Get-Credential" to generate a credential object
    C:\PS> $Credential = Get-Credential
.PARAMETER NSCsVipName
    Name of the HTTP ADC Content Switch used for the domain validation
.PARAMETER NSCsVipBinding
    ADC Content Switch binding used for the validation
    Default: 11
.PARAMETER NSSvcName
    ADC Load Balance service name
    Default "svc_letsencrypt_cert_dummy"
.PARAMETER NSSvcDestination
    IP Address used for the ADC Service (leave default 1.2.3.4, only change when already used
.PARAMETER NSLbName
    ADC Load Balance VIP name
    Default: "lb_letsencrypt_cert"
.PARAMETER NSRspName
    ADC Responder Policy name
    Default: "rsp_letsencrypt"
.PARAMETER NSRsaName
    ADC Responder Action name
    Default: "rsa_letsencrypt"
.PARAMETER NSCspName
    ADC Content Switch Policy name
    Default: "csp_NSCertCsp"
.PARAMETER NSCertNameToUpdate
    ADC SSL Certkey name currently in use, that needs to be renewed
.PARAMETER CertDir
    Directory where to store the certificates
.PARAMETER PfxPassword
    Specify a password for the PFX certificate, if not specified a new password is generated at the end
.PARAMETER KeyLength
    Specify the KeyLength of the new to be generated certificate
    Default: 2048
.PARAMETER EmailAddress
    The email address used to request the certificates and receive a notification when the certificates (almost) expires
.PARAMETER GetValuesFromExistingCertificate
    Set this switch to extract the CommonName (ad if present also the SAN records) from an existing certificate already present on the Citrix ADC.
    If you set this switch -ExistingCertificateName must also be configured.
.PARAMETER ExistingCertificateName
    The name of an existing certificate on the ADC. Us the CertKeyName (Name visible in the GUI, not the filename)
.PARAMETER CN
    (Common Name) The Primary (first) dns record for the certificate
    Example: "domain.com"
.PARAMETER SAN
    (Subject Alternate Name) every following domain listed in this certificate. separated via an comma , and between quotes "".
    Example: "sts.domain.com","www.domain.com","vpn.domain.com"
    Example Wildcard: "*.domain.com","*.pub.domain.com"
    NOTE: Only a DNS verification is possible when using WildCards!
.PARAMETER FriendlyName
    The displayname of the certificate, if not specified the CN will used. You can specify an empty value if required.
    Example (Empty display name) : ""
    Example (Set your own name) : "Custom Name"
.PARAMETER Production
    Use the production Let's encryt server, without this parameter the staging (test) server will be used
.PARAMETER DisableIPCheck
    If you want to skip the IP Address verification, specify this parameter
.PARAMETER CleanPoshACMEStorage
    Force cleanup of the Posh-Acme certificates located in "%LOCALAPPDATA%\Posh-ACME"
.PARAMETER SaveNSConfig
    Save the ADC config after all the changes
.PARAMETER EnableLogging
    Start logging to file. The name of the logfile can be specified with the "-LogLocation" parameter
.PARAMETER LogLocation
    Specify the logfile name, default "<Current Script Dir>\GenLeCertForNS_log.txt"
.EXAMPLE
    .\GenLeCertForNS.ps1 -CN "domain.com" -EmailAddress "hostmaster@domain.com" -SAN "sts.domain.com","www.domain.com","vpn.domain.com" -PfxPassword "P@ssw0rd" -CertDir "C:\Certificates" -ManagementURL "http://192.168.100.1" -NSCsVipName "cs_domain.com_http" -Password "P@ssw0rd" -Username "nsroot" -NSCertNameToUpdate "san_domain_com" -Production -Verbose
    Generate a (Production) certificate for hostname "domain.com" with alternate names : "sts.domain.com, www.domain.com, vpn.domain.com". Using the email address "hostmaster@domain.com". At the end storing the certificates  in "C:\Certificates" and uploading them to the ADC. The Content Switch "cs_domain.com_http" will be used to validate the certificates.
.EXAMPLE
    .\GenLeCertForNS.ps1 -CN "domain.com" -EmailAddress "hostmaster@domain.com" -SAN "*.domain.com","*.test.domain.com" -PfxPassword "P@ssw0rd" -CertDir "C:\Certificates" -ManagementURL "http://192.168.100.1" -Password "P@ssw0rd" -Username "nsroot" -NSCertNameToUpdate "san_domain_com" -Production -Verbose
    Generate a (Production) Wildcard (*) certificate for hostname "domain.com" with alternate names : "*.domain.com, *.test.domain.com. Using the email address "hostmaster@domain.com". At the end storing the certificates  in "C:\Certificates" and uploading them to the ADC.
    NOTE: Only a DNS verification is possible when using WildCards!
.EXAMPLE
    .\GenLeCertForNS.ps1 -CleanADC -ManagementURL "http://192.168.100.1" -NSCsVipName "cs_domain.com_http" -Password "P@ssw0rd" -Username "nsroot" -Verbose
    Cleaning left over configuration from this script when something went wrong during a previous attempt to generate new certificates and generating Verbose output.
.EXAMPLE
    .\GenLeCertForNS.ps1 -RemoveTestCertificates -ManagementURL "http://192.168.100.1" -Password "P@ssw0rd" -Username "nsroot" -Verbose
    Removing ALL the test certificates from your ADC.
.NOTES
    File Name : GenLeCertForNS.ps1
    Version   : v2.4.1
    Author    : John Billekens
    Requires  : PowerShell v5.1 and up
                ADC 11.x and up
                Run As Administrator
                Posh-ACME 3.8.0 (Will be installed via this script) Thank you @rmbolger for providing the HTTP validation method!
                Microsoft .NET Framework 4.7.1 or later (when using Posh-ACME/WildCard certificates)
.LINK
    https://blog.j81.nl
#>

[cmdletbinding(DefaultParameterSetName = "LECertificates")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword','')]
param(
    [Parameter(ParameterSetName = "Help", Mandatory = $true)]
    [alias("h")]
    [switch]$Help,
    
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $true)]
    [alias("CleanNS")]
    [switch]$CleanADC,

    [Parameter(ParameterSetName = "GetExisting", Mandatory = $true)]
    [switch]$GetValuesFromExistingCertificate,

    [Parameter(ParameterSetName = "GetExisting", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ExistingCertificateName,

    [Parameter(ParameterSetName = "CleanTestCertificate", Mandatory = $true)]
    [switch]$RemoveTestCertificates,
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanTestCertificate", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanPoshACMEStorage", Mandatory = $true)]
    [switch]$CleanPoshACMEStorage,
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $true)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $true)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $true)]
    [Parameter(ParameterSetName = "CleanTestCertificate", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [alias("URL","NSManagementURL")]
    [string]$ManagementURL,
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanTestCertificate", Mandatory = $false)]
    [alias("User", "NSUsername")]
    [string]$Username,
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanTestCertificate", Mandatory = $false)]
    [ValidateScript( {
            if ($_ -is [SecureString]) {
                return $true
            } elseif ($_ -is [string]) {
                $Script:Password = ConvertTo-SecureString -String $_ -AsPlainText -Force
                return $true
            } else {
                throw "You passed an unexpected object type for the credential (-Password)"
            }
        })][alias("NSPassword")]
    [object]$Password,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanTestCertificate", Mandatory = $false)]
    [ValidateScript( {
            if ($_ -is [System.Management.Automation.PSCredential]) {
                return $true
            } elseif ($_ -is [string]) {
                $Script:Credential = Get-Credential -Credential $_
                return $true
            } else {
                throw "You passed an unexpected object type for the credential (-Credential)"
            }
        })][alias("NSCredential")]
    [object]$Credential,
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CN,
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [string[]]$SAN = @(),
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [string]$FriendlyName = $CN,
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [ValidateSet(
        'http',
        'dns',
        ignorecase = $true
    )][string]$ValidationMethod = "http",

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [string]$NSCsVipName,
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [string]$NSCsVipBinding = 11,
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [string]$NSSvcName = "svc_letsencrypt_cert_dummy",
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [string]$NSSvcDestination = "1.2.3.4",
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [string]$NSLbName = "lb_letsencrypt_cert",
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [string]$NSRspName = "rsp_letsencrypt",
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [string]$NSRsaName = "rsa_letsencrypt",
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [string]$NSCspName = "csp_NSCertCsp",
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [string]$NSCertNameToUpdate,
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $true)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CertDir,
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [string]$PfxPassword = $null,
            
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [ValidateScript( {
            if ($_ -lt 2048 -or $_ -gt 4096 -or ($_ % 128) -ne 0) {
                throw "Unsupported RSA key size. Must be 2048-4096 in 8 bit increments."
            } else {
                $true
            }
        })][int32]$KeyLength = 2048,    
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $true)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $true)]
    [string]$EmailAddress,
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [switch]$DisableIPCheck,
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [switch]$SaveNSConfig,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableLogging,

    [ValidateNotNullOrEmpty()]
    [string]$LogLocation = "$PSScriptRoot\GenLeCertForNS_log.txt",
    
    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [switch]$Production
    
)

#requires -version 5.1
#requires -runasadministrator
$ScriptVersion = "v2.4.1"

#region Functions

function Invoke-ADCRestApi {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSObject]$Session,

        [Parameter(Mandatory = $true)]
        [ValidateSet('DELETE', 'GET', 'POST', 'PUT')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Type,

        [string]$Resource,

        [string]$Action,

        [hashtable]$Arguments = @{},

        [switch]$Stat = $false,

        [ValidateScript( {$Method -eq 'GET'})]
        [hashtable]$Filters = @{},

        [ValidateScript( {$Method -ne 'GET'})]
        [hashtable]$Payload = @{},

        [switch]$GetWarning = $false,

        [ValidateSet('EXIT', 'CONTINUE', 'ROLLBACK')]
        [string]$OnErrorAction = 'EXIT'
    )
    # https://github.com/devblackops/NetScaler
    if ([string]::IsNullOrEmpty($($Session.ManagementURL))) {
        throw "ERROR. Probably not logged into the ADC"
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
            Uri           = $uri
            ContentType   = 'application/json'
            Method        = $Method
            WebSession    = $Session.WebSession
            ErrorVariable = 'restError'
            Verbose       = $false
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
    } catch [Exception] {
        if ($Type -eq 'reboot' -and $restError[0].Message -eq 'The underlying connection was closed: The connection was closed unexpectedly.') {
            Write-Verbose -Message 'Connection closed due to reboot'
        } else {
            throw $_
        }
    }
}

function Connect-ADC {
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        [string]$ManagementURL,

        [parameter(Mandatory)]
        [pscredential]$Credential,

        [int]$Timeout = 3600,

        [switch]$PassThru
    )
    # https://github.com/devblackops/NetScaler

    function Ignore-SSLCertificates {
        $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
        $Provider.CreateCompiler() | Out-Null
        $Params = New-Object System.CodeDom.Compiler.CompilerParameters
        $Params.GenerateExecutable = $false
        $Params.GenerateInMemory = $true
        $Params.IncludeDebugInformation = $false
        $Params.ReferencedAssemblies.Add("System.DLL") > $null
        $TASource=@'
            namespace Local.ToolkitExtensions.Net.CertificatePolicy
            {
                public class TrustAll : System.Net.ICertificatePolicy
                {
                    public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                    {
                        return true;
                    }
                }
            }
'@ 
        $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
        $TAAssembly=$TAResults.CompiledAssembly
        $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
        [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
    }
	if ($ManagementURL -like "https://*") {
        Write-Verbose "SSL Connection"
        Ignore-SSLCertificates
	}
    Write-Verbose -Message "Connecting to $ManagementURL..."
    try {
        $login = @{
            login = @{
                Username = $Credential.Username;
                password = $Credential.GetNetworkCredential().Password
                timeout  = $Timeout
            }
        }
        $loginJson = ConvertTo-Json -InputObject $login
        Write-Verbose "JSON Data:`n$($loginJson | Out-String)"
        $saveSession = @{}
        $params = @{
            Uri             = "$ManagementURL/nitro/v1/config/login"
            Method          = 'POST'
            Body            = $loginJson
            SessionVariable = 'saveSession'
            ContentType     = 'application/json'
            ErrorVariable   = 'restError'
            Verbose         = $false
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
        ManagementURL = [string]$ManagementURL;
        WebSession    = [Microsoft.PowerShell.Commands.WebRequestSession]$saveSession;
        Username      = $Credential.Username;
        Version       = "UNKNOWN";
    }

    try {
        Write-Verbose -Message "Trying to retreive the ADC version"
        $params = @{
            Uri           = "$ManagementURL/nitro/v1/config/nsversion"
            Method        = 'GET'
            WebSession    = $Session.WebSession
            ContentType   = 'application/json'
            ErrorVariable = 'restError'
            Verbose       = $false
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
    
    if ($PassThru) {
        return $session
    }
}
function ConvertTo-TxtValue([string]$KeyAuthorization) {
    $keyAuthBytes = [Text.Encoding]::UTF8.GetBytes($KeyAuthorization)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    $keyAuthHash = $sha256.ComputeHash($keyAuthBytes)
    $base64 = [Convert]::ToBase64String($keyAuthHash)
    $txtValue = ($base64.Split('=')[0]).Replace('+', '-').Replace('/', '_')
    return $txtValue
}

function Get-ADCCurrentCertificate {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Session,
        
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    try {
        $adcCert = Invoke-ADCRestApi -Session $Session -Method GET -Type sslcertkey -Resource $Name -ErrorAction SilentlyContinue
        $currentCert = $adcCert.sslcertkey
        Write-Verbose -Message "Certificate match: $($currentCert | Select-Object certkey,subject,status,clientcertnotbefore,clientcertnotafter | Format-List | Out-String)"
        if ($currentCert.certKey -eq $Name){
            $payload = @{"filename" = "$($currentCert.cert)"; "filelocation" = "/nsconfig/ssl/" }
            $response = Invoke-ADCRestApi -Session $Session -Method GET -Type systemfile -Arguments $payload -ErrorAction SilentlyContinue
            if (-Not ([string]::IsNullOrWhiteSpace($response.systemfile.filecontent))){
                Write-Verbose "Certificate available, getting the details"
                $content = [System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($response.systemfile.filecontent))
                $Pattern = '(?smi)^-{2,}BEGIN CERTIFICATE-{2,}.*?-{2,}END CERTIFICATE-{2,}'
                $result = [Regex]::Match($content, $Pattern)
                $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $Cert.Import([byte[]][char[]]$($result[0].Value))
                $cn = $cert.Subject.Replace("CN=","")
                Write-Verbose -Message "CN: $($cn)"
                $san = $cert.DnsNameList.Unicode
                Write-Verbose -Message "SAN: $($san)"
            } else {
                Write-Warning "Could not retreive the certificate"
            }
        } else {
            Write-Verbose "Certificate `"$Name`" not found"
        }
    } catch {
        Write-Warning "Could not retreive certificate info"
        Write-Warning "Details: $($_.Exception.Message | Out-String)"
        $cn = $null
        $san = $null
    }
    return [pscustomobject] @{
        CN = $cn
        SAN = $san
        Certificate = $Cert
    }
}

#endregion Functions

#region Script Basics

if ($EnableLogging) {
    try { Stop-Transcript } catch { }
    Start-Transcript -Path $LogLocation -IncludeInvocationHeader
    Write-Verbose "Logging is started: $LogLocation"
}

Write-Verbose "Script version: $ScriptVersion"
Write-Verbose "Script was started with the following Parameters: $($PSBoundParameters | Out-String)"

if ($GetValuesFromExistingCertificate) {
    ""
    Write-Warning "The option -GetValuesFromExistingCertificate is still BETA!"
    ""
}

#endregion Script Basics

#region Help

if ($Help -or ($PSBoundParameters.Count -eq 0)) {
    Write-Verbose "Displaying the Detailed help info for: `"$PSScriptRoot\GenLeCertForNS.ps1`""
    Get-Help "$PSScriptRoot\GenLeCertForNS.ps1" -Detailed
    Exit(0)
}
#endregion Help

#region DOTNETCheck
Write-Verbose "Checking if .NET Framework 4.7.1 or higher is installed."
$NetRelease = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release).Release
if ($NetRelease -lt 461308) {
    Write-Verbose ".NET Framework 4.7.1 or higher is NOT installed."
    Write-Host -NoNewLine -ForeGroundColor RED "`n`nWARNING: "
    Write-Host ".NET Framework 4.7.1 or higher is not installed, please install before continuing!"
    Start-Process https://www.microsoft.com/net/download/dotnet-framework-runtime
    Exit (1)
} else {
    Write-Verbose ".NET Framework 4.7.1 or higher is installed."
}

#endregion DOTNETCheck

#region Script variables

Write-Verbose "ValidationMethod is set to: `"$ValidationMethod`""
$PublicDnsServer = "1.1.1.1"

Write-Verbose "Setting session DATE/TIME variable"
[datetime]$ScriptDateTime = Get-Date
[string]$SessionDateTime = $ScriptDateTime.ToString("yyyyMMdd-HHmmss")
Write-Verbose "Session DATE/TIME variable value: `"$SessionDateTime`""

if (-not $PfxPassword) {
    try {
        $length = 15
        Add-Type -AssemblyName System.Web | Out-Null
        $PfxPassword = [System.Web.Security.Membership]::GeneratePassword($length, 2)
        $PfxPasswordGenerated = $true
    } catch {
        Write-Verbose "An error occurred while generating a Password."
    }
} else {
    $PfxPasswordGenerated = $false
    Write-Verbose "PfxPassword supplied"
}

if (-not([string]::IsNullOrWhiteSpace($Credential))) {
    Write-Verbose "Using Credential"
} elseif ((-not([string]::IsNullOrWhiteSpace($Username))) -and (-not([string]::IsNullOrWhiteSpace($Password)))) {
    Write-Verbose "Using Username / Password"
    if (-not ($Password -is [securestring])) {
        [securestring]$Password = ConvertTo-SecureString -String $Password -AsPlainText -Force
    }
    [pscredential]$Credential = New-Object System.Management.Automation.PSCredential ($Username, $Password)
} else {
    Write-Verbose "No valid Username/password or credential specified. Enter a Username and password, e.g. `"nsroot`""
    [pscredential]$Credential = Get-Credential -Message "ADC Username and password:"
}
Write-Verbose "Starting new session"


#endregion Script variables

#region CleanPoshACMEStorage

$ACMEStorage = Join-Path -Path $($env:LOCALAPPDATA) -ChildPath "Posh-ACME"
if ($CleanPoshACMEStorage) {
    Write-Verbose "Removing `"$ACMEStorage`""
    Remove-Item -Path $ACMEStorage -Recurse -Force -ErrorAction SilentlyContinue
}

#endregion CleanPoshACMEStorage 

#region Load Module

if ((-not ($CleanADC)) -and (-not ($RemoveTestCertificates))) {
    $PoshACMEVersion = "3.8.0"
    Write-Verbose "Try loading the Posh-ACME v$PoshACMEVersion Modules"
    $modules = Get-Module -ListAvailable -Verbose:$false | Where-Object {($_.Name -like "*Posh-ACME*") -And ($_.Version -ge [System.Version]$PoshACMEVersion) }
    if ([string]::IsNullOrEmpty($modules)) {
        Write-Verbose "Checking for PackageManagement"
        if ([string]::IsNullOrWhiteSpace($(Get-Module -ListAvailable -Verbose:$false| Where-Object {$_.Name -eq "PackageManagement"}))) {
            Write-Warning "PackageManagement is not available please install this first or manually install Posh-ACME"
            Write-Warning "Visit `"https://docs.microsoft.com/en-us/powershell/gallery/psget/get_psget_module`" to download Package Management"
            Write-Warning "Posh-ACME: https://www.powershellgallery.com/packages/Posh-ACME/$PoshACMEVersion"
            Start-Process "https://www.powershellgallery.com/packages/Posh-ACME/$PoshACMEVersion"
            Exit (1)
        } else {
            try {
                if (-not ((Get-PackageProvider | Where-Object {$_.Name -like "*nuget*"}).Version -ge [System.Version]"2.8.5.208")) {
                    Write-Verbose "Installing Nuget"
                    Get-PackageProvider -Name NuGet -Force -ErrorAction SilentlyContinue | Out-Null
                }
                $installationPolicy = (Get-PSRepository -Name PSGallery).InstallationPolicy
                if (-not ($installationPolicy.ToLower() -eq "trusted")) {
                    Write-Verbose "Defining PSGallery PSRepository as trusted"
                    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
                }
                Write-Verbose "Installing Posh-ACME v$PoshACMEVersion"
                try {
                    Install-Module -Name Posh-ACME -Scope AllUsers -RequiredVersion $PoshACMEVersion -Force -AllowClobber
                } catch {
                    Write-Verbose "Installing Posh-ACME again but without the -AllowClobber option"
                    Install-Module -Name Posh-ACME -Scope AllUsers -RequiredVersion $PoshACMEVersion -Force
                }
                if (-not ((Get-PSRepository -Name PSGallery).InstallationPolicy -eq $installationPolicy)) {
                    Write-Verbose "Returning the PSGallery PSRepository InstallationPolicy to previous value"
                    Set-PSRepository -Name "PSGallery" -InstallationPolicy $installationPolicy | Out-Null
                }
                Write-Verbose "Try loading module Posh-ACME"
                Import-Module Posh-ACME -ErrorAction Stop
            } catch {
                Write-Verbose "Error Details: $($_.Exception.Message)"
                Write-Error "Error while loading and/or installing module"
                Write-Warning "PackageManagement is not available please install this first or manually install Posh-ACME"
                Write-Warning "Visit `"https://docs.microsoft.com/en-us/powershell/gallery/psget/get_psget_module`" to download Package Management"
                Write-Warning "Posh-ACME: https://www.powershellgallery.com/packages/Posh-ACME/$PoshACMEVersion"
                Start-Process "https://www.powershellgallery.com/packages/Posh-ACME/$PoshACMEVersion"
                Exit (1)
            }
		}
	} else {
	    Write-Verbose "v$PoshACMEVersion of Posh-ACME is installed, continuing"
        Write-Verbose "Try loading module Posh-ACME"
        Import-Module Posh-ACME -ErrorAction Stop
	}

}

#endregion Load Module

#region ADC Check

if ((-not ($CleanADC)) -and (-not ($RemoveTestCertificates))) {
    Write-Verbose "Login to ADC and save session to global variable"
    Write-Host -ForeGroundColor White "`r`nADC Info"
    $ADCSession = Connect-ADC -ManagementURL $ManagementURL -Credential $Credential -PassThru
    Write-Host -ForeGroundColor White -NoNewLine " -URL..............: "
    Write-Host -ForeGroundColor Blue "$ManagementURL"
    Write-Host -ForeGroundColor White -NoNewLine " -Username.........: "
    Write-Host -ForeGroundColor Blue "$($ADCSession.Username)"
    Write-Host -ForeGroundColor White -NoNewLine " -Password.........: "
    Write-Host -ForeGroundColor Blue "**********"
    Write-Host -ForeGroundColor White -NoNewLine " -Version..........: "
    Write-Host -ForeGroundColor Blue "$($ADCSession.Version)"
    try {
        $NSVersion = [double]$($ADCSession.version.split(" ")[1].Replace("NS", "").Replace(":", ""))
        if ($NSVersion -lt 11) {
            Write-Host -ForeGroundColor RED -NoNewLine "ERROR: "
            Write-Host -ForeGroundColor White "Only ADC version 11 and up is supported, please use an older version of this script!"
            Start-Process "https://github.com/j81blog/GenLeCertForNS/tree/master-v1-api"
            Exit (1)
        }
    } catch {
        Write-Verbose "Caught an error while retrieving the version!"
        Write-Verbose "Error Details: $($_.Exception.Message)"
    }

}

#endregion ADC Check

#region Cert Values Check

    Write-Host -ForeGroundColor White -NoNewline "`r`n -Keysize..........: "
    Write-Host -ForeGroundColor Blue "$KeyLength"

if ($GetValuesFromExistingCertificate) {
    $CurrentCertificateValues = Get-ADCCurrentCertificate -Session $ADCSession -Name $ExistingCertificateName
    Write-Verbose "Retreived the following certificate data: $($CurrentCertificateValues | Out-String)"
    if (-Not [string]::IsNullOrEmpty($($CurrentCertificateValues.CN))){
        $CN = $CurrentCertificateValues.CN
        Write-Host -ForeGroundColor White "`r`n  Got the following values from an existing certificate"
        Write-Host -ForeGroundColor White -NoNewline " -Existing CN......: "
        Write-Host -ForeGroundColor Blue $CN
        } else {
        Write-Verbose "No SAN entries received"
        Write-Error "Could not retreive CN from certificate `"$NSCertNameToUpdate`""
        EXIT (1)
    }
    if (-Not [string]::IsNullOrEmpty($($CurrentCertificateValues.SAN))) {
        $SAN = $CurrentCertificateValues.SAN
        Write-Host -ForeGroundColor White -NoNewline " -Existing SAN(s)..: "
        Write-Host -ForeGroundColor Blue "$($SAN -Join "`r`n                     ")"
    } else {
        Write-Verbose "No SAN entries received"
    }
} else {
    Write-Verbose "Retreiving values from an existing certificate was not requested"
}

if ($RemoveTestCertificates -or $CleanADC) {
    $ValidationMethod = $null
} elseif (($CN -match "\*") -or ($SAN -match "\*")) {
    Write-Host -ForeGroundColor Yellow "`r`nNOTE: -CN or -SAN contains a wildcard entry, continuing with the `"dns`" validation method!"
    Write-Host -ForeGroundColor White -NoNewline " -CN...............: "
    Write-Host -ForeGroundColor Yellow $CN
    Write-Host -ForeGroundColor White -NoNewline " -SAN(s)...........: "
    Write-Host -ForeGroundColor Yellow "$($SAN -Join ", ")"
    $ValidationMethod = "dns"
    $DisableIPCheck = $true
} else {
    $ValidationMethod = $ValidationMethod.ToLower()
    if ((-not ($RemoveTestCertificates)) -and (-not $CleanADC) -and (([string]::IsNullOrWhiteSpace($NSCsVipName)) -and ($ValidationMethod -eq "http"))) {
        Write-Host -ForeGroundColor Red "`r`nERROR: The `"-NSCsVipName`" cannot be empty!`r`n"
        Exit (1)
    }
}


$DNSObjects = @()
$DNSObjects += [PSCustomObject]@{
    DNSName   = $CN
    IPAddress = $null
    Status    = $null
    Match     = $null
    SAN       = $false
    Challenge = $null
    Done      = $false
}
if (-not ([string]::IsNullOrWhiteSpace($SAN))) {
    [string[]]$SAN = @($SAN.Split(","))
    Write-Verbose "Checking for double SAN values"
    $SANCount = $SAN.Count
    $SAN = $SAN | Select-Object -Unique
    if (-Not ($SANCount -eq $SAN.Count)){
        Write-Warning "There were $($SANCount - $SAN.Count) double SAN values, only continuing with unique ones."
    } else {
        Write-Verbose "No double SAN values found"
    }
    Foreach ($Entry in $SAN) {
        if (-Not ($Entry -eq $CN)) {
            $DNSObjects += [PSCustomObject]@{
                DNSName   = $Entry
                IPAddress = $null
                Status    = $null
                Match     = $null
                SAN       = $true
                Challenge = $null
                Done      = $false
            }
        } else {
            Write-Warning "Double record found, SAN value `"$Entry`" is the same as CN value `"$CN`". Removed double SAN entry"
        }
    }
}
Write-Verbose "DNS Data: $($DNSObjects | Select-Object DNSName,SAN | Format-List | Out-String)"

if ((-not ($CleanADC)) -and (-not ($RemoveTestCertificates))) {
    if ($ValidationMethod -eq "http") {
        try {
            Write-Verbose "Verifying Content Switch"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csvserver -Resource $NSCsVipName
        } catch {
            $ExceptMessage = $_.Exception.Message
            Write-Verbose "Error Details: $ExceptMessage"
        } finally {
            if (($response.errorcode -eq "0") -and `
                ($response.csvserver.type -eq "CONTENT") -and `
                ($response.csvserver.curstate -eq "UP") -and `
                ($response.csvserver.servicetype -eq "HTTP") -and `
                ($response.csvserver.port -eq "80") ) {
                Write-Host -ForeGroundColor White -NoNewLine " -Content Switch...: "
                Write-Host -ForeGroundColor Blue -NoNewLine "`"$NSCsVipName`""
                Write-Host -ForeGroundColor Green " (found)"
                Write-Host -ForeGroundColor White -NoNewLine " -Connection.......: "
                Write-Host -ForeGroundColor Green "OK`r`n"
            } elseif ($ExceptMessage -like "*(404) Not Found*") {
                Write-Host -ForeGroundColor White -NoNewLine " -Content Switch...: "
                Write-Host -ForeGroundColor Red "ERROR: The Content Switch `"$NSCsVipName`" does NOT exist!"
                Write-Host -ForeGroundColor White -NoNewLine "  -Error message...: "
                Write-Host -ForeGroundColor Red "`"$ExceptMessage`"`r`n"
                Write-Host -ForeGroundColor Yellow "  IMPORTANT: Please make sure a HTTP Content Switch is available`r`n"
                Write-Host -ForeGroundColor White -NoNewLine " -Connection.......: "
                Write-Host -ForeGroundColor Red "FAILED! Exiting now`r`n"
                Exit (1)
            } elseif ($ExceptMessage -like "*The remote server returned an error*") {
                Write-Host -ForeGroundColor White -NoNewLine " -Content Switch...: "
                Write-Host -ForeGroundColor Red "ERROR: Unknown error found while checking the Content Switch"
                Write-Host -ForeGroundColor White -NoNewLine "  -Error message...: "
                Write-Host -ForeGroundColor Red "`"$ExceptMessage`"`r`n"
                Write-Host -ForeGroundColor White -NoNewLine " -Connection.......: "
                Write-Host -ForeGroundColor Red "FAILED! Exiting now`r`n"
                Exit (1)
            } elseif (($response.errorcode -eq "0") -and (-not ($response.csvserver.servicetype -eq "HTTP"))) {
                Write-Host -ForeGroundColor White -NoNewLine " -Content Switch...: "
                Write-Host -ForeGroundColor Red "ERROR: Content Switch `"$NSCsVipName`" is $($response.csvserver.servicetype) and NOT HTTP"
                if (-not ([string]::IsNullOrWhiteSpace($ExceptMessage))) {
                    Write-Host -ForeGroundColor White -NoNewLine "  -Error message...: "
                    Write-Host -ForeGroundColor Red "`"$ExceptMessage`""
                }
                Write-Host -ForeGroundColor Yellow "`r`n  IMPORTANT: Please use a HTTP (Port 80) Content Switch!`r`n  This is required for the validation.`r`n"
                Write-Host -ForeGroundColor White -NoNewLine " -Connection.......: "
                Write-Host -ForeGroundColor Red "FAILED! Exiting now`r`n"
                Exit (1)
            } else {
                Write-Host -ForeGroundColor White -NoNewLine " -Content Switch...: "
                Write-Host -ForeGroundColor Green "Found"
                Write-Host -ForeGroundColor White -NoNewLine "  -State...........: "
                if ($response.csvserver.curstate -eq "UP") {
                    Write-Host -ForeGroundColor Green "UP"
                } else {
                    Write-Host -ForeGroundColor RED "$($response.csvserver.curstate)"
                }
                Write-Host -ForeGroundColor White -NoNewLine "  -Type............: "
                if ($response.csvserver.type -eq "CONTENT") {
                    Write-Host -ForeGroundColor Green "CONTENT"
                } else {
                    Write-Host -ForeGroundColor RED "$($response.csvserver.type)"
                }
                if (-not ([string]::IsNullOrWhiteSpace($ExceptMessage))) {
                    Write-Host -ForeGroundColor White -NoNewLine "  -Error message...: "
                    Write-Host -ForeGroundColor Red "`"$ExceptMessage`""
                }
                Write-Host -ForeGroundColor White -NoNewLine " -Data.............: "
                Write-Host -ForeGroundColor Yellow $($response.csvserver  | Format-List -Property * | Out-String)
                Write-Host -ForeGroundColor White -NoNewLine " -Connection.......: "
                Write-Host -ForeGroundColor Red "FAILED! Exiting now`r`n"
                Exit (1)
            }
        }
    } elseif ($ValidationMethod -eq "dns") {
        Write-Host -ForeGroundColor White -NoNewLine " -Connection.......: "
        if (-Not [string]::IsNullOrEmpty($ADCSession.Version)) {
            Write-Host -ForeGroundColor Green "OK"
        } else {
            Write-Host -ForeGroundColor Red "FAILED! Exiting now`r`n"
            Exit (1)
        }
    }
}

#endregion Cert Values Check

#region Services
if ((-not $CleanADC) -and (-not $RemoveTestCertificates)) {
    Write-Host -NoNewLine -ForeGroundColor Yellow "`r`nIMPORTANT: By running this script you agree with the terms specified by Let's Encrypt."
    if ($Production) {
        $BaseService = "LE_PROD"
        Write-Verbose "Using the production service for real certificates"
    } else {
        $BaseService = "LE_STAGE"
        Write-Verbose "Using the staging service for test certificates"
    }
    ""
    Posh-ACME\Set-PAServer $BaseService
    $PAServer = Posh-ACME\Get-PAServer -Refresh
    Write-Verbose "All account data is being saved to `"$ACMEStorage`""
}
#endregion Services

#region Registration

if ((-not ($CleanADC)) -and (-not ($RemoveTestCertificates))) {
    try {
        Write-Verbose "Try to retrieve the existing Registration"
        $PARegistration = Posh-ACME\Get-PAAccount -List -Contact $EmailAddress -Refresh | Where-Object {($_.status -eq "valid") -and ($_.KeyLength -eq $KeyLength)}
        if ($PARegistration -is [system.array]) {
            $PARegistration = $PARegistration | Sort-Object id | Select-Object -Last 1
        }
        if ($PARegistration.Contact -contains "mailto:$($EmailAddress)") {
            Write-Verbose "Existing registration found, no changes necessary"
        } else {
            Write-Verbose "Current registration `"$($PARegistration.Contact)`" is not equal to `"$EmailAddress`", setting new registration"
            $PARegistration = Posh-ACME\New-PAAccount -Contact $EmailAddress -KeyLength $KeyLength -AcceptTOS
        }
    } catch {
        Write-Verbose "Setting new registration to `"$EmailAddress`""
        try {
            $PARegistration = Posh-ACME\New-PAAccount -Contact $EmailAddress -KeyLength $KeyLength -AcceptTOS
            Write-Verbose "New registration successful"
        } catch {
            Write-Verbose "Error New registration failed!"
            Write-Verbose "Error Details: $($_.Exception.Message)"
            Write-Host -ForeGroundColor Red "`nError New registration failed!"
        }
    }
    try {
        Set-PAAccount -ID $PARegistration.id | out-null
        Write-Verbose "Account $($PARegistration.id) set as default"
    } catch {
        Write-Verbose "Could not set default account"
        Write-Verbose "Error Details: $($_.Exception.Message)"
    }
    $PARegistration = Posh-ACME\Get-PAAccount -List -Contact $EmailAddress -Refresh | Where-Object {($_.status -eq "valid") -and ($_.KeyLength -eq $KeyLength)}
	Write-Verbose "Registration: $($PARegistration | Format-List | Out-String)"
    if (-not ($PARegistration.Contact -contains "mailto:$($EmailAddress)")) {
        throw "User registration failed"
        exit(1)
    }
    if ($PARegistration.status -ne "valid") {
        throw "Account status is $($Account.status)"
        exit(1)
    } else {
        Write-Verbose "Registration ID: $($PARegistration.id), Status: $($PARegistration.status)"
        Write-Verbose "Setting Account as default for new order"
        Posh-ACME\Set-PAAccount -ID $PARegistration.id -Force
    }
}

#endregion Registration

#region DNS

#region Order

if ((-not $CleanADC) -and (-not $RemoveTestCertificates)) {
    try {
        Write-Verbose "Trying to create a new order"
        $domains = $DNSObjects | Select-Object DNSName -ExpandProperty DNSName
        $PAOrder = Posh-ACME\New-PAOrder -Domain $domains -KeyLength $KeyLength -Force -FriendlyName $FriendlyName
        Start-Sleep -Seconds 1
        Write-Verbose "Order data: $($PAOrder | Format-List | Out-String)"
        $PAChallenges = $PAOrder | Posh-ACME\Get-PAOrder -Refresh | Posh-ACME\Get-PAAuthorizations | Select-Object fqdn, DnsId, HTTP01Status, HTTP01Token, HTTP01Url, DNS01Status, DNS01Token, DNS01Url
        Write-Verbose "Challenges: $($PAChallenges | Format-List | Out-String)"
    } catch {
        Write-Verbose "Error Details: $($_.Exception.Message)"
        Write-Host -ForeGroundColor Red "ERROR: Could not create the order."
        Exit (1)
    }
}

#endregion Order

#region DNS Validation
if ($ValidationMethod -in "http", "dns") {
    Write-Verbose "Validating DNS record(s)"
    Foreach ($DNSObject in $DNSObjects) {
        $DNSObject.IPAddress = "0.0.0.0"
        $DNSObject.Status = $false
        $DNSObject.Match = $false
        try {
            $PAChallenge = $PAChallenges | Where-Object {$_.fqdn -eq $DNSObject.DNSName}
            if ([string]::IsNullOrWhiteSpace($PAChallenge)) {
                throw "No valid validation found"
            } else {
                $DNSObject.Challenge = $PAChallenge
            }
            if ($DisableIPCheck) {
                $DNSObject.IPAddress = "NoIPCheck"
                $DNSObject.Match = $true
                $DNSObject.Status = $true
            } else {
                Write-Verbose "Using public DNS server ($PublicDnsServer) to verify dns records"
                Write-Verbose "Trying to get IP Address"
                $PublicIP = (Resolve-DnsName -Server $PublicDnsServer -Name $DNSObject.DNSName -DnsOnly -Type A -ErrorAction SilentlyContinue).IPAddress
                if ([string]::IsNullOrWhiteSpace($PublicIP)) {
                    throw "No valid (public) IP Address found for DNSName:`"$($DNSObject.DNSName)`""
                } elseif ($PublicIP -is [system.array]) {
                    Write-Warning "More than one ip address found`n$($PublicIP | Format-List | Out-String)"
                    $DNSObject.IPAddress = $PublicIP | Select-Object -First 1
                    Write-Warning "using the first one`"$($DNSObject.IPAddress)`""
                } else {
                    Write-Verbose "Saving IP Address `"$PublicIP`""
                    $DNSObject.IPAddress = $PublicIP
                }
            }
        } catch {
            Write-Verbose "Error Details: $($_.Exception.Message)"
            Write-Host -ForeGroundColor Red "`nError while retrieving IP Address,"
            if ($DNSObject.SAN) {
                Write-Host -ForeGroundColor Red "you can try to re-run the script with the -DisableIPCheck parameter."
                Write-Host -ForeGroundColor Red "The script will continue but `"$DNSRecord`" will be skipped`n"
                $DNSObject.IPAddress = "Skipped"
                $DNSObject.Match = $true
            } else {
                Write-Host -ForeGroundColor Red "you can try to re-run the script with the -DisableIPCheck parameter.`n"
                Exit (1)
            }
        }
        if ($DNSObject.SAN) {
            $CNObject = $DNSObjects | Where-Object {$_.SAN -eq $false}
            Write-Verbose "All IP Addresses must match, checking"
            if ($DNSObject.IPAddress -match $CNObject.IPAddress) {
                Write-Verbose "`"$($DNSObject.IPAddress) ($($DNSObject.DNSName))`" matches to `"$($CNObject.IPAddress) ($($CNObject.DNSName))`""
                $DNSObject.Match = $true
                $DNSObject.Status = $true
            } else {
                Write-Verbose "`"$($DNSObject.IPAddress) ($($DNSObject.DNSName))`" Doesn't match to `"$($CNObject.IPAddress) ($($CNObject.DNSName))`""
                $DNSObject.Match = $false
            }
        } else {
            Write-Verbose "`"$($DNSObject.IPAddress) ($($DNSObject.DNSName))`" is the first entry, continuing"
            $DNSObject.Status = $true
            $DNSObject.Match = $true
        }
        Write-Verbose "Finished with object: `"$($DNSObject | Format-List | Out-String)`""
    }
    Write-Verbose "SAN Objects:`n$($DNSObjects | Format-List | Out-String)"
}

if ((-not $CleanADC) -and (-not ($RemoveTestCertificates)) -and ($ValidationMethod -eq "http")) {
    Write-Verbose "Checking for invalid DNS Records"
    $InvalidDNS = $DNSObjects | Where-Object {$_.Status -eq $false}
    $SkippedDNS = $DNSObjects | Where-Object {$_.IPAddress -eq "Skipped"}
    if ($InvalidDNS) {
        Write-Verbose "Invalid DNS object(s):`n$($InvalidDNS | Select-Object DNSName,Status | Format-List | Out-String)"
        $DNSObjects | Select-Object DNSName, IPAddress -First 1 | Format-List | Out-String | ForEach-Object {Write-Host -ForeGroundColor Green "$_"}
        $InvalidDNS | Select-Object DNSName, IPAddress | Format-List | Out-String | ForEach-Object {Write-Host -ForeGroundColor Red "$_"}
        Write-Error -Message "ERROR, invalid (not registered?) DNS Record(s) found!"
        Exit (1)
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
        $DNSObjects[0] | Select-Object DNSName, IPAddress | Format-List | Out-String | ForEach-Object {Write-Host -ForeGroundColor Green "$_"}
        $DNSNoMatch | Select-Object DNSName, IPAddress | Format-List | Out-String | ForEach-Object {Write-Host -ForeGroundColor Red "$_"}
        throw "ERROR: Non-matching records found, must match to `"$($DNSObjects[0].DNSName)`" ($($DNSObjects[0].IPAddress))"
    } elseif ($DisableIPCheck) {
        Write-Verbose "IP Addresses checking was skipped"
    } else {
        Write-Verbose "All IP Addresses match"
    }
}

#endregion DNS Validation

#region ACME DNS Verification

if ((-not $CleanADC) -and (-not $RemoveTestCertificates) -and ($ValidationMethod -eq "http")) {
    Write-Verbose "Checking if validation is required"
    $PAOrderItems = Posh-ACME\Get-PAOrder -Refresh -MainDomain $CN | Posh-ACME\Get-PAAuthorizations
    $ValidationRequired = $PAOrderItems | Where-Object {$_.status -ne "valid"}
    Write-Verbose "$($ValidationRequired.Count) validations required: $($ValidationRequired | Select-Object fqdn,status,HTTP01Status,Expires| Format-Table | Out-String)"
    if ($ValidationRequired.Count -eq 0) {
        Write-Verbose "Validation NOT required"
        $ADCActionsRequired = $false
    } else {
        Write-Verbose "Validation IS required"
        $ADCActionsRequired = $true
    
    }
    Write-Verbose "ADC actions required: $($ADCActionsRequired | Select-Object fqdn,status,HTTP01Status,Expires| Format-Table | Out-String)"
}

#region ADC pre dns
    
if ((-not $CleanADC) -and (-not $RemoveTestCertificates) -and $ADCActionsRequired -and ($ValidationMethod -eq "http")) {
    try {
        Write-Verbose "Login to ADC and save session to global variable"
        $ADCSession = Connect-ADC -ManagementURL $ManagementURL -Credential $Credential -PassThru
        Write-Verbose "Enable required ADC Features, Load Balancer, Responder, Content Switch and SSL"
        $payload = @{"feature" = "LB RESPONDER CS SSL"}
        $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type nsfeature -Payload $payload -Action enable
        try {
            Write-Verbose "Verifying Content Switch"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csvserver -Resource $NSCsVipName
        } catch {
            $ExceptMessage = $_.Exception.Message
            Write-Verbose "Error Details: $ExceptMessage"
            throw "Could not find/read out the content switch `"$NSCsVipName`" not available?"
        } finally {
            if ($ExceptMessage -like "*(404) Not Found*") {
                Write-Host -ForeGroundColor Red "`nThe Content Switch `"$NSCsVipName`" does NOT exist!"
                Exit (1)
            } elseif ($ExceptMessage -like "*The remote server returned an error*") {
                Write-Host -ForeGroundColor Red "`nUnknown error found while checking the Content Switch: `"$NSCsVipName`""
                Write-Host -ForeGroundColor Red "Error message: `"$ExceptMessage`""
                Exit (1)
            } elseif (($response.errorcode -eq "0") -and (-not ($response.csvserver.servicetype -eq "HTTP"))) {
                Write-Host -ForeGroundColor Red "`nThe Content Switch is $($response.csvserver.servicetype) and NOT HTTP"
                Write-Host -ForeGroundColor Red "Please use a HTTP (Port 80) Content Switch this is required for the validation. Exiting now`n"
                Exit (1)
            }
        }
        try { 
            Write-Verbose "Configuring ADC: Check if Load Balancer Service exists"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type service -Resource $NSSvcName
            Write-Verbose "Yep it exists, continuing"
        } catch {
            Write-Verbose "It does not exist, continuing"
            Write-Verbose "Configuring ADC: Create Load Balance Service `"$NSSvcName`""
            $payload = @{"name" = "$NSSvcName"; "ip" = "$NSSvcDestination"; "servicetype" = "HTTP"; "port" = "80"; "healthmonitor" = "NO"; } 
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type service -Payload $payload -Action add
        }
        try { 
            Write-Verbose "Configuring ADC: Check if Load Balancer exists"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type lbvserver -Resource $NSLbName
            Write-Verbose "Yep it exists, continuing"
        } catch {
            Write-Verbose "Nope, continuing"
            Write-Verbose "Configuring ADC: Create Load Balance Vip `"$NSLbName`""
            $payload = @{"name" = "$NSLbName"; "servicetype" = "HTTP"; "ipv46" = "0.0.0.0"; "Port" = "0"; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type lbvserver -Payload $payload -Action add
        } finally {
            Write-Verbose "Configuring ADC: Bind Service `"$NSSvcName`" to Load Balance Vip `"$NSLbName`""
            Write-Verbose "Checking LB Service binding"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type lbvserver_service_binding -Resource $NSLbName
            if ($response.lbvserver_service_binding.servicename -eq $NSSvcName) {
                Write-Verbose "LB Service binding is ok"
            } else {
                $payload = @{"name" = "$NSLbName"; "servicename" = "$NSSvcName"; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type lbvserver_service_binding -Payload $payload
            }
        }
        try {
            Write-Verbose "Configuring ADC: Check if Responder Action exists"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderaction -Resource $NSRsaName
            try {
                Write-Verbose "Yep it exists, continuing"
                Write-Verbose "Configuring ADC: Change Responder Action to default values"
                $payload = @{"name" = "$NSRsaName"; "target" = '"HTTP/1.0 200 OK" +"\r\n\r\n" + "XXXX"'; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type responderaction -Payload $payload -Action set
            } catch {
                throw "Something went wrong with re-configuring the existing action `"$NSRsaName`", exiting now..."
            }    
        } catch {
            $payload = @{"name" = "$NSRsaName"; "type" = "respondwith"; "target" = '"HTTP/1.0 200 OK" +"\r\n\r\n" + "XXXX"'; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type responderaction -Payload $payload -Action add
        }
        try { 
            Write-Verbose "Configuring ADC: Check if Responder Policy exists"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderpolicy -Resource $NSRspName
            try {
                Write-Verbose "Yep it exists, continuing"
                Write-Verbose "Configuring ADC: Change Responder Policy to default values"
                $payload = @{"name" = "$NSRspName"; "action" = "rsa_letsencrypt"; "rule" = 'HTTP.REQ.URL.CONTAINS(".well-known/acme-challenge/XXXX")'; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type responderpolicy -Payload $payload -Action set

            } catch {
                throw "Something went wrong with re-configuring the existing policy `"$NSRspName`", exiting now..."
            }    
        } catch {
            $payload = @{"name" = "$NSRspName"; "action" = "$NSRsaName"; "rule" = 'HTTP.REQ.URL.CONTAINS(".well-known/acme-challenge/XXXX")'; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type responderpolicy -Payload $payload -Action add
        } finally {
            $payload = @{"name" = "$NSLbName"; "policyname" = "$NSRspName"; "priority" = 100; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type lbvserver_responderpolicy_binding -Payload $payload -Resource $NSLbName
        }
        try { 
            Write-Verbose "Configuring ADC: Check if Content Switch Policy exists"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type cspolicy -Resource $NSCspName
            Write-Verbose "It does, continuing"
            if (-not($response.cspolicy.rule -eq "HTTP.REQ.URL.CONTAINS(`"well-known/acme-challenge/`")")) {
                $payload = @{"policyname" = "$NSCspName"; "rule" = "HTTP.REQ.URL.CONTAINS(`"well-known/acme-challenge/`")"; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type cspolicy -Payload $payload
            }
        } catch {
            Write-Verbose "Configuring ADC: Create Content Switch Policy"
            $payload = @{"policyname" = "$NSCspName"; "rule" = 'HTTP.REQ.URL.CONTAINS("well-known/acme-challenge/")'; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type cspolicy -Payload $payload -Action add
            
            
        }
        Write-Verbose "Configuring ADC: Bind Load Balancer `"$NSLbName`" to Content Switch `"$NSCsVipName`" with prio: $NSCsVipBinding"
        $payload = @{"name" = "$NSCsVipName"; "policyname" = "$NSCspName"; "priority" = "$NSCsVipBinding"; "targetlbvserver" = "$NSLbName"; "gotopriorityexpression" = "END"; }
        $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type csvserver_cspolicy_binding -Payload $payload
        Write-Verbose "Finished configuring the ADC"
    } catch {
        Write-Verbose "Error Details: $($_.Exception.Message)"
        throw "ERROR: Could not configure the ADC, exiting now"
    }
    Start-Sleep -Seconds 2
}

#endregion ADC pre dns

#region Test NS CS

if ((-not $CleanADC) -and (-not $RemoveTestCertificates) -and ($ADCActionsRequired) -and ($ValidationMethod -eq "http")) {
    Write-Host -ForeGroundColor White "Executing some tests, can take a couple of seconds/minutes..."
    Write-Host -ForeGroundColor Yellow "`r`n    NOTE: Should a DNS test fails, the script will try to continue!`r`n"
    Write-Host -ForeGroundColor White "`r`nChecking DNS"
    ForEach ($DNSObject in $DNSObjects ) {
        Write-Host -ForeGroundColor White -NoNewLine " -DNS Hostname.....: "
        Write-Host -ForeGroundColor Blue "$($DNSObject.DNSName) [$($DNSObject.IPAddress)]"
        $TestURL = "http://$($DNSObject.DNSName)/.well-known/acme-challenge/XXXX"
        Write-Verbose "Testing if the Content Switch is available on `"http://$($DNSObject.DNSName)`" (via internal DNS)"
        try {
            Write-Verbose "Retrieving data"
            $Result = Invoke-WebRequest -URI $TestURL -TimeoutSec 2 -UseBasicParsing
            Write-Verbose "Success, output: $($Result| Out-String)"
        } catch {
            $Result = $null
            Write-Verbose "Internal check failed, error Details: $($_.Exception.Message)"
        }
        if ($Result.RawContent -eq "HTTP/1.0 200 OK" + "`r`n`r`n" + "XXXX") {
            Write-Host -ForeGroundColor White -NoNewLine " -Test (Int. DNS)..: "
            Write-Host -ForeGroundColor Green "OK"
        } else {
            Write-Host -ForeGroundColor White -NoNewLine " -Test (Int. DNS)..: "
            Write-Host -ForeGroundColor Yellow "Not successful, maybe not resolvable internally?"
            Write-Verbose "Output: $($Result| Out-String)"
        }
        
        try {
            Write-Verbose "Checking if Public IP is available for external DNS testing"
            [ref]$ValidIP = [ipaddress]::None
            if (([ipaddress]::TryParse("$($DNSObject.IPAddress)", $ValidIP)) -and (-not ($DisableIPCheck))) {
                Write-Verbose "Testing if the Content Switch is available on `"$TestURL`" (via external DNS)"
                $TestURL = "http://$($DNSObject.IPAddress)/.well-known/acme-challenge/XXXX"
                $Headers = @{"Host" = "$($DNSObject.DNSName)"}
                Write-Verbose "Retrieving data"
                $Result = Invoke-WebRequest -URI $TestURL -Headers $Headers -TimeoutSec 2 -UseBasicParsing
                Write-Verbose "Success, output: $($Result| Out-String)"
            } else {
                Write-Verbose "Public IP is not available for external DNS testing"
            }
        } catch {
            $Result = $null
            Write-Verbose "External check failed, error Details: $($_.Exception.Message)"
        }
        [ref]$ValidIP = [ipaddress]::None
        if (([ipaddress]::TryParse("$($DNSObject.IPAddress)", $ValidIP)) -and (-not ($DisableIPCheck))) {
            if ($Result.RawContent -eq "HTTP/1.0 200 OK" + "`r`n`r`n" + "XXXX") {
                Write-Host -ForeGroundColor White -NoNewLine " -Test (Ext. DNS)..: "
                Write-Host -ForeGroundColor Green "OK"
            } else {
                Write-Host -ForeGroundColor White -NoNewLine " -Test (Ext. DNS)..: "
                Write-Host -ForeGroundColor Yellow "Not successful, maybe not resolvable externally?"
                Write-Verbose "Output: $($Result| Out-String)"
            }
        }
    }
    Write-Host -ForeGroundColor White "`r`nFinished the tests, script will continue"
}

#endregion Test NS CS

#region Validation

if ((-not $CleanADC) -and (-not $RemoveTestCertificates) -and ($ValidationMethod -eq "http")) {
    Write-Verbose "OrderItems: $($PAOrderItems | Select-Object * | Format-List | Out-String)"
    Write-Verbose "PAOrderItems: $($PAOrderItems | Select-Object fqdn,status | Format-Table | Out-String)"
    Write-Host -ForeGroundColor White "`r`nVerification"
    foreach ($DNSObject in $DNSObjects) {
        $NSKeyAuthorization = $null
        $PAOrderItem = $PAOrderItems | Where-Object {$_.fqdn -eq $DNSObject.DNSName}
        Write-Verbose "Checking validation for `"$($DNSObject.DNSName)`" => $($PAOrderItem.status)"
        if ($PAOrderItem.status -eq "valid") {
            Write-Host -ForeGroundColor White -NoNewLine " -DNS Hostname.....: "
            Write-Host -ForeGroundColor Blue "$($DNSObject.DNSName)"
            Write-Host -ForeGroundColor White -NoNewLine " -Validation.......: "
            Write-Host -ForeGroundColor Green "=> Still valid"
        } else { 
            Write-Verbose "New validation required, Start verifying"
            Write-Host -ForeGroundColor White -NoNewLine " -DNS Hostname.....: "
            Write-Host -ForeGroundColor Blue "$($DNSObject.DNSName)"
            Write-Host -ForeGroundColor White -NoNewLine " -Validation.......: "
            try {
                $PAToken = ".well-known/acme-challenge/$($PAOrderItem.HTTP01Token)"
                Write-Verbose "Configuring ADC: Change Responder Policy `"$NSRspName`" to: `"HTTP.REQ.URL.CONTAINS(`"$PAToken`")`""
                $payload = @{"name" = "$NSRspName"; "action" = "$NSRsaName"; "rule" = "HTTP.REQ.URL.CONTAINS(`"$PAToken`")"; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type responderpolicy -Payload $payload -Action set
                Write-Host -ForeGroundColor Yellow -NoNewLine "*"
                Write-Verbose "Configuring ADC: Change Responder Action `"$NSRsaName`" to return "
                $KeyAuth = Posh-ACME\Get-KeyAuthorization -Token $($PAOrderItem.HTTP01Token) -Account $PAAccount
                $NSKeyAuthorization = "`"HTTP/1.0 200 OK\r\n\r\n$($KeyAuth)`""
                Write-Verbose $NSKeyAuthorization
                $payload = @{"name" = "$NSRsaName"; "target" = $NSKeyAuthorization; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type responderaction -Payload $payload -Action set
                Write-Verbose "Wait 1 second"
                Start-Sleep -Seconds 1
                Write-Verbose -Message "Start submitting Challenge"
                Write-Host -ForeGroundColor Yellow -NoNewLine "*"
                try {
                    Send-ChallengeAck -ChallengeUrl $($PAOrderItem.HTTP01Url) -Account $PAAccount
                } catch {
                    Write-Verbose "Error Details: $($_.Exception.Message)"
                    throw "Error while submitting the Challenge"
                }
                Write-Verbose "Wait 1 seconds"
                Start-Sleep -Seconds 1
                Write-Host -ForeGroundColor Yellow -NoNewLine "*"
                Write-Verbose "Retreiving validation status"
                try {
                    $webrequest = Invoke-WebRequest -Uri $PAOrderItem.HTTP01Url -UseBasicParsing | ConvertFrom-Json
                    Write-Verbose "Status: $($webrequest.status)"
                } catch {
                    Write-Verbose "Error Details: $($_.Exception.Message)"
                    throw "Error while retreiving validation status"
                }
                $i = 0
                while (-NOT ($webrequest.status -eq "valid")) {
                    Write-Host -ForeGroundColor Yellow -NoNewLine "*"
                    $i++
                    Write-Verbose "$i $DNSRecord is not (yet) validated, Wait 3 second"
                    Start-Sleep -Seconds 2
                    Write-Verbose "Retreiving validation status"
                    try {
                        $webrequest = Invoke-WebRequest -Uri $PAOrderItem.HTTP01Url -UseBasicParsing | ConvertFrom-Json
                        Write-Verbose "Status: $($webrequest.status)"
                    } catch {
                        Write-Verbose "Error Details: $($_.Exception.Message)"
                        throw "Error while retreiving validation status"
                    }
                    if (($i -ge 20) -or ($webrequest.status.ToLower() -eq "invalid")) {break}
                }
                switch ($webrequest.status.ToLower()) {
                    "pending" {
                        Write-Host -ForeGroundColor Red " ERROR [$($webrequest.status)]"
                        throw "It took to long for the validation ($($DNSObject.DNSName)) to complete, exiting now."
                    }
                    "invalid" {
                        Write-Host -ForeGroundColor Red " ERROR [$($webrequest.status)]"
                        throw "Validation for `"$($DNSObject.DNSName)`" is invalid! Exiting now."
                    }
                    "valid" {
                        Write-Host -ForeGroundColor Green " $($webrequest.status)"
                    }
                    default {
                        Write-Host -ForeGroundColor Red " ERROR  [$($webrequest.status)]"
                        throw "Unexpected status for `"$($DNSObject.DNSName)`" is `"$($webrequest.status)`", exiting now."
                    }
                }
            } catch {
                Write-Verbose "Error Details: $($_.Exception.Message)"
                throw "Error while verifying `"$($DNSObject.DNSName)`", exiting now"
            }
        }
    }
    Write-Verbose "Final check"
    $PAOrderItems = Posh-ACME\Get-PAOrder -Refresh -MainDomain $CN | Posh-ACME\Get-PAAuthorizations
    Write-Verbose "PAOrderItems: $($PAOrderItems | Select-Object fqdn,status | Format-Table | Out-String)"
}

#endregion Validation

#region ADC post DNS

if ((-not $RemoveTestCertificates) -and (($CleanADC) -or ($ValidationMethod -in "http", "dns"))) {
    Write-Verbose "Login to ADC and save session to global variable"
    Connect-ADC -ManagementURL $ManagementURL -Credential $Credential
    try {
        Write-Verbose "Checking if a binding exists for `"$NSCspName`""
        $Filters = @{"policyname" = "$NSCspName"}
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csvserver_cspolicy_binding -Resource "$NSCsVipName" -Filters $Filters
        if ($response.csvserver_cspolicy_binding.policyname -eq $NSCspName) {
            Write-Verbose "Removing Content Switch Loadbalance Binding"
            $Arguments = @{"name" = "$NSCsVipName"; "policyname" = "$NSCspName"; "priority" = "$NSCsVipBinding"; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type csvserver_cspolicy_binding -Arguments $Arguments
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
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type cspolicy -Resource "$NSCspName"
        } catch {}
        if ($response.cspolicy.policyname -eq $NSCspName) {
            Write-Verbose "Removing Content Switch Policy"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type cspolicy -Resource "$NSCspName"
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
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type lbvserver -Resource "$NSLbName"
        } catch {}
        if ($response.lbvserver.name -eq $NSLbName) {
            Write-Verbose "Removing the Load Balance vServer"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type lbvserver -Resource "$NSLbName"
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
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type service -Resource "$NSSvcName"
        } catch {}
        if ($response.service.name -eq $NSSvcName) {
            Write-Verbose "Removing Service `"$NSSvcName`""
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type service -Resource "$NSSvcName"
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
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type server -Resource "$NSSvcDestination"
        } catch {}
        if ($response.server.name -eq $NSSvcDestination) {
            Write-Verbose "Removing Server `"$NSSvcDestination`""
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type server -Resource "$NSSvcDestination"
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
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderpolicy -Resource "$NSRspName"
        } catch {}
        if ($response.responderpolicy.name -eq $NSRspName) {
            Write-Verbose "Removing Responder Policy `"$NSRspName`""
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type responderpolicy -Resource "$NSRspName" 
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
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderaction -Resource "$NSRsaName"
        } catch {}
        if ($response.responderaction.name -eq $NSRsaName) {
            Write-Verbose "Removing Responder Action `"$NSRsaName`""
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type responderaction -Resource $NSRsaName
        } else {
            Write-Verbose "Responder Action not found"
        }
    } catch { 
        Write-Verbose "Error Details: $($_.Exception.Message)"
        Write-Warning "Not able to remove the Responder Action" 
    }
}    

#endregion ADC Post DNS

#endregion ACME DNS Verification

#endregion DNS

#region DNS Challenge

if ((-not $CleanADC) -and (-not $RemoveTestCertificates) -and ($ValidationMethod -eq "dns")) {
    $PAOrderItems = Posh-ACME\Get-PAOrder -Refresh -MainDomain $CN | Posh-ACME\Get-PAAuthorizations
    $TXTRecords = $PAOrderItems | Select-Object fqdn, `
    @{L = 'TXTName'; E = {"_acme-challenge.$($_.fqdn.Replace('*.',''))"}}, `
    @{L = 'TXTValue'; E = {ConvertTo-TxtValue (Get-KeyAuthorization $_.DNS01Token)}}
    Write-Host -ForegroundColor White "`r`n********************************************************************"
    Write-Host -ForegroundColor White "* Make sure the following TXT records are configured at your DNS   *"
    Write-Host -ForegroundColor White "* provider before continuing! If not, DNS validation will fail!    *"
    Write-Host -ForegroundColor White "********************************************************************"
    foreach ($Record in $TXTRecords) {
        ""
        Write-Host -ForeGroundColor White -NoNewLine " -DNS Hostname.....: "
        Write-Host -ForeGroundColor Blue "$($Record.fqdn)"
        Write-Host -ForeGroundColor White -NoNewLine " -TXT Record Name..: "
        Write-Host -ForeGroundColor Yellow "$($Record.TXTName)"
        Write-Host -ForeGroundColor White -NoNewLine " -TXT Record Value.: "
        Write-Host -ForeGroundColor Yellow "$($Record.TXTValue)"
    }
    ""        
    Write-Host -ForegroundColor White "********************************************************************"
    $($TXTRecords | Format-List | Out-String).Trim() | clip.exe
    Write-Host -ForegroundColor Yellow "`r`nINFO: Data is copied tot the clipboard"
    $answer = Read-Host -Prompt "Enter `"yes`" when ready to continue"
    if (-not ($answer.ToLower() -eq "yes")) {
        Write-Host -ForegroundColor Yellow "You've entered `"$answer`", last chance to continue"
        $answer = Read-Host -Prompt "Enter `"yes`" when ready to continue, or something else to stop and exit"
        if (-not ($answer.ToLower() -eq "yes")) {
            Write-Host -ForegroundColor Yellow "You've entered `"$answer`", ending now!"
            Exit (0)
        }
    }
    Write-Host "Continuing, Waiting 30 seconds for the records to settle"
    Start-Sleep -Seconds 30
    Write-Verbose -Message "Start verifying the TXT records."
    $issues = $false
    try {
        Write-Host -ForegroundColor White "`r`nPre-Checking the TXT records"
        Foreach ($Record in $TXTRecords) {
            Write-Host -ForeGroundColor White -NoNewLine " -DNS Hostname.....: "
            Write-Host -ForeGroundColor Blue "$($Record.fqdn)"
            Write-Host -ForeGroundColor White -NoNewLine " -TXT Record check.: "
            Write-Verbose "`r`nTrying to retreive the TXT record"
            $result = $null
            $dnsserver = Resolve-DnsName -Name $Record.TXTName -Server $PublicDnsServer -DnsOnly
            if ([string]::IsNullOrWhiteSpace($dnsserver.PrimaryServer)) {
                Write-Verbose -Message "Using DNS Server `"$PublicDnsServer`" for resolving the TXT records"
                $result = Resolve-DnsName -Name $Record.TXTName -Type TXT -Server $PublicDnsServer -DnsOnly
            } else {
                Write-Verbose -Message "Using DNS Server `"$($dnsserver.PrimaryServer)`" for resolving the TXT records"
                $result = Resolve-DnsName -Name $Record.TXTName -Type TXT -Server $dnsserver.PrimaryServer -DnsOnly
            }
            Write-Verbose "Result:$($result | Format-List | Out-String)"
            if ([string]::IsNullOrWhiteSpace($result.Strings -like "*$($Record.TXTValue)*")) {
                Write-Host -ForegroundColor Yellow "Could not determine"
                $issues = $true
            } else {
                Write-Host -ForegroundColor Green "OK"
            }
        }
    } catch {
        Write-Verbose "Details: $($_.Exception.Message | Out-String)" -Verbose
        $issues = $true
    }
    if ($issues) {
       ""
       Write-Warning "Found issues during the initial test. TXT validation might fail. Waiting an aditional 30 seconds before continuing"
       Start-Sleep -Seconds 20
    }
}

#endregion DNS Challenge

#region Finalizing DNS Order
    
if ((-not $CleanADC) -and (-not $RemoveTestCertificates) -and ($ValidationMethod -in "dns")) {
    Write-Verbose "Check if DNS Records need to be validated"
    Write-Host -ForeGroundColor White "`r`nSending Acknowledgment"
    Foreach ($DNSObject in $DNSObjects) {
        Write-Host -ForeGroundColor White -NoNewLine " -DNS Hostname.....: "
        Write-Host -ForeGroundColor Blue "$($DNSObject.DNSName)"
        Write-Host -ForeGroundColor White -NoNewLine " -Send Ack.........: "
        $PAOrderItem = Posh-ACME\Get-PAOrder -MainDomain $CN | Posh-ACME\Get-PAAuthorizations | Where-Object {$_.fqdn -eq $DNSObject.DNSName}
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        Write-Verbose -Message "OrderItem: $($PAOrderItem| Select-Object fqdn,status,DNS01Status,expires | Format-List | Out-String)"
        if (($PAOrderItem.DNS01Status -notlike "valid") -and ($PAOrderItem.DNS01Status -notlike "invalid")) {
            try {
                Write-Verbose "Start submitting Challenge"
                Posh-ACME\Send-ChallengeAck -ChallengeUrl $($PAOrderItem.DNS01Url) -Account $PAAccount
                Write-Host -ForeGroundColor Yellow -NoNewLine "*"
                Write-Verbose "Done"
            } catch {
                Write-Host -ForeGroundColor Red " ERROR"
                Write-Verbose "Error Details: $($_.Exception.Message)" -Verbose
                throw "Error while submitting the Challenge"
            }
            Write-Verbose -Message "Finished submitting Challenge"
            Write-Host -ForeGroundColor Green " Sent Successfully"
        } elseif ($PAOrderItem.DNS01Status -like "valid") {
            Write-Verbose -Message "This order is done"
            $DNSObject.Done = $true
            Write-Host -ForeGroundColor Green " Still valid"
        }
        $PAOrderItem = $null
    }
    $i = 1
    Write-Host -ForeGroundColor White "`r`nValidation"
    while ($i -le 20) {
        Write-Host -ForeGroundColor White " -Attempt..........: $i"
        $PAOrderItems = Posh-ACME\Get-PAOrder -MainDomain $CN | Posh-ACME\Get-PAAuthorizations
        Foreach ($DNSObject in $DNSObjects) {
            if ($DNSObject.Done -eq $false) {
                Write-Host -ForeGroundColor White -NoNewLine " -DNS Hostname.....: "
                Write-Host -ForeGroundColor Blue "$($DNSObject.DNSName)"
                try {
                    $PAOrderItem = $PAOrderItems | Where-Object {$_.fqdn -eq $DNSObject.DNSName}
                    Write-Verbose -Message "OrderItem: $($PAOrderItem | Select-Object fqdn,status,DNS01Status,expires | Format-List | Out-String)"
                    Write-Host -ForeGroundColor White -NoNewLine " -Status...........: "
                    switch ($PAOrderItem.DNS01Status.ToLower()) {
                        "pending" {
                            Write-Host -ForeGroundColor Yellow "$($PAOrderItem.DNS01Status)"
                        }
                        "invalid" {
                            Write-Verbose -Message "This order is done. Status: $($PAOrderItem.DNS01Status)"
                            $DNSObject.Done = $true
                            Write-Host -ForeGroundColor Red "$($PAOrderItem.DNS01Status)"
                        }
                        "valid" {
                            Write-Verbose -Message "This order is done. Status: $($PAOrderItem.DNS01Status)"
                            $DNSObject.Done = $true
                            Write-Host -ForeGroundColor Green "$($PAOrderItem.DNS01Status)"
                        }
                        default {
                            Write-Host -ForeGroundColor Red "UNKNOWN [$($PAOrderItem.DNS01Status)]"
                        }
                    }
                } catch {
                    Write-Verbose "Error Details: $($_.Exception.Message)"
                    throw "Error while retreiving validation status"
                }
                $PAOrderItem = $null
            }
        }
        if (-NOT ($DNSObjects | Where-Object {$_.Done -eq $false})) {
            Write-Verbose -Message "All items validated"
            if ($PAOrderItems | Where-Object {$_.DNS01Status -eq "invalid"}) {
                Write-Host -ForegroundColor Red "`r`nERROR: Validation Failed, invalid items found! Exiting now!"
                Exit (1)
            }
            if ($PAOrderItems | Where-Object {$_.DNS01Status -eq "pending"}) {
                Write-Host -ForegroundColor Red "`r`nERROR: Validation Failed, still pending items left! Exiting now!"
                Exit (1)
            }
            break
        }
        Write-Verbose -Message "Waiting, round: $i"
        Start-Sleep -Seconds 1
        $i++
        ""
    }
}

if ((-not $CleanADC) -and (-not $RemoveTestCertificates) -and ($ValidationMethod -in "http", "dns")) {
    $Order = $PAOrder | Posh-ACME\Get-PAOrder -Refresh
    Write-Verbose -Message "Order state: $($Order.status)"
    if ($Order.status -eq "ready") {
        Write-Verbose "Order is ready"
    } else {
        Write-Verbose "Order is still not ready, validation failed?" -Verbose
    }
    Write-Verbose -Message "Requesting Certificate "
    $NewCertificates = New-PACertificate -Domain $($DNSObjects.DNSName) -DirectoryUrl $BaseService -PfxPass $PfxPassword -CertKeyLength $KeyLength -FriendlyName $FriendlyName
    Write-Verbose "$($NewCertificates | Format-List | Out-String)"
    Start-Sleep -Seconds 1
}
    
#endregion Finalizing DNS Order

#region Certificates
    
if ((-not ($CleanADC)) -and (-not ($RemoveTestCertificates))) {
    $CertificateAlias = "CRT-SAN-$SessionDateTime-$($CN.Replace('*.',''))"
    $CertificateDirectory = Join-Path -Path $CertDir -ChildPath $CertificateAlias
    Write-Verbose "Create directory `"$CertificateDirectory`" for storing the new certificates"
    New-Item $CertificateDirectory -ItemType directory -force | Out-Null
    $CertificateName = "$($ScriptDateTime.ToString("yyyyMMddHHmm"))-$($CN.Replace('*.',''))"
    if (Test-Path $CertificateDirectory) {
        Write-Verbose "Retreiving certificate info"
        $PACertificate = Posh-ACME\Get-PACertificate -MainDomain $cn

        $ChainFile = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 "$($PACertificate.ChainFile)"
        $CAName = $ChainFile.DnsNameList.Unicode.Replace("'","")
        $IntermediateCACertKeyName = "$($CAName)-int"
        $IntermediateCAFileName = "$($IntermediateCACertKeyName).crt"
        $IntermediateCAFullPath = Join-Path -Path $CertificateDirectory -ChildPath $IntermediateCAFileName

        Write-Verbose "Intermediate: `"$IntermediateCAFileName`""
        Copy-Item $PACertificate.ChainFile -Destination $IntermediateCAFullPath -Force
        if ($Production) {
            if ($CertificateName.length -ge 31) {
                $CertificateName = "$($CertificateName.subString(0,31))"
                Write-Verbose "CertificateName (new name): `"$CertificateName`" ($($CertificateName.length) max 31)"
            } else {
                $CertificateName = "$CertificateName"
                Write-Verbose "CertificateName: `"$CertificateName`" ($($CertificateName.length) max 31)"
            }
            if ($CertificateAlias.length -ge 59) {
                $CertificateFileName = "$($CertificateAlias.subString(0,59)).crt"
                Write-Verbose "Certificate (new name): `"$CertificateFileName`"($($CertificateFileName.length) max 63)"
                $CertificateKeyFileName = "$($CertificateAlias.subString(0,59)).key"
                Write-Verbose "Key (new name): `"$CertificateKeyFileName`"($($CertificateFileName.length) max 63)"
            } else {
                $CertificateFileName = "$($CertificateAlias).crt"
                Write-Verbose "Certificate: `"$CertificateFileName`" ($($CertificateFileName.length) max 63)"
                $CertificateKeyFileName = "$($CertificateAlias).key"
                Write-Verbose "Key: `"$CertificateKeyFileName`"($($CertificateFileName.length) max 63)"
            }
            $CertificatePfxFileName = "$CertificateAlias.pfx"
            $CertificatePemFileName = "$CertificateAlias.pem"
            $CertificatePfxWithChainFileName = "$($CertificateAlias)-WithChain.pfx"
        } else {
            if ($CertificateName.length -ge 27) {
                $CertificateName = "TST-$($CertificateName.subString(0,27))"
                Write-Verbose "CertificateName (new name): `"$CertificateName`" ($($CertificateName.length) max 31)"
            } else {
                $CertificateName = "TST-$($CertificateName)"
                Write-Verbose "CertificateName: `"$CertificateName`" ($($CertificateName.length) max 31)"
            }
            if ($CertificateAlias.length -ge 55) {
                $CertificateFileName = "TST-$($CertificateAlias.subString(0,55)).crt"
                Write-Verbose "Certificate (new name): `"$CertificateFileName`"($($CertificateFileName.length) max 63)"
                $CertificateKeyFileName = "TST-$($CertificateAlias.subString(0,55)).key"
                Write-Verbose "Key (new name): `"$CertificateKeyFileName`"($($CertificateFileName.length) max 63)"
            } else {
                $CertificateFileName = "TST-$($CertificateAlias).crt"
                Write-Verbose "Certificate: `"$CertificateFileName`"($($CertificateFileName.length) max 63)"
                $CertificateKeyFileName = "TST-$($CertificateAlias).key"
                Write-Verbose "Key: `"$CertificateKeyFileName`"($($CertificateFileName.length) max 63)"
            }
            $CertificatePfxFileName = "TST-$CertificateAlias.pfx"
            $CertificatePemFileName = "TST-$CertificateAlias.pem"
            $CertificatePfxWithChainFileName = "TST-$($CertificateAlias)-WithChain.pfx"
        }
        
        $CertificateFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificateFileName
        $CertificateKeyFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificateKeyFileName
        $CertificatePfxFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificatePfxFileName
        $CertificatePfxWithChainFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificatePfxWithChainFileName
        Write-Verbose "PFX: `"$CertificatePfxFileName`" ($($CertificatePfxFileName.length))"
        Copy-Item $PACertificate.CertFile -Destination $CertificateFullPath -Force
        Copy-Item $PACertificate.KeyFile -Destination $CertificateKeyFullPath -Force
        Copy-Item $PACertificate.PfxFullChain -Destination $CertificatePfxWithChainFullPath -Force
        $certificate = Get-PfxData -FilePath $CertificatePfxWithChainFullPath -Password $(ConvertTo-SecureString -String $PfxPassword -AsPlainText -Force)
        $NewCertificates = Export-PfxCertificate -PfxData $certificate -FilePath $CertificatePfxFullPath -Password $(ConvertTo-SecureString -String $PfxPassword -AsPlainText -Force) -ChainOption EndEntityCertOnly -Force
    }
}

#endregion Certificates

#region Upload certificates to ADC

if ((-not ($CleanADC)) -and (-not ($RemoveTestCertificates))) {
    try {
        Write-Verbose "Retreiving existing CA Intermediate Certificate"
        $Filters = @{"serial" = "$($ChainFile.SerialNumber)"}
        $ADCIntermediateCA = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey -Filters $Filters -ErrorAction SilentlyContinue
        if ([string]::IsNullOrEmpty($($ADCIntermediateCA.sslcertkey.certkey))) {
            Write-Verbose "Second attempt, trying without leading zero's"
            $Filters = @{"serial" = "$($ChainFile.SerialNumber.TrimStart("00"))"}
            $ADCIntermediateCA = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey -Filters $Filters -ErrorAction SilentlyContinue
        }
        Write-Verbose "Details: $($ADCIntermediateCA.sslcertkey | Select-Object certkey,issuer,subject,serial,clientcertnotbefore,clientcertnotafter | Format-List | Out-String)"
        Write-Verbose "Checking if IntermediateCA `"$IntermediateCACertKeyName`" already exists"
        if ([string]::IsNullOrEmpty($($ADCIntermediateCA.sslcertkey.certkey))) {
            try {
                Write-Verbose "Uploading `"$IntermediateCAFileName`" to the ADC"
                $IntermediateCABase64 = [System.Convert]::ToBase64String($(Get-Content $IntermediateCAFullPath -Encoding "Byte"))
                $payload = @{"filename" = "$IntermediateCAFileName"; "filecontent" = "$IntermediateCABase64"; "filelocation" = "/nsconfig/ssl/"; "fileencoding" = "BASE64"; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type systemfile -Payload $payload
                Write-Verbose "Succeeded, Add the certificate to the ADC config"
                $payload = @{"certkey" = "$IntermediateCACertKeyName"; "cert" = "/nsconfig/ssl/$($IntermediateCAFileName)"; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload
                Write-Verbose "Finished"
            } catch {
                Write-Warning "Could not upload or get the Intermediate CA ($($ChainFile.DnsNameList.Unicode)), manual action may be required"
            }
        } else {
            $IntermediateCACertKeyName = $ADCIntermediateCA.sslcertkey.certkey
            Write-Verbose "IntermediateCA exists, saving existing name `"$IntermediateCACertKeyName`" for later use"
        }
        Write-Verbose "NSCertNameToUpdate: `"$NSCertNameToUpdate`""
		if ([string]::IsNullOrEmpty($NSCertNameToUpdate)) {
		    Write-Verbose "NSCertNameToUpdate variable was not configured"
		    $ExistingCertificateDetails = $Null
		} else {
		    Write-Verbose "NSCertNameToUpdate variable was configured, trying to retreive data"
		    $Filters = @{"certkey" = "$NSCertNameToUpdate"}
            $ExistingCertificateDetails = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey -Filters $Filters -ErrorAction SilentlyContinue
        }
        if (-Not [string]::IsNullOrEmpty($($ExistingCertificateDetails.sslcertkey.certkey))) {
            $CertificateCertKeyName = $($ExistingCertificateDetails.sslcertkey.certkey)
            Write-Verbose "Existing certificate `"$CertificateCertKeyName`" found on the ADC, start updating"
            try {
                Write-Verbose "Unlinking certificate"
                $payload = @{"certkey" = "$CertificateCertKeyName"; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action unlink
                
            } catch {
                Write-Verbose "Certificate was not linked"
            }
            $NSUpdating = $true
        } else {
            $CertificateCertKeyName = $CertificateName
            $ExistingCertificateDetails = try {Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey -Resource $CertificateName -ErrorAction SilentlyContinue } catch {$null}
            if (-Not [string]::IsNullOrEmpty($ExistingCertificateDetails)) {
                Write-Warning "Certificate `"$CertificateCertKeyName`" already exists, please update manually"
                exit(1)
            }
            $NSUpdating = $false
        }
        $CertificatePfxBase64 = [System.Convert]::ToBase64String($(Get-Content $CertificatePfxFullPath -Encoding "Byte"))
        Write-Verbose "Uploading the Pfx certificate"
        $payload = @{"filename" = "$CertificatePfxFileName"; "filecontent" = "$CertificatePfxBase64"; "filelocation" = "/nsconfig/ssl/"; "fileencoding" = "BASE64"; }
        $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type systemfile -Payload $payload
        Write-Verbose "Converting the Pfx certificate to a pem file ($CertificatePemFileName)"
        $payload = @{"outfile" = "$CertificatePemFileName"; "Import" = "true"; "pkcs12file" = "$CertificatePfxFileName"; "des3" = "true"; "password" = "$PfxPassword"; "pempassphrase" = "$PfxPassword"}
        $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslpkcs12 -Payload $payload -Action convert
        try {
            $payload = @{"certkey" = "$CertificateCertKeyName"; "cert" = "$($CertificatePemFileName)"; "key" = "$($CertificatePemFileName)"; "password" = "true"; "inform" = "PEM"; "passplain" = "$PfxPassword"}
            if ($NSUpdating) {
                Write-Verbose "Update the certificate and key to the ADC config"
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action update
                Write-Verbose "Succeeded"
        
            } else {
                Write-Verbose "Add the certificate and key to the ADC config"
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload
                Write-Verbose "Succeeded"
            }
        } catch {
            Write-Warning "Caught an error, certificate not added to the ADC Config"
            Write-Warning "Details: $($_.Exception.Message | Out-String)"
        }
        Write-Verbose "Link `"$CertificateCertKeyName`" to `"$IntermediateCACertKeyName`""
        try {
            $payload = @{"certkey" = "$CertificateCertKeyName"; "linkcertkeyname" = "$IntermediateCACertKeyName"; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action link
            Write-Verbose "Succeeded"
        } catch {

        }
        if ($SaveNSConfig) {
            Write-Verbose "Saving ADC configuration"
            Invoke-ADCRestApi -Session $ADCSession -Method POST -Type nsconfig -Action save
        }
        ""
        if ($PfxPasswordGenerated) {
            Write-Warning "No Password was specified, so a random password was generated!"
            Write-Host -ForeGroundColor Yellow "`r`n***********************************`r`n"
            Write-Host -ForeGroundColor Yellow "PFX Password.......: $PfxPassword"
            Write-Host -ForeGroundColor Yellow "`r`n***********************************`r`n"
        }
        Write-Host -ForegroundColor White "Certificates"
        Write-Host -ForegroundColor White " -Cert Dir.........: $CertificateDirectory"
        Write-Host -ForegroundColor White " -CRT Filename.....: $CertificateFileName"
        Write-Host -ForegroundColor White " -KEY Filename.....: $CertificateKeyFileName"
        Write-Host -ForegroundColor White " -PFX Filename.....: $CertificatePfxFileName"
        Write-Host -ForegroundColor White " -PFX (with Chain).: $CertificatePfxWithChainFileName"
        ""
        Write-Host -ForeGroundColor Green "Finished with the certificates!"
        ""
        if ($ValidationMethod -eq "dns") {
            Write-Host -ForegroundColor Yellow "`r`n********************************************************************"
            Write-Host -ForegroundColor Yellow "* IMPORTANT: Don't forget to delete the created DNS records!!      *"
            Write-Host -ForegroundColor Yellow "********************************************************************"
            foreach ($Record in $TXTRecords) {
                ""
                Write-Host -ForeGroundColor Yellow -NoNewLine " -DNS Hostname.....: "
                Write-Host -ForeGroundColor Blue "$($Record.fqdn)"
                Write-Host -ForeGroundColor Yellow -NoNewLine " -TXT Record Name..: "
                Write-Host -ForeGroundColor Yellow "$($Record.TXTName)"
            }
            ""        
            Write-Host -ForegroundColor Yellow "********************************************************************"
        }
        if (-not $Production) {
            Write-Host -ForeGroundColor Green "`r`nYou are now ready for the Production version!"
            Write-Host -ForeGroundColor Green "Add the `"-Production`" parameter and rerun the same script.`r`n"
        }
    } catch {
        Write-Verbose "ERROR: $_.Exception.Message"
        Write-Verbose "ERROR: $($_.Exception | Out-String)"
        throw "ERROR. Certificate completion failed, details: $($_.Exception.Message | Out-String)"
    }
}

#endregion Upload certificates to ADC

#region Remove Test Certificates

if ((-not ($CleanADC)) -and $RemoveTestCertificates) {
    Write-Verbose "Login to ADC and save session to global variable"
    $ADCSession = Connect-ADC -ManagementURL $ManagementURL -Credential $Credential -PassThru
    $IntermediateCACertKeyName = "Fake LE Intermediate X1"
    $IntermediateCASerial = "8be12a0e5944ed3c546431f097614fe5"
    Write-Verbose "Retreiving existing certificates"
    $CertDetails = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey
    Write-Verbose "Checking if IntermediateCA `"$IntermediateCACertKeyName`" already exists"
    $IntermediateCADetails = $CertDetails.sslcertkey | Where-Object {$_.serial -eq $IntermediateCASerial}
    $LinkedCertificates = $CertDetails.sslcertkey | Where-Object {$_.linkcertkeyname -eq $IntermediateCADetails.certkey}
    Write-Verbose "The following certificates were found:`n$($LinkedCertificates | Select-Object certkey,linkcertkeyname,serial | Format-List | Out-String)"
    ForEach ($LinkedCertificate in $LinkedCertificates) {
        $payload = @{"certkey" = "$($LinkedCertificate.certkey)"; }
        try {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action unlink
            Write-Host -NoNewLine "ADC, unlinked: "
            Write-Host -ForeGroundColor Green "$($LinkedCertificate.certkey)"
        } catch {
            Write-Warning "Could not unlink certkey `"$($LinkedCertificate.certkey)`""
        }
    }
    $FakeCerts = $CertDetails.sslcertkey | Where-Object {$_.issuer -match $IntermediateCACertKeyName}
    ForEach ($FakeCert in $FakeCerts) {
        try {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type sslcertkey -Resource $($FakeCert.certkey)
            Write-Host -NoNewLine "ADC, removing: "
            Write-Host -ForeGroundColor Green "$($FakeCert.certkey)"
        } catch {
            Write-Warning "Could not delete certkey `"$($FakeCert.certkey)`" from the ADC"
        }
        $CertFilePath = (split-path $($FakeCert.cert) -Parent).Replace("\", "/")
        if ([string]::IsNullOrEmpty($CertFilePath)) {
            $CertFilePath = "/nsconfig/ssl/"
        }
        $CertFileName = split-path $($FakeCert.cert) -Leaf
        Write-Host -NoNewLine "ADC, deleted: "
        Write-Host -ForeGroundColor Green "$(Join-Path -Path $CertFilePath -ChildPath $CertFileName)"
        $KeyFilePath = (split-path $($FakeCert.key) -Parent).Replace("\", "/")
        if ([string]::IsNullOrEmpty($KeyFilePath)) {
            $KeyFilePath = "/nsconfig/ssl/"
        }
        $KeyFileName = split-path $($FakeCert.key) -Leaf
        Write-Host -NoNewLine "ADC, deleted: "
        Write-Host -ForeGroundColor Green "$(Join-Path -Path $KeyFilePath -ChildPath $KeyFileName)"
        $Arguments = @{"filelocation" = "$CertFilePath"; }
        try {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type systemfile -Resource $CertFileName -Arguments $Arguments
        } catch {
            Write-Warning "Could not delete file: `"$CertFileName`" from location: `"$CertFilePath`""
        }
        $Arguments = @{"filelocation" = "$KeyFilePath"; }
        try {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type systemfile -Resource $KeyFileName -Arguments $Arguments
        } catch {
            Write-Warning "Could not delete file: `"$KeyFileName`" from location: `"$KeyFilePath`""
        }
        
    }
    $Arguments = @{"filelocation" = "/nsconfig/ssl"; }
    $CertFiles = Invoke-ADCRestApi -Session $ADCSession -Method Get -Type systemfile -Arguments $Arguments
    $CertFilesToRemove = $CertFiles.systemfile | Where-Object {$_.filename -match "TST-"}
    ForEach ($CertFileToRemove in $CertFilesToRemove) {
        $Arguments = @{"filelocation" = "$($CertFileToRemove.filelocation)"; }
        try {
            Write-Host -NoNewLine "File deleted: "
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type systemfile -Resource $($CertFileToRemove.filename) -Arguments $Arguments
            Write-Host -ForeGroundColor Green "$($CertFileToRemove.filename)"
        } catch {
            Write-Host -ForeGroundColor Red "$($CertFileToRemove.filename) (Error, not removed)"
            Write-Warning "Could not delete file: `"$($CertFileToRemove.filename)`" from location: `"$($CertFileToRemove.filelocation)`""
        }
    }
}

#endregion Remove Test Certificates

#region Final Actions

if ($EnableLogging) {
    Write-Verbose "Stopping the Logging"
    Stop-Transcript
}

#endregion Final Actions
