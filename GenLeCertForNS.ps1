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
    The name of an existing certificate on the ADC. Use the CertKeyName (Name visible in the GUI, not the filename)
    This option will not update this certificate (Use NSCertNameToUpdate parameter for this) instead it will read the values (cn and san) from the certificate.
.PARAMETER CN
    (Common Name) The Primary (first) dns record for the certificate
    Example: "domain.com"
.PARAMETER SAN
    (Subject Alternate Name) every following domain listed in this certificate. separated via an comma , and between quotes "".
    Example: "sts.domain.com","www.domain.com","vpn.domain.com"
    Example Wildcard: "*.domain.com","*.pub.domain.com"
    NOTE: Only a DNS verification is possible when using WildCards!
.PARAMETER FriendlyName
    The display name of the certificate, if not specified the CN will used. You can specify an empty value if required.
    Example (Empty display name) : ""
    Example (Set your own name) : "Custom Name"
.PARAMETER Production
    Use the production Let's encrypt server, without this parameter the staging (test) server will be used
.PARAMETER DisableIPCheck
    If you want to skip the IP Address verification, specify this parameter
.PARAMETER CleanPoshACMEStorage
    Force cleanup of the Posh-Acme certificates located in "%LOCALAPPDATA%\Posh-ACME"
.PARAMETER SaveNSConfig
    Save the ADC config after all the changes
.PARAMETER SendMail
    Specify this parameter if you want to send a mail at the end, don't forget to specify SMTPTo, SMTPFrom, SMTPServer and if required SMTPCredential
.PARAMETER SMTPTo
    Specify one or more email addresses.
    Email addresses can be specified as "user.name@domain.com" or "User Name <user.name@domain.com>"
    If specifying multiple email addresses, separate them wit a comma.
.PARAMETER SMTPFrom
    Specify the Email address where mails are send from
    The email addres can be specified as "user.name@domain.com" or "User Name <user.name@domain.com>"
.PARAMETER SMTPServer
    Specify the SMTP Mail server fqdn or IP-address
.PARAMETER SMTPCredential
    Specify the Mail server credentials, only if credentials are required to send mails
.PARAMETER EnableLogging
    Start logging to file. The name of the log file can be specified with the "-LogLocation" parameter
.PARAMETER LogLocation
    Specify the log file name, default "<Current Script Dir>\GenLeCertForNS_log.txt"
.PARAMETER LogLevel
    The Log level you want to have specified.
    With LogLevel: Error; Only Error (E) data will be written or shown.
    With LogLevel: Warning; Only Error (E) and Warning (W) data will be written or shown.
    With LogLevel: Info; Only Error (E), Warning (W) and Info (I) data will be written or shown.
    With LogLevel: Debug; All, Error (E), Warning (W), Info (I) and Debug (D) data will be written or shown.
    You can also define a (Global) variable in your script $LogLevel, the function will use this level instead (if not specified with the command)
    Default value: Info
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
    Version   : v2.7.5
    Author    : John Billekens
    Requires  : PowerShell v5.1 and up
                ADC 11.x and up
                Run As Administrator
                Posh-ACME 3.12.0 (Will be installed via this script) Thank you @rmbolger for providing the HTTP validation method!
                Microsoft .NET Framework 4.7.1 or later (when using Posh-ACME/WildCard certificates)
.LINK
    https://blog.j81.nl
#>

[cmdletbinding(DefaultParameterSetName = "LECertificates")]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", "")]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "")]
param(
    [Parameter(ParameterSetName = "Help", Mandatory = $true)]
    [alias("h")]
    [Switch]$Help,

    [Parameter(ParameterSetName = "CleanADC", Mandatory = $true)]
    [alias("CleanNS")]
    [Switch]$CleanADC,

    [Parameter(ParameterSetName = "GetExisting", Mandatory = $true)]
    [Switch]$GetValuesFromExistingCertificate,

    [Parameter(ParameterSetName = "GetExisting", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$ExistingCertificateName,

    [Parameter(ParameterSetName = "CleanTestCertificate", Mandatory = $true)]
    [Switch]$RemoveTestCertificates,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanTestCertificate", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanPoshACMEStorage", Mandatory = $true)]
    [Switch]$CleanPoshACMEStorage,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $true)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $true)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $true)]
    [Parameter(ParameterSetName = "CleanTestCertificate", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [alias("URL", "NSManagementURL")]
    [String]$ManagementURL,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanTestCertificate", Mandatory = $false)]
    [alias("User", "NSUsername")]
    [String]$Username,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanTestCertificate", Mandatory = $false)]
    [ValidateScript( {
            if ($_ -is [SecureString]) {
                return $true
            } elseif ($_ -is [String]) {
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
            } elseif ($_ -is [String]) {
                $Script:Credential = Get-Credential -Credential $_
                return $true
            } else {
                throw "You passed an unexpected object type for the credential (-Credential)"
            }
        })][alias("NSCredential")]
    [object]$Credential,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$CN,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [string[]]$SAN = @(),

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [String]$FriendlyName = $CN,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [ValidateSet('http', 'dns', IgnoreCase = $true)]
    [String]$ValidationMethod = "http",

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [String]$NSCsVipName,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [String]$NSCsVipBinding = 11,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [String]$NSSvcName = "svc_letsencrypt_cert_dummy",

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [String]$NSSvcDestination = "1.2.3.4",

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [String]$NSLbName = "lb_letsencrypt_cert",

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [String]$NSRspName = "rsp_letsencrypt",

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [String]$NSRsaName = "rsa_letsencrypt",

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [String]$NSCspName = "csp_NSCertCsp",

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [String]$NSCertNameToUpdate,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $true)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$CertDir,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [String]$PfxPassword = $null,

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
    [String]$EmailAddress,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Switch]$DisableIPCheck,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $false)]
    [Switch]$SaveNSConfig,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Switch]$SendMail,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [String[]]$SMTPTo,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [String]$SMTPFrom,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]$SMTPCredential = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [String]$SMTPServer,

    [Parameter(Mandatory = $false)]
    [Switch]$EnableLogging,

    [Parameter(Mandatory = $false)]
    [Switch]$DisableLogging,

    [ValidateNotNullOrEmpty()]
    [alias("LogLocation")]
    [String]$LogFile = "$($PSScriptRoot)\GenLeCertForNS_log.txt",

    [ValidateSet("Error", "Warning", "Info", "Debug", "None", IgnoreCase = $false)]
    [String]$LogLevel = "Info",

    [Parameter(ParameterSetName = "LECertificates", Mandatory = $false)]
    [Parameter(ParameterSetName = "GetExisting", Mandatory = $false)]
    [Switch]$Production

)

#requires -version 5.1
#Requires -RunAsAdministrator
$ScriptVersion = "2.7.5"
$PoshACMEVersion = "3.12.0"
$VersionURI = "https://drive.google.com/uc?export=download&id=1WOySj40yNHEza23b7eZ7wzWKymKv64JW"

#region Functions

function Write-ToLogFile {
    <#
.SYNOPSIS
    Write messages to a log file.
.DESCRIPTION
    Write info to a log file.
.PARAMETER Message
    The message you want to have written to the log file.
.PARAMETER Block
    If you have a (large) block of data you want to have written without Date/Component tags, you can specify this parameter.
.PARAMETER E
    Define the Message as an Error message.
.PARAMETER W
    Define the Message as a Warning message.
.PARAMETER I
    Define the Message as an Informational message.
    Default value: This is the default value for all messages if not otherwise specified.
.PARAMETER D
    Define the Message as a Debug Message
.PARAMETER Component
    If you want to have a Component name in your log file, you can specify this parameter.
    Default value: Name of calling script
.PARAMETER DateFormat
    The date/time stamp used in the LogFile.
    Default value: "yyyy-MM-dd HH:mm:ss:ffff"
.PARAMETER NoDate
    If NoDate is defined, no date string will be added to the log file.
    Default value: False
.PARAMETER Show
    Show the Log Entry only to console.
.PARAMETER LogFile
    The FileName of your log file.
    You can also define a (Global) variable in your script $LogFile, the function will use this path instead (if not specified with the command).
    Default value: <ScriptRoot>\Log.txt or if $PSScriptRoot is not available .\Log.txt
.PARAMETER Delimiter
    Define your Custom Delimiter of the log file.
    Default value: <TAB>
.PARAMETER LogLevel
    The Log level you want to have specified.
    With LogLevel: Error; Only Error (E) data will be written or shown.
    With LogLevel: Warning; Only Error (E) and Warning (W) data will be written or shown.
    With LogLevel: Info; Only Error (E), Warning (W) and Info (I) data will be written or shown.
    With LogLevel: Debug; All, Error (E), Warning (W), Info (I) and Debug (D) data will be written or shown.
    With LogLevel: None; Nothing will be written to disk or screen.
    You can also define a (Global) variable in your script $LogLevel, the function will use this level instead (if not specified with the command)
    Default value: Info
.PARAMETER NoLogHeader
    Specify parameter if you don't want the log file to start with a header.
    Default value: False
.PARAMETER WriteHeader
    Only Write header with info to the log file.
.PARAMETER ExtraHeaderInfo
    Specify a string with info you want to add to the log header.
.PARAMETER NewLog
    Force to start a new log, previous log will be removed.
.EXAMPLE
    Write-ToLogFile "This message will be written to a log file"
    To write a message to a log file just specify the following command, it will be a default informational message.
.EXAMPLE
    Write-ToLogFile -E "This message will be written to a log file"
    To write a message to a log file just specify the following command, it will be a error message type.
.EXAMPLE
    Write-ToLogFile "This message will be written to a log file" -NewLog
    To start a new log file (previous log file will be removed)
.EXAMPLE
    Write-ToLogFile "This message will be written to a log file"
    If you have the variable $LogFile defined in your script, the Write-ToLogFile function will use that LofFile path to write to.
    E.g. $LogFile = "C:\Path\LogFile.txt"
.NOTES
    Function Name : Write-ToLogFile
    Version       : v0.2.6
    Author        : John Billekens
    Requires      : PowerShell v5.1 and up
.LINK
    https://blog.j81.nl
#>
    #requires -version 5.1

    [CmdletBinding(DefaultParameterSetName = "Info")]
    Param
    (
        [Parameter(ParameterSetName = "Error", Mandatory = $true, Position = 0)]
        [Parameter(ParameterSetName = "Warning", Mandatory = $true, Position = 0)]
        [Parameter(ParameterSetName = "Info", Mandatory = $true, Position = 0)]
        [Parameter(ParameterSetName = "Debug", Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias("M")]
        [string[]]$Message,

        [Parameter(ParameterSetName = "Block", Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("B")]
        [object[]]$Block,

        [Parameter(ParameterSetName = "Block", Mandatory = $false)]
        [Alias("BI")]
        [Switch]$BlockIndent,

        [Parameter(ParameterSetName = "Error")]
        [Switch]$E,

        [Parameter(ParameterSetName = "Warning")]
        [Switch]$W,

        [Parameter(ParameterSetName = "Info")]
        [Switch]$I,

        [Parameter(ParameterSetName = "Debug")]
        [Switch]$D,

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Alias("C")]
        [String]$Component = $(try { $(Split-Path -Path $($MyInvocation.ScriptName) -Leaf) } catch { "LOG" }),

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Alias("ND")]
        [Switch]$NoDate,

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [ValidateNotNullOrEmpty()]
        [Alias("DF")]
        [String]$DateFormat = "yyyy-MM-dd HH:mm:ss:ffff",

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Parameter(ParameterSetName = "Block")]
        [Alias("S")]
        [Switch]$Show,

        [String]$LogFile = "$PSScriptRoot\Log.txt",

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [String]$Delimiter = "`t",

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [ValidateSet("Error", "Warning", "Info", "Debug", "None", IgnoreCase = $false)]
        [String]$LogLevel,

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Parameter(ParameterSetName = "Block")]
        [Alias("NH", "NoHead")]
        [Switch]$NoLogHeader,
        
        [Parameter(ParameterSetName = "Head")]
        [Alias("H", "Head")]
        [Switch]$WriteHeader,

        [Alias("HI")]
        [String]$ExtraHeaderInfo = $null,

        [Alias("NL")]
        [Switch]$NewLog
    )
    # Set Message Type to Informational if nothing is defined.
    if ((-Not $I) -and (-Not $W) -and (-Not $E) -and (-Not $D) -and (-Not $Block) -and (-Not $WriteHeader)) {
        $I = $true
    }
    #Check if a log file is defined in a Script. If defined, get value.
    try {
        $LogFileVar = Get-Variable -Scope Global -Name LogFile -ValueOnly -ErrorAction Stop
        if (-Not [String]::IsNullOrWhiteSpace($LogFileVar)) {
            $LogFile = $LogFileVar
            
        }
    } catch {
        #Continue, no script variable found for LogFile
    }
    #Check if a LogLevel is defined in a script. If defined, get value.
    try {
        if ([String]::IsNullOrEmpty($LogLevel) -and (-Not $Block) -and (-Not $WriteHeader)) {
            $LogLevelVar = Get-Variable -Scope Global -Name LogLevel -ValueOnly -ErrorAction Stop
            $LogLevel = $LogLevelVar
        }
    } catch { 
        if ([String]::IsNullOrEmpty($LogLevel) -and (-Not $Block)) {
            $LogLevel = "Info"
        }
    }
    if (-Not ($LogLevel -eq "None")) {
        #Check if LogFile parameter is empty
        if ([String]::IsNullOrWhiteSpace($LogFile)) {
            if (-Not $Show) {
                Write-Warning "Messages not written to log file, LogFile path is empty!"
            }
            #Only Show Entries to Console
            $Show = $true
        } else {
            #If Not Run in a Script "$PSScriptRoot" wil only contain "\" this will be changed to the current directory
            $ParentPath = Split-Path -Path $LogFile -Parent -ErrorAction SilentlyContinue
            if (([String]::IsNullOrEmpty($ParentPath)) -or ($ParentPath -eq "\")) {
                $LogFile = $(Join-Path -Path $((Get-Item -Path ".\").FullName) -ChildPath $(Split-Path -Path $LogFile -Leaf))
            }
        }
        Write-Verbose "LogFile: $LogFile"
        #Define Log Header
        if (-Not $Show) {
            if (
                (-Not ($NoLogHeader -eq $True) -and (-Not (Test-Path -Path $LogFile -ErrorAction SilentlyContinue))) -or 
                (-Not ($NoLogHeader -eq $True) -and ($NewLog)) -or
                ($WriteHeader)) {
                $LogHeader = @"
**********************
LogFile: $LogFile
Start time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Username: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)
RunAs Admin: $((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Machine: $($Env:COMPUTERNAME) ($([System.Environment]::OSVersion.VersionString))
PSCulture: $($PSCulture)
PSVersion: $($PSVersionTable.PSVersion)
PSEdition: $($PSVersionTable.PSEdition)
PSCompatibleVersions: $($PSVersionTable.PSCompatibleVersions -join ', ')
BuildVersion: $($PSVersionTable.BuildVersion)
PSCommandPath: $($PSCommandPath)
LanguageMode: $($ExecutionContext.SessionState.LanguageMode)
"@
                if (-Not [String]::IsNullOrEmpty($ExtraHeaderInfo)) {
                    $LogHeader += "`r`n"
                    $LogHeader += $ExtraHeaderInfo.TrimEnd("`r`n")
                }
                $LogHeader += "`r`n**********************`r`n"

            } else {
                $LogHeader = $null
            }
        }
    } else {
        Write-Verbose "LogLevel is set to None!"
    }
    #Define date string to start log message with. If NoDate is defined no date string will be added to the log file.
    if (-Not ($LogLevel -eq "None")) {
        if (-Not ($NoDate) -and (-Not $Block) -and (-Not $WriteHeader)) {
            $DateString = "{0}{1}" -f $(Get-Date -Format $DateFormat), $Delimiter
        } else {
            $DateString = $null
        }
        if (-Not [String]::IsNullOrEmpty($Component) -and (-Not $Block) -and (-Not $WriteHeader)) {
            $Component = " {0}{1}{0}" -f $Delimiter, $Component.ToUpper()
        } else {
            $Component = "{0}{0}" -f $Delimiter
        }
        #Define the log sting for the Message Type
        if ($Block -or $WriteHeader) {
            $WriteLog = $true
        } elseif ($E -and (($LogLevel -eq "Error") -or ($LogLevel -eq "Warning") -or ($LogLevel -eq "Info") -or ($LogLevel -eq "Debug"))) {
            Write-Verbose -Message "LogType: [Error], LogLevel: [$LogLevel]"
            $MessageType = "ERROR"
            $WriteLog = $true
        } elseif ($W -and (($LogLevel -eq "Warning") -or ($LogLevel -eq "Info") -or ($LogLevel -eq "Debug"))) {
            Write-Verbose -Message "LogType: [Warning], LogLevel: [$LogLevel]"
            $MessageType = "WARN "
            $WriteLog = $true
        } elseif ($I -and (($LogLevel -eq "Info") -or ($LogLevel -eq "Debug"))) {
            Write-Verbose -Message "LogType: [Info], LogLevel: [$LogLevel]"
            $MessageType = "INFO "
            $WriteLog = $true
        } elseif ($D -and (($LogLevel -eq "Debug"))) {
            Write-Verbose -Message "LogType: [Debug], LogLevel: [$LogLevel]"
            $MessageType = "DEBUG"
            $WriteLog = $true
        } else {
            Write-Verbose -Message "No Log entry is made LogType: [Error: $E, Warning: $W, Info: $I, Debug: $D] LogLevel: [$LogLevel]"
            $WriteLog = $false
        }
    } else {
        $WriteLog = $false
    }
    #Write the line(s) of text to a file.
    if ($WriteLog) {
        if ($WriteHeader) {
            $LogString = $LogHeader
        } elseif ($Block) {
            if ($BlockIndent) {
                $BlockLineStart = "{0}{0}{0}" -f $Delimiter
            } else {
                $BlockLineStart = ""
            }
            if ($Block -is [System.String]) {
                $LogString = "{0]{1}" -f $BlockLineStart, $Block.Replace("`r`n", "`r`n$BlockLineStart")
            } else {
                $LogString = "{0}{1}" -f $BlockLineStart, $($Block | Out-String).Replace("`r`n", "`r`n$BlockLineStart")
            }
            $LogString = "$($LogString.TrimEnd("$BlockLineStart").TrimEnd("`r`n"))`r`n"
        } else {
            $LogString = "{0}{1}{2}{3}" -f $DateString, $MessageType, $Component, $($Message | Out-String)
        }
        if ($Show) {
            "$($LogString.TrimEnd("`r`n"))"
            Write-Verbose -Message "Data shown in console, not written to file!"

        } else {
            if (($LogHeader) -and (-Not $WriteHeader)) {
                $LogString = "{0}{1}" -f $LogHeader, $LogString
            }
            try {
                if ($NewLog) {
                    try {
                        Remove-Item -Path $LogFile -Force -ErrorAction Stop
                        Write-Verbose -Message "Old log file removed"
                    } catch {
                        Write-Verbose -Message "Could not remove old log file, trying to append"
                    }
                }
                [System.IO.File]::AppendAllText($LogFile, $LogString, [System.Text.Encoding]::Unicode)
                Write-Verbose -Message "Data written to LogFile:`r`n         `"$LogFile`""
            } catch {
                #If file cannot be written, give an error
                Write-Error -Category WriteError -Message "Could not write to file `"$LogFile`""
            }
        }
    } else {
        Write-Verbose -Message "Data not written to file!"
    }
}

function Invoke-ADCRestApi {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSObject]$Session,

        [Parameter(Mandatory = $true)]
        [ValidateSet('DELETE', 'GET', 'POST', 'PUT')]
        [String]$Method,

        [Parameter(Mandatory = $true)]
        [String]$Type,

        [String]$Resource,

        [String]$Action,

        [hashtable]$Arguments = @{ },

        [Switch]$Stat = $false,

        [ValidateScript( { $Method -eq 'GET' })]
        [hashtable]$Filters = @{ },

        [ValidateScript( { $Method -ne 'GET' })]
        [hashtable]$Payload = @{ },

        [Switch]$GetWarning = $false,

        [ValidateSet('EXIT', 'CONTINUE', 'ROLLBACK')]
        [String]$OnErrorAction = 'EXIT'
    )
    # https://github.com/devblackops/NetScaler
    if ([String]::IsNullOrEmpty($($Session.ManagementURL))) {
        Write-ToLogFile -E -C Invoke-ADCRestApi -M "Probably not logged into the Citrix ADC!"
        throw "ERROR. Probably not logged into the ADC"
    }
    if ($Stat) {
        $uri = "$($Session.ManagementURL)/nitro/v1/stat/$Type"
    } else {
        $uri = "$($Session.ManagementURL)/nitro/v1/config/$Type"
    }
    if (-not ([String]::IsNullOrEmpty($Resource))) {
        $uri += "/$Resource"
    }
    if ($Method -ne 'GET') {
        if (-not ([String]::IsNullOrEmpty($Action))) {
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
    Write-ToLogFile -D -C Invoke-ADCRestApi -M "URI: $uri"

    $jsonPayload = $null
    if ($Method -ne 'GET') {
        $warning = if ($GetWarning) { 'YES' } else { 'NO' }
        $hashtablePayload = @{ }
        $hashtablePayload.'params' = @{'warning' = $warning; 'onerror' = $OnErrorAction; <#"action"=$Action#> }
        $hashtablePayload.$Type = $Payload
        $jsonPayload = ConvertTo-Json -InputObject $hashtablePayload -Depth 100 -Compress
        Write-ToLogFile -D -C Invoke-ADCRestApi -M "JSON Payload: $($jsonPayload | ConvertTo-Json -Compress)"
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
                Write-ToLogFile -E -C Invoke-ADCRestApi -M "Got an ERROR response: $($response| ConvertTo-Json -Compress)"
                throw "Error. See log"
            } else {
                Write-ToLogFile -D -C Invoke-ADCRestApi -M "Response: $($response | ConvertTo-Json -Compress)"
                if ($Method -eq "GET") { 
                    return $response 
                }
            }
        }
    } catch [Exception] {
        if ($Type -eq 'reboot' -and $restError[0].Message -eq 'The underlying connection was closed: The connection was closed unexpectedly.') {
            Write-ToLogFile -I -C Invoke-ADCRestApi -M "Connection closed due to reboot."
        } else {
            Write-ToLogFile -E -C Invoke-ADCRestApi -M "Caught an error. Exception Message: $($_.Exception.Message)"
            throw $_
        }
    }
}

function TerminateScript {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [int]$ExitCode,

        [Parameter(Position = 1)]
        [String]$ExitMessage = $null
    )
    if (-Not [String]::IsNullOrEmpty($ExitMessage)) {
        Write-ToLogFile -I -C Final -M "$ExitMessage"
    }
    if ($SendMail) {
        Write-ToLogFile -I -C Final -M "Script Terminated, Sending mail. ExitCode: $ExitCode"
        if (-Not ($ExitCode -eq 0)) {
            $SMTPSubject = "GenLeCertForNS Finished with an Error - $CN"
            $SMTPBody = @"
GenLeCertForNS Finished with an Error!
$ExitMessage

Check log for errors and more details.
"@
        } else {
            $SMTPSubject = "GenLeCertForNS Finished Successfully - $CN"
            $SMTPBody = @"
GenLeCertForNS Finished Successfully

$($MailData | Out-String)
"@
        }
        try {
            Write-Host -ForeGroundColor White "`r`nEmail"
            Write-Host -ForeGroundColor White -NoNewLine " -Sending Mail..........: "
        
            $message = New-Object System.Net.Mail.MailMessage
            $message.From = $SMTPFrom
            foreach ($to in $SMTPTo) {
                $message.To.Add($to)
            }
            $message.Subject = $SMTPSubject
            $message.IsBodyHTML = $false
        
            $message.Body = $SMTPBody
            try {
                $message.Attachments.Add($(New-Object System.Net.Mail.Attachment "$LogFile"))
            } catch {
                Write-ToLogFile -E -C SendMail -M "Could not attach LogFile, Error Details: $($_.Exception.Message)"
                Write-Host -ForeGroundColor Red -NoNewLine "Could not attach LogFile "
            }
            $smtp = New-Object Net.Mail.SmtpClient($SMTPServer)
            if (-Not ($SMTPCredential -eq [PSCredential]::Empty)) {
                $smtp.Credentials = $SMTPCredential
            }
            $smtp.Send($message)
            Write-Host -ForeGroundColor Green "OK"
        } catch {
            Write-ToLogFile -E -C SendMail -M "Could not send mail: $($_.Exception.Message)"
            Write-Host -ForeGroundColor Red "ERROR, Could not send mail: $($_.Exception.Message)"
        }
        
    } else {
        Write-ToLogFile -I -C Final -M "Script Terminated, ExitCode: $ExitCode"
        
    }

    if ($ExitCode -eq 0) {
        ""
        Write-Host -ForegroundColor Green "Finished! $ExitMessage"
    } else {
        ""
        Write-Host -ForegroundColor Red "Finished with Errors! $ExitMessage"
    }
    exit $ExitCode
}

function Connect-ADC {
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        [String]$ManagementURL,

        [parameter(Mandatory)]
        [PSCredential]$Credential,

        [int]$Timeout = 3600,

        [Switch]$PassThru
    )
    # https://github.com/devblackops/NetScaler


    if ($ManagementURL -like "https://*") {
        Write-ToLogFile -D -C Connect-ADC -M "SSL Connection, Trusting all certificates."
        $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
        $Provider.CreateCompiler() | Out-Null
        $Params = New-Object System.CodeDom.Compiler.CompilerParameters
        $Params.GenerateExecutable = $false
        $Params.GenerateInMemory = $true
        $Params.IncludeDebugInformation = $false
        $Params.ReferencedAssemblies.Add("System.DLL") > $null
        $TASource = @'
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
        $TAResults = $Provider.CompileAssemblyFromSource($Params, $TASource)
        $TAAssembly = $TAResults.CompiledAssembly
        $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
        [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
    }
    Write-ToLogFile -I -C Connect-ADC -M "Connecting to $ManagementURL..."
    try {
        $login = @{
            login = @{
                Username = $Credential.Username;
                password = $Credential.GetNetworkCredential().Password
                timeout  = $Timeout
            }
        }
        $loginJson = ConvertTo-Json -InputObject $login -Compress
        $saveSession = @{ }
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
            Write-ToLogFile -E -C Connect-ADC -M "Caught an error. Response: $($response | Select-Object message,severity,errorcode | ConvertTo-Json -Compress)"
            Write-Error "Error. See log"
            TerminateScript 1 "Error. See log"
        } else {
            Write-ToLogFile -D -C Connect-ADC -M "Response: $($response | Select-Object message,severity,errorcode | ConvertTo-Json -Compress)"
        }
    } catch [Exception] {
        throw $_
    }
    $session = [PSObject]@{
        ManagementURL = [String]$ManagementURL;
        WebSession    = [Microsoft.PowerShell.Commands.WebRequestSession]$saveSession;
        Username      = $Credential.Username;
        Version       = "UNKNOWN";
    }
    try {
        Write-ToLogFile -D -C Connect-ADC -M "Trying to retrieve the ADC version"
        $params = @{
            Uri           = "$ManagementURL/nitro/v1/config/nsversion"
            Method        = 'GET'
            WebSession    = $Session.WebSession
            ContentType   = 'application/json'
            ErrorVariable = 'restError'
            Verbose       = $false
        }
        $response = Invoke-RestMethod @params
        Write-ToLogFile -D -C Connect-ADC -M "Response: $($response | ConvertTo-Json -Compress)"
        $version = $response.nsversion.version.Split(",")[0]
        if (-not ([String]::IsNullOrWhiteSpace($version))) {
            $session.version = $version
        }
        Write-ToLogFile -I -C Connect-ADC -M "Connected"
    } catch {
        Write-ToLogFile -E -C Connect-ADC -M "Caught an error. Exception Message: $($_.Exception.Message)"
        Write-ToLogFile -E -C Connect-ADC -M "Response: $($response | ConvertTo-Json -Compress)"
    }
    $Script:NSSession = $session

    if ($PassThru) {
        return $session
    }
}

function ConvertTo-TxtValue([String]$KeyAuthorization) {
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
        [String]$Name
    )
    try {
        Write-ToLogFile -I -C Get-ADCCurrentCertificate -M "Trying to retrieve current certificate data from the Citrix ADC."
        $adcCert = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey -Resource $Name -ErrorAction SilentlyContinue
        $currentCert = $adcCert.sslcertkey
        Write-ToLogFile -D -C Get-ADCCurrentCertificate -M "Certificate match:"
        $currentCert | Select-Object certkey, subject, status, clientcertnotbefore, clientcertnotafter | ForEach-Object {
            Write-ToLogFile -D -C Get-ADCCurrentCertificate -M "$($_ | ConvertTo-Json -Compress)"
        }
        if ($currentCert.certKey -eq $Name) {
            $payload = @{"filename" = "$(($currentCert.cert).Replace('/nsconfig/ssl/',''))"; "filelocation" = "/nsconfig/ssl/" }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type systemfile -Arguments $payload -ErrorAction SilentlyContinue
            if (-Not ([String]::IsNullOrWhiteSpace($response.systemfile.filecontent))) {
                Write-ToLogFile -D -C Get-ADCCurrentCertificate -M "Certificate available, getting the details."
                $content = [System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($response.systemfile.filecontent))
                $Pattern = '(?smi)^-{2,}BEGIN CERTIFICATE-{2,}.*?-{2,}END CERTIFICATE-{2,}'
                $result = [Regex]::Match($content, $Pattern)
                $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $Cert.Import([byte[]][char[]]$($result[0].Value))
                $cn = $cert.Subject.Replace("CN=", "")
                Write-ToLogFile -I -C Get-ADCCurrentCertificate -M "CN: $($cn)"
                $san = $cert.DnsNameList.Unicode
                Write-ToLogFile -I -C Get-ADCCurrentCertificate -M "SAN: $($san | ConvertTo-Json -Compress)"
            } else {
                Write-Warning "Could not retrieve the certificate"
                Write-ToLogFile -W -C Get-ADCCurrentCertificate -M "Could not retrieve the certificate."
            }
        } else {
            Write-ToLogFile -D -C Get-ADCCurrentCertificate -M "Certificate `"$Name`" not found."
        }
    } catch {
        Write-Warning "Could not retrieve certificate info"
        Write-ToLogFile -W -C Get-ADCCurrentCertificate -M "Could not retrieve certificate info."
        Write-Warning "Details: $($_.Exception.Message | Out-String)"
        Write-ToLogFile -W -C Get-ADCCurrentCertificate -M "Details: $($_.Exception.Message | Out-String)"
        $cn = $null
        $san = $null
    }
    Write-ToLogFile -I -C Get-ADCCurrentCertificate -M "Finished."
    return [pscustomobject] @{
        CN          = $cn
        SAN         = $san
        Certificate = $Cert
    }
}

function Invoke-CheckScriptVersions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$URI
    )
    try {
        Write-ToLogFile -D -C Invoke-CheckScriptVersions -M "Retrieving data for URI: $URI"
        $AvailableVersions = Invoke-RestMethod -Method Get -UseBasicParsing -Uri $URI -ErrorAction SilentlyContinue
        Write-ToLogFile -D -C Invoke-CheckScriptVersions -M "Successfully retrieved the requested data"
    } catch {
        Write-ToLogFile -D -C Invoke-CheckScriptVersions -M "Could not retrieve version info. Exception Message: $($_.Exception.Message)"
        $AvailableVersions = $null
    }
    return $AvailableVersions
}

#endregion Functions

#region ScriptBasics

if ($EnableLogging) {
    Write-Warning "-EnableLogging is deprecated"
}
if ($DisableLogging) {
    $LogLevel = "None"
} else {
    $LogPath = Split-Path -Path $LogFile -Parent -ErrorAction SilentlyContinue
    if ([String]::IsNullOrEmpty($LogPath)) {
        if ([String]::IsNullOrEmpty($PSScriptRoot)) {
            $LogPath = "."
        } else {
            $LogPath = "$PSScriptRoot"
        }
    }
    $LogPath = Resolve-Path $LogPath
    $LogFileName = Split-Path -Path $LogFile -Leaf
    $LogFile = Join-Path -Path $LogPath -ChildPath $LogFileName
    $Global:LogFile = $LogFile
    $ExtraHeaderInfo = @"
PSScriptRoot: $PSScriptRoot
Script Version: $ScriptVersion
PoSH ACME Version: $PoshACMEVersion
PSBoundParameters:
$($PSBoundParameters | Out-String)
"@
    Write-ToLogFile -I -C ScriptBasics -M "Starting a new log" -NewLog -ExtraHeaderInfo $ExtraHeaderInfo
    Write-Host -ForeGroundColor White "`r`nLogging Active"
    Write-Host -ForeGroundColor White -NoNewLine " -Log File..............: "
    Write-Host -ForeGroundColor Blue "$LogFile"
    Write-Host -ForeGroundColor White -NoNewLine " -Log Level.............: "
    Write-Host -ForeGroundColor Blue "$LogLevel"
}

if ($GetValuesFromExistingCertificate) {
    "`r`n"
    Write-Warning "The option -GetValuesFromExistingCertificate is still BETA!"
    Write-ToLogFile -W -C ScriptBasics -M "The option -GetValuesFromExistingCertificate is still BETA!"
    "`r`n"
}

#endregion ScriptBasics

#region EmailSetup

$MailData = @()
if ($SendMail) {
    $SMTPError = @()
    Write-Host -ForeGroundColor White "`r`nEmail Details"
    Write-Host -ForeGroundColor White -NoNewLine " -Email To Address......: "
    if ([String]::IsNullOrEmpty($SMTPTo)) {
        Write-Host -ForeGroundColor Red "None"
        Write-ToLogFile -E -C EmailSettings -M "No To Address specified (-SMTPTo)"
        $SMTPError += "No To Address specified (-SMTPTo)"
    } else {
        Write-Host -ForeGroundColor Blue "$SMTPTo"
        Write-ToLogFile -I -C EmailSettings -M "Email To Address: $SMTPTo"
    }
    Write-Host -ForeGroundColor White -NoNewLine " -Email From Address....: "
    if ([String]::IsNullOrEmpty($SMTPFrom)) {
        Write-Host -ForeGroundColor Red "None"
        Write-ToLogFile -E -C EmailSettings -M "No From Address specified (-SMTPFrom)"
        $SMTPError += "No From Address specified (-SMTPFrom)"
    } else {
        Write-Host -ForeGroundColor Blue "$SMTPFrom"
        Write-ToLogFile -I -C EmailSettings -M "Email To Address: $SMTPFrom"
    }
    Write-Host -ForeGroundColor White -NoNewLine " -Email Server..........: "
    if ([String]::IsNullOrEmpty($SMTPServer)) {
        Write-Host -ForeGroundColor Red "None"
        Write-ToLogFile -E -C EmailSettings -M "No Email (SMTP) Server specified (-SMTPServer)"
        $SMTPError += "No Email (SMTP) Server specified (-SMTPServer)"
    } else {
        Write-Host -ForeGroundColor Blue "$SMTPServer"
        Write-ToLogFile -I -C EmailSettings -M "Email Server: $SMTPServer"
    }
    Write-Host -ForeGroundColor White -NoNewLine " -Email Credentials.....: "
    if ($SMTPCredential -eq [PSCredential]::Empty) {
        Write-Host -ForeGroundColor Blue "(Optional) None"
        Write-ToLogFile -I -C EmailSettings -M "No Email Credential specified, this is optional"
    } else {
        Write-Host -ForeGroundColor Blue "$($SMTPCredential.UserName) (Credential)"
        Write-ToLogFile -I -C EmailSettings -M "Email Credential: $($SMTPCredential.UserName)"
    }
    if (-Not [String]::IsNullOrEmpty($SMTPError)) {
        $SendMail = $false
        TerminateScript 1 "Incorrect values, check mail settings.`r`n$($SMTPError | Out-String)"
    }
}

#endregion MailSetup

#region Help

if ($Help -or ($PSBoundParameters.Count -eq 0)) {
    Get-Help "$PSScriptRoot\GenLeCertForNS.ps1" -Detailed
    TerminateScript 0 "Displaying the Detailed help info for: `"$PSScriptRoot\GenLeCertForNS.ps1`""
    $SendMail = $false
}
#endregion Help

#region DOTNETCheck
Write-ToLogFile -I -C DOTNETCheck -M "Checking if .NET Framework 4.7.1 or higher is installed."
$NetRelease = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release).Release
if ($NetRelease -lt 461308) {
    Write-ToLogFile -W -C DOTNETCheck -M ".NET Framework 4.7.1 or higher is NOT installed."
    Write-Host -NoNewLine -ForeGroundColor RED "`n`nWARNING: "
    Write-Host ".NET Framework 4.7.1 or higher is not installed, please install before continuing!"
    Start-Process https://www.microsoft.com/net/download/dotnet-framework-runtime
    TerminateScript 1 ".NET Framework 4.7.1 or higher is not installed, please install before continuing!"
} else {
    Write-ToLogFile -I -C DOTNETCheck -M ".NET Framework 4.7.1 or higher is installed."
}

#endregion DOTNETCheck

#region ScriptVariables

Write-ToLogFile -I -C ScriptVariables -M "ValidationMethod is set to: `"$ValidationMethod`"."
$PublicDnsServer = "1.1.1.1"

Write-ToLogFile -D -C ScriptVariables -M "Setting session DATE/TIME variable."
[DateTime]$ScriptDateTime = Get-Date
[String]$SessionDateTime = $ScriptDateTime.ToString("yyyyMMdd-HHmmss")
Write-ToLogFile -D -C ScriptVariables -M "Session DATE/TIME variable value: `"$SessionDateTime`"."

if (-not $PfxPassword) {
    try {
        $length = 15
        Add-Type -AssemblyName System.Web | Out-Null
        $PfxPassword = [System.Web.Security.Membership]::GeneratePassword($length, 2)
        $PfxPasswordGenerated = $true
        Write-ToLogFile -I -C ScriptVariables -M "No PfxPassword was specified therefore a new one was generated."
    } catch {
        Write-ToLogFile -E -C ScriptVariables -M "An error occurred while generating a Password. Exception Message: $($_.Exception.Message)"
    }
} else {
    $PfxPasswordGenerated = $false
    Write-ToLogFile -I -C ScriptVariables -M "PfxPassword was specified via parameter."
}

if (-not([String]::IsNullOrWhiteSpace($Credential))) {
    Write-ToLogFile -D -C ScriptVariables -M "Using Credential."
} elseif ((-not([String]::IsNullOrWhiteSpace($Username))) -and (-not([String]::IsNullOrWhiteSpace($Password)))) {
    Write-ToLogFile -D -C ScriptVariables -M "Using Username / Password."
    if (-not ($Password -is [SecureString])) {
        [SecureString]$Password = ConvertTo-SecureString -String $Password -AsPlainText -Force
    }
    [PSCredential]$Credential = New-Object System.Management.Automation.PSCredential ($Username, $Password)
} else {
    Write-ToLogFile -W -C ScriptVariables -M "No valid Username/password or credential specified. Requested for credentials."
    [PSCredential]$Credential = Get-Credential -Message "ADC Username and password:"
}
Write-ToLogFile -I -C ScriptVariables -M "Starting new session."


#endregion ScriptVariables

#region CleanPoshACMEStorage

$ACMEStorage = Join-Path -Path $($env:LOCALAPPDATA) -ChildPath "Posh-ACME"
if ($CleanPoshACMEStorage) {
    Write-ToLogFile -I -C CleanPoshACMEStorage -M "Parameter CleanPoshACMEStorage was specified, removing `"$ACMEStorage`"."
    Remove-Item -Path $ACMEStorage -Recurse -Force -ErrorAction SilentlyContinue
}

#endregion CleanPoshACMEStorage

#region VersionInfo

Write-Host -ForeGroundColor White "`r`nVersion Info"
Write-Host -ForeGroundColor White -NoNewLine " -Script Version........: "
Write-Host -ForeGroundColor Blue "v$ScriptVersion"
Write-ToLogFile -I -C VersionInfo -M "Current script version: v$($ScriptVersion), checking if a new version is available."
try {
    $AvailableVersions = Invoke-CheckScriptVersions -URI $VersionURI
    if ([version]$AvailableVersions.master -gt [version]$ScriptVersion) {
        Write-Host -ForeGroundColor White -NoNewLine " -New Production Note...: "
        Write-Host -ForeGroundColor Blue "$($AvailableVersions.masternote)"
        Write-ToLogFile -I -C VersionInfo -M "Note: $($AvailableVersions.masternote)"
        Write-Host -ForeGroundColor White -NoNewLine " -New Production Version: "
        Write-Host -ForeGroundColor Blue "v$($AvailableVersions.master)"
        Write-ToLogFile -I -C VersionInfo -M "Version: v$($AvailableVersions.master)"
        Write-Host -ForeGroundColor White -NoNewLine " -New Production URL....: "
        Write-Host -ForeGroundColor Blue "$($AvailableVersions.masterurl)"
        Write-ToLogFile -I -C VersionInfo -M "URL: $($AvailableVersions.masterurl)"
        if (-Not [String]::IsNullOrEmpty($($AvailableVersions.masterimportant))) {
            ""
            Write-Host -ForeGroundColor White -NoNewLine " -IMPORTANT Note........: "
            Write-Host -ForeGroundColor Yellow "$($AvailableVersions.masterimportant)"
            Write-ToLogFile -I -C VersionInfo -M "IMPORTANT Note: $($AvailableVersions.masterimportant)"
        }
        $MailData += "$($AvailableVersions.masternote)`r`nVersion: v$($AvailableVersions.master)`r`nURL:$($AvailableVersions.masterurl)"
    }
    if ([version]$AvailableVersions.dev -gt [version]$ScriptVersion) {
        Write-Host -ForeGroundColor White -NoNewLine " -New Develop Note......: "
        Write-Host -ForeGroundColor Blue "$($AvailableVersions.devnote)"
        Write-ToLogFile -I -C VersionInfo -M "Note: $($AvailableVersions.devnote)"
        Write-Host -ForeGroundColor White -NoNewLine " -New Develop Version...: "
        Write-Host -ForeGroundColor Blue "v$($AvailableVersions.dev)"
        Write-ToLogFile -I -C VersionInfo -M "Version: v$($AvailableVersions.dev)"
        Write-Host -ForeGroundColor White -NoNewLine " -New Develop URL.......: "
        Write-Host -ForeGroundColor Blue "$($AvailableVersions.devurl)"
        Write-ToLogFile -I -C VersionInfo -M "URL: $($AvailableVersions.devurl)"
        if (-Not [String]::IsNullOrEmpty($($AvailableVersions.devimportant))) {
            ""
            Write-Host -ForeGroundColor White -NoNewLine " -IMPORTANT Note........: "
            Write-Host -ForeGroundColor Yellow "$($AvailableVersions.devimportant)"
            Write-ToLogFile -I -C VersionInfo -M "IMPORTANT Note: $($AvailableVersions.devimportant)"
        }
    }
} catch {
    Write-ToLogFile -E -C VersionInfo -M "Caught an error while retrieving version info. Exception Message: $($_.Exception.Message)"
}
Write-ToLogFile -I -C VersionInfo -M "Version check finished."
#endregion VersionInfo

#region LoadModule

if ((-not ($CleanADC)) -and (-not ($RemoveTestCertificates))) {
    Write-ToLogFile -I -C LoadModule -M "Try loading the Posh-ACME v$PoshACMEVersion Modules."
    $modules = Get-Module -ListAvailable -Verbose:$false | Where-Object { ($_.Name -like "*Posh-ACME*") -And ($_.Version -ge [System.Version]$PoshACMEVersion) }
    if ([String]::IsNullOrEmpty($modules)) {
        Write-ToLogFile -D -C LoadModule -M "Checking for PackageManagement."
        if ([String]::IsNullOrWhiteSpace($(Get-Module -ListAvailable -Verbose:$false | Where-Object { $_.Name -eq "PackageManagement" }))) {
            Write-Warning "PackageManagement is not available please install this first or manually install Posh-ACME"
            Write-Warning "Visit `"https://docs.microsoft.com/en-us/powershell/gallery/psget/get_psget_module`" to download Package Management"
            Write-Warning "Posh-ACME: https://www.powershellgallery.com/packages/Posh-ACME/$PoshACMEVersion"
            Write-ToLogFile -W -C LoadModule -M "PackageManagement is not available please install this first or manually install Posh-ACME."
            Write-ToLogFile -W -C LoadModule -M "Visit `"https://docs.microsoft.com/en-us/powershell/gallery/psget/get_psget_module`" to download Package Management."
            Write-ToLogFile -W -C LoadModule -M "Posh-ACME: https://www.powershellgallery.com/packages/Posh-ACME/$PoshACMEVersion"
            Start-Process "https://www.powershellgallery.com/packages/Posh-ACME/$PoshACMEVersion"
            TerminateScript 1 "PackageManagement is not available please install this first or manually install Posh-ACME"
        } else {
            try {
                if (-not ((Get-PackageProvider | Where-Object { $_.Name -like "*nuget*" }).Version -ge [System.Version]"2.8.5.208")) {
                    Write-ToLogFile -I -C LoadModule -M "Installing Nuget."
                    Get-PackageProvider -Name NuGet -Force -ErrorAction SilentlyContinue | Out-Null
                }
                $installationPolicy = (Get-PSRepository -Name PSGallery).InstallationPolicy
                if (-not ($installationPolicy.ToLower() -eq "trusted")) {
                    Write-ToLogFile -D -C LoadModule -M "Defining PSGallery PSRepository as trusted."
                    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
                }
                Write-ToLogFile -I -C LoadModule -M "Installing Posh-ACME v$PoshACMEVersion"
                try {
                    Install-Module -Name Posh-ACME -Scope AllUsers -RequiredVersion $PoshACMEVersion -Force -AllowClobber
                } catch {
                    Write-ToLogFile -D -C LoadModule -M "Installing Posh-ACME again but without the -AllowClobber option."
                    Install-Module -Name Posh-ACME -Scope AllUsers -RequiredVersion $PoshACMEVersion -Force
                }
                if (-not ((Get-PSRepository -Name PSGallery).InstallationPolicy -eq $installationPolicy)) {
                    Write-ToLogFile -D -C LoadModule -M "Returning the PSGallery PSRepository InstallationPolicy to previous value."
                    Set-PSRepository -Name "PSGallery" -InstallationPolicy $installationPolicy | Out-Null
                }
                Write-ToLogFile -D -C LoadModule -M "Try loading module Posh-ACME."
                Import-Module Posh-ACME -ErrorAction Stop
            } catch {
                Write-ToLogFile -E -C LoadModule -M "Error while loading and/or installing module. Exception Message: $($_.Exception.Message)"
                Write-Error "Error while loading and/or installing module"
                Write-Warning "PackageManagement is not available please install this first or manually install Posh-ACME"
                Write-Warning "Visit `"https://docs.microsoft.com/en-us/powershell/gallery/psget/get_psget_module`" to download Package Management"
                Write-Warning "Posh-ACME: https://www.powershellgallery.com/packages/Posh-ACME/$PoshACMEVersion"
                Start-Process "https://www.powershellgallery.com/packages/Posh-ACME/$PoshACMEVersion"
                Write-ToLogFile -W -C LoadModule -M "PackageManagement is not available please install this first or manually install Posh-ACME."
                Write-ToLogFile -W -C LoadModule -M "Visit `"https://docs.microsoft.com/en-us/powershell/gallery/psget/get_psget_module`" to download Package Management."
                Write-ToLogFile -W -C LoadModule -M "Posh-ACME: https://www.powershellgallery.com/packages/Posh-ACME/$PoshACMEVersion"
                TerminateScript 1 "PackageManagement is not available please install this first or manually install Posh-ACME."
            } finally {
                Write-Host -ForeGroundColor White -NoNewLine " -Posh-ACME Version.: "
                Write-Host -ForeGroundColor Blue "v$PoshACMEVersion"
            }
        }
    } else {
        Write-ToLogFile -I -C LoadModule -M "v$PoshACMEVersion of Posh-ACME is installed, loading module."
        try {
            Import-Module Posh-ACME -ErrorAction Stop
        } catch {
            Write-ToLogFile -E -C LoadModule -M "Importing module Posh-ACME failed."
            Write-Error "Importing module Posh-ACME failed"
            TerminateScript 1 "Importing module Posh-ACME failed"
        }
    }
    Write-ToLogFile -I -C LoadModule -M "Posh-ACME loaded successfully."
}

#endregion LoadModule

#region ADC-Check

Write-ToLogFile -I -C ADC-Check -M "Trying to login into the Citrix ADC."
Write-Host -ForeGroundColor White "`r`nADC Info"
$ADCSession = Connect-ADC -ManagementURL $ManagementURL -Credential $Credential -PassThru
Write-Host -ForeGroundColor White -NoNewLine " -URL...................: "
Write-Host -ForeGroundColor Blue "$ManagementURL"
Write-Host -ForeGroundColor White -NoNewLine " -Username..............: "
Write-Host -ForeGroundColor Blue "$($ADCSession.Username)"
Write-Host -ForeGroundColor White -NoNewLine " -Password..............: "
Write-Host -ForeGroundColor Blue "**********"
Write-Host -ForeGroundColor White -NoNewLine " -Version...............: "
Write-Host -ForeGroundColor Blue "$($ADCSession.Version)"
Write-ToLogFile -I -C ADC-Check -M "Connected to Citrix ADC $ManagementURL, as user $($ADCSession.Username), ADC Version $($ADCSession.Version)"
try {
    $NSVersion = [double]$($ADCSession.version.split(" ")[1].Replace("NS", "").Replace(":", ""))
    if ($NSVersion -lt 11) {
        Write-Host -ForeGroundColor RED -NoNewLine "ERROR: "
        Write-Host -ForeGroundColor White "Only ADC version 11 and up is supported, please use an older version (v1-api) of this script!"
        Write-ToLogFile -E -C ADC-Check -M "Only ADC version 11 and up is supported, please use an older version (v1-api) of this script!"
        Start-Process "https://github.com/j81blog/GenLeCertForNS/tree/master-v1-api"
        TerminateScript 1 "Only ADC version 11 and up is supported, please use an older version (v1-api) of this script!"
    }
} catch {
    Write-ToLogFile -E -C ADC-Check -M "Caught an error while retrieving the version! Exception Message: $($_.Exception.Message)"
}

#endregion ADC-Check

#region CertificatePreCheck
if ((-not ($CleanADC)) -and (-not ($RemoveTestCertificates))) {
    Write-Host -ForeGroundColor White -NoNewline "`r`n -Keysize...............: "
    Write-Host -ForeGroundColor Blue "$KeyLength"
    Write-ToLogFile -I -C CertificatePreCheck -M "Keysize: $KeyLength"
}

if ($GetValuesFromExistingCertificate -And (-not ($CleanADC)) -and (-not ($RemoveTestCertificates))) {
    $CurrentCertificateValues = Get-ADCCurrentCertificate -Session $ADCSession -Name $ExistingCertificateName
    Write-ToLogFile -D -C CertificatePreCheck -M "Retrieved the following certificate data: $($CurrentCertificateValues | ConvertTo-Json -Compress)"
    if (-Not [String]::IsNullOrEmpty($($CurrentCertificateValues.CN))) {
        $CN = $CurrentCertificateValues.CN
        Write-Host -ForeGroundColor White "`r`n  Got the following values from an existing certificate"
        Write-Host -ForeGroundColor White -NoNewline " -Existing CN...........: "
        Write-Host -ForeGroundColor Blue $CN
        Write-ToLogFile -I -C CertificatePreCheck -M "Got the following values from an existing certificate."
        Write-ToLogFile -I -C CertificatePreCheck -M "Using existing CN: $CN"
    } else {
        Write-ToLogFile -E -C CertificatePreCheck -M "No SAN entries received, could not retrieve CN from certificate `"$ExistingCertificateName`"."
        Write-Error "Could not retrieve CN from certificate `"$ExistingCertificateName`""
        TerminateScript 1 "Could not retrieve CN from certificate `"$ExistingCertificateName`""
    }
    if (-Not [String]::IsNullOrEmpty($($CurrentCertificateValues.SAN))) {
        $SAN = $CurrentCertificateValues.SAN
        Write-Host -ForeGroundColor White -NoNewline " -Existing SAN(s).......: "
        Write-Host -ForeGroundColor Blue "$($SAN -Join "`r`n                     ")"
        Write-ToLogFile -I -C CertificatePreCheck -M "Using existing SAN(s): $($SAN | ConvertTo-Json -Compress)"
    } else {
        Write-ToLogFile -D -C CertificatePreCheck -M "No SAN entries received."
    }
} else {
    Write-ToLogFile -D -C CertificatePreCheck -M "Retrieving values from an existing certificate was not requested."
}

#endregion CertificatePreCheck

#region DNSPreCheck

if ($RemoveTestCertificates -or $CleanADC) {
    #skip
} elseif (($CN -match "\*") -or ($SAN -match "\*")) {
    Write-Host -ForeGroundColor Yellow "`r`nNOTE: -CN or -SAN contains a wildcard entry, continuing with the `"dns`" validation method!"
    Write-Host -ForeGroundColor White -NoNewline " -CN....................: "
    Write-Host -ForeGroundColor Yellow $CN
    Write-Host -ForeGroundColor White -NoNewline " -SAN(s)................: "
    Write-Host -ForeGroundColor Yellow "$($SAN -Join ", ")"
    Write-ToLogFile -I -C DNSPreCheck -M "-CN or -SAN contains a wildcard entry, continuing with the `"dns`" validation method!"
    Write-ToLogFile -I -C DNSPreCheck -M "CN: $CN"
    Write-ToLogFile -I -C DNSPreCheck -M "SAN(s): $($SAN | ConvertTo-Json -Compress)"
    $ValidationMethod = "dns"
    $DisableIPCheck = $true
} else {
    $ValidationMethod = $ValidationMethod.ToLower()
    if (([String]::IsNullOrWhiteSpace($NSCsVipName)) -and ($ValidationMethod -eq "http")) {
        Write-Host -ForeGroundColor Red "`r`nERROR: The `"-NSCsVipName`" cannot be empty!`r`n"
        Write-ToLogFile -E -C DNSPreCheck -M "The `"-NSCsVipName`" cannot be empty!"
        TerminateScript 1 "The `"-NSCsVipName`" cannot be empty!"
    }
    Write-ToLogFile -I -C DNSPreCheck -M "continuing with the `"$ValidationMethod`" validation method!"
}

$DNSObjects = @()
$ResponderPrio = 10
$DNSObjects += [PSCustomObject]@{
    DNSName       = $CN
    IPAddress     = $null
    Status        = $null
    Match         = $null
    SAN           = $false
    Challenge     = $null
    ResponderPrio = $ResponderPrio
    Done          = $false
}
if (-not ([String]::IsNullOrWhiteSpace($SAN))) {
    [string[]]$SAN = @($SAN.Split(","))
    Write-ToLogFile -I -C DNSPreCheck -M "Checking for double SAN values."
    $SANCount = $SAN.Count
    $SAN = $SAN | Select-Object -Unique
    if (-Not ($SANCount -eq $SAN.Count)) {
        Write-Warning "There were $($SANCount - $SAN.Count) double SAN values, only continuing with unique ones."
        Write-ToLogFile -W -C DNSPreCheck -M "There were $($SANCount - $SAN.Count) double SAN values, only continuing with unique ones."
    } else {
        Write-ToLogFile -I -C DNSPreCheck -M "No double SAN values found."
    }
    Foreach ($Entry in $SAN) {
        $ResponderPrio += 10
        if (-Not ($Entry -eq $CN)) {
            $DNSObjects += [PSCustomObject]@{
                DNSName       = $Entry
                IPAddress     = $null
                Status        = $null
                Match         = $null
                SAN           = $true
                Challenge     = $null
                ResponderPrio = $ResponderPrio
                Done          = $false
            }
        } else {
            Write-Warning "Double record found, SAN value `"$Entry`" is the same as CN value `"$CN`". Removed double SAN entry."
            Write-ToLogFile -W -C DNSPreCheck -M "Double record found, SAN value `"$Entry`" is the same as CN value `"$CN`". Removed double SAN entry."
        }
    }
}
Write-ToLogFile -D -C DNSPreCheck -M "DNS Data:"
$DNSObjects | Select-Object DNSName, SAN | ForEach-Object {
    Write-ToLogFile -D -C DNSPreCheck -M "$($_ | ConvertTo-Json -Compress)"
}

if ((-not ($CleanADC)) -and (-not ($RemoveTestCertificates))) {
    if ($ValidationMethod -eq "http") {
        try {
            Write-ToLogFile -I -C DNSPreCheck -M "Verifying Content Switch."
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csvserver -Resource $NSCsVipName
            Write-ToLogFile -D -C DNSPreCheck -M "Response: $($response | ConvertTo-Json -Compress)"
        } catch {
            $ExceptMessage = $_.Exception.Message
            Write-ToLogFile -E -C DNSPreCheck -M "Error Verifying Content Switch. Details: $ExceptMessage"
        } finally {
            if (($response.errorcode -eq "0") -and `
                ($response.csvserver.type -eq "CONTENT") -and `
                ($response.csvserver.curstate -eq "UP") -and `
                ($response.csvserver.servicetype -eq "HTTP") -and `
                ($response.csvserver.port -eq "80") ) {
                Write-Host -ForeGroundColor White -NoNewLine " -Content Switch........: "
                Write-Host -ForeGroundColor Blue -NoNewLine "$NSCsVipName"
                Write-Host -ForeGroundColor Green " (found)"
                Write-Host -ForeGroundColor White -NoNewLine " -Connection............: "
                Write-Host -ForeGroundColor Green "OK`r`n"
                Write-ToLogFile -I -C DNSPreCheck -M "Content Switch OK"
            } elseif ($ExceptMessage -like "*(404) Not Found*") {
                Write-Host -ForeGroundColor White -NoNewLine " -Content Switch........: "
                Write-Host -ForeGroundColor Red "ERROR: The Content Switch `"$NSCsVipName`" does NOT exist!"
                Write-Host -ForeGroundColor White -NoNewLine "  -Error message........: "
                Write-Host -ForeGroundColor Red "`"$ExceptMessage`"`r`n"
                Write-Host -ForeGroundColor Yellow "  IMPORTANT: Please make sure a HTTP Content Switch is available`r`n"
                Write-Host -ForeGroundColor White -NoNewLine " -Connection............: "
                Write-Host -ForeGroundColor Red "FAILED! Exiting now`r`n"
                Write-ToLogFile -E -C DNSPreCheck -M "The Content Switch `"$NSCsVipName`" does NOT exist! Please make sure a HTTP Content Switch is available."
                TerminateScript 1 "The Content Switch `"$NSCsVipName`" does NOT exist! Please make sure a HTTP Content Switch is available."
            } elseif ($ExceptMessage -like "*The remote server returned an error*") {
                Write-Host -ForeGroundColor White -NoNewLine " -Content Switch........: "
                Write-Host -ForeGroundColor Red "ERROR: Unknown error found while checking the Content Switch"
                Write-Host -ForeGroundColor White -NoNewLine "  -Error message........: "
                Write-Host -ForeGroundColor Red "`"$ExceptMessage`"`r`n"
                Write-Host -ForeGroundColor White -NoNewLine " -Connection............: "
                Write-Host -ForeGroundColor Red "FAILED! Exiting now`r`n"
                Write-ToLogFile -E -C DNSPreCheck -M "Unknown error found while checking the Content Switch"
                TerminateScript 1 "Unknown error found while checking the Content Switch"
            } elseif (($response.errorcode -eq "0") -and (-not ($response.csvserver.servicetype -eq "HTTP"))) {
                Write-Host -ForeGroundColor White -NoNewLine " -Content Switch........: "
                Write-Host -ForeGroundColor Red "ERROR: Content Switch `"$NSCsVipName`" is $($response.csvserver.servicetype) and NOT HTTP"
                if (-not ([String]::IsNullOrWhiteSpace($ExceptMessage))) {
                    Write-Host -ForeGroundColor White -NoNewLine "  -Error message........: "
                    Write-Host -ForeGroundColor Red "`"$ExceptMessage`""
                }
                Write-Host -ForeGroundColor Yellow "`r`n  IMPORTANT: Please use a HTTP (Port 80) Content Switch!`r`n  This is required for the validation.`r`n"
                Write-Host -ForeGroundColor White -NoNewLine " -Connection............: "
                Write-Host -ForeGroundColor Red "FAILED! Exiting now`r`n"
                Write-ToLogFile -E -C DNSPreCheck -M "Content Switch `"$NSCsVipName`" is $($response.csvserver.servicetype) and NOT HTTP. Please use a HTTP (Port 80) Content Switch! This is required for the validation."
                TerminateScript 1 "Content Switch `"$NSCsVipName`" is $($response.csvserver.servicetype) and NOT HTTP. Please use a HTTP (Port 80) Content Switch! This is required for the validation."
            } else {
                Write-Host -ForeGroundColor White -NoNewLine " -Content Switch........: "
                Write-Host -ForeGroundColor Green "Found"
                Write-ToLogFile -I -C DNSPreCheck -M "Content Switch Found"
                Write-Host -ForeGroundColor White -NoNewLine "  -State................: "
                if ($response.csvserver.curstate -eq "UP") {
                    Write-Host -ForeGroundColor Green "UP"
                    Write-ToLogFile -I -C DNSPreCheck -M "Content Switch is UP"
                } else {
                    Write-Host -ForeGroundColor RED "$($response.csvserver.curstate)"
                    Write-ToLogFile -I -C DNSPreCheck -M "Content Switch Not OK, Current Status: $($response.csvserver.curstate)."
                }
                Write-Host -ForeGroundColor White -NoNewLine "  -Type.................: "
                if ($response.csvserver.type -eq "CONTENT") {
                    Write-Host -ForeGroundColor Green "CONTENT"
                    Write-ToLogFile -I -C DNSPreCheck -M "Content Switch type OK, Type: $($response.csvserver.type)"
                } else {
                    Write-Host -ForeGroundColor RED "$($response.csvserver.type)"
                    Write-ToLogFile -I -C DNSPreCheck -M "Content Switch type Not OK, Type: $($response.csvserver.type)"
                }
                if (-not ([String]::IsNullOrWhiteSpace($ExceptMessage))) {
                    Write-Host -ForeGroundColor White -NoNewLine "  -Error message........: "
                    Write-Host -ForeGroundColor Red "`"$ExceptMessage`""
                }
                Write-Host -ForeGroundColor White -NoNewLine " -Data..................: "
                Write-Host -ForeGroundColor Yellow $($response.csvserver | Format-List -Property * | Out-String)
                Write-Host -ForeGroundColor White -NoNewLine " -Connection............: "
                Write-Host -ForeGroundColor Red "FAILED! Exiting now`r`n"
                Write-ToLogFile -E -C DNSPreCheck -M "Content Switch verification failed."
                TerminateScript 1 "Content Switch verification failed."
            }
        }
    } elseif ($ValidationMethod -eq "dns") {
        Write-Host -ForeGroundColor White -NoNewLine " -Connection............: "
        if (-Not [String]::IsNullOrEmpty($ADCSession.Version)) {
            Write-Host -ForeGroundColor Green "OK"
            Write-ToLogFile -I -C DNSPreCheck -M "Connection OK."
        } else {
            Write-Warning "Could not verify the Citrix ADC Connection!"
            Write-Warning "Script will continue but uploading of certificates will probably Fail"
            Write-ToLogFile -W -C DNSPreCheck -M "Could not verify the Citrix ADC Connection! Script will continue but uploading of certificates will probably Fail."
        }
    }
}

#endregion DNSPreCheck

#region Services
if ((-not $CleanADC) -and (-not $RemoveTestCertificates)) {
    Write-Host -NoNewLine -ForeGroundColor Yellow "`r`nIMPORTANT: By running this script you agree with the terms specified by Let's Encrypt.`r`n"
    Write-ToLogFile -I -C Services -M "By running this script you agree with the terms specified by Let's Encrypt."
    if ($Production) {
        $BaseService = "LE_PROD"
        Write-ToLogFile -I -C Services -M "Using the production service for supported certificates."
    } else {
        $BaseService = "LE_STAGE"
        Write-ToLogFile -I -C Services -M "Using the staging service for test certificates."
        $MailData += "IMPORTANT: This is a test certificate!"
    }
    Posh-ACME\Set-PAServer $BaseService
    $PAServer = Posh-ACME\Get-PAServer -Refresh
    Write-ToLogFile -I -C Services -M "Terms Of Service: $($PAServer.meta.termsOfService)"
    Write-ToLogFile -I -C Services -M "Website: $($PAServer.meta.website)"
    Write-ToLogFile -D -C Services -M "All account data is being saved to `"$ACMEStorage`"."
    ""
}
#endregion Services

#region Registration

if ((-not ($CleanADC)) -and (-not ($RemoveTestCertificates))) {
    Write-Host -ForeGroundColor White "`r`nLet's Encrypt Preparation"
    Write-Host -ForeGroundColor White -NoNewLine " -Registration..........: "
    try {
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        Write-ToLogFile -I -C Registration -M "Try to retrieve the existing Registration."
        $PARegistration = Posh-ACME\Get-PAAccount -List -Contact $EmailAddress -Refresh | Where-Object { ($_.status -eq "valid") -and ($_.KeyLength -eq $KeyLength) }
        if ($PARegistration -is [system.array]) {
            $PARegistration = $PARegistration | Sort-Object id | Select-Object -Last 1
        }
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        if ($PARegistration.Contact -contains "mailto:$($EmailAddress)") {
            Write-ToLogFile -I -C Registration -M "Existing registration found, no changes necessary."
        } else {
            if ([String]::IsNullOrEmpty($($PARegistration.Contact))) {
                $CurrentAddress = "<empty>"
            } else {
                $CurrentAddress = $PARegistration.Contact
            }
            Write-Host -ForeGroundColor Yellow -NoNewLine "*"
            Write-ToLogFile -I -C Registration -M "Current registration `"$CurrentAddress`" is not equal to `"$EmailAddress`", setting new registration."
            $PARegistration = Posh-ACME\New-PAAccount -Contact $EmailAddress -KeyLength $KeyLength -AcceptTOS
        }
    } catch {
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        Write-ToLogFile -I -C Registration -M "Setting new registration to `"$EmailAddress`"."
        try {
            $PARegistration = Posh-ACME\New-PAAccount -Contact $EmailAddress -KeyLength $KeyLength -AcceptTOS
            Write-ToLogFile -I -C Registration -M "New registration successful."
        } catch {
            Write-ToLogFile -E -C Registration -M "Error New registration failed! Exception Message: $($_.Exception.Message)"
            Write-Host -ForeGroundColor Red "`nError New registration failed!"
        }
    }
    try {
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        Set-PAAccount -ID $PARegistration.id | out-null
        Write-ToLogFile -I -C Registration -M "Account $($PARegistration.id) set as default."
    } catch {
        Write-ToLogFile -E -C Registration -M "Could not set default account. Exception Message: $($_.Exception.Message)."
    }
    Write-Host -ForeGroundColor Yellow -NoNewLine "*"
    $PARegistration = Posh-ACME\Get-PAAccount -List -Contact $EmailAddress -Refresh | Where-Object { ($_.status -eq "valid") -and ($_.KeyLength -eq $KeyLength) }
    Write-ToLogFile -D -C Registration -M "Registration: $($PARegistration | ConvertTo-Json -Compress)."
    if (-not ($PARegistration.Contact -contains "mailto:$($EmailAddress)")) {
        Write-Host -ForeGroundColor Red " Error"
        Write-ToLogFile -E -C Registration -M "User registration failed."
        Write-Error "User registration failed"
        TerminateScript 1 "User registration failed"
    }
    if ($PARegistration.status -ne "valid") {
        Write-Host -ForeGroundColor Red " Error"
        Write-ToLogFile -E -C Registration -M "Account status is $($Account.status)."
        Write-Error  "Account status is $($Account.status)"
        TerminateScript 1 "Account status is $($Account.status)"
    } else {
        Write-ToLogFile -I -C Registration -M "Registration ID: $($PARegistration.id), Status: $($PARegistration.status)."
        Write-ToLogFile -I -C Registration -M "Setting Account as default for new order."
        Posh-ACME\Set-PAAccount -ID $PARegistration.id -Force
    }
    Write-Host -ForeGroundColor Green " Ready"
}

#endregion Registration

#region Order

if ((-not $CleanADC) -and (-not $RemoveTestCertificates)) {
    Write-Host -ForeGroundColor White -NoNewLine " -Order.................: "
    Write-Host -ForeGroundColor Yellow -NoNewLine "*"
    try {
        Write-ToLogFile -I -C Order -M "Trying to create a new order."
        $domains = $DNSObjects | Select-Object DNSName -ExpandProperty DNSName
        $PAOrder = Posh-ACME\New-PAOrder -Domain $domains -KeyLength $KeyLength -Force -FriendlyName $FriendlyName -PfxPass $PfxPassword
        Start-Sleep -Seconds 1
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        Write-ToLogFile -D -C Order -M "Order data:"
        $PAOrder | Select-Object MainDomain, FriendlyName, SANs, status, expires, KeyLength | ForEach-Object {
            Write-ToLogFile -D -C Order -M "$($_ | ConvertTo-Json -Compress)"
        }
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        $PAChallenges = $PAOrder | Posh-ACME\Get-PAOrder -Refresh | Posh-ACME\Get-PAAuthorizations
        Write-ToLogFile -D -C Order -M "Challenge status: "
        $PAChallenges | Select-Object DNSId, status, HTTP01Status, DNS01Status | ForEach-Object {
            Write-ToLogFile -D -C Order -M "$($_ | ConvertTo-Json -Compress)"
        }
        Write-ToLogFile -I -C Order -M "Order created successfully."
    } catch {
        Write-Host -ForeGroundColor Red " Error"
        Write-ToLogFile -E -C Order -M "Could not create the order. You can retry with specifying the `"-CleanPoshACMEStorage`" parameter. "
        Write-ToLogFile -E -C Order -M "Exception Message: $($_.Exception.Message)"
        Write-Host -ForeGroundColor Red "ERROR: Could not create the order. You can retry with specifying the `"-CleanPoshACMEStorage`" parameter."
        TerminateScript 1 "Could not create the order. You can retry with specifying the `"-CleanPoshACMEStorage`" parameter."
    }
    Write-Host -ForeGroundColor Green " Ready"
}

#endregion Order

#region DNS-Validation

if (($ValidationMethod -in "http", "dns") -and (-not $CleanADC) -and (-not $RemoveTestCertificates)) {
    Write-Host -ForeGroundColor White "`r`nDNS - Validate Records"
    Write-Host -ForeGroundColor White -NoNewLine " -Checking records......: "
    Write-ToLogFile -I -C DNS-Validation -M "Validate DNS record(s)."
    Foreach ($DNSObject in $DNSObjects) {
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        $DNSObject.IPAddress = "0.0.0.0"
        $DNSObject.Status = $false
        $DNSObject.Match = $false
        try {
            $PAChallenge = $PAChallenges | Where-Object { $_.fqdn -eq $DNSObject.DNSName }
            if ([String]::IsNullOrWhiteSpace($PAChallenge)) {
                Write-Host -ForeGroundColor Red " Error [$($DNSObject.DNSName)]"
                Write-ToLogFile -E -C DNS-Validation -M "No valid Challenge found."
                Write-Error "No valid Challenge found"
                TerminateScript 1 "No valid Challenge found"
            } else {
                $DNSObject.Challenge = $PAChallenge
            }
            if ($DisableIPCheck) {
                $DNSObject.IPAddress = "NoIPCheck"
                $DNSObject.Match = $true
                $DNSObject.Status = $true
            } else {
                Write-Host -ForeGroundColor Yellow -NoNewLine "*"
                Write-ToLogFile -I -C DNS-Validation -M "Using public DNS server ($PublicDnsServer) to verify dns records."
                Write-ToLogFile -D -C DNS-Validation -M "Trying to get IP Address."
                $PublicIP = (Resolve-DnsName -Server $PublicDnsServer -Name $DNSObject.DNSName -DnsOnly -Type A -ErrorAction SilentlyContinue).IPAddress
                if ([String]::IsNullOrWhiteSpace($PublicIP)) {
                    Write-Host -ForeGroundColor Red " Error [$($DNSObject.DNSName)]"
                    Write-ToLogFile -E -C DNS-Validation -M "No valid (public) IP Address found for DNSName:`"$($DNSObject.DNSName)`"."
                    Write-Error "No valid (public) IP Address found for DNSName:`"$($DNSObject.DNSName)`""
                    TerminateScript 1 "No valid (public) IP Address found for DNSName:`"$($DNSObject.DNSName)`""
                } elseif ($PublicIP -is [system.array]) {
                    Write-ToLogFile -W -C DNS-Validation -M "More than one ip address found:"
                    $PublicIP | ForEach-Object {
                        Write-ToLogFile -D -C DNS-Validation -M "$($_ | ConvertTo-Json -Compress)"
                    }
                    
                    Write-Warning "More than one ip address found`n$($PublicIP | Format-List | Out-String)"
                    $DNSObject.IPAddress = $PublicIP | Select-Object -First 1
                    Write-ToLogFile -W -C DNS-Validation -M "using the first one`"$($DNSObject.IPAddress)`"."
                    Write-Warning "using the first one`"$($DNSObject.IPAddress)`""
                } else {
                    Write-ToLogFile -D -C DNS-Validation -M "Saving Public IP Address `"$PublicIP`"."
                    $DNSObject.IPAddress = $PublicIP
                }
            }
        } catch {
            Write-ToLogFile -E -C DNS-Validation -M "Error while retrieving IP Address. Exception Message: $($_.Exception.Message)"
            Write-Host -ForeGroundColor Red "Error while retrieving IP Address,"
            if ($DNSObject.SAN) {
                Write-Host -ForeGroundColor Red "you can try to re-run the script with the -DisableIPCheck parameter."
                Write-Host -ForeGroundColor Red "The script will continue but `"$DNSRecord`" will be skipped"
                Write-ToLogFile -E -C DNS-Validation -M "You can try to re-run the script with the -DisableIPCheck parameter. The script will continue but `"$DNSRecord`" will be skipped."
                $DNSObject.IPAddress = "Skipped"
                $DNSObject.Match = $true
            } else {
                Write-Host -ForeGroundColor Red " Error [$($DNSObject.DNSName)]"
                Write-Host -ForeGroundColor Red "you can try to re-run the script with the -DisableIPCheck parameter."
                Write-ToLogFile -E -C DNS-Validation -M "You can try to re-run the script with the -DisableIPCheck parameter."
                TerminateScript 1 "You can try to re-run the script with the -DisableIPCheck parameter."
            }
        }
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        if ($DNSObject.SAN) {
            $CNObject = $DNSObjects | Where-Object { $_.SAN -eq $false }
            Write-ToLogFile -I -C DNS-Validation -M "All IP Addresses must match, checking..."
            if ($DNSObject.IPAddress -match $CNObject.IPAddress) {
                Write-ToLogFile -I -C DNS-Validation -M "`"$($DNSObject.IPAddress)/($($DNSObject.DNSName))`" matches to `"$($CNObject.IPAddress)/($($CNObject.DNSName))`"."
                $DNSObject.Match = $true
                $DNSObject.Status = $true
            } else {
                Write-ToLogFile -W -C DNS-Validation -M "`"$($DNSObject.IPAddress)/($($DNSObject.DNSName))`" Doesn't match to `"$($CNObject.IPAddress)/($($CNObject.DNSName))`"."
                $DNSObject.Match = $false
            }
        } else {
            Write-ToLogFile -I -C DNS-Validation -M "`"$($DNSObject.IPAddress)/($($DNSObject.DNSName))`" is the first entry, continuing."
            $DNSObject.Status = $true
            $DNSObject.Match = $true
        }
        Write-ToLogFile -I -C DNS-Validation -M "Finished, DNSObject: $($DNSObject | Select-Object DNSName,IPAddress,Status,Match | ConvertTo-Json -Compress)."
    }
    Write-ToLogFile -D -C DNS-Validation -M "SAN Objects:"
    $DNSObjects | Select-Object DNSName, IPAddress, Status, Match | ForEach-Object {
        Write-ToLogFile -D -C DNS-Validation -M "$($_ | ConvertTo-Json -Compress)"
    }
    Write-Host -ForeGroundColor Green " Ready"
}

if ((-not $CleanADC) -and (-not ($RemoveTestCertificates)) -and ($ValidationMethod -eq "http")) {
    Write-Host -ForeGroundColor White -NoNewLine " -Checking for errors...: "
    Write-ToLogFile -I -C DNS-Validation -M "Checking for invalid DNS Records."
    $InvalidDNS = $DNSObjects | Where-Object { $_.Status -eq $false }
    $SkippedDNS = $DNSObjects | Where-Object { $_.IPAddress -eq "Skipped" }
    if ($InvalidDNS) {
        Write-Host -ForeGroundColor Red " Error"
        Write-ToLogFile -E -C DNS-Validation -M "Invalid DNS object(s):"
        $InvalidDNS | Select-Object DNSName, Status | ForEach-Object {
            Write-ToLogFile -D -C DNS-Validation -M "$($_ | ConvertTo-Json -Compress)"
        }
        $DNSObjects | Select-Object DNSName, IPAddress -First 1 | Format-List | Out-String | ForEach-Object { Write-Host -ForeGroundColor Green "$_" }
        $InvalidDNS | Select-Object DNSName, IPAddress | Format-List | Out-String | ForEach-Object { Write-Host -ForeGroundColor Red "$_" }
        Write-Error -Message "Invalid (not registered?) DNS Record(s) found!"
        TerminateScript 1 "Invalid (not registered?) DNS Record(s) found!"
    } else {
        Write-ToLogFile -I -C DNS-Validation -M "None found, continuing"
    }
    if ($SkippedDNS) {
        Write-Warning "The following DNS object(s) will be skipped:`n$($SkippedDNS | Select-Object DNSName | Format-List | Out-String)"
        Write-ToLogFile -W -C DNS-Validation -M "The following DNS object(s) will be skipped:"
        $SkippedDNS | Select-Object DNSName | ForEach-Object {
            Write-ToLogFile -D -C DNS-Validation -M "Skipped: $($_ | ConvertTo-Json -Compress)"
        }
    }
    Write-ToLogFile -I -C DNS-Validation -M "Checking non-matching DNS Records"
    $DNSNoMatch = $DNSObjects | Where-Object { $_.Match -eq $false }
    if ($DNSNoMatch -and (-not $DisableIPCheck)) {
        Write-Host -ForeGroundColor Red " Error"
        Write-ToLogFile -E -C DNS-Validation -M "Non-matching records found, must match to `"$($DNSObjects[0].DNSName)`" ($($DNSObjects[0].IPAddress))"
        $DNSNoMatch | Select-Object DNSName, Match | ForEach-Object {
            Write-ToLogFile -D -C DNS-Validation -M "$($_ | ConvertTo-Json -Compress)"
        }
        $DNSObjects[0] | Select-Object DNSName, IPAddress | Format-List | Out-String | ForEach-Object { Write-Host -ForeGroundColor Green "$_" }
        $DNSNoMatch | Select-Object DNSName, IPAddress | Format-List | Out-String | ForEach-Object { Write-Host -ForeGroundColor Red "$_" }
        Write-Error "Non-matching records found, must match to `"$($DNSObjects[0].DNSName)`" ($($DNSObjects[0].IPAddress))."
        TerminateScript 1 "Non-matching records found, must match to `"$($DNSObjects[0].DNSName)`" ($($DNSObjects[0].IPAddress))."
    } elseif ($DisableIPCheck) {
        Write-ToLogFile -I -C DNS-Validation -M "IP Addresses checking was skipped."
    } else {
        Write-ToLogFile -I -C DNS-Validation -M "All IP Addresses match."
    }
    Write-Host -ForeGroundColor Green "Done"
}

#endregion DNS-Validation

#region CheckOrderValidation

if ((-not $CleanADC) -and (-not $RemoveTestCertificates) -and ($ValidationMethod -eq "http")) {
    Write-ToLogFile -I -C CheckOrderValidation -M "Checking if validation is required."
    $PAOrderItems = Posh-ACME\Get-PAOrder -Refresh -MainDomain $CN | Posh-ACME\Get-PAAuthorizations
    $ValidationRequired = $PAOrderItems | Where-Object { $_.status -ne "valid" }
    Write-ToLogFile -D -C CheckOrderValidation -M "$($ValidationRequired.Count) validations required:"
    $ValidationRequired | Select-Object fqdn, status, HTTP01Status, Expires | ForEach-Object {
        Write-ToLogFile -D -C CheckOrderValidation -M "$($_ | ConvertTo-Json -Compress)"
    }
    
    if ($ValidationRequired.Count -eq 0) {
        Write-ToLogFile -I -C CheckOrderValidation -M "Validation NOT required."
        $ADCActionsRequired = $false
    } else {
        Write-ToLogFile -I -C CheckOrderValidation -M "Validation IS required."
        $ADCActionsRequired = $true

    }
    Write-ToLogFile -D -C CheckOrderValidation -M "ADC actions required: $($ADCActionsRequired)."
}

#endregion CheckOrderValidation

#region ConfigureADC

if ((-not $CleanADC) -and (-not $RemoveTestCertificates) -and $ADCActionsRequired -and ($ValidationMethod -eq "http")) {
    try {
        Write-ToLogFile -I -C ConfigureADC -M "Trying to login into the Citrix ADC."
        Write-Host -ForeGroundColor White "`r`nADC - Configure Prerequisites"
        $ADCSession = Connect-ADC -ManagementURL $ManagementURL -Credential $Credential -PassThru
        Write-ToLogFile -I -C ConfigureADC -M "Connected to Citrix ADC $ManagementURL, as user $($ADCSession.Username)"
        Write-ToLogFile -I -C ConfigureADC -M "Enabling required ADC Features: Load Balancer, Responder, Content Switch and SSL."
        Write-Host -ForeGroundColor White -NoNewLine " -Prerequisites.........: "
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        $payload = @{"feature" = "LB RESPONDER CS SSL" }
        try {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type nsfeature -Payload $payload -Action enable
            Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        } catch {
            Write-Host -ForeGroundColor Red " Error"
        }
        try {
            Write-ToLogFile -I -C ConfigureADC -M "Features enabled, verifying Content Switch."
            Write-Host -ForeGroundColor Yellow -NoNewLine "*"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csvserver -Resource $NSCsVipName
        } catch {
            $ExceptMessage = $_.Exception.Message
            Write-Host -ForeGroundColor Red " Error"
            Write-ToLogFile -E -C ConfigureADC -M "Could not find/read out the content switch `"$NSCsVipName`" not available? Exception Message: $ExceptMessage"
            Write-Error "Could not find/read out the content switch `"$NSCsVipName`" not available?"
            TerminateScript 1 "Could not find/read out the content switch `"$NSCsVipName`" not available?"
            if ($ExceptMessage -like "*(404) Not Found*") {
                Write-Host -ForeGroundColor Red "The Content Switch `"$NSCsVipName`" does NOT exist!"
                Write-ToLogFile -E -C ConfigureADC -M "The Content Switch `"$NSCsVipName`" does NOT exist!"
                TerminateScript 1 "The Content Switch `"$NSCsVipName`" does NOT exist!"
            } elseif ($ExceptMessage -like "*The remote server returned an error*") {
                Write-Host -ForeGroundColor Red "Unknown error found while checking the Content Switch: `"$NSCsVipName`"."
                Write-Host -ForeGroundColor Red "Error message: `"$ExceptMessage`""
                Write-ToLogFile -E -C ConfigureADC -M "Unknown error found while checking the Content Switch: `"$NSCsVipName`". Exception Message: $ExceptMessage"
                TerminateScript 1 "Unknown error found while checking the Content Switch: `"$NSCsVipName`". Exception Message: $ExceptMessage"
            } elseif (-Not [String]::IsNullOrEmpty($ExceptMessage)) {
                Write-Host -ForeGroundColor Red "Unknown Error, `"$ExceptMessage`""
                Write-ToLogFile -E -C ConfigureADC -M "Caught an unknown error. Exception Message: $ExceptMessage"
                TerminateScript 1 "Caught an unknown error. Exception Message: $ExceptMessage"
            }
        } 
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        try {
            Write-ToLogFile -I -C ConfigureADC -M "Content Switch is OK, check if Load Balancer Service exists."
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type service -Resource $NSSvcName
            Write-ToLogFile -I -C ConfigureADC -M "Load Balancer Service exists, continuing."
        } catch {
            Write-ToLogFile -I -C ConfigureADC -M "Load Balancer Service does not exist, create Load Balance Service `"$NSSvcName`"."
            $payload = @{"name" = "$NSSvcName"; "ip" = "$NSSvcDestination"; "servicetype" = "HTTP"; "port" = "80"; "healthmonitor" = "NO"; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type service -Payload $payload -Action add
            Write-ToLogFile -I -C ConfigureADC -M "Load Balance Service created."
        }
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        try {
            Write-ToLogFile -I -C ConfigureADC -M "Check if Load Balance VIP exists."
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type lbvserver -Resource $NSLbName
            Write-ToLogFile -I -C ConfigureADC -M "Load Balance VIP exists, continuing"
        } catch {
            Write-ToLogFile -I -C ConfigureADC -M "Load Balance VIP does not exist, create Load Balance VIP `"$NSLbName`"."
            $payload = @{"name" = "$NSLbName"; "servicetype" = "HTTP"; "ipv46" = "0.0.0.0"; "Port" = "0"; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type lbvserver -Payload $payload -Action add
            Write-ToLogFile -I -C ConfigureADC -M "Load Balance VIP Created."
        } finally {
            Write-Host -ForeGroundColor Yellow -NoNewLine "*"
            Write-ToLogFile -I -C ConfigureADC -M "Checking if LB Service `"$NSSvcName`" is bound to Load Balance VIP `"$NSLbName`"."
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type lbvserver_service_binding -Resource $NSLbName
            if ($response.lbvserver_service_binding.servicename -eq $NSSvcName) {
                Write-ToLogFile -I -C ConfigureADC -M "LB Service binding is OK"
            } else {
                Write-ToLogFile -I -C ConfigureADC -M "LB Service binding must be configured"
                $payload = @{"name" = "$NSLbName"; "servicename" = "$NSSvcName"; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type lbvserver_service_binding -Payload $payload
                Write-ToLogFile -I -C ConfigureADC -M "LB Service binding is OK"
            }
        }
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        try {
            Write-ToLogFile -D -C ConfigureADC -M "Checking if Responder Policies exists starting with `"$NSRspName`""
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderpolicy -Filter @{name = "/$NSRspName/" }
        } catch {
            Write-ToLogFile -E -C ConfigureADC -M "Failed to retrieve Responder Policies. Exception Message: $($_.Exception.Message)"
        }
        if (-Not([String]::IsNullOrEmpty($($response.responderpolicy)))) {
            Write-ToLogFile -D -C ConfigureADC -M "Responder Policies found:"
            $response.responderpolicy | Select-Object name, action, rule | ForEach-Object {
                Write-ToLogFile -D -C ConfigureADC -M "$($_ | ConvertTo-Json -Compress)"
            }
            ForEach ($ResponderPolicy in $response.responderpolicy) {
                try {
                    Write-Host -ForeGroundColor Yellow -NoNewLine "*"
                    Write-ToLogFile -I -C ConfigureADC -M "Checking if policy `"$($ResponderPolicy.name)`" is bound to Load Balance VIP."
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderpolicy_binding -Resource "$($ResponderPolicy.name)"
                    ForEach ($ResponderBinding in $response.responderpolicy_binding) {
                        try {
                            $args = @{"bindpoint" = "REQUEST" ; "policyname" = "$($ResponderBinding.responderpolicy_lbvserver_binding.name)"; "priority" = "$($ResponderBinding.responderpolicy_lbvserver_binding.priority)"; }
                            Write-ToLogFile -I -C ConfigureADC -M "Trying to unbind with the following arguments: $($args | ConvertTo-Json -Compress)"
                            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type lbvserver_responderpolicy_binding -Arguments $args -Resource $NSLbName
                            Write-ToLogFile -I -C ConfigureADC -M "Responder Policy unbound successfully."
                        } catch {
                            Write-ToLogFile -E -C ConfigureADC -M "Failed to unbind Responder. Exception Message: $($_.Exception.Message)"
                        }
                    }
                } catch {
                    Write-ToLogFile -E -C ConfigureADC -M "Something went wrong while Retrieving data. Exception Message: $($_.Exception.Message)"
                }
                try {
                    Write-ToLogFile -I -C ConfigureADC -M "Trying to remove the Responder Policy `"$($ResponderPolicy.name)`"."
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type responderpolicy -Resource "$($ResponderPolicy.name)"
                    Write-ToLogFile -I -C ConfigureADC -M "Responder Policy removed successfully."
                } catch {
                    Write-ToLogFile -E -C ConfigureADC -M "Failed to remove the Responder Policy. Exception Message: $($_.Exception.Message)"
                }
            }
    
        } else {
            Write-ToLogFile -I -C ConfigureADC -M "No Responder Policies found."
        }
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        Write-ToLogFile -I -C ConfigureADC -M "Checking if Responder Actions exists starting with `"$NSRsaName`"."
        try {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderaction -Filter @{name = "/$NSRsaName/" }
        } catch {
            Write-ToLogFile -E -C ConfigureADC -M "Failed to retrieve Responder Actions. Exception Message: $($_.Exception.Message)"
        }
        if (-Not([String]::IsNullOrEmpty($($response.responderaction)))) {
            Write-ToLogFile -D -C ConfigureADC -M "Responder Actions found:"
            $response.responderaction | Select-Object name, target | ForEach-Object {
                Write-ToLogFile -D -C ConfigureADC -M "$($_ | ConvertTo-Json -Compress)"
            }
            ForEach ($ResponderAction in $response.responderaction) {
                Write-Host -ForeGroundColor Yellow -NoNewLine "*"
                try {
                    Write-ToLogFile -I -C ConfigureADC -M "Trying to remove the Responder Action `"$($ResponderAction.name)`""
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type responderaction -Resource "$($ResponderAction.name)"
                    Write-ToLogFile -I -C ConfigureADC -M "Responder Action removed successfully."
                } catch {
                    Write-ToLogFile -E -C ConfigureADC -M "Failed to remove the Responder Action. Exception Message: $($_.Exception.Message)"
                }
            }
        } else {
            Write-ToLogFile -I -C ConfigureADC -M "No Responder Actions found."
        }
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        Write-ToLogFile -D -C ConfigureADC -M "Creating a test Responder Action."
        $payload = @{"name" = "$($NSRsaName)_test"; "type" = "respondwith"; "target" = '"HTTP/1.0 200 OK" +"\r\n\r\n" + "XXXX"'; }
        $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type responderaction -Payload $payload -Action add
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        Write-ToLogFile -D -C ConfigureADC -M "Responder Action created, creating a test Responder Policy."
        $payload = @{"name" = "$($NSRspName)_test"; "action" = "$($NSRsaName)_test"; "rule" = 'HTTP.REQ.URL.CONTAINS(".well-known/acme-challenge/XXXX")'; }
        $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type responderpolicy -Payload $payload -Action add
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        Write-ToLogFile -D -C ConfigureADC -M "Responder Policy created, binding Responder Policy `"$($NSRspName)_test`" to Load Balance VIP: `"$NSLbName`"."
        $payload = @{"name" = "$NSLbName"; "policyname" = "$($NSRspName)_test"; "priority" = 5; }
        $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type lbvserver_responderpolicy_binding -Payload $payload -Resource $NSLbName
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        try {
            Write-ToLogFile -I -C ConfigureADC -M "Responder Policy bound successfully, check if Content Switch Policy exists."
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type cspolicy -Resource $NSCspName
            Write-ToLogFile -I -C ConfigureADC -M "Content Switch Policy exists, continuing."
            if (-not($response.cspolicy.rule -eq "HTTP.REQ.URL.CONTAINS(`"well-known/acme-challenge/`")")) {
                $payload = @{"policyname" = "$NSCspName"; "rule" = "HTTP.REQ.URL.CONTAINS(`"well-known/acme-challenge/`")"; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type cspolicy -Payload $payload
                Write-ToLogFile -D -C ConfigureADC -M "Response: $($response | ConvertTo-Json -Compress)"
            }
        } catch {
            Write-ToLogFile -I -C ConfigureADC -M "Create Content Switch Policy."
            $payload = @{"policyname" = "$NSCspName"; "rule" = 'HTTP.REQ.URL.CONTAINS("well-known/acme-challenge/")'; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type cspolicy -Payload $payload -Action add
        }
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        Write-ToLogFile -I -C ConfigureADC -M "Content Switch Policy created successfully, bind Load Balancer `"$NSLbName`" to Content Switch `"$NSCsVipName`" with prio: $NSCsVipBinding"
        $payload = @{"name" = "$NSCsVipName"; "policyname" = "$NSCspName"; "priority" = "$NSCsVipBinding"; "targetlbvserver" = "$NSLbName"; "gotopriorityexpression" = "END"; }
        $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type csvserver_cspolicy_binding -Payload $payload
        Write-ToLogFile -I -C ConfigureADC -M "Binding created successfully! Finished configuring the ADC"
    } catch {
        Write-Host -ForeGroundColor Red " Error"
        Write-ToLogFile -E -C ConfigureADC -M "Could not configure the ADC. Exception Message: $($_.Exception.Message)"
        Write-Error "Could not configure the ADC!"
        TerminateScript 1 "Could not configure the ADC!"
    }
    Start-Sleep -Seconds 2
    Write-Host -ForeGroundColor Green " Ready"
}
#endregion ConfigureADC

#region CheckDNS

if ((-not $CleanADC) -and (-not $RemoveTestCertificates) -and ($ADCActionsRequired) -and ($ValidationMethod -eq "http")) {
    ""
    Write-Host -ForeGroundColor White "Executing some tests, can take a couple of seconds/minutes..."
    Write-Host -ForeGroundColor Yellow "`r`nNOTE: Should a DNS test fail, the script will try to continue!"
    Write-Host -ForeGroundColor White "`r`nDNS Validation & Verifying ADC config"
    Write-ToLogFile -I -C CheckDNS -M "DNS Validation & Verifying ADC config."
    ForEach ($DNSObject in $DNSObjects ) {
        Write-Host -ForeGroundColor White -NoNewLine " -DNS Hostname..........: "
        Write-Host -ForeGroundColor Blue "$($DNSObject.DNSName) [$($DNSObject.IPAddress)]"
        $TestURL = "http://$($DNSObject.DNSName)/.well-known/acme-challenge/XXXX"
        Write-ToLogFile -I -C CheckDNS -M "Testing if the Citrix ADC (Content Switch) is configured successfully by accessing URL: `"$TestURL`" (via internal DNS)."
        try {
            Write-ToLogFile -D -C CheckDNS -M "Retrieving data"
            $result = Invoke-WebRequest -URI $TestURL -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
            Write-ToLogFile -I -C CheckDNS -M "Retrieved successfully."
            Write-ToLogFile -D -C CheckDNS -M "output: $($result | Select-Object StatusCode,StatusDescription,RawContent | ConvertTo-Json -Compress)"
        } catch {
            $result = $null
            Write-ToLogFile -E -C CheckDNS -M "Internal check failed. Exception Message: $($_.Exception.Message)"
        }
        if ($result.RawContent -eq "HTTP/1.0 200 OK`r`n`r`nXXXX") {
            Write-Host -ForeGroundColor White -NoNewLine " -Test (Int. DNS).......: "
            Write-Host -ForeGroundColor Green "OK"
            Write-ToLogFile -I -C CheckDNS -M "Test (Int. DNS): OK"
        } else {
            Write-Host -ForeGroundColor White -NoNewLine " -Test (Int. DNS).......: "
            Write-Host -ForeGroundColor Yellow "Not successful, maybe not resolvable internally?"
            Write-ToLogFile -W -C CheckDNS -M "Test (Int. DNS): Not successful, maybe not resolvable externally?"
            Write-ToLogFile -D -C CheckDNS -M "Output: $($result | Select-Object StatusCode,StatusDescription,RawContent | ConvertTo-Json -Compress)"
        }

        try {
            Write-ToLogFile -I -C CheckDNS -M "Checking if Public IP is available for external DNS testing."
            [ref]$ValidIP = [IPAddress]::None
            if (([IPAddress]::TryParse("$($DNSObject.IPAddress)", $ValidIP)) -and (-not ($DisableIPCheck))) {
                Write-ToLogFile -I -C CheckDNS -M "Testing if the Citrix ADC (Content Switch) is configured successfully by accessing URL: `"$TestURL`" (via external DNS)."
                $TestURL = "http://$($DNSObject.IPAddress)/.well-known/acme-challenge/XXXX"
                $Headers = @{"Host" = "$($DNSObject.DNSName)" }
                Write-ToLogFile -D -C CheckDNS -M "Retrieving data with the following headers: $($Headers | ConvertTo-Json -Compress)"
                $result = Invoke-WebRequest -URI $TestURL -Headers $Headers -TimeoutSec 10 -UseBasicParsing
                Write-ToLogFile -I -C CheckDNS -M "Success"
                Write-ToLogFile -D -C CheckDNS -M "Output: $($result | Select-Object StatusCode,StatusDescription,RawContent | ConvertTo-Json -Compress)"
            } else {
                Write-ToLogFile -I -C CheckDNS -M "Public IP is not available for external DNS testing"
            }
        } catch {
            $result = $null
            Write-ToLogFile -E -C CheckDNS -M "External check failed. Exception Message: $($_.Exception.Message)"
        }
        [ref]$ValidIP = [IPAddress]::None
        if (([IPAddress]::TryParse("$($DNSObject.IPAddress)", $ValidIP)) -and (-not ($DisableIPCheck))) {
            if ($result.RawContent -eq "HTTP/1.0 200 OK`r`n`r`nXXXX") {
                Write-Host -ForeGroundColor White -NoNewLine " -Test (Ext. DNS)..: "
                Write-Host -ForeGroundColor Green "OK"
                Write-ToLogFile -I -C CheckDNS -M "Test (Ext. DNS): OK"
            } else {
                Write-Host -ForeGroundColor White -NoNewLine " -Test (Ext. DNS)..: "
                Write-Host -ForeGroundColor Yellow "Not successful, maybe not resolvable externally?"
                Write-ToLogFile -W -C CheckDNS -M "Test (Ext. DNS): Not successful, maybe not resolvable externally?"
                Write-ToLogFile -D -C CheckDNS -M "Output: $($result | Select-Object StatusCode,StatusDescription,RawContent | ConvertTo-Json -Compress)"
            }
        }
    }
    Write-Host -ForeGroundColor White "`r`nFinished the tests, script will continue"
    Write-ToLogFile -I -C CheckDNS -M "Finished the tests, script will continue."
}
#endregion CheckDNS

#region OrderValidation

if ((-not $CleanADC) -and (-not $RemoveTestCertificates) -and ($ValidationMethod -eq "http")) {
    Write-ToLogFile -I -C OrderValidation -M "Configuring the ADC Responder Policies/Actions required for the validation."
    Write-ToLogFile -D -C OrderValidation -M "PAOrderItems:"
    $PAOrderItems | Select-Object fqdn, status, Expires, HTTP01Status, DNS01Status | ForEach-Object {
        Write-ToLogFile -D -C OrderValidation -M "$($_ | ConvertTo-Json -Compress)"
    }
    Write-Host -ForeGroundColor White "`r`nADC - Order Validation"
    foreach ($DNSObject in $DNSObjects) {
        $ADCKeyAuthorization = $null
        $PAOrderItem = $PAOrderItems | Where-Object { $_.fqdn -eq $DNSObject.DNSName }
        Write-Host -ForeGroundColor White -NoNewLine " -DNS Hostname..........: "
        Write-Host -ForeGroundColor Blue "$($DNSObject.DNSName)"
        Write-Host -ForeGroundColor White -NoNewLine " -Ready for Validation..: "
        if ($PAOrderItem.status -eq "valid") {
            Write-Host -ForeGroundColor Green "=> N/A, Still valid"
            Write-ToLogFile -I -C OrderValidation -M "`"$($DNSObject.DNSName)`" is valid, nothing to configure."
        } else {
            Write-ToLogFile -I -C OrderValidation -M "New validation required for `"$($DNSObject.DNSName)`", Start configuring the ADC."
            $PAToken = ".well-known/acme-challenge/$($PAOrderItem.HTTP01Token)"
            $KeyAuth = Posh-ACME\Get-KeyAuthorization -Token $($PAOrderItem.HTTP01Token) -Account $PAAccount
            $ADCKeyAuthorization = "HTTP/1.0 200 OK\r\n\r\n$($KeyAuth)"
            $RspName = "{0}_{1}" -f $NSRspName, $DNSObject.ResponderPrio
            $RsaName = "{0}_{1}" -f $NSRsaName, $DNSObject.ResponderPrio
            Write-Host -ForeGroundColor Yellow -NoNewLine "*"
            try {
                Write-ToLogFile -I -C OrderValidation -M "Add Responder Action `"$RsaName`" to return `"$ADCKeyAuthorization`"."
                $payload = @{"name" = "$RsaName"; "type" = "respondwith"; "target" = "`"$ADCKeyAuthorization`""; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type responderaction -Payload $payload -Action add
                Write-ToLogFile -I -C OrderValidation -M "Responder Action added successfully."
                Write-ToLogFile -D -C OrderValidation -M "Output: $($response | ConvertTo-Json -Compress)"
                Write-Host -ForeGroundColor Yellow -NoNewLine "*"
                try {
                    Write-ToLogFile -I -C OrderValidation -M "Add Responder Policy `"$RspName`" to: `"HTTP.REQ.URL.CONTAINS(`"$PAToken`")`""
                    $payload = @{"name" = "$RspName"; "action" = "$RsaName"; "rule" = "HTTP.REQ.URL.CONTAINS(`"$PAToken`")"; }
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type responderpolicy -Payload $payload -Action add
                    Write-ToLogFile -I -C OrderValidation -M "Responder Policy added successfully."
                    Write-ToLogFile -D -C OrderValidation -M "Output: $($response | ConvertTo-Json -Compress)"
                    Write-Host -ForeGroundColor Yellow -NoNewLine "*"
                    try {
                        Write-ToLogFile -I -C OrderValidation -M "Trying to bind the Responder Policy `"$RspName`" to LoadBalance VIP: `"$NSLbName`""
                        $payload = @{"name" = "$NSLbName"; "policyname" = "$RspName"; "priority" = "$($DNSObject.ResponderPrio)"; }
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type lbvserver_responderpolicy_binding -Payload $payload -Resource $NSLbName
                        Write-ToLogFile -I -C OrderValidation -M "Responder Policy successfully bound to Load Balance VIP."
                        Write-ToLogFile -D -C OrderValidation -M "Output: $($response | ConvertTo-Json -Compress)"
                        try {
                            Write-ToLogFile -I -C OrderValidation -M "Sending acknowledgment to Let's Encrypt."
                            Send-ChallengeAck -ChallengeUrl $($PAOrderItem.HTTP01Url) -Account $PAAccount
                            Write-ToLogFile -I -C OrderValidation -M "Successfully send."
                            Write-ToLogFile -D -C OrderValidation -M "Output: $($response | ConvertTo-Json -Compress)"
                        } catch {
                            Write-ToLogFile -E -C OrderValidation -M "Error while submitting the Challenge. Exception Message: $($_.Exception.Message)"
                            Write-Error "Error while submitting the Challenge."
                            TerminateScript 1 "Error while submitting the Challenge."
                        }
                        Write-Host -ForeGroundColor Green " Ready"
                    } catch {
                        Write-ToLogFile -E -C OrderValidation -M "Failed to bind Responder Policy to Load Balance VIP. Exception Message: $($_.Exception.Message)"
                        Write-Host -ForeGroundColor Red " ERROR  [Responder Policy Binding - $RspName]"
                        $ValidationMethod = $null
                        Write-Error  $($_.Exception.Message)
                        TerminateScript 1 "Failed to bind Responder Policy to Load Balance VIP"
                    }
                } catch {
                    Write-ToLogFile -E -C OrderValidation -M "Failed to add Responder Policy. Exception Message: $($_.Exception.Message)"
                    Write-Host -ForeGroundColor Red " ERROR  [Responder Policy - $RspName]"
                    Write-Error  $($_.Exception.Message)
                    TerminateScript 1 "Failed to add Responder Policy"
                }
            } catch {
                Write-ToLogFile -E -C OrderValidation -M "Failed to add Responder Action. Error Details: $($_.Exception.Message)"
                Write-Host -ForeGroundColor Red " ERROR  [Responder Action - $RsaName]"
                Write-Error  $($_.Exception.Message)
                TerminateScript 1 "Failed to add Responder Action"
            }
        }
    }
    Write-Host -ForeGroundColor White "`r`nWaiting for Order completion"
    Write-Host -ForeGroundColor White -NoNewLine " -Completion............: "
    Write-ToLogFile -I -C OrderValidation -M "Retrieving validation status."
    Write-Host -ForeGroundColor Yellow -NoNewLine "*"
    $PAOrderItems = Posh-ACME\Get-PAOrder -Refresh -MainDomain $CN | Posh-ACME\Get-PAAuthorizations
    Write-ToLogFile -D -C OrderValidation -M "PAOrderItems:"
    $PAOrderItems | Select-Object fqdn, status, Expires, HTTP01Status, DNS01Status | ForEach-Object {
        Write-ToLogFile -D -C OrderValidation -M "$($_ | ConvertTo-Json -Compress)"
    }
    $WaitLoop = 10
    Write-Host -ForeGroundColor Yellow -NoNewLine "*"
    while (($WaitLoop -gt 0) -and (($PAOrderItems | Where-Object { $_.status -eq "pending" }).Count -gt 0)) {
        Write-ToLogFile -I -C OrderValidation -M "Still $(($PAOrderItems | Where-Object {$_.status -eq "pending"}).Count) `"pending`" items left. Waiting an extra couple of seconds."
        Start-Sleep -Seconds 6
        $PAOrderItems = Posh-ACME\Get-PAOrder -Refresh -MainDomain $CN | Posh-ACME\Get-PAAuthorizations
        $WaitLoop--
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
    }
    if ($PAOrderItems | Where-Object { $_.status -ne "valid" }) {
        Write-Host -ForeGroundColor Red "Failed"
        Write-ToLogFile -E -C OrderValidation -M "Unfortunately there are invalid items."
        Write-ToLogFile -E -C OrderValidation -M "Failed Records: $($PAOrderItems | Where-Object { $_.status -ne "valid" } | Select-Object fqdn,status,Expires,HTTP01Status,DNS01Status | Format-Table | Out-String)"
        Write-Host -ForeGroundColor White "`r`nInvalid items:"
        ForEach ($Item in $($PAOrderItems | Where-Object { $_.status -ne "valid" })) {
            Write-Host -ForeGroundColor White -NoNewLine " -DNS Hostname..........: "
            Write-Host -ForeGroundColor Blue "$($Item.fqdn)"
            Write-Host -ForeGroundColor White -NoNewLine " -Status................: "
            Write-Host -ForeGroundColor Red " ERROR [$($Item.status)]"
        }
        Write-Error "There are some items invalid"
        TerminateScript 1 "There are some items invalid"
    } else {
        Write-Host -ForeGroundColor Green " Completed"
        Write-ToLogFile -I -C OrderValidation -M "Validation status finished."
    }
}

#endregion OrderValidation

#region CleanupADC

if ((-not $RemoveTestCertificates) -and (($CleanADC) -or ($ValidationMethod -in "http", "dns"))) {
    Write-ToLogFile -I -C CleanupADC -M "Cleaning the Citrix ADC Configuration."
    Write-Host -ForeGroundColor White "`r`nADC - Cleanup"
    Write-Host -ForeGroundColor White -NoNewLine " -Cleanup...............: "
    Write-ToLogFile -I -C CleanupADC -M "Trying to login into the Citrix ADC."
    $ADCSession = Connect-ADC -ManagementURL $ManagementURL -Credential $Credential -PassThru
    Write-ToLogFile -I -C CleanupADC -M "Connected to Citrix ADC $ManagementURL, as user $($ADCSession.Username)"
    try {
        Write-ToLogFile -I -C CleanupADC -M "Checking if a binding exists for `"$NSCspName`"."
        $Filters = @{"policyname" = "$NSCspName" }
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csvserver_cspolicy_binding -Resource "$NSCsVipName" -Filters $Filters
        if ($response.csvserver_cspolicy_binding.policyname -eq $NSCspName) {
            Write-ToLogFile -I -C CleanupADC -M "Binding exists, removing Content Switch LoadBalance Binding."
            $Arguments = @{"name" = "$NSCsVipName"; "policyname" = "$NSCspName"; "priority" = "$NSCsVipBinding"; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type csvserver_cspolicy_binding -Arguments $Arguments
        } else {
            Write-ToLogFile -I -C CleanupADC -M "No binding found."
        }
    } catch {
        Write-ToLogFile -E -C CleanupADC -M "Not able to remove the Content Switch LoadBalance Binding. Exception Message: $($_.Exception.Message)"
        Write-Warning "Not able to remove the Content Switch LoadBalance Binding"
    }
    Write-Host -ForeGroundColor Yellow -NoNewLine "*"
    try {
        Write-ToLogFile -I -C CleanupADC -M "Checking if Content Switch Policy `"$NSCspName`" exists."
        try {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type cspolicy -Resource "$NSCspName"
        } catch { }
        if ($response.cspolicy.policyname -eq $NSCspName) {
            Write-ToLogFile -I -C CleanupADC -M "Content Switch Policy exist, removing Content Switch Policy."
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type cspolicy -Resource "$NSCspName"
            Write-ToLogFile -I -C CleanupADC -M "Removed Content Switch Policy successfully."
        } else {
            Write-ToLogFile -I -C CleanupADC -M "Content Switch Policy not found."
        }
    } catch {
        Write-ToLogFile -E -C CleanupADC -M "Not able to remove the Content Switch Policy. Exception Message: $($_.Exception.Message)"
        Write-Warning "Not able to remove the Content Switch Policy"
    }
    Write-Host -ForeGroundColor Yellow -NoNewLine "*"
    try {
        Write-ToLogFile -I -C CleanupADC -M "Checking if Load Balance VIP `"$NSLbName`" exists."
        try {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type lbvserver -Resource "$NSLbName"
        } catch { }
        if ($response.lbvserver.name -eq $NSLbName) {
            Write-ToLogFile -I -C CleanupADC -M "Load Balance VIP exist, removing the Load Balance VIP."
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type lbvserver -Resource "$NSLbName"
        } else {
            Write-ToLogFile -I -C CleanupADC -M "Load Balance VIP not found."
        }
    } catch {
        Write-ToLogFile -E -C CleanupADC -M "Not able to remove the Load Balance VIP. Exception Message: $($_.Exception.Message)"
        Write-Warning "Not able to remove the Load Balance VIP"
    }
    Write-Host -ForeGroundColor Yellow -NoNewLine "*"
    try {
        Write-ToLogFile -I -C CleanupADC -M "Checking if Load Balance Service `"$NSSvcName`" exists."
        try {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type service -Resource "$NSSvcName"
        } catch { }
        if ($response.service.name -eq $NSSvcName) {
            Write-ToLogFile -I -C CleanupADC -M "Load Balance Service exist, removing Service `"$NSSvcName`"."
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type service -Resource "$NSSvcName"
        } else {
            Write-ToLogFile -I -C CleanupADC -M "Load Balance Service not found."
        }
    } catch {
        Write-ToLogFile -E -C CleanupADC -M "Not able to remove the Service. Exception Message: $($_.Exception.Message)"
        Write-Warning "Not able to remove the Service"
    }
    Write-Host -ForeGroundColor Yellow -NoNewLine "*"
    try {
        Write-ToLogFile -I -C CleanupADC -M "Checking if Load Balance Server `"$NSSvcDestination`" exists."
        try {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type server -Resource "$NSSvcDestination"
        } catch { }
        if ($response.server.name -eq $NSSvcDestination) {
            Write-ToLogFile -I -C CleanupADC -M "Load Balance Server exist, removing Load Balance Server `"$NSSvcDestination`"."
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type server -Resource "$NSSvcDestination"
        } else {
            Write-ToLogFile -I -C CleanupADC -M "Load Balance Server not found."
        }
    } catch {
        Write-ToLogFile -E -C CleanupADC -M "Not able to remove the Server. Exception Message: $($_.Exception.Message)"
        Write-Warning "Not able to remove the Server"
    }
    Write-ToLogFile -I -C CleanupADC -M "Checking if there are Responder Policies starting with the name `"$NSRspName`"."
    Write-Host -ForeGroundColor Yellow -NoNewLine "*"
    try {
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderpolicy -Filter @{name = "/$NSRspName/" }
    } catch {
        Write-ToLogFile -E -C CleanupADC -M "Failed to retrieve Responder Policies. Exception Message: $($_.Exception.Message)"
    }
    if (-Not([String]::IsNullOrEmpty($response.responderpolicy))) {
        Write-ToLogFile -D -C CleanupADC -M "Responder Policies found:"
        $response.responderpolicy | Select-Object name, action, rule | ForEach-Object {
            Write-ToLogFile -D -C CleanupADC -M "$($_ | ConvertTo-Json -Compress)"
        }
        ForEach ($ResponderPolicy in $response.responderpolicy) {
            try {
                Write-ToLogFile -I -C CleanupADC -M "Checking if policy `"$($ResponderPolicy.name)`" is bound to Load Balance VIP."
                $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderpolicy_binding -Resource "$($ResponderPolicy.name)"
                ForEach ($ResponderBinding in $response.responderpolicy_binding) {
                    try {
                        $args = @{"bindpoint" = "REQUEST" ; "policyname" = "$($ResponderBinding.responderpolicy_lbvserver_binding.name)"; "priority" = "$($ResponderBinding.responderpolicy_lbvserver_binding.priority)"; }
                        Write-ToLogFile -I -C CleanupADC -M "Trying to unbind with the following arguments: $($args | ConvertTo-Json -Compress)"

                        $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type lbvserver_responderpolicy_binding -Arguments $args -Resource $NSLbName
                        Write-ToLogFile -I -C CleanupADC -M "Responder Policy unbound successfully."
                    } catch {
                        Write-ToLogFile -E -C CleanupADC -M "Failed to unbind Responder. Exception Message: $($_.Exception.Message)"
                    }
                }
            } catch {
                Write-ToLogFile -E -C CleanupADC -M "Something went wrong while Retrieving data. Exception Message: $($_.Exception.Message)"
            }
            try {
                Write-ToLogFile -I -C CleanupADC -M "Trying to remove the Responder Policy `"$($ResponderPolicy.name)`"."
                $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type responderpolicy -Resource "$($ResponderPolicy.name)"
                Write-ToLogFile -I -C CleanupADC -M "Responder Policy removed successfully."
            } catch {
                Write-ToLogFile -E -C CleanupADC -M "Failed to remove the Responder Policy. Exception Message: $($_.Exception.Message)"
            }
        }
    } else {
        Write-ToLogFile -I -C CleanupADC -M "No Responder Policies found."
    }
    Write-ToLogFile -I -C CleanupADC -M "Checking if there are Responder Actions starting with the name `"$NSRsaName`"."
    Write-Host -ForeGroundColor Yellow -NoNewLine "*"
    try {
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderaction -Filter @{name = "/$NSRsaName/" }
    } catch {
        Write-ToLogFile -E -C CleanupADC -M "Failed to retrieve Responder Actions. Exception Message: $($_.Exception.Message)"
    }
    if (-Not([String]::IsNullOrEmpty($response.responderaction))) {
        Write-ToLogFile -D -C CleanupADC -M "Responder Actions found:"
        $response.responderaction | Select-Object name, target | ForEach-Object {
            Write-ToLogFile -D -C CleanupADC -M "$($_ | ConvertTo-Json -Compress)"
        }
        ForEach ($ResponderAction in $response.responderaction) {
            try {
                Write-ToLogFile -I -C CleanupADC -M "Trying to remove the Responder Action `"$($ResponderAction.name)`""
                $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type responderaction -Resource "$($ResponderAction.name)"
                Write-ToLogFile -I -C CleanupADC -M "Responder Action removed successfully."
            } catch {
                Write-ToLogFile -E -C CleanupADC -M "Failed to remove the Responder Action. Exception Message: $($_.Exception.Message)"
            }
        }
    } else {
        Write-ToLogFile -I -C CleanupADC -M "No Responder Actions found."
    }
    Write-Host -ForeGroundColor Green " Completed"
    Write-ToLogFile -I -C CleanupADC -M "Finished cleaning up."
}

#endregion CleanupADC

#region DNSChallenge

if ((-not $CleanADC) -and (-not $RemoveTestCertificates) -and ($ValidationMethod -eq "dns")) {
    $PAOrderItems = Posh-ACME\Get-PAOrder -Refresh -MainDomain $CN | Posh-ACME\Get-PAAuthorizations
    $TXTRecords = $PAOrderItems | Select-Object fqdn, `
    @{L = 'TXTName'; E = { "_acme-challenge.$($_.fqdn.Replace('*.',''))" } }, `
    @{L = 'TXTValue'; E = { ConvertTo-TxtValue (Get-KeyAuthorization $_.DNS01Token) } }
    Write-Host -ForegroundColor White "`r`n********************************************************************"
    Write-Host -ForegroundColor White "* Make sure the following TXT records are configured at your DNS   *"
    Write-Host -ForegroundColor White "* provider before continuing! If not, DNS validation will fail!    *"
    Write-Host -ForegroundColor White "********************************************************************"
    Write-ToLogFile -I -C DNSChallenge -M "Make sure the following TXT records are configured at your DNS provider before continuing! If not, DNS validation will fail!"
    foreach ($Record in $TXTRecords) {
        ""
        Write-Host -ForeGroundColor White -NoNewLine " -DNS Hostname..........: "
        Write-Host -ForeGroundColor Blue "$($Record.fqdn)"
        Write-Host -ForeGroundColor White -NoNewLine " -TXT Record Name.......: "
        Write-Host -ForeGroundColor Yellow "$($Record.TXTName)"
        Write-Host -ForeGroundColor White -NoNewLine " -TXT Record Value......: "
        Write-Host -ForeGroundColor Yellow "$($Record.TXTValue)"
        Write-ToLogFile -I -C DNSChallenge -M "DNS Hostname: `"$($Record.fqdn)`" => TXT Record Name: `"$($Record.TXTName)`", Value: `"$($Record.TXTValue)`"."
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
    Write-ToLogFile -I -C DNSChallenge -M "Start verifying the TXT records."
    $issues = $false
    try {
        Write-Host -ForegroundColor White "`r`nPre-Checking the TXT records"
        Foreach ($Record in $TXTRecords) {
            Write-Host -ForeGroundColor White -NoNewLine " -DNS Hostname..........: "
            Write-Host -ForeGroundColor Blue "$($Record.fqdn)"
            Write-Host -ForeGroundColor White -NoNewLine " -TXT Record check......: "
            Write-ToLogFile -I -C DNSChallenge -M "Trying to retrieve the TXT record for `"$($Record.fqdn)`"."
            $result = $null
            $dnsserver = Resolve-DnsName -Name $Record.TXTName -Server $PublicDnsServer -DnsOnly
            if ([String]::IsNullOrWhiteSpace($dnsserver.PrimaryServer)) {
                Write-ToLogFile -D -C DNSChallenge -M "Using DNS Server `"$PublicDnsServer`" for resolving the TXT records."
                $result = Resolve-DnsName -Name $Record.TXTName -Type TXT -Server $PublicDnsServer -DnsOnly
            } else {
                Write-ToLogFile -D -C DNSChallenge -M "Using DNS Server `"$($dnsserver.PrimaryServer)`" for resolving the TXT records."
                $result = Resolve-DnsName -Name $Record.TXTName -Type TXT -Server $dnsserver.PrimaryServer -DnsOnly
            }
            Write-ToLogFile -D -C DNSChallenge -M "Output: $($result | ConvertTo-Json -Compress)"
            if ([String]::IsNullOrWhiteSpace($result.Strings -like "*$($Record.TXTValue)*")) {
                Write-Host -ForegroundColor Yellow "Could not determine"
                $issues = $true
                Write-ToLogFile -W -C DNSChallenge -M "Could not determine."
            } else {
                Write-Host -ForegroundColor Green "OK"
                Write-ToLogFile -I -C DNSChallenge -M "Check OK."
            }
        }
    } catch {
        Write-ToLogFile -E -C DNSChallenge -M "Caught an error. Exception Message: $($_.Exception.Message)"
        $issues = $true
    }
    if ($issues) {
        ""
        Write-Warning "Found issues during the initial test. TXT validation might fail. Waiting an additional 30 seconds before continuing..."
        Write-ToLogFile -W -C DNSChallenge -M "Found issues during the initial test. TXT validation might fail."
        Start-Sleep -Seconds 20
    }
}

#endregion DNSChallenge

#region FinalizingOrder

if ((-not $CleanADC) -and (-not $RemoveTestCertificates) -and ($ValidationMethod -in "dns")) {
    Write-ToLogFile -I -C FinalizingOrder -M "Check if DNS Records need to be validated."
    Write-Host -ForeGroundColor White "`r`nSending Acknowledgment"
    Foreach ($DNSObject in $DNSObjects) {
        Write-Host -ForeGroundColor White -NoNewLine " -DNS Hostname..........: "
        Write-Host -ForeGroundColor Blue "$($DNSObject.DNSName)"
        Write-ToLogFile -I -C FinalizingOrder -M "Validating item: `"$($DNSObject.DNSName)`"."
        Write-Host -ForeGroundColor White -NoNewLine " -Send Ack..............: "
        $PAOrderItem = Posh-ACME\Get-PAOrder -MainDomain $CN | Posh-ACME\Get-PAAuthorizations | Where-Object { $_.fqdn -eq $DNSObject.DNSName }
        Write-Host -ForeGroundColor Yellow -NoNewLine "*"
        Write-ToLogFile -D -C FinalizingOrder -M "OrderItem:"
        $PAOrderItem | Select-Object fqdn, status, DNS01Status, expires | ForEach-Object {
            Write-ToLogFile -D -C FinalizingOrder -M "$($_ | ConvertTo-Json -Compress)"
        }
        if (($PAOrderItem.DNS01Status -notlike "valid") -and ($PAOrderItem.DNS01Status -notlike "invalid")) {
            try {
                Write-ToLogFile -I -C FinalizingOrder -M "Validation required, start submitting Challenge."
                Posh-ACME\Send-ChallengeAck -ChallengeUrl $($PAOrderItem.DNS01Url) -Account $PAAccount
                Write-Host -ForeGroundColor Yellow -NoNewLine "*"
                Write-ToLogFile -I -C FinalizingOrder -M "Submitted the Challenge successfully."
            } catch {
                Write-Host -ForeGroundColor Red " ERROR"
                Write-ToLogFile -E -C FinalizingOrder -M "Caught an error. Exception Message: $($_.Exception.Message)"
                Write-Error "Error while submitting the Challenge"
                TerminateScript 1 "Error while submitting the Challenge"
            }
            Write-Host -ForeGroundColor Green " Sent Successfully"
        } elseif ($PAOrderItem.DNS01Status -like "valid") {
            Write-ToLogFile -I -C FinalizingOrder -M "The item is valid."
            $DNSObject.Done = $true
            Write-Host -ForeGroundColor Green " Still valid"
        } else {
            Write-ToLogFile -W -C FinalizingOrder -M "Unexpected status: $($PAOrderItem.DNS01Status)"
        }
        $PAOrderItem = $null
    }
    $i = 1
    Write-Host -ForeGroundColor White "`r`nValidation"
    Write-ToLogFile -I -C FinalizingOrder -M "Start validation."
    while ($i -le 20) {
        Write-Host -ForeGroundColor White " -Attempt...............: $i"
        Write-ToLogFile -I -C FinalizingOrder -M "Validation attempt: $i"
        $PAOrderItems = Posh-ACME\Get-PAOrder -MainDomain $CN | Posh-ACME\Get-PAAuthorizations
        Foreach ($DNSObject in $DNSObjects) {
            if ($DNSObject.Done -eq $false) {
                Write-Host -ForeGroundColor White -NoNewLine " -DNS Hostname..........: "
                Write-Host -ForeGroundColor Blue "$($DNSObject.DNSName)"
                try {
                    $PAOrderItem = $PAOrderItems | Where-Object { $_.fqdn -eq $DNSObject.DNSName }
                    Write-ToLogFile -D -C FinalizingOrder -M "OrderItem:"
                    $PAOrderItem | Select-Object fqdn, status, DNS01Status, expires | ForEach-Object {
                        Write-ToLogFile -D -C FinalizingOrder -M "$($_ | ConvertTo-Json -Compress)"
                    }
                    Write-Host -ForeGroundColor White -NoNewLine " -Status................: "
                    switch ($PAOrderItem.DNS01Status.ToLower()) {
                        "pending" {
                            Write-Host -ForeGroundColor Yellow "$($PAOrderItem.DNS01Status)"
                        }
                        "invalid" {
                            $DNSObject.Done = $true
                            Write-Host -ForeGroundColor Red "$($PAOrderItem.DNS01Status)"
                        }
                        "valid" {
                            $DNSObject.Done = $true
                            Write-Host -ForeGroundColor Green "$($PAOrderItem.DNS01Status)"
                        }
                        default {
                            Write-Host -ForeGroundColor Red "UNKNOWN [$($PAOrderItem.DNS01Status)]"
                        }
                    }
                    Write-ToLogFile -I -C FinalizingOrder -M "$($DNSObject.DNSName): $($PAOrderItem.DNS01Status)"
                } catch {
                    Write-ToLogFile -E -C FinalizingOrder -M "Error while Retrieving validation status. Exception Message: $($_.Exception.Message)"
                    Write-Error "Error while Retrieving validation status"
                    TerminateScript 1 "Error while Retrieving validation status"
                }
                $PAOrderItem = $null
            }
        }
        if (-NOT ($DNSObjects | Where-Object { $_.Done -eq $false })) {
            Write-ToLogFile -I -C FinalizingOrder -M "All items validated."
            if ($PAOrderItems | Where-Object { $_.DNS01Status -eq "invalid" }) {
                Write-Host -ForegroundColor Red "`r`nERROR: Validation Failed, invalid items found! Exiting now!"
                Write-ToLogFile -E -C FinalizingOrder -M "Validation Failed, invalid items found!"
                TerminateScript 1 "Validation Failed, invalid items found!"
            }
            if ($PAOrderItems | Where-Object { $_.DNS01Status -eq "pending" }) {
                Write-Host -ForegroundColor Red "`r`nERROR: Validation Failed, still pending items left! Exiting now!"
                Write-ToLogFile -E -C FinalizingOrder -M "Validation Failed, still pending items left!"
                TerminateScript 1 "Validation Failed, still pending items left!"
            }
            break
        }
        Write-ToLogFile -I -C FinalizingOrder -M "Waiting, round: $i"
        Start-Sleep -Seconds 1
        $i++
        ""
    }
}

if ((-not $CleanADC) -and (-not $RemoveTestCertificates) -and ($ValidationMethod -in "http", "dns")) {
    Write-ToLogFile -I -C FinalizingOrder -M "Checking if order is ready."
    $Order = $PAOrder | Posh-ACME\Get-PAOrder -Refresh
    Write-ToLogFile -D -C FinalizingOrder -M "Order state: $($Order.status)"
    if ($Order.status -eq "ready") {
        Write-ToLogFile -I -C FinalizingOrder -M "Order is ready."
    } else {
        Write-ToLogFile -I -C FinalizingOrder -M "Order is still not ready, validation failed?" -Verbose
    }
    Write-ToLogFile -I -C FinalizingOrder -M "Requesting certificate."
    try {
        $NewCertificates = New-PACertificate -Domain $($DNSObjects.DNSName) -DirectoryUrl $BaseService -PfxPass $PfxPassword -CertKeyLength $KeyLength -FriendlyName $FriendlyName -ErrorAction Stop
        Write-ToLogFile -D -C FinalizingOrder -M "$($NewCertificates | Select-Object Subject,NotBefore,NotAfter,KeyLength | ConvertTo-Json -Compress)"
        Write-ToLogFile -I -C FinalizingOrder -M "Certificate requested successfully."
    } catch {
        Write-ToLogFile -I -C FinalizingOrder -M "Failed to request certificate."
    }

    Start-Sleep -Seconds 1
}

#endregion FinalizingOrder

#region CertFinalization

if ((-not ($CleanADC)) -and (-not ($RemoveTestCertificates))) {
    $CertificateAlias = "CRT-SAN-$SessionDateTime-$($CN.Replace('*.',''))"
    $CertificateDirectory = Join-Path -Path $CertDir -ChildPath $CertificateAlias
    Write-ToLogFile -I -C CertFinalization -M "Create directory `"$CertificateDirectory`" for storing the new certificates."
    New-Item $CertificateDirectory -ItemType directory -force | Out-Null
    $CertificateName = "$($ScriptDateTime.ToString("yyyyMMddHHmm"))-$($CN.Replace('*.',''))"
    if (Test-Path $CertificateDirectory) {
        Write-ToLogFile -I -C CertFinalization -M "Retrieving certificate info."
        $PACertificate = Posh-ACME\Get-PACertificate -MainDomain $cn
        Write-ToLogFile -I -C CertFinalization -M "Retrieved successfully."
        $ChainFile = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 "$($PACertificate.ChainFile)"
        $CAName = $ChainFile.DnsNameList.Unicode.Replace("'", "")
        $IntermediateCACertKeyName = "$($CAName)-int"
        $IntermediateCAFileName = "$($IntermediateCACertKeyName).crt"
        $IntermediateCAFullPath = Join-Path -Path $CertificateDirectory -ChildPath $IntermediateCAFileName

        Write-ToLogFile -D -C CertFinalization -M "Intermediate: `"$IntermediateCAFileName`"."
        Copy-Item $PACertificate.ChainFile -Destination $IntermediateCAFullPath -Force
        if ($Production) {
            if ($CertificateName.length -ge 31) {
                $CertificateName = "$($CertificateName.subString(0,31))"
                Write-ToLogFile -D -C CertFinalization -M "CertificateName (new name): `"$CertificateName`" ($($CertificateName.length) max 31)"
            } else {
                $CertificateName = "$CertificateName"
                Write-ToLogFile -D -C CertFinalization -M "CertificateName: `"$CertificateName`" ($($CertificateName.length) max 31)"
            }
            if ($CertificateAlias.length -ge 59) {
                $CertificateFileName = "$($CertificateAlias.subString(0,59)).crt"
                Write-ToLogFile -D -C CertFinalization -M "Certificate (new name): `"$CertificateFileName`"($($CertificateFileName.length) max 63)"
                $CertificateKeyFileName = "$($CertificateAlias.subString(0,59)).key"
                Write-ToLogFile -D -C CertFinalization -M "Key (new name): `"$CertificateKeyFileName`"($($CertificateFileName.length) max 63)"
            } else {
                $CertificateFileName = "$($CertificateAlias).crt"
                Write-ToLogFile -D -C CertFinalization -M "Certificate: `"$CertificateFileName`" ($($CertificateFileName.length) max 63)"
                $CertificateKeyFileName = "$($CertificateAlias).key"
                Write-ToLogFile -D -C CertFinalization -M "Key: `"$CertificateKeyFileName`"($($CertificateFileName.length) max 63)"
            }
            $CertificatePfxFileName = "$CertificateAlias.pfx"
            $CertificatePemFileName = "$CertificateAlias.pem"
            $CertificatePfxWithChainFileName = "$($CertificateAlias)-WithChain.pfx"
        } else {
            if ($CertificateName.length -ge 27) {
                $CertificateName = "TST-$($CertificateName.subString(0,27))"
                Write-ToLogFile -D -C CertFinalization -M "CertificateName (new name): `"$CertificateName`" ($($CertificateName.length) max 31)"
            } else {
                $CertificateName = "TST-$($CertificateName)"
                Write-ToLogFile -D -C CertFinalization -M "CertificateName: `"$CertificateName`" ($($CertificateName.length) max 31)"
            }
            if ($CertificateAlias.length -ge 55) {
                $CertificateFileName = "TST-$($CertificateAlias.subString(0,55)).crt"
                Write-ToLogFile -D -C CertFinalization -M "Certificate (new name): `"$CertificateFileName`"($($CertificateFileName.length) max 63)"
                $CertificateKeyFileName = "TST-$($CertificateAlias.subString(0,55)).key"
                Write-ToLogFile -D -C CertFinalization -M "Key (new name): `"$CertificateKeyFileName`"($($CertificateFileName.length) max 63)"
            } else {
                $CertificateFileName = "TST-$($CertificateAlias).crt"
                Write-ToLogFile -D -C CertFinalization -M "Certificate: `"$CertificateFileName`"($($CertificateFileName.length) max 63)"
                $CertificateKeyFileName = "TST-$($CertificateAlias).key"
                Write-ToLogFile -D -C CertFinalization -M "Key: `"$CertificateKeyFileName`"($($CertificateFileName.length) max 63)"
            }
            $CertificatePfxFileName = "TST-$CertificateAlias.pfx"
            $CertificatePemFileName = "TST-$CertificateAlias.pem"
            $CertificatePfxWithChainFileName = "TST-$($CertificateAlias)-WithChain.pfx"
        }

        $CertificateFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificateFileName
        $CertificateKeyFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificateKeyFileName
        $CertificatePfxFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificatePfxFileName
        $CertificatePfxWithChainFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificatePfxWithChainFileName
        Write-ToLogFile -D -C CertFinalization -M "PFX: `"$CertificatePfxFileName`" ($($CertificatePfxFileName.length))"
        Copy-Item $PACertificate.CertFile -Destination $CertificateFullPath -Force
        Copy-Item $PACertificate.KeyFile -Destination $CertificateKeyFullPath -Force
        Copy-Item $PACertificate.PfxFullChain -Destination $CertificatePfxWithChainFullPath -Force
        $certificate = Get-PfxData -FilePath $CertificatePfxWithChainFullPath -Password $(ConvertTo-SecureString -String $PfxPassword -AsPlainText -Force)
        $NewCertificates = Export-PfxCertificate -PfxData $certificate -FilePath $CertificatePfxFullPath -Password $(ConvertTo-SecureString -String $PfxPassword -AsPlainText -Force) -ChainOption EndEntityCertOnly -Force
        Write-ToLogFile -I -C CertFinalization -M "Certificates Finished."
    } else {
        Write-ToLogFile -E -C CertFinalization -M "Could not test Certificate directory."
    }
}

#endregion CertFinalization

#region ADC-CertUpload

if ((-not ($CleanADC)) -and (-not ($RemoveTestCertificates))) {
    try {
        Write-ToLogFile -I -C ADC-CertUpload -M "Uploading the certificate to the Citrix ADC."
        Write-ToLogFile -D -C ADC-CertUpload -M "Retrieving existing CA Intermediate Certificate."
        $Filters = @{"serial" = "$($ChainFile.SerialNumber)" }
        $ADCIntermediateCA = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey -Filters $Filters -ErrorAction SilentlyContinue
        if ([String]::IsNullOrEmpty($($ADCIntermediateCA.sslcertkey.certkey))) {
            Write-ToLogFile -D -C ADC-CertUpload -M "Second attempt, trying without leading zero's."
            $Filters = @{"serial" = "$($ChainFile.SerialNumber.TrimStart("00"))" }
            $ADCIntermediateCA = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey -Filters $Filters -ErrorAction SilentlyContinue
        }
        Write-ToLogFile -D -C ADC-CertUpload -M "Details:"
        $ADCIntermediateCA.sslcertkey | Select-Object certkey, issuer, subject, serial, clientcertnotbefore, clientcertnotafter | ForEach-Object {
            Write-ToLogFile -D -C ADC-CertUpload -M "$($_ | ConvertTo-Json -Compress)"
        }
        Write-ToLogFile -D -C ADC-CertUpload -M "Checking if IntermediateCA `"$IntermediateCACertKeyName`" already exists."
        if ([String]::IsNullOrEmpty($($ADCIntermediateCA.sslcertkey.certkey))) {
            try {
                Write-ToLogFile -I -C ADC-CertUpload -M "Uploading `"$IntermediateCAFileName`" to the ADC."
                $IntermediateCABase64 = [System.Convert]::ToBase64String($(Get-Content $IntermediateCAFullPath -Encoding "Byte"))
                $payload = @{"filename" = "$IntermediateCAFileName"; "filecontent" = "$IntermediateCABase64"; "filelocation" = "/nsconfig/ssl/"; "fileencoding" = "BASE64"; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type systemfile -Payload $payload
                Write-ToLogFile -I -C ADC-CertUpload -M "Succeeded, Add the certificate to the ADC config."
                $payload = @{"certkey" = "$IntermediateCACertKeyName"; "cert" = "/nsconfig/ssl/$($IntermediateCAFileName)"; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload
                Write-ToLogFile -I -C ADC-CertUpload -M "Certificate added."
            } catch {
                Write-Warning "Could not upload or get the Intermediate CA ($($ChainFile.DnsNameList.Unicode)), manual action may be required"
                Write-ToLogFile -W -C ADC-CertUpload -M "Could not upload or get the Intermediate CA ($($ChainFile.DnsNameList.Unicode)), manual action may be required."
            }
        } else {
            $IntermediateCACertKeyName = $ADCIntermediateCA.sslcertkey.certkey
            Write-ToLogFile -D -C ADC-CertUpload -M "IntermediateCA exists, saving existing name `"$IntermediateCACertKeyName`" for later use."
        }
        Write-ToLogFile -D -C ADC-CertUpload -M "NSCertNameToUpdate: `"$NSCertNameToUpdate`""
        if ([String]::IsNullOrEmpty($NSCertNameToUpdate)) {
            Write-ToLogFile -I -C ADC-CertUpload -M "NSCertNameToUpdate variable was not configured."
            $ExistingCertificateDetails = $Null
        } else {
            Write-ToLogFile -I -C ADC-CertUpload -M "NSCertNameToUpdate variable was configured, trying to retrieve data."
            $Filters = @{"certkey" = "$NSCertNameToUpdate" }
            $ExistingCertificateDetails = try { Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey -Resource $NSCertNameToUpdate -ErrorAction SilentlyContinue } catch { $null }
        }
        if (-Not [String]::IsNullOrEmpty($($ExistingCertificateDetails.sslcertkey.certkey))) {
            $CertificateCertKeyName = $($ExistingCertificateDetails.sslcertkey.certkey)
            Write-ToLogFile -I -C ADC-CertUpload -M "Existing certificate `"$CertificateCertKeyName`" found on the ADC, start updating."
            try {
                Write-ToLogFile -D -C ADC-CertUpload -M "Unlinking certificate."
                $payload = @{"certkey" = "$CertificateCertKeyName"; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action unlink

            } catch {
                Write-ToLogFile -D -C ADC-CertUpload -M "Certificate was not linked."
            }
            $NSUpdating = $true
        } else {
            Write-ToLogFile -I -C ADC-CertUpload -M "Existing certificate `"$NSCertNameToUpdate`" NOT found on the ADC."
            if (-Not [String]::IsNullOrEmpty($NSCertNameToUpdate)) {
                $CertificateCertKeyName = $NSCertNameToUpdate
                Write-ToLogFile -I -C ADC-CertUpload -M "Adding new certificate as `"$NSCertNameToUpdate`""
            } else {
                $CertificateCertKeyName = $CertificateName
                $ExistingCertificateDetails = try { Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey -Resource $CertificateName -ErrorAction SilentlyContinue } catch { $null }
                if (-Not [String]::IsNullOrEmpty($ExistingCertificateDetails)) {
                    Write-Warning "Certificate `"$CertificateCertKeyName`" already exists, please update manually! Or if you need to update an existing Certificate, specify the `"-NSCertNameToUpdate`" Parameter."
                    Write-ToLogFile -W -C ADC-CertUpload -M "Certificate `"$CertificateCertKeyName`" already exists, please update manually! Or if you need to update an existing Certificate, specify the `"-NSCertNameToUpdate`" Parameter."
                    TerminateScript 1 "Certificate `"$CertificateCertKeyName`" already exists, please update manually! Or if you need to update an existing Certificate, specify the `"-NSCertNameToUpdate`" Parameter."
                }
            }
            $NSUpdating = $false
        }
        $CertificatePfxBase64 = [System.Convert]::ToBase64String($(Get-Content $CertificatePfxFullPath -Encoding "Byte"))
        Write-ToLogFile -I -C ADC-CertUpload -M "Uploading the Pfx certificate."
        $payload = @{"filename" = "$CertificatePfxFileName"; "filecontent" = "$CertificatePfxBase64"; "filelocation" = "/nsconfig/ssl/"; "fileencoding" = "BASE64"; }
        $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type systemfile -Payload $payload
        Write-ToLogFile -D -C ADC-CertUpload -M "Converting the Pfx certificate to a pem file ($CertificatePemFileName)"
        $payload = @{"outfile" = "$CertificatePemFileName"; "Import" = "true"; "pkcs12file" = "$CertificatePfxFileName"; "des3" = "true"; "password" = "$PfxPassword"; "pempassphrase" = "$PfxPassword" }
        $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslpkcs12 -Payload $payload -Action convert
        try {
            $payload = @{"certkey" = "$CertificateCertKeyName"; "cert" = "$($CertificatePemFileName)"; "key" = "$($CertificatePemFileName)"; "password" = "true"; "inform" = "PEM"; "passplain" = "$PfxPassword" }
            if ($NSUpdating) {
                Write-ToLogFile -I -C ADC-CertUpload -M "Update the certificate and key to the ADC config."
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action update
                Write-ToLogFile -I -C ADC-CertUpload -M "Updated successfully."

            } else {
                Write-ToLogFile -I -C ADC-CertUpload -M "Add the certificate and key to the ADC config."
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload
                Write-ToLogFile -I -C ADC-CertUpload -M "Added successfully."
            }
        } catch {
            Write-Warning "Caught an error, certificate not added to the ADC Config"
            Write-Warning "Details: $($_.Exception.Message | Out-String)"
            Write-ToLogFile -E -C ADC-CertUpload -M "Caught an error, certificate not added to the ADC Config. Exception Message: $($_.Exception.Message)"
        }
        Write-ToLogFile -I -C ADC-CertUpload -M "Link `"$CertificateCertKeyName`" to `"$IntermediateCACertKeyName`""
        try {
            $payload = @{"certkey" = "$CertificateCertKeyName"; "linkcertkeyname" = "$IntermediateCACertKeyName"; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action link
            Write-ToLogFile -I -C ADC-CertUpload -M "Link successfully."
        } catch {
            Write-Warning -Message "Could not link the certificate `"$CertificateCertKeyName`" to Intermediate `"$IntermediateCACertKeyName`""
            Write-ToLogFile -E -C ADC-CertUpload -M "Could not link the certificate `"$CertificateCertKeyName`" to Intermediate `"$IntermediateCACertKeyName`"."
            Write-ToLogFile -E -C ADC-CertUpload -M "Exception Message: $($_.Exception.Message)"
        }
        Write-Host -ForeGroundColor White "`r`nADC Configuration"
        Write-Host -ForeGroundColor White -NoNewLine " -Config Saved..........: "
        if ($SaveNSConfig) {
            Write-ToLogFile -I -C ADC-CertUpload -M "Saving ADC configuration.  (`"-SaveNSConfig`" Parameter set)"
            Invoke-ADCRestApi -Session $ADCSession -Method POST -Type nsconfig -Action save
            Write-Host -ForeGroundColor Green "Saved!"
        } else {
            Write-Host -ForeGroundColor Yellow "NOT Saved! (`"-SaveNSConfig`" Parameter not defined)"
            Write-ToLogFile -I -C ADC-CertUpload -M "ADC configuration NOT Saved! (`"-SaveNSConfig`" Parameter not defined)"
            $MailData += "`r`nIMPORTANT: Your Citrix ADC configuration was NOT saved!`r`n"
        }
        if ($PfxPasswordGenerated) {
            Write-Warning "No Password was specified, so a random password was generated!"
            Write-ToLogFile -W -C ADC-CertUpload -M "No Password was specified, so a random password was generated! (Password not saved in Log)"
            Write-Host -ForeGroundColor Yellow "`r`n***********************************`r`n"
            Write-Host -ForeGroundColor White -NoNewline "PFX Password............: "
            Write-Host -ForeGroundColor Yellow $PfxPassword
            Write-Host -ForeGroundColor Yellow "`r`n***********************************`r`n"
        }
        Write-Host -ForegroundColor White "`r`nCertificates"
        Write-Host -ForegroundColor White -NoNewline " -Certkey Name..........: " 
        Write-Host -ForegroundColor Blue $CertificateCertKeyName
        Write-Host -ForegroundColor White -NoNewline " -Cert Dir..............: " 
        Write-Host -ForegroundColor Blue $CertificateDirectory
        Write-Host -ForegroundColor White -NoNewline " -CRT Filename..........: "
        Write-Host -ForegroundColor Blue $CertificateFileName
        Write-Host -ForegroundColor White -NoNewline " -KEY Filename..........: "
        Write-Host -ForegroundColor Blue $CertificateKeyFileName
        Write-Host -ForegroundColor White -NoNewline " -PFX Filename..........: "
        Write-Host -ForegroundColor Blue $CertificatePfxFileName
        Write-Host -ForegroundColor White -NoNewline " -PFX (with Chain)......: "
        Write-Host -ForegroundColor Blue $CertificatePfxWithChainFileName
        ""
        Write-Host -ForegroundColor White -NoNewline " -Certificate State.....: "
        Write-Host -ForeGroundColor Green "Finished with the certificates!"
        ""
        Write-ToLogFile -I -C ADC-CertUpload -M "Cert Dir: $CertificateDirectory"
        Write-ToLogFile -I -C ADC-CertUpload -M "CRT Filename: $CertificateFileName"
        Write-ToLogFile -I -C ADC-CertUpload -M "KEY Filename: $CertificateKeyFileName"
        Write-ToLogFile -I -C ADC-CertUpload -M "PFX Filename: $CertificatePfxFileName"
        Write-ToLogFile -I -C ADC-CertUpload -M "PFX (with Chain): $CertificatePfxWithChainFileName"
        Write-ToLogFile -I -C ADC-CertUpload -M "Finished with the certificates!"

        $MailData += "Certificates stored in: $CertificateDirectory"
        try {
            $MailCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 "$(Join-Path -Path $CertificateDirectory -ChildPath $CertificateFileName)"
            $MailData += "CRT Filename: $CertificateFileName"
            $MailData += "PFX Filename: $CertificatePfxFileName"
            $MailData += "Valid until: $($MailCertificate.NotAfter.ToUniversalTime())"
            $MailData += "Approved by CA: $($MailCertificate.Issuer)"
            $MailData += "CN: $($MailCertificate.Subject)"
            $MailData += "SANs: $($MailCertificate.DnsNameList.Unicode -Join ", ")"
            $MailData += "Public Key Size: $($MailCertificate.PublicKey.key.KeySize)"
        } catch { }

        if ($ValidationMethod -eq "dns") {
            Write-Host -ForegroundColor Yellow "`r`n********************************************************************"
            Write-Host -ForegroundColor Yellow "* IMPORTANT: Don't forget to delete the created DNS records!!      *"
            Write-Host -ForegroundColor Yellow "********************************************************************"
            Write-ToLogFile -I -C ADC-CertUpload -M "Don't forget to delete the created DNS records!!"
            foreach ($Record in $TXTRecords) {
                ""
                Write-Host -ForeGroundColor Yellow -NoNewLine " -DNS Hostname..........: "
                Write-Host -ForeGroundColor Blue "$($Record.fqdn)"
                Write-Host -ForeGroundColor Yellow -NoNewLine " -TXT Record Name.......: "
                Write-Host -ForeGroundColor Yellow "$($Record.TXTName)"
                Write-ToLogFile -I -C ADC-CertUpload -M "TXT Record: `"$($Record.TXTName)`""
            }
            ""
            Write-Host -ForegroundColor Yellow "********************************************************************"
        }
        if (-not $Production) {
            Write-Host -ForeGroundColor Yellow "`r`nYou are now ready for the Production version!"
            Write-Host -ForeGroundColor Yellow "Add the `"-Production`" parameter and rerun the same script.`r`n"
            Write-ToLogFile -I -C ADC-CertUpload -M "You are now ready for the Production version! Add the `"-Production`" parameter and rerun the same script."
        }
    } catch {
        Write-ToLogFile -E -C ADC-CertUpload -M "Certificate completion failed. Exception Message: $($_.Exception.Message)"
        Write-Error "Certificate completion failed. Exception Message: $($_.Exception.Message)"
        TerminateScript 1 "Certificate completion failed. Exception Message: $($_.Exception.Message)"
    }
}

#endregion ADC-CertUpload

#region RemoveTestCerts

if ((-not ($CleanADC)) -and $RemoveTestCertificates) {
    Write-Host -ForeGroundColor White "`r`nADC - (Test) Certificate Cleanup"
    Write-ToLogFile -I -C RemoveTestCerts -M "Start removing the test certificates."
    Write-ToLogFile -I -C RemoveTestCerts -M "Trying to login into the Citrix ADC."
    $ADCSession = Connect-ADC -ManagementURL $ManagementURL -Credential $Credential -PassThru
    Write-ToLogFile -I -C RemoveTestCerts -M "Connected to Citrix ADC $ManagementURL, as user $($ADCSession.Username)"
    $IntermediateCACertKeyName = "Fake LE Intermediate X1"
    $IntermediateCASerial = "8be12a0e5944ed3c546431f097614fe5"
    Write-ToLogFile -I -C RemoveTestCerts -M "Retrieving existing certificates."
    $CertDetails = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey
    Write-ToLogFile -D -C RemoveTestCerts -M "Checking if IntermediateCA `"$IntermediateCACertKeyName`" already exists."
    $IntermediateCADetails = $CertDetails.sslcertkey | Where-Object { $_.serial -eq $IntermediateCASerial }
    $LinkedCertificates = $CertDetails.sslcertkey | Where-Object { $_.linkcertkeyname -eq $IntermediateCADetails.certkey }
    Write-ToLogFile -D -C RemoveTestCerts -M "The following certificates were found:"
    $LinkedCertificates | Select-Object certkey, linkcertkeyname, serial | ForEach-Object {
        Write-ToLogFile -D -C RemoveTestCerts -M "$($_ | ConvertTo-Json -Compress)"
    }
    Write-Host -ForeGroundColor White -NoNewLine " -Linked Certkeys found.: "
    Write-Host -ForeGroundColor Blue "$(($LinkedCertificates | Measure-Object).Count)"
    ForEach ($LinkedCertificate in $LinkedCertificates) {
        $payload = @{"certkey" = "$($LinkedCertificate.certkey)"; }
        try {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action unlink
            Write-Host -ForeGroundColor White -NoNewLine " -Unlinking Certkey.....: "
            Write-Host -ForeGroundColor Green "Done    [$($LinkedCertificate.certkey)]"
            Write-ToLogFile -I -C RemoveTestCerts -M "Unlinked: `"$($LinkedCertificate.certkey)`""
        } catch {
            Write-Host -ForeGroundColor Yellow "WARNING, Could not unlink `"$($LinkedCertificate.certkey)`""
            Write-ToLogFile -E -C RemoveTestCerts -M "Could not unlink certkey `"$($LinkedCertificate.certkey)`". Exception Message: $($_.Exception.Message)"
        }
    }
    $FakeCerts = $CertDetails.sslcertkey | Where-Object { $_.issuer -match $IntermediateCACertKeyName }
    Write-ToLogFile -D -C RemoveTestCerts -M "Test Cert data:"
    $FakeCerts | ForEach-Object {
        Write-ToLogFile -D -C RemoveTestCerts -M "$($_ | ConvertTo-Json -Compress)"
    }
    Write-Host -ForeGroundColor White -NoNewLine " -Certificates found....: "
    Write-Host -ForeGroundColor Blue "$(($FakeCerts | Measure-Object).Count)"
    ForEach ($FakeCert in $FakeCerts) {
        try {
            Write-ToLogFile -I -C RemoveTestCerts -M "Trying to delete `"$($FakeCert.certkey)`"."
            Write-Host -ForeGroundColor White -NoNewLine " -SSL Certkey...........: "
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type sslcertkey -Resource $($FakeCert.certkey)
            Write-Host -ForeGroundColor Green "Deleted [$($FakeCert.certkey)]"
        } catch {
            Write-Host -ForeGroundColor Yellow "WARNING, could not remove certkey `"$($FakeCert.certkey)`""
            Write-ToLogFile -W -C RemoveTestCerts -M "Could not remove certkey `"$($FakeCert.certkey)`" from the ADC. Exception Message: $($_.Exception.Message)"
        }
        Write-ToLogFile -W -C RemoveTestCerts -M "Getting Certificate details"
        try {
            $CertFilePath = (split-path $($FakeCert.cert) -Parent).Replace("\", "/")
            if ([String]::IsNullOrEmpty($CertFilePath)) {
                $CertFilePath = "/nsconfig/ssl/"
            }
        } catch {
            $CertFilePath = "/nsconfig/ssl/"
        }
        try {
            $CertFileName = split-path $($FakeCert.cert) -Leaf
        } catch {
            $CertFileName = $null
        }
        Write-ToLogFile -W -C RemoveTestCerts -M "Certificate name: `"$($CertFileName)`" in path: `"$($CertFilePath)`""
        Write-ToLogFile -W -C RemoveTestCerts -M "Getting Certificate Key details"
        try {
            $KeyFilePath = (split-path $($FakeCert.key) -Parent).Replace("\", "/")
            if ([String]::IsNullOrEmpty($KeyFilePath)) {
                $KeyFilePath = "/nsconfig/ssl/"
            }
        } catch {
            $KeyFilePath = "/nsconfig/ssl/"
        }
        try {
            $KeyFileName = split-path $($FakeCert.key) -Leaf
        } catch {
            $KeyFileName = $null
        }
        Write-ToLogFile -W -C RemoveTestCerts -M "Certificate name: `"$($KeyFileName)`" in path: `"$($KeyFilePath)`""
        Write-Host -ForeGroundColor White -NoNewLine " -SSL Certificate File..: "
        $Arguments = @{"filelocation" = "$CertFilePath"; }
        try {
            Write-ToLogFile -I -C RemoveTestCerts -M "Trying to delete `"$(Join-Path -Path $CertFilePath -ChildPath $CertFileName)`"."
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type systemfile -Resource $CertFileName -Arguments $Arguments
            Write-Host -ForeGroundColor Green "Deleted [$(Join-Path -Path $CertFilePath -ChildPath $CertFileName)]"
            Write-ToLogFile -I -C RemoveTestCerts -M "File deleted."

        } catch {
            Write-Host -ForeGroundColor Yellow "WARNING, could not delete file `"$(Join-Path -Path $CertFilePath -ChildPath $CertFileName)`""
            Write-ToLogFile -E -C RemoveTestCerts -M "Could not delete file `"$(Join-Path -Path $CertFilePath -ChildPath $CertFileName)`". Exception Message: $($_.Exception.Message)"
        }
        if (-Not ($(Join-Path -Path $CertFilePath -ChildPath $CertFileName) -eq $(Join-Path -Path $KeyFilePath -ChildPath $KeyFileName))) {
            Write-Host -ForeGroundColor White -NoNewLine " -SSL Key File..........: "
            $Arguments = @{"filelocation" = "$KeyFilePath"; }
            try {
                Write-ToLogFile -I -C RemoveTestCerts -M "Trying to delete `"$(Join-Path -Path $KeyFilePath -ChildPath $KeyFileName)`"."
                $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type systemfile -Resource $KeyFileName -Arguments $Arguments
                Write-Host -ForeGroundColor Green "Deleted [$(Join-Path -Path $KeyFilePath -ChildPath $KeyFileName)]"
                Write-ToLogFile -I -C RemoveTestCerts -M "File deleted."
            } catch {
                Write-Host -ForeGroundColor Yellow "WARNING, could not delete file `"$(Join-Path -Path $KeyFilePath -ChildPath $KeyFileName)`""
                Write-ToLogFile -E -C RemoveTestCerts -M "Could not delete file `"$(Join-Path -Path $KeyFilePath -ChildPath $KeyFileName)`". Exception Message: $($_.Exception.Message)"
            }
        }
    }
    $Arguments = @{"filelocation" = "/nsconfig/ssl"; }
    $CertFiles = Invoke-ADCRestApi -Session $ADCSession -Method Get -Type systemfile -Arguments $Arguments
    $CertFilesToRemove = $CertFiles.systemfile | Where-Object { $_.filename -match "TST-" }
    Write-Host -ForeGroundColor White -NoNewLine " -Misc. Files Found.....: "
    Write-Host -ForeGroundColor Blue "$(($CertFilesToRemove | Measure-Object).Count)"
    ForEach ($CertFileToRemove in $CertFilesToRemove) {
        Write-Host -ForeGroundColor White -NoNewLine " -File..................: "
        $Arguments = @{"filelocation" = "$($CertFileToRemove.filelocation)"; }
        try {
            Write-ToLogFile -I -C RemoveTestCerts -M "Trying to delete `"$(Join-Path -Path $CertFileToRemove.filelocation -ChildPath $CertFileToRemove.filename)`"."
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type systemfile -Resource $($CertFileToRemove.filename) -Arguments $Arguments
            Write-Host -ForeGroundColor Green "Deleted [$(Join-Path -Path $CertFileToRemove.filelocation -ChildPath $CertFileToRemove.filename)]"
            Write-ToLogFile -I -C RemoveTestCerts -M "File deleted."
        } catch {
            Write-Host -ForeGroundColor Yellow "WARNING, could not delete file [$(Join-Path -Path $CertFileToRemove.filelocation -ChildPath $CertFileToRemove.filename)]"
            Write-ToLogFile -E -C RemoveTestCerts -M "Could not delete file: `"$(Join-Path -Path $CertFileToRemove.filelocation -ChildPath $CertFileToRemove.filename)`". Exception Message: $($_.Exception.Message)"
        }
    }
}

#endregion RemoveTestCerts

#region Final Actions

TerminateScript 0

#endregion Final Actions
