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
.PARAMETER CsVipName
    Name of the HTTP ADC Content Switch used for the domain validation.
    Specify only one when requesting a certificate
    Specify all possible VIPs when creating a Command Policy (User group, -NSCPName), so they all can be used by the members
.PARAMETER UseLbVip
    Skip the use of a Content Switch vServer (for example when using a GateWay Edition)\
    Don't forget to specify a HTTP LB Vip Name, with the -LbVip parameter!
.PARAMETER LbName
    ADC Load Balance VIP name
    Default: "lb_letsencrypt_cert"
.PARAMETER CsVipBinding
    ADC Content Switch binding used for the validation
    Default: 11
.PARAMETER SvcName
    ADC Load Balance service name
    Default "svc_letsencrypt_cert_dummy"
.PARAMETER SvcDestination
    IP Address used for the ADC Service (leave default 1.2.3.4, only change when already used
.PARAMETER RspName
    ADC Responder Policy name
    Default: "rsp_letsencrypt"
.PARAMETER RsaName
    ADC Responder Action name
    Default: "rsa_letsencrypt"
.PARAMETER CspName
    ADC Content Switch Policy name
    Default: "csp_NSCertCsp"
.PARAMETER CertKeyNameToUpdate
    ADC SSL Certkey name currently in use, that needs to be renewed
.PARAMETER RemovePrevious
    If the new certificate was updated successfully, remove the previous files.
    This parameter works only if -CertKeyNameToUpdate was specified and previous files are found. Else this setting will be ignored!
.PARAMETER CertDir
    Directory where to store the certificates
.PARAMETER PfxPassword
    Specify a password for the PFX certificate, if not specified a new password is generated at the end
.PARAMETER KeyLength
    Specify the KeyLength of the new to be generated certificate
    Default: 2048
.PARAMETER EmailAddress
    The email address used to request the certificates and receive a notification when the certificates (almost) expires
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
.PARAMETER ValidationMethod
    The validation method, this will be determined automatically. By default the 'http' validation method is being chosen unless you have defined a wildcard (*.domain.com) request.
    Options: 'http' or 'dns'
.PARAMETER DNSPlugin
    Refer to the Posh-ACME plugins for the parameters, https://github.com/rmbolger/Posh-ACME/tree/main/Posh-ACME/Plugins
    Define the name with this parameter. You must also configure the 'DNSParams' parameter.
    Example: -DNSPlugin 'Aurora'
.PARAMETER DNSParams
    Define the Parameters required for the DNS plugin to be used with the 'DNSPlugin' parameter.
    You can define the value as a hashtable: -DNSParams @{ Api='api.auroradns.eu'; Key='XXXXXXXXXX'; Secret='YYYYYYYYYYYYYYYY' }
    Or as a string value (to be used in batch files): -DNSParams "Api=api.auroradns.eu;Key=XXXXXXXXXX;Secret=YYYYYYYYYYYYYYYY"
.PARAMETER Production
    Use the production Let's encrypt server, without this parameter the staging (test) server will be used
.PARAMETER CreateUserPermissions
    When this parameter is configured, a User Group (Command Policy) will be created with a limited set of permissions required to run this script.
    Also specify all VIP, LB svc names if you want other than default values.
    Mandatory parameter is the CsVipName.
.PARAMETER NSCPName
    You can change the name of the Command Policy that will be created when you configure the -CreateUserPermissions parameter
    Default: `"script-GenLeCertForNS`"
.PARAMETER CreateApiUser
    When this parameter is configured, a (System) User will be created. This will me a member of the Command policy configured with -NSCPName
.PARAMETER ApiUsername
    The Username for the (System) User
.PARAMETER ApiPassword
    The Password for the (System) User
.PARAMETER DisableIPCheck
    If you want to skip the IP Address verification, specify this parameter
.PARAMETER CleanPoshACMEStorage
    Force cleanup of the Posh-Acme certificates located in "%LOCALAPPDATA%\Posh-ACME"
.PARAMETER ConfigFile
    Use an existing or save all the "current" parameters to a json file of your choosing for later reuse of the same parameters.
.PARAMETER AutoRun
    This parameter is used to make sure you are deliberately using the parameters from the config file and run the script automatically.
.PARAMETER ForceCertRenew
    Specify this parameter if you want to renew certificate even though it's still valid.
.PARAMETER IPv6
    If specified, the script will try run with IPv6 checks (EXPERIMENTAL)
.PARAMETER UpdateIIS
    If specified, the script will try to add the generated certificate to the personal computer store and bind it to the site
.PARAMETER IISSiteToUpdate
    Select a IIS Site you want to add the certificate to.
    Default value when not specifying this parameter is "Default Web Site".
.PARAMETER PostPoSHScriptFilename
    Configure this parameter with a full path name to a PowerShell script.
    This script will be executed after a successful certificate request. The script needs three parameters:
    1. [String]$Thumbprint => This will contain the thumbprint of the newly generated certificate
    2. [String]$PFXfilename => This will contain the full path to the PFX certificate
    3. [String]$PFXPassword => This will contain the PFX password
    Return an exit code 0 for success or 1 if failed!
    You can specify your own parameters (if needed) by specifying the "-PostPoSHScriptExtraParameters" parameter.
    The GenLECertForNS script will continue even if the script failed! But it will generate an error message on the console or email.
.PARAMETER PostPoSHScriptExtraParameters
    To be used together with the "-PostPoSHScriptFilename" parameter.
    With this parameter you can pass your own parameters needed for the script (e.g. api credentials or a IIS Site name)
    Specify as a hashtable
    E.g. -PostPoSHScriptExtraParameters @{ IISSiteName="Default Web Site" }
.PARAMETER CleanExpiredCertsOnDisk
    Files older than the days specified in the CleanExpiredCertsOnDiskDays parameter will be deleted in the in the -CertDir specified directory.
    In an AutoRun configuration, you can specify a CertDir per request. This parameter will run per certificate request.
.PARAMETER CleanExpiredCertsOnDiskDays
    Files older than the days specified will be deleted in the in the CertDir specified directory.
    Default value: 100 days
.PARAMETER CleanAllExpiredCertsOnDisk
    Files older than the days specified will be deleted in the in the CertDir specified directory.
    This command can be used to only (manually) cleanup the in the CertDir specified directory.
.PARAMETER SendMail
    Specify this parameter if you want to send a mail at the end, don't forget to specify SMTPTo, SMTPFrom, SMTPServer and if required SMTPCredential
.PARAMETER SMTPTo
    Specify one or more email addresses.
    Email addresses can be specified as "user.name@domain.com" or "User Name <user.name@domain.com>"
    If specifying multiple email addresses, separate them wit a comma.
.PARAMETER SMTPFrom
    Specify the Email address where mails are send from
    The email address can be specified as "user.name@domain.com" or "User Name <user.name@domain.com>"
.PARAMETER SMTPServer
    Specify the SMTP Mail server fqdn or IP-address
.PARAMETER SMTPPort
    Specify the SMTP Mail server port
.PARAMETER SMTPUseSSL
    Specify if the SMTP Mail server must use SSL
.PARAMETER SMTPCredential
    Specify the Mail server credentials, only if credentials are required to send mails
.PARAMETER LogAsAttachment
    If you specify this parameter, the log will be attached as attachment when sending the mail.
.PARAMETER DisableLogging
    Turn off logging to logfile. Default ON
.PARAMETER LogFile
    Specify the log file name, default ".\GenLeCertForNS.txt"
.PARAMETER LogLevel
    The Log level you want to have specified.
    With LogLevel: Error; Only Error (E) data will be written or shown.
    With LogLevel: Warning; Only Error (E) and Warning (W) data will be written or shown.
    With LogLevel: Info; Only Error (E), Warning (W) and Info (I) data will be written or shown.
    With LogLevel: Debug; All, Error (E), Warning (W), Info (I) and Debug (D) data will be written or shown.
    You can also define a (Global) variable in your script $LogLevel, the function will use this level instead (if not specified with the command)
    Default value: Info
.PARAMETER NoConsoleOutput
    When Specified, no output will be written to the console.
    Exception: Warning, Verbose and Error messages.
.EXAMPLE
    .\GenLeCertForNS.ps1 -CreateUserPermissions -CreateApiUser -CsVipName "CSVIPNAME" -ApiUsername "le-user" -ApiPassword "LEP@ssw0rd" -NSCPName "MinLePermissionGroup" -Username nsroot -Password "nsroot" -ManagementURL https://citrixadc.domain.local
    This command will create a Command Policy with the minimum set of permissions, you need to run this once to create (or when you want to change something).
    Be sure to run the script next with the same parameters as specified when running this command, the same for -SvcName (Default "svc_letsencrypt_cert_dummy"), -LbName (Default: "lb_letsencrypt_cert"), -RspName (Default: "rsp_letsencrypt"), -RsaName (Default: "rsa_letsencrypt"), -CspName (Default: "csp_NSCertCsp")
    Next time you want to generate certificates you can specify the new user  -Username le-user -Password "LEP@ssw0rd"
.EXAMPLE
    .\GenLeCertForNS.ps1 -CN "domain.com" -EmailAddress "hostmaster@domain.com" -SAN "sts.domain.com","www.domain.com","vpn.domain.com" -PfxPassword "P@ssw0rd" -CertDir "C:\Certificates" -ManagementURL "http://192.168.100.1" -CsVipName "cs_domain.com_http" -Password "P@ssw0rd" -Username "nsroot" -CertKeyNameToUpdate "san_domain_com" -LogLevel Debug -Production
    Generate a (Production) certificate for hostname "domain.com" with alternate names : "sts.domain.com, www.domain.com, vpn.domain.com". Using the email address "hostmaster@domain.com". At the end storing the certificates  in "C:\Certificates" and uploading them to the ADC. The Content Switch "cs_domain.com_http" will be used to validate the certificates.
.EXAMPLE
    .\GenLeCertForNS.ps1 -CN "domain.com" -EmailAddress "hostmaster@domain.com" -SAN "*.domain.com","*.test.domain.com" -PfxPassword "P@ssw0rd" -CertDir "C:\Certificates" -ManagementURL "http://192.168.100.1" -Password "P@ssw0rd" -Username "nsroot" -CertKeyNameToUpdate "wildcard_domain_com" -LogLevel Debug -Production
    Generate a (Production) Wildcard (*) certificate for hostname "domain.com" with alternate names : "*.domain.com, *.test.domain.com. Using the email address "hostmaster@domain.com". At the end storing the certificates  in "C:\Certificates" and uploading them to the ADC.
    NOTE: Only a DNS verification is possible when using WildCards!
.EXAMPLE
    .\GenLeCertForNS.ps1 -CN "domain.com" -EmailAddress "hostmaster@domain.com" -SAN "*.domain.com" -PfxPassword "P@ssw0rd" -CertDir "C:\Certificates" -ManagementURL "http://192.168.100.1" -Password "P@ssw0rd" -Username "nsroot" -CertKeyNameToUpdate "wildcard_domain_com" -DNSPlugin "Aurora" -DNSParams  @{AuroraCredential=$((New-Object PSCredential 'KEYKEYKEY',$(ConvertTo-SecureString -String 'SECRETSECRETSECRET' -AsPlainText -Force))); AuroraApi='api.auroradns.eu'} -Production
    Generate a (Production) Wildcard (*) certificate for hostname "domain.com" with alternate names : "*.domain.com, *.test.domain.com. Using the email address "hostmaster@domain.com". At the end storing the certificates  in "C:\Certificates" and uploading them to the ADC.
    NOTE: Only a DNS verification is possible when using WildCards!
.EXAMPLE
    .\GenLeCertForNS.ps1 -CleanADC -ManagementURL "http://192.168.100.1" -CsVipName "cs_domain.com_http" -Password "P@ssw0rd" -Username "nsroot"
    Cleaning left over configuration from this script when something went wrong during a previous attempt to generate new certificates.
.EXAMPLE
    .\GenLeCertForNS.ps1 -RemoveTestCertificates -ManagementURL "http://192.168.100.1" -Password "P@ssw0rd" -Username "nsroot"
    Removing ALL the test certificates from your ADC.
.EXAMPLE
    .\GenLeCertForNS.ps1 -RemoveTestCertificates -CleanAllExpiredCertsOnDisk -CertDir C:\Certificates -CleanExpiredCertsOnDiskDays 100
    All subdirectories in "C:\Certificates" older than 100 days will be deleted.
.EXAMPLE
    .\GenLeCertForNS.ps1 -AutoRun -ConfigFile ".\GenLe-Config.json"
    Running the script with previously saved parameters. To create a test certificate.
    NOTE: you can create the json file by specifying the -ConfigFile ".\GenLe-Config.json" parameter with your previous parameters
.EXAMPLE
    .\GenLeCertForNS.ps1 -AutoRun -ConfigFile ".\GenLe-Config.json" -Production
    Running the script with previously saved parameters. To create a Production (trusted) certificate
    NOTE: you can create the json file by specifying the -ConfigFile ".\GenLe-Config.json" parameter with your previous parameters
.EXAMPLE
    .\GenLeCertForNS.ps1 -CreateUserPermissions -NSCPName script-GenLeCertForNS -CreateApiUser -ApiUsername GenLEUser -ApiPassword P@ssw0rd! -ManagementURL https://citrixadc.domain.local -Username nsroot -Password nsr00t! -CsVipName cs_domain2.com_http,cs_domain2.com_http,cs_domain3.com_http
    Create a Group (Command Policy) with limited user permissions required to run the script and a user that will be member of that group.
    With all VIPs that can be used by the script.
.NOTES
    File Name : GenLeCertForNS.ps1
    Version   : v2.15.0
    Author    : John Billekens
    Requires  : PowerShell v5.1 and up
                ADC 12.1 and higher
                Run As Administrator
                Posh-ACME 4.17.0 (Will be installed via this script) Thank you @rmbolger for providing the HTTP validation method!
                Microsoft .NET Framework 4.7.2 or later
.LINK
    https://blog.j81.nl
#>

[CmdletBinding(DefaultParameterSetName = "LECertificatesHTTP")]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingWriteHost", "")]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "")]
param(
    [Parameter(ParameterSetName = "Help", Mandatory = $true)]
    [alias("h")]
    [Switch]$Help,

    [Parameter(ParameterSetName = "CleanADC", Mandatory = $true)]
    [alias("CleanNS")]
    [Switch]$CleanADC,

    [Parameter(ParameterSetName = "CleanTestCertificate", Mandatory = $true)]
    [Switch]$RemoveTestCertificates,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanTestCertificate")]
    [Switch]$CleanPoshACMEStorage,

    [Parameter(ParameterSetName = "CommandPolicy", Mandatory = $true)]
    [Parameter(ParameterSetName = "CommandPolicyUser", Mandatory = $true)]
    [Parameter(ParameterSetName = "LECertificatesHTTP", Mandatory = $true)]
    [Parameter(ParameterSetName = "LECertificatesDNS", Mandatory = $true)]
    [Parameter(ParameterSetName = "CleanADC", Mandatory = $true)]
    [Parameter(ParameterSetName = "CleanTestCertificate", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [alias("URL", "NSManagementURL")]
    [String]$ManagementURL,

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [Parameter(ParameterSetName = "CleanTestCertificate")]
    [ValidateNotNullOrEmpty()]
    [alias("User", "NSUsername", "ADCUsername")]
    [String]$Username,

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [Parameter(ParameterSetName = "CleanTestCertificate")]
    [ValidateNotNullOrEmpty()]
    [ValidateScript( {
            if ($_ -is [SecureString]) {
                return $true
            } elseif ($_ -is [String]) {
                return $true
            } else {
                throw "You passed an unexpected object type for the credential (-Password)"
            }
        })][alias("NSPassword", "ADCPassword")]
    [object]$Password,

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [Parameter(ParameterSetName = "CleanTestCertificate")]
    [alias("NSCredential", "ADCCredential")]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(ParameterSetName = "LECertificatesHTTP", Mandatory = $true)]
    [Parameter(ParameterSetName = "LECertificatesDNS", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$CN,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [String[]]$SAN = @(),

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [String]$FriendlyName,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [ValidateSet('http', 'dns', IgnoreCase = $true)]
    [String]$ValidationMethod = "http",

    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [String]$DNSPlugin = "Manual",

    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Object]$DNSParams = @{ },

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [alias("NSCertNameToUpdate")]
    [ValidateLength(1, 31)]
    [String]$CertKeyNameToUpdate,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$RemovePrevious,

    [Parameter(ParameterSetName = "LECertificatesHTTP", Mandatory = $true)]
    [Parameter(ParameterSetName = "LECertificatesDNS", Mandatory = $true)]
    [Parameter(ParameterSetName = "CleanExpiredCerts", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$CertDir,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [ValidateScript( {
            if ($_ -is [SecureString]) {
                return $true
            } elseif ($_ -is [String]) {
                return $true
            } else {
                throw "You passed an unexpected object type for the password (-PfxPassword). Must be (Secure)String"
            }
        })][object]$PfxPassword = $null,

    [Parameter(ParameterSetName = "LECertificatesHTTP", Mandatory = $true)]
    [Parameter(ParameterSetName = "LECertificatesDNS", Mandatory = $true)]
    [String]$EmailAddress,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [ValidateScript( {
            if ($_ -lt 2048 -Or $_ -gt 4096 -Or ($_ % 128) -ne 0) {
                throw "Unsupported RSA key size. Must be 2048-4096 in 8 bit increments."
            } else {
                $true
            }
        })][int32]$KeyLength = 2048,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "AutoRun")]
    [Switch]$Production,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [Parameter(ParameterSetName = "CleanTestCertificate")]
    [Switch]$DisableLogging,

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [Parameter(ParameterSetName = "CleanTestCertificate")]
    [ValidateNotNullOrEmpty()]
    [alias("LogLocation")]
    [String]$LogFile = "<DEFAULT>",

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [Parameter(ParameterSetName = "CleanTestCertificate")]
    [ValidateSet("Error", "Warning", "Info", "Debug", "None", IgnoreCase = $false)]
    [String]$LogLevel = "Info",
   
    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [alias("SaveNSConfig")]
    [Switch]$SaveADCConfig,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$SendMail,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [String[]]$SMTPTo,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [String]$SMTPFrom,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]$SMTPCredential = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [String]$SMTPServer,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Int]$SMTPPort = 25,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$SMTPUseSSL,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$LogAsAttachment,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$DisableIPCheck,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$IPv6,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$UpdateIIS,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [String]$IISSiteToUpdate = "Default Web Site",
    
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [String]$PostPoSHScriptFilename,
    
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Hashtable]$PostPoSHScriptExtraParameters = @{},
    
    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [alias("NSCsVipName")]
    [String[]]$CsVipName,

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$UseLbVip,

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [alias("NSCspName")]
    [String]$CspName = "csp_letsencrypt",

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [alias("NSCsVipBinding")]
    [String]$CsVipBinding = 11,

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [alias("NSSvcName")]
    [String]$SvcName = "svc_letsencrypt_cert_dummy",

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [alias("NSSvcDestination")]
    [String]$SvcDestination = "1.2.3.4",

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [alias("NSLbName")]
    [String]$LbName = "lb_letsencrypt_cert",

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [alias("TD")]
    [Int]$TrafficDomain = 0,

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [alias("NSRspName")]
    [String]$RspName = "rsp_letsencrypt",

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [alias("NSRsaName")]
    [String]$RsaName = "rsa_letsencrypt",

    [Parameter(ParameterSetName = "CommandPolicy", DontShow)]
    [Parameter(ParameterSetName = "CommandPolicyUser", DontShow)]
    [Parameter(ParameterSetName = "LECertificatesHTTP", DontShow)]
    [Parameter(ParameterSetName = "LECertificatesDNS", DontShow)]
    [Parameter(ParameterSetName = "CleanADC", DontShow)]
    [String[]]$Partitions = @("default"),

    [Parameter(ParameterSetName = "CommandPolicy", Mandatory = $true)]
    [Parameter(ParameterSetName = "CommandPolicyUser", Mandatory = $true)]
    [Switch]$CreateUserPermissions,

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [String]$NSCPName = "script-GenLeCertForNS",

    [Parameter(ParameterSetName = "CommandPolicyUser", Mandatory = $true)]
    [Switch]$CreateApiUser,

    [Parameter(ParameterSetName = "CommandPolicyUser", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]$ApiUsername,

    [Parameter(ParameterSetName = "CommandPolicyUser", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript( {
            if ($_ -is [SecureString]) {
                return $true
            } elseif ($_ -is [String]) {
                return $true
            } else {
                throw "You passed an unexpected object type for the credential (-ApiPassword)"
            }
        })]
    [object]$ApiPassword,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "AutoRun", Mandatory = $true)]
    [String]$ConfigFile = $null,

    [Parameter(ParameterSetName = "AutoRun", Mandatory = $true)]
    [Switch]$AutoRun = $false,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "AutoRun")]
    [Alias('Force')]
    [Switch]$ForceCertRenew = $false,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$CleanExpiredCertsOnDisk,

    [Parameter(ParameterSetName = "CleanExpiredCerts", Mandatory = $true)]
    [Switch]$CleanAllExpiredCertsOnDisk,

    [Parameter(ParameterSetName = "CleanExpiredCerts")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [int16]$CleanExpiredCertsOnDiskDays = 100,

    [Switch]$NoConsoleOutput
)

#requires -version 5.1
#Requires -RunAsAdministrator
$ScriptVersion = "2.15.0"
$PoshACMEVersion = "4.17.0"
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
    Param (
        [Parameter(ParameterSetName = "Error", Mandatory = $true, Position = 0)]
        [Parameter(ParameterSetName = "Warning", Mandatory = $true, Position = 0)]
        [Parameter(ParameterSetName = "Info", Mandatory = $true, Position = 0)]
        [Parameter(ParameterSetName = "Debug", Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias("M")]
        [string[]]$Message,

        [Parameter(ParameterSetName = "Block", Mandatory = $true)]
        [Alias("B")]
        [object[]]$Block,

        [Parameter(ParameterSetName = "Block")]
        [Alias("BI")]
        [Switch]$BlockIndent,

        [Parameter(ParameterSetName = "Error")]
        [Switch]$E,

        [Parameter(ParameterSetName = "Warning")]
        [Switch]$W,

        [Parameter(ParameterSetName = "Info")]
        [Switch]$I,

        [Parameter(ParameterSetName = "Block")]
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

        [String]$LogFile = "Log.txt",

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [String]$Delimiter = "`t",

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Parameter(ParameterSetName = "Block")]
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
    $RootPath = $(if ($psISE) { Split-Path -Path $psISE.CurrentFile.FullPath } else { $(if ($global:PSScriptRoot.Length -gt 0) { $global:PSScriptRoot } else { $global:pwd.Path }) })

    # Set Message Type to Informational if nothing is defined.
    if ((-Not $I) -and (-Not $W) -and (-Not $E) -and (-Not $D) -and (-Not $Block) -and (-Not $WriteHeader)) {
        $I = $true
    }
    #Check if a log file is defined in a Script. If defined, get value.
    try {
        $LogFileVar = Get-Variable -Scope Global -Name LogFile -ValueOnly -ErrorAction SilentlyContinue
        if (-Not [String]::IsNullOrWhiteSpace($LogFileVar)) {
            $LogFile = $LogFileVar
        }
        $LogFileVar = Get-Variable -Scope Script -Name LogFile -ValueOnly -ErrorAction SilentlyContinue
        if (-Not [String]::IsNullOrWhiteSpace($LogFileVar)) {
            $LogFile = $LogFileVar
        }
    } catch {
        #Continue, no script variable found for LogFile
    }
    #Check if a LogLevel is defined in a script. If defined, get value.
    try {
        if ([String]::IsNullOrEmpty($LogLevel) -and (-Not $WriteHeader)) {
            $LogLevelVar = Get-Variable -Scope Global -Name LogLevel -ValueOnly -ErrorAction Stop
            $LogLevel = $LogLevelVar
        }
    } catch { 
        if ([String]::IsNullOrEmpty($LogLevel)) {
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
            if (([String]::IsNullOrEmpty($ParentPath)) -Or ($ParentPath -eq "\")) {
                $LogFile = $(Join-Path -Path $RootPath -ChildPath $(Split-Path -Path $LogFile -Leaf))
            }
        }
        Write-Verbose "LogFile: $LogFile"
        #Define Log Header
        if (-Not $Show) {
            if (
                (-Not ($NoLogHeader -eq $true) -and (-Not (Test-Path -Path $LogFile -ErrorAction SilentlyContinue))) -Or 
                (-Not ($NoLogHeader -eq $true) -and ($NewLog)) -Or
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
                $LogHeader += "`r`n`r`n**********************`r`n`r`n"

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
            $Component = " {0}[{1}]{0}" -f $Delimiter, $Component.ToUpper()
        } else {
            $Component = "{0}{0}" -f $Delimiter
        }
        #Define the log sting for the Message Type
        if ($Block -Or $WriteHeader) {
            $WriteLog = $true
            if ($D -and ($LogLevel -ne "Debug")) {
                $WriteLog = $false
            }
        } elseif ($E -and (($LogLevel -eq "Error") -Or ($LogLevel -eq "Warning") -Or ($LogLevel -eq "Info") -Or ($LogLevel -eq "Debug"))) {
            Write-Verbose -Message "LogType: [Error], LogLevel: [$LogLevel]"
            $MessageType = "ERROR"
            $WriteLog = $true
        } elseif ($W -and (($LogLevel -eq "Warning") -Or ($LogLevel -eq "Info") -Or ($LogLevel -eq "Debug"))) {
            Write-Verbose -Message "LogType: [Warning], LogLevel: [$LogLevel]"
            $MessageType = "WARN "
            $WriteLog = $true
        } elseif ($I -and (($LogLevel -eq "Info") -Or ($LogLevel -eq "Debug"))) {
            Write-Verbose -Message "LogType: [Info], LogLevel: [$LogLevel]"
            $MessageType = "INFO "
            $WriteLog = $true
        } elseif ($D -and ($LogLevel -eq "Debug")) {
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
                try {
                    [System.IO.File]::AppendAllText($LogFile, $LogString, [System.Text.Encoding]::Unicode)
                    Write-Verbose -Message "Data written to LogFile:`r`n         `"$LogFile`""
                } catch {
                    Write-Verbose -Message "Error while writing to log"
                }
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
    <#
    .SYNOPSIS
        Invoke NetScaler NITRO REST API
    .DESCRIPTION
        Invoke NetScaler NITRO REST API
    .PARAMETER Session
        An existing custom NetScaler Web Request Session object returned by Connect-NetScaler
    .PARAMETER Method
        Specifies the method used for the web request
    .PARAMETER Type
        Type of the NS appliance resource
    .PARAMETER Resource
        Name of the NS appliance resource, optional
    .PARAMETER Action
        Name of the action to perform on the NS appliance resource
    .PARAMETER Arguments
        One or more arguments for the web request, in hashtable format
    .PARAMETER Query
        Specifies a query that can be send  in the web request
    .PARAMETER Filters
        Specifies a filter that can be send to the remote server, in hashtable format
    .PARAMETER Payload
        Payload  of the web request, in hashtable format
    .PARAMETER GetWarning
        Switch parameter, when turned on, warning message will be sent in 'message' field and 'WARNING' value is set in severity field of the response in case there is a warning.
        Turned off by default
    .PARAMETER OnErrorAction
        Use this parameter to set the onerror status for nitro request. Applicable only for bulk requests.
        Acceptable values: "EXIT", "CONTINUE", "ROLLBACK", default to "EXIT"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [alias("ADCSession")]
        [PSObject]$Session,

        [Parameter(Mandatory = $true)]
        [ValidateSet('DELETE', 'GET', 'POST', 'PUT')]
        [String]$Method,

        [Parameter(Mandatory = $true)]
        [String]$Type,

        [String]$Resource,

        [String]$Action,

        [hashtable]$Arguments = @{ },

        [hashtable]$Query = @{ },

        [Switch]$Stat = $false,

        [ValidateScript( { $Method -eq 'GET' })]
        [hashtable]$Filters = @{ },

        [ValidateScript( { $Method -ne 'GET' })]
        [hashtable]$Payload = @{ },

        [Switch]$GetWarning = $false,

        [ValidateSet('EXIT', 'CONTINUE', 'ROLLBACK')]
        [String]$OnErrorAction = 'EXIT',
        
        [Switch]$Clean
    )
    # Based on https://github.com/devblackops/NetScaler
    if ([String]::IsNullOrEmpty($($Session.ManagementURL))) {
        if ($Script:LoggingEnabled) { Write-ToLogFile -E -C Invoke-ADCRestApi -M "Probably not logged into the Citrix ADC!" } 
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
        if ($Query.Count -gt 0) {
            $uri += $Query.GetEnumerator() | ForEach-Object { "?$($_.Name)=$([System.Uri]::EscapeDataString($_.Value))" }
        }
    }
    if ($Script:LoggingEnabled) { Write-ToLogFile -D -C Invoke-ADCRestApi -M "URI: `"$uri`", METHOD: `"$method`"" } 

    $jsonPayload = $null
    if ($Method -ne 'GET') {
        $warning = if ($GetWarning) { 'YES' } else { 'NO' }
        $hashtablePayload = @{ }
        $hashtablePayload.'params' = @{'warning' = $warning; 'onerror' = $OnErrorAction; <#"action"=$Action#> }
        $hashtablePayload.$Type = $Payload
        $jsonPayload = ConvertTo-Json -InputObject $hashtablePayload -Depth 100 -Compress
        if ($Script:LoggingEnabled) { Write-ToLogFile -D -C Invoke-ADCRestApi -M "JSON Payload: $($jsonPayload | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)" } 
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
                if ($Script:LoggingEnabled) { Write-ToLogFile -E -C Invoke-ADCRestApi -M "Got an ERROR response: $($response| ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)" } 
                throw "Error. See log"
            } else {
                if ($Script:LoggingEnabled) { Write-ToLogFile -D -C Invoke-ADCRestApi -M "Response: $($response | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)" } 
                if ($Method -eq "GET") { 
                    if ($Clean -and (-not ([String]::IsNullOrEmpty($Type)))) {
                        return $response | Select-Object -ExpandProperty $Type -ErrorAction SilentlyContinue
                    } else {
                        return $response 
                    }
                }
            }
        }
    } catch [Exception] {
        if ($Type -eq 'reboot' -and $restError[0].Message -eq 'The underlying connection was closed: The connection was closed unexpectedly.') {
            if ($Script:LoggingEnabled) { Write-ToLogFile -I -C Invoke-ADCRestApi -M "Connection closed due to reboot." } 
        } else {
            if ($Script:LoggingEnabled) { Write-ToLogFile -E -C Invoke-ADCRestApi -M "Caught an error. Exception Message: $($_.Exception.Message)" } 
            throw $_
        }
    }
}

function Connect-ADC {
    <#
    .SYNOPSIS
        Establish a session with Citrix NetScaler.
    .DESCRIPTION
        Establish a session with Citrix NetScaler.
    .PARAMETER ManagementURL
        The URI/URL to connect to, E.g. "https://citrixadc.domain.local".
    .PARAMETER Credential
        The credential to authenticate to the NetScaler with.
    .PARAMETER Timeout
        Timeout in seconds for session object.
    .PARAMETER PassThru
        Return the NetScaler session object.
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        [uri]$ManagementURL,

        [parameter(Mandatory)]
        [PSCredential]$Credential,

        [int]$Timeout = 3600,

        [Switch]$PassThru
    )
    # Based on https://github.com/devblackops/NetScaler
    if ($Script:LoggingEnabled) { Write-ToLogFile -I -C Connect-ADC -M "Connecting to $ManagementURL..." }
    if ($ManagementURL -like "https://*") {
        if ('PSEdition' -notin $PSVersionTable.Keys -or $PSVersionTable.PSEdition -eq 'Desktop') {
            if (-Not ("TrustAllCertsPolicy" -as [type])) {
                Add-Type -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
    ServicePoint srvPoint, X509Certificate certificate,
    WebRequest request, int certificateProblem) {
        return true;
    }
}
"@ 
            }
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
        $currentMaxTls = [Math]::Max([Net.ServicePointManager]::SecurityProtocol.value__, [Net.SecurityProtocolType]::Tls.value__)
        $newTlsTypes = [enum]::GetValues('Net.SecurityProtocolType') | Where-Object { $_ -gt $currentMaxTls }
        $newTlsTypes | ForEach-Object {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $_
        }            
    }
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
            Uri             = "$($ManagementURL)nitro/v1/config/login"
            Method          = 'POST'
            Body            = $loginJson
            SessionVariable = 'saveSession'
            ContentType     = 'application/json'
            ErrorVariable   = 'restError'
            Verbose         = $false
        }
        $response = Invoke-RestMethod @params

        if ($response.severity -eq 'ERROR') {
            if ($Script:LoggingEnabled) { Write-ToLogFile -E -C Connect-ADC -M "Caught an error. Response: $($response | Select-Object message,severity,errorcode | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)" }
            Write-Error "Error. See log"
            TerminateScript 1 "Error. See log"
        } else {
            if ($Script:LoggingEnabled) { Write-ToLogFile -D -C Connect-ADC -M "Response: $($response | Select-Object message,severity,errorcode | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)" }
        }
    } catch [Exception] {
        throw $_
    }
    $session = [PSObject]@{
        ManagementURL = $ManagementURL.ToString().TrimEnd('/');
        WebSession    = [Microsoft.PowerShell.Commands.WebRequestSession]$saveSession;
        Username      = $Credential.Username;
        Version       = "UNKNOWN";
    }
    try {
        if ($Script:LoggingEnabled) { Write-ToLogFile -D -C Connect-ADC -M "Trying to retrieve the ADC version" }
        $params = @{
            Uri           = "$($ManagementURL)nitro/v1/config/nsversion"
            Method        = 'GET'
            WebSession    = $Session.WebSession
            ContentType   = 'application/json'
            ErrorVariable = 'restError'
            Verbose       = $false
        }
        $response = Invoke-RestMethod @params
        if ($Script:LoggingEnabled) { Write-ToLogFile -D -C Connect-ADC -M "Response: $($response | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)" }
        $version = $response.nsversion.version.Split(",")[0]
        if (-not ([String]::IsNullOrWhiteSpace($version))) {
            $session.version = $version
        }
        if ($Script:LoggingEnabled) { Write-ToLogFile -I -C Connect-ADC -M "Connected" } 
        if ($Script:LoggingEnabled) { Write-ToLogFile -I -C Connect-ADC -M "Connected to Citrix ADC $ManagementURL, as user $($Credential.Username), ADC Version $($session.Version)" }
    } catch {
        if ($Script:LoggingEnabled) { Write-ToLogFile -E -C Connect-ADC -M "Caught an error. Exception Message: $($_.Exception.Message)" }
        if ($Script:LoggingEnabled) { Write-ToLogFile -E -C Connect-ADC -M "Response: $($response | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)" } 
    }
    if ($PassThru) {
        return $session
    }
}

function Invoke-ADCGetHanode {
    <#
        .SYNOPSIS
            Get High Availability configuration object(s)
        .DESCRIPTION
            Get High Availability configuration object(s)
        .PARAMETER id 
           Number that uniquely identifies the node. For self node, it will always be 0. Peer node values can . 
        .PARAMETER GetAll 
            Retrieve all hanode object(s)
        .PARAMETER Count
            If specified, the count of the hanode object(s) will be returned
        .PARAMETER Filter
            Specify a filter
            -Filter @{ 'name'='<value>' }
        .EXAMPLE
            Invoke-ADCGetHanode
        .EXAMPLE 
            Invoke-ADCGetHanode -GetAll 
        .EXAMPLE 
            Invoke-ADCGetHanode -Count
        .EXAMPLE
            Invoke-ADCGetHanode -name <string>
        .EXAMPLE
            Invoke-ADCGetHanode -Filter @{ 'name'='<value>' }
        .NOTES
            File Name : Invoke-ADCGetHanode
            Version   : v2101.0322
            Author    : John Billekens
            Reference : https://developer-docs.citrix.com/projects/citrix-adc-nitro-api-reference/en/latest/configuration/ha/hanode/
            Requires  : PowerShell v5.1 and up
                        ADC 11.x and up
        .LINK
            https://blog.j81.nl
    #>
    [CmdletBinding(DefaultParameterSetName = "Getall")]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPasswordParams', '')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseBOMForUnicodeEncodedFile', '')]
    param(
        [hashtable]$ADCSession,
    
        [Parameter(ParameterSetName = 'GetByResource')]
        [ValidateRange(1, 64)]
        [double]$id,
    
        [Parameter(ParameterSetName = 'Count', Mandatory = $true)]
        [Switch]$Count,
                
        [hashtable]$Filter = @{ },
    
        [Parameter(ParameterSetName = 'GetAll')]
        [Switch]$GetAll
    
    )
    begin {
        Write-Verbose "Invoke-ADCGetHanode: Beginning"
    }
    process {
        try {
            if ( $PsCmdlet.ParameterSetName -eq 'Getall' ) {
                $Query = @{ }
                Write-Verbose "Retrieving all hanode objects"
                $response = Invoke-ADCRestApi -ADCSession $ADCSession -Method GET -Type hanode -Query $Query -Filter $Filter -GetWarning
            } elseif ( $PsCmdlet.ParameterSetName -eq 'Count' ) {
                if ($PSBoundParameters.ContainsKey('Count')) { $Query = @{ 'count' = 'yes' } }
                Write-Verbose "Retrieving total count for hanode objects"
                $response = Invoke-ADCRestApi -ADCSession $ADCSession -Method GET -Type hanode -Query $Query -Filter $Filter -GetWarning
            } elseif ( $PsCmdlet.ParameterSetName -eq 'GetByArgument' ) {
                Write-Verbose "Retrieving hanode objects by arguments"
                $Arguments = @{ } 
                $response = Invoke-ADCRestApi -ADCSession $ADCSession -Method GET -Type hanode -Arguments $Arguments -GetWarning
            } elseif ( $PsCmdlet.ParameterSetName -eq 'GetByResource' ) {
                Write-Verbose "Retrieving hanode configuration for property 'id'"
                $response = Invoke-ADCRestApi -ADCSession $ADCSession -Method GET -Type hanode -Resource $id -Filter $Filter -GetWarning
            } else {
                Write-Verbose "Retrieving hanode configuration objects"
                $response = Invoke-ADCRestApi -ADCSession $ADCSession -Method GET -Type hanode -Filter $Filter -GetWarning
            }
        } catch {
            Write-Verbose "ERROR: $($_.Exception.Message)"
            $response = $null
        }
        Write-Output $response
    }
    end {
        Write-Verbose "Invoke-ADCGetHanode: Ended"
    }
}

function New-Password {
    <#
    .SYNOPSIS
        Generate a random password.
    .DESCRIPTION
        Generate a random password.
    .NOTES
        Source:https://gist.github.com/indented-automation/2093bd088d59b362ec2a5b81a14ba84e
        Change log:
            27/11/2017 - faustonascimento - Swapped Get-Random for System.Random.
                                            Swapped Sort-Object for Fisher-Yates shuffle.
            17/03/2017 - Chris Dent - Created.
    #>

    [CmdletBinding()]
    [OutputType([String])]
    param (
        # The length of the password which should be created.
        [Parameter(ValueFromPipeline)]        
        [ValidateRange(8, 255)]
        [Int32]$Length = 10,

        # The character sets the password may contain. A password will contain at least one of each of the characters.
        [String[]]$CharacterSet = ('abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '0123456789', '!$%^&#@*'),

        # The number of characters to select from each character set.
        [Int32[]]$CharacterSetCount = (@(1) * $CharacterSet.Count)
    )

    begin {
        $bytes = [Byte[]]::new(4)
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($bytes)

        $seed = [System.BitConverter]::ToInt32($bytes, 0)
        $rnd = [Random]::new($seed)

        if ($CharacterSet.Count -ne $CharacterSetCount.Count) {
            throw "The number of items in -CharacterSet needs to match the number of items in -CharacterSetCount"
        }

        $allCharacterSets = [String]::Concat($CharacterSet)
    }

    process {
        try {
            $requiredCharLength = 0
            foreach ($i in $CharacterSetCount) {
                $requiredCharLength += $i
            }

            if ($requiredCharLength -gt $Length) {
                throw "The sum of characters specified by CharacterSetCount is higher than the desired password length"
            }

            $password = [Char[]]::new($Length)
            $index = 0
        
            for ($i = 0; $i -lt $CharacterSet.Count; $i++) {
                for ($j = 0; $j -lt $CharacterSetCount[$i]; $j++) {
                    $password[$index++] = $CharacterSet[$i][$rnd.Next($CharacterSet[$i].Length)]
                }
            }

            for ($i = $index; $i -lt $Length; $i++) {
                $password[$index++] = $allCharacterSets[$rnd.Next($allCharacterSets.Length)]
            }
            for ($i = $Length; $i -gt 0; $i--) {
                $n = $i - 1
                $m = $rnd.Next($i)
                $j = $password[$m]
                $password[$m] = $password[$n]
                $password[$n] = $j
            }

            Write-Output $([String]::new($password))
        } catch {
            Write-Error -ErrorRecord $_
        }
    }
}

function ConvertTo-TxtValue {
    [cmdletbinding()]
    param(
        [String]$KeyAuthorization
    ) 
    $keyAuthBytes = [Text.Encoding]::UTF8.GetBytes($KeyAuthorization)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    $keyAuthHash = $sha256.ComputeHash($keyAuthBytes)
    $base64 = [Convert]::ToBase64String($keyAuthHash)
    $txtValue = ($base64.Split('=')[0]).Replace('+', '-').Replace('/', '_')
    return $txtValue
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

function ConvertTo-PlainText {
    [CmdletBinding()]
    param    (
        [parameter(Mandatory = $true)]
        [System.Security.SecureString]$SecureString
    )
    Process {
        $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString);
        try {
            $result = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR);
        } finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($BSTR);
            
        }
        return $result
    }
}

function Invoke-RegisterError {
    [cmdletbinding()]
    param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [int]$ExitCode = 0,

        [Parameter(Position = 1)]
        [String]$ErrorMessage = $null,

        [Switch]$ExitNow
    )
    Write-ToLogFile -E -C Invoke-RegisterError -M "[$ExitCode] $ErrorMessage"
    if (-Not $ExitNow) {
        Write-ToLogFile -E -C Invoke-RegisterError -M "Registering error only, continuing to cleanup."
        $Script:SessionRequestObject.ErrorOccurred++
        $Script:SessionRequestObject.ExitCode = $ExitCode
        if (-Not [String]::IsNullOrEmpty($ErrorMessage)) {
            $Script:SessionRequestObject.Messages += $ErrorMessage
            $mailDataItem.Text += "ERROR: $ErrorMessage"
        }
        $Script:CleanADC = $true
    } else {
        Write-Error $ErrorMessage
        TerminateScript -ExitCode $ExitCode -ExitMessage $ErrorMessage
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
    if ($Parameters.settings.SendMail) {
        Write-ToLogFile -I -C Final -M "Script Terminated, Sending mail. ExitCode: $ExitCode"
        $MailResultData = $MailData | Sort-Object -Property Code, CertExpiresDays | ForEach-Object {
            "------------------------------"
            "Status: $($_.Code)"
            "CN: $($_.CN)"
            if ("" -ne $_.SAN) { "SANs: $($_.SAN)" }
            if ("" -ne $_.Location) { "Path: $($_.Location)" }
            if ("" -ne $_.CertKeyName) { "CertKeyName: $($_.CertKeyName)" }
            "$($_.Text)"
        }
        
        $Script:MailLog += "`r`n=============================="
        if (-Not ($ExitCode -eq 0)) {
            $SMTPSubject = "GenLeCertForNS Finished with one or more Error(s) $((Get-Date).ToString('yyyy-MM-dd HH:mm'))"
            $SMTPBody = @"
GenLeCertForNS Finished with at least one Error!
$ExitMessage

Check log for errors and more details.
Other info:
$($Script:MailLog | Out-String)
Log details:
$($MailResultData | Out-String)
==============================
"@
        } else {
            $SMTPSubject = "GenLeCertForNS Results $((Get-Date).ToString('yyyy-MM-dd HH:mm'))"
            $SMTPBody = @"
GenLeCertForNS Executed successfully!

$($Script:MailLog | Out-String)
Log details:
$($MailResultData | Out-String)
==============================
"@
        }
        try {
            Write-DisplayText -ForeGroundColor White "`r`nEmail"
            Write-DisplayText -Line "Sending Mail"
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            $message = New-Object System.Net.Mail.MailMessage
            $message.From = $($Script:Parameters.settings.SMTPFrom)
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            foreach ($to in $Script:Parameters.settings.SMTPTo) {
                $message.To.Add($to)
            }
            $message.Subject = $SMTPSubject
            $message.IsBodyHTML = $false
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            $message.Body = $SMTPBody
            $smtp = New-Object Net.Mail.SmtpClient($($Script:Parameters.settings.SMTPServer))
            if (-Not ($Script:SMTPCredential -eq [PSCredential]::Empty)) {
                Write-ToLogFile -D -C SendMail -M "Setting SMTP Credentials, Username: $($Script:SMTPCredential.Username)"
                $smtp.Credentials = $Script:SMTPCredential
            }
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            if (-Not ([String]::IsNullOrEmpty(($Script:Parameters.settings.SMTPPort)))) {
                Write-ToLogFile -D -C SendMail -M "Configuring SMTP Port: $($Script:Parameters.settings.SMTPPort)"
                $smtp.Port = $Script:Parameters.settings.SMTPPort
            }
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            if ($Script:Parameters.settings.SMTPUseSSL) {
                Write-ToLogFile -D -C SendMail -M "Enabling SSL for mail"
                $smtp.EnableSsl = $Script:Parameters.settings.SMTPUseSSL
            } else {
                Write-ToLogFile -D -C SendMail -M "Disabling SSL for mail"
                $smtp.EnableSsl = $false
            }
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            if ($Script:Parameters.settings.LogAsAttachment) {
                try {
                    $message.Attachments.Add($(New-Object System.Net.Mail.Attachment $Script:Parameters.settings.LogFile))
                } catch {
                    Write-ToLogFile -E -C SendMail -M "Could not attach LogFile, Error Details: $($_.Exception.Message)"
                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    Write-DisplayText -ForeGroundColor Red -NoNewLine " Could not attach LogFile "
                }
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            }
            try {
                $smtp.Send($message)
                $smtp.Dispose()
                $message.Dispose()
                Write-DisplayText -ForeGroundColor Green " OK"
            } catch {
                $smtp.Dispose()
                $message.Dispose()
                Write-DisplayText -ForeGroundColor Red " Failed, Could not send mail"
                Write-ToLogFile -E -C SendMail -M "Could not send mail: $($_.Exception.Message)"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            }
        } catch {
            Write-ToLogFile -E -C SendMail -M "Could not send mail: $($_.Exception.Message)"
            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            Write-DisplayText -ForeGroundColor Red " ERROR, Could not send mail: $($_.Exception.Message)"
        }
        
    } else {
        Write-ToLogFile -I -C Final -M "Script Terminated, ExitCode: $ExitCode"
    }

    if ($ExitCode -eq 0) {
        Write-DisplayText -ForegroundColor Green "Finished! $ExitMessage" -PostBlank -PreBlank
    } else {
        Write-DisplayText -ForegroundColor Red "Finished with Errors! $ExitMessage" -PostBlank -PreBlank
    }
    exit $ExitCode
}

function Save-ADCConfig {
    [cmdletbinding()]
    param (
        [Switch]$SaveADCConfig
    )
    Write-DisplayText -Title "ADC Configuration"
    Write-DisplayText -Line "Config Saved"
    if ($SaveADCConfig) {
        Write-ToLogFile -I -C SaveADCConfig -M "Saving ADC configuration.  (`"-SaveADCConfig`" Parameter set)"
        $payload = @{"nsconfig" = "all" }
        try {
            try {
                Invoke-ADCRestApi -Session $ADCSession -Method POST -Type nsconfig -Action save -Payload $payload
                Write-DisplayText -ForeGroundColor Green "All - Saved!"
                Write-ToLogFile -I -C SaveADCConfig -M "Config saved!"
            } catch {
                Write-ToLogFile -I -C SaveADCConfig -M "Save-All not available, trying again with only save."
                Invoke-ADCRestApi -Session $ADCSession -Method POST -Type nsconfig -Action save
                Write-DisplayText -ForeGroundColor Green "Saved!"
                Write-ToLogFile -I -C SaveADCConfig -M "Config saved!"
            }
        } catch {
            Write-DisplayText -ForeGroundColor Red "ERROR, NOT Saved!"
            Write-ToLogFile -E -C SaveADCConfig -M "ERROR, ADC configuration NOT Saved! $($_.Exception.Message)"
        }
    } else {
        Write-DisplayText -ForeGroundColor Yellow "NOT Saved! (`"-SaveADCConfig`" Parameter not defined)"
        Write-ToLogFile -I -C SaveADCConfig -M "ADC configuration NOT Saved! (`"-SaveADCConfig`" Parameter not defined)"
        $Script:MailLog += "`r`nIMPORTANT: Your Citrix ADC configuration was NOT saved!`r`n"
    }
}

function Invoke-ADCCleanup {
    [CmdletBinding()]
    param (
        [Switch]$Full
    )
    process {
        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Cleaning the Citrix ADC Configuration."
        Write-DisplayText -Title "ADC - Cleanup"
        Write-DisplayText -Line "Cleanup type"
        #ToDo - Create two options, for now only Full
        if ($Full) {
            Write-DisplayText -ForegroundColor Cyan "Full"
        } else {
            Write-DisplayText -ForegroundColor Cyan "Full"
        }
        Write-DisplayText -Line "Cleanup"
        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Trying to login into the Citrix ADC."
        $ADCSession = Connect-ADC -ManagementURL $Parameters.settings.ManagementURL -Credential $Credential -PassThru
        if (-Not $CertRequest.UseLbVip) {
            try {
                Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if a binding exists for `"$($Parameters.settings.CspName)`"."
                try {
                    $Filters = @{"policyname" = "$($Parameters.settings.CspName)" }
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csvserver_cspolicy_binding -Resource "$($CertRequest.CsVipName)" -Filters $Filters -ErrorAction SilentlyContinue
                } catch { }
                if ($response.csvserver_cspolicy_binding.policyname -eq $($Parameters.settings.CspName)) {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Binding exists, removing Content Switch LoadBalance Binding."
                    $Arguments = @{"name" = "$($CertRequest.CsVipName)"; "policyname" = "$($Parameters.settings.CspName)"; "priority" = "$($Parameters.settings.CsVipBinding)"; }
                    $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type csvserver_cspolicy_binding -Arguments $Arguments
                } else {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "No binding found."
                }
                Write-DisplayText -ForeGroundColor Green -NoNewLine "CS-Vip$([Char]8730)"
            } catch {
                Write-ToLogFile -E -C Invoke-ADCCleanup -M "Not able to remove the Content Switch LoadBalance Binding. Exception Message: $($_.Exception.Message)"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                Write-DisplayText -ForeGroundColor Yellow " WARNING: Not able to remove the Content Switch LoadBalance Binding"
                Write-DisplayText -Line "Cleanup"
            }
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            try {
                Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if Content Switch Policy `"$($Parameters.settings.CspName)`" exists."
                try {
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type cspolicy -Resource "$($Parameters.settings.CspName)"
                } catch { }
                if ($response.cspolicy.policyname -eq $($Parameters.settings.CspName)) {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Content Switch Policy exist, removing Content Switch Policy."
                    $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type cspolicy -Resource "$($Parameters.settings.CspName)"
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Removed Content Switch Policy successfully."
                } else {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Content Switch Policy not found."
                }
                Write-DisplayText -ForeGroundColor Green -NoNewLine "CS-Pol$([Char]8730)"
            } catch {
                Write-ToLogFile -E -C Invoke-ADCCleanup -M "Not able to remove the Content Switch Policy. Exception Message: $($_.Exception.Message)"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                Write-DisplayText -ForeGroundColor Yellow " WARNING: Not able to remove the Content Switch Policy"
                Write-DisplayText -Line "Cleanup"
            }
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            try {
                Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if Load Balance VIP `"$($Parameters.settings.LbName)`" exists."
                try {
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type lbvserver -Resource "$($Parameters.settings.LbName)"
                } catch { }
                if ($response.lbvserver.name -eq $($Parameters.settings.LbName)) {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance VIP exist, removing the Load Balance VIP."
                    $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type lbvserver -Resource "$($Parameters.settings.LbName)"
                } else {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance VIP not found."
                }
                Write-DisplayText -ForeGroundColor Green -NoNewLine "LB-Vip$([Char]8730)"
            } catch {
                Write-ToLogFile -E -C Invoke-ADCCleanup -M "Not able to remove the Load Balance VIP. Exception Message: $($_.Exception.Message)"
                Write-DisplayText -ForeGroundColor Yellow " WARNING: Not able to remove the Load Balance VIP"
                Write-DisplayText -Line "Cleanup"
            }
        } else {
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            try {
                Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if service `"$($Parameters.settings.SvcName)`" is bound to Load Balance VIP `"$($Parameters.settings.LbName)`"."
                try {
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type lbvserver_service_binding -Resource "$($Parameters.settings.LbName)"
                } catch { }
                if ($response.lbvserver_service_binding.servicename -eq $($Parameters.settings.SvcName)) {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance VIP binding with Service exists, removing the Load Balance VIP-Service binding."
                    $Arguments = @{"servicename" = "$($Parameters.settings.SvcName)" }
                    $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type lbvserver_service_binding -Resource "$($Parameters.settings.LbName)" -Arguments $arguments
                    Write-DisplayText -ForeGroundColor Green -NoNewLine "LB-Vip-Svc-Binding$([Char]8730)"
                } else {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance VIP - Service binding not found."
                }
            } catch {
                Write-ToLogFile -E -C Invoke-ADCCleanup -M "Not able to remove the Load Balance VIP - Service binding. Exception Message: $($_.Exception.Message)"
                Write-DisplayText -ForeGroundColor Yellow " WARNING: Not able to remove the Load Balance VIP - Service binding"
                Write-DisplayText -Line "Cleanup"
            }
        }
        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
        try {
            Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if Load Balance Service `"$($Parameters.settings.SvcName)`" exists."
            try {
                $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type service -Resource "$($Parameters.settings.SvcName)"
            } catch { }
            if ($response.service.name -eq $($Parameters.settings.SvcName)) {
                Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance Service exist, removing Service `"$($Parameters.settings.SvcName)`"."
                $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type service -Resource "$($Parameters.settings.SvcName)"
            } else {
                Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance Service not found."
            }
            Write-DisplayText -ForeGroundColor Green -NoNewLine "LB-Svc$([Char]8730)"
        } catch {
            Write-ToLogFile -E -C Invoke-ADCCleanup -M "Not able to remove the Service. Exception Message: $($_.Exception.Message)"
            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            Write-DisplayText -ForeGroundColor Yellow " WARNING: Not able to remove the Service"
            Write-DisplayText -Line "Cleanup"
        }
        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
        try {
            Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if Load Balance Server `"$($Parameters.settings.SvcDestination)`" exists."
            try {
                $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type server -Resource "$($Parameters.settings.SvcDestination)"
            } catch { }
            if ($response.server.name -eq $($Parameters.settings.SvcDestination)) {
                Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance Server exist, removing Load Balance Server `"$($Parameters.settings.SvcDestination)`"."
                $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type server -Resource "$($Parameters.settings.SvcDestination)"
            } else {
                Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance Server not found."
            }
            Write-DisplayText -ForeGroundColor Green -NoNewLine "LB-Srv$([Char]8730)"
        } catch {
            Write-ToLogFile -E -C Invoke-ADCCleanup -M "Not able to remove the Server. Exception Message: $($_.Exception.Message)"
            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            Write-DisplayText -ForeGroundColor Yellow " WARNING: Not able to remove the Server"
            Write-DisplayText -Line "Cleanup"
        }
        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if there are Responder Policies starting with the name `"$($Parameters.settings.RspName)`"."
        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
        try {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderpolicy -Filter @{name = "/$($Parameters.settings.RspName)/" }
        } catch {
            Write-ToLogFile -E -C Invoke-ADCCleanup -M "Failed to retrieve Responder Policies. Exception Message: $($_.Exception.Message)"
            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
        }
        if (-Not([String]::IsNullOrEmpty($($response.responderpolicy)))) {
            Write-ToLogFile -D -C Invoke-ADCCleanup -M "Responder Policies found:"
            $response.responderpolicy | Select-Object name, action, rule | ForEach-Object {
                Write-ToLogFile -D -C Invoke-ADCCleanup -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
            }
            ForEach ($ResponderPolicy in $response.responderpolicy) {
                try {
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if policy `"$($ResponderPolicy.name)`" is bound to Load Balance VIP."
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderpolicy_binding -Resource "$($ResponderPolicy.name)"
                    ForEach ($ResponderBinding in $response.responderpolicy_binding) {
                        try {
                            if ($null -eq $ResponderBinding.responderpolicy_lbvserver_binding.priority) {
                                Write-ToLogFile -I -C Invoke-ADCCleanup -M "Responder Policy not bound."
                            } else {
                                Write-ToLogFile -D -C Invoke-ADCCleanup -M "ResponderBinding: $($ResponderBinding | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                                $arguments = @{"bindpoint" = "REQUEST" ; "policyname" = "$($ResponderBinding.responderpolicy_lbvserver_binding.name)"; "priority" = "$($ResponderBinding.responderpolicy_lbvserver_binding.priority)"; }
                                Write-ToLogFile -I -C Invoke-ADCCleanup -M "Trying to unbind with the following arguments: $($arguments | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                                $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type lbvserver_responderpolicy_binding -Arguments $arguments -Resource $($Parameters.settings.LbName)
                                Write-ToLogFile -I -C Invoke-ADCCleanup -M "Responder Policy unbound successfully."
                            }
                        } catch {
                            Write-ToLogFile -E -C Invoke-ADCCleanup -M "Failed to unbind Responder. Exception Message: $($_.Exception.Message)"
                            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                        }
                    }
                } catch {
                    Write-ToLogFile -E -C Invoke-ADCCleanup -M "Something went wrong while Retrieving data. Exception Message: $($_.Exception.Message)"
                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                }
                try {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Trying to remove the Responder Policy `"$($ResponderPolicy.name)`"."
                    $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type responderpolicy -Resource "$($ResponderPolicy.name)"
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Responder Policy removed successfully."
                } catch {
                    Write-ToLogFile -E -C Invoke-ADCCleanup -M "Failed to remove the Responder Policy. Exception Message: $($_.Exception.Message)"
                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                }
            }
        } else {
            Write-ToLogFile -I -C Invoke-ADCCleanup -M "No Responder Policies found."
        }
        Write-DisplayText -ForeGroundColor Green -NoNewLine "RS-Pol$([Char]8730)"
        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if there are Responder Actions starting with the name `"$($Parameters.settings.RsaName)`"."
        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
        try {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderaction -Filter @{name = "/$($Parameters.settings.RsaName)/" }
        } catch {
            Write-ToLogFile -E -C Invoke-ADCCleanup -M "Failed to retrieve Responder Actions. Exception Message: $($_.Exception.Message)"
            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
        }
        if (-Not([String]::IsNullOrEmpty($($response.responderaction)))) {
            Write-ToLogFile -D -C Invoke-ADCCleanup -M "Responder Actions found:"
            $response.responderaction | Select-Object name, target | ForEach-Object {
                Write-ToLogFile -D -C Invoke-ADCCleanup -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
            }
            ForEach ($ResponderAction in $response.responderaction) {
                try {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Trying to remove the Responder Action `"$($ResponderAction.name)`""
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type responderaction -Resource "$($ResponderAction.name)"
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Responder Action removed successfully."
                } catch {
                    Write-ToLogFile -E -C Invoke-ADCCleanup -M "Failed to remove the Responder Action. Exception Message: $($_.Exception.Message)"
                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                }
            }
        } else {
            Write-ToLogFile -I -C Invoke-ADCCleanup -M "No Responder Actions found."
        }
        Write-DisplayText -ForeGroundColor Green -NoNewLine "RS-Act$([Char]8730)"
        Write-DisplayText -ForeGroundColor Green " Completed"
        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Finished cleaning up."        
    }
}

function Invoke-AddInitialADCConfig {
    [CmdletBinding()]
    param (
        
    )
   
    process {
        try {
            Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Trying to login into the Citrix ADC."
            Write-DisplayText -Title "ADC - Configure Prerequisites"
            $ADCSession = Connect-ADC -ManagementURL $Parameters.settings.ManagementURL -Credential $Credential -PassThru
            Write-DisplayText -Line "Prerequisites"
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            try {
                $license = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type nslicense -ErrorAction SilentlyContinue | Select-Object -ExpandProperty nslicense
            } catch {
                Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Caught an error while retrieving licenses! If using an api user, update the api user by running the command again!"
                Write-DisplayText -ForeGroundColor RED "`r`nCaught an error while retrieving licenses! If using an api user, update the api user by running the command again!`r`n"
                Throw $_
            }
            if ($CertRequest.UseLbVip) {
                $FeaturesRequired = @("RESPONDER", "SSL")
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Enabling (if disabled) required ADC Features: Responder and SSL."
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "`"-UseLbVip`" parameter was specified."
            } elseif ((-not $license.lb) -and (-not $license.cs)) {
                Write-DisplayText -ForeGroundColor Red -NoNewLine " Error - Feature `"LB`" and `"CS`" are not licensed"
                Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Feature `"LB`" and `"CS`" are not licensed, probably a Gateway edition. If GW edition, specify the `"-UseLbVip`" and `"-LbVip LBVIPNAME`" parameter."
                TerminateScript 1 "Feature `"LB`" and `"CS`" are not licensed, probably a Gateway edition. If GW edition, specify the `"-UseLbVip`" and `"-LbVip LBVIPNAME`" parameter."
            } else {
                $FeaturesRequired = @("LB", "RESPONDER", "CS", "SSL")
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Enabling (if disabled) required ADC Features: Load Balancer, Responder, Content Switch and SSL."
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "License OK."
            }
            $response = try { Invoke-ADCRestApi -Session $ADCSession -Method GET -Type nsfeature -ErrorAction SilentlyContinue } catch { $null }
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            $FeaturesToBeEnabled = @()
            foreach ($Feature in $FeaturesRequired) {
                if ($Feature -in $response.nsfeature.feature) {
                    Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "Feature `"$Feature`" already enabled."
                } else {
                    Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "Feature `"$Feature`" disabled, must be enabled."
                    $FeaturesToBeEnabled += $Feature
                }
            }
            if ($FeaturesToBeEnabled.Count -gt 0) {
                $payload = @{"feature" = $FeaturesToBeEnabled }
                try {
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type nsfeature -Payload $payload -Action enable
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                } catch {
                    Write-DisplayText -ForeGroundColor Red " Error"
                }
            }
            try {
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Features enabled, verifying Content Switch."
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                if (-not $CertRequest.UseLbVip) {
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csvserver -Resource $($CertRequest.CsVipName)
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Content Switch is OK, check if Load Balance Service exists."
                } else {
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Skipped, UseLbVip was configured."
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Check if Load Balance Service exists."
                }
            } catch {
                $ExceptMessage = $_.Exception.Message
                Write-DisplayText -ForeGroundColor Red " Error"
                Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Could not find/read out the content switch `"$($CertRequest.CsVipName)`" not available? Exception Message: $ExceptMessage"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                Write-Error "Could not find/read out the content switch `"$($CertRequest.CsVipName)`" not available?"
                TerminateScript 1 "Could not find/read out the content switch `"$($CertRequest.CsVipName)`" not available?"
                if ($ExceptMessage -like "*(404) Not Found*") {
                    Write-DisplayText -ForeGroundColor Red "The Content Switch `"$($CertRequest.CsVipName)`" does NOT exist!"
                    Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "The Content Switch `"$($CertRequest.CsVipName)`" does NOT exist!"
                    TerminateScript 1 "The Content Switch `"$($CertRequest.CsVipName)`" does NOT exist!"
                } elseif ($ExceptMessage -like "*The remote server returned an error*") {
                    Write-DisplayText -ForeGroundColor Red "Unknown error found while checking the Content Switch: `"$($CertRequest.CsVipName)`"."
                    Write-DisplayText -ForeGroundColor Red "Error message: `"$ExceptMessage`""
                    Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Unknown error found while checking the Content Switch: `"$($CertRequest.CsVipName)`". Exception Message: $ExceptMessage"
                    TerminateScript 1 "Unknown error found while checking the Content Switch: `"$($CertRequest.CsVipName)`". Exception Message: $ExceptMessage"
                } elseif (-Not [String]::IsNullOrEmpty($ExceptMessage)) {
                    Write-DisplayText -ForeGroundColor Red "Unknown Error, `"$ExceptMessage`""
                    Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Caught an unknown error. Exception Message: $ExceptMessage"
                    TerminateScript 1 "Caught an unknown error. Exception Message: $ExceptMessage"
                }
            } 
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            try {
                
                $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type service -Resource $($Parameters.settings.SvcName)
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Load Balancer Service exists, continuing."
            } catch {
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Load Balancer Service does not exist, create Load Balance Service `"$($Parameters.settings.SvcName)`"."
                $payload = @{"name" = "$($Parameters.settings.SvcName)"; "ip" = "$($Parameters.settings.SvcDestination)"; "servicetype" = "HTTP"; "port" = "80"; "healthmonitor" = "NO"; }
                if ($Parameters.settings.TrafficDomain -gt 0) {
                    $payload.td = $Parameters.settings.TrafficDomain
                }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type service -Payload $payload -Action add
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Load Balance Service created."
            }
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            try {
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Check if Load Balance VIP exists."
                $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type lbvserver -Resource $($Parameters.settings.LbName) -Filter @{'servicetype' = 'http'; 'port' = '80' }
                if ($response.lbvserver.Count -gt 1) {
                    Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "More than one LbVip's ($($response.lbvserver.Count)) found, cannot continue!"
                    TerminateScript 1 "More than one LbVip's ($($response.lbvserver.Count)) found, cannot continue!"
                } elseif ($response.lbvserver.Count -lt 1) {
                    Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "No LbVip with the name `"$($Parameters.settings.LbName)`" found, cannot continue!"
                    TerminateScript 1 "No LbVip with the name `"$($Parameters.settings.LbName)`" found, cannot continue!"
                } else {
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Load Balance VIP exists, continuing"
                }
            } catch {
                if (-not $CertRequest.UseLbVip) {
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Load Balance VIP does not exist, create Load Balance VIP `"$($Parameters.settings.LbName)`"."
                    $payload = @{"name" = "$($Parameters.settings.LbName)"; "servicetype" = "HTTP"; "ipv46" = "0.0.0.0"; "Port" = "0"; }
                    if ($Parameters.settings.TrafficDomain -gt 0) {
                        $payload.td = $Parameters.settings.TrafficDomain
                    }
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type lbvserver -Payload $payload -Action add
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Load Balance VIP Created."
                } else {
                    Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Load Balance VIP does not exist, is required when using `"-UseLbVip`" parameter!"
                    Write-DisplayText -ForeGroundColor Red " Error - Load Balance VIP does not exist, is required when using `"-UseLbVip`" parameter!"
                    TerminateScript 1 "Load Balance VIP does not exist, is required when using `"-UseLbVip`" parameter!"
                }
            } finally {
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Checking if LB Service `"$($Parameters.settings.SvcName)`" is bound to Load Balance VIP `"$($Parameters.settings.LbName)`"."
                $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type lbvserver_service_binding -Resource $($Parameters.settings.LbName)
    
                if ($response.lbvserver_service_binding.servicename -eq $($Parameters.settings.SvcName)) {
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "LB Service binding is OK"
                } else {
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "LB Service binding must be configured"
                    $payload = @{"name" = "$($Parameters.settings.LbName)"; "servicename" = "$($Parameters.settings.SvcName)"; }
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type lbvserver_service_binding -Payload $payload
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "LB Service binding is OK"
                }
            }
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            try {
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Checking if Responder Policies exists starting with `"$($Parameters.settings.RspName)`""
                $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderpolicy -Filter @{name = "/$($Parameters.settings.RspName)/" }
            } catch {
                Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Failed to retrieve Responder Policies. Exception Message: $($_.Exception.Message)"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            }
            if (-Not([String]::IsNullOrEmpty($($response.responderpolicy)))) {
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Responder Policies found"
                $response.responderpolicy | Select-Object name, action, rule | ForEach-Object {
                    Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                }
                ForEach ($ResponderPolicy in $response.responderpolicy) {
                    try {
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                        Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Checking if policy `"$($ResponderPolicy.name)`" is bound to Load Balance VIP."
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderpolicy_binding -Resource "$($ResponderPolicy.name)"
                        ForEach ($ResponderBinding in $response.responderpolicy_binding) {
                            try {
                                if ($null -eq $ResponderBinding.responderpolicy_lbvserver_binding.priority) {
                                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Responder Policy not bound."
                                } else {
                                    Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "ResponderBinding: $($ResponderBinding | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                                    $arguments = @{"bindpoint" = "REQUEST" ; "policyname" = "$($ResponderBinding.responderpolicy_lbvserver_binding.name)"; "priority" = "$($ResponderBinding.responderpolicy_lbvserver_binding.priority)"; }
                                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Trying to unbind with the following arguments: $($arguments | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                                    $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type lbvserver_responderpolicy_binding -Arguments $arguments -Resource $($Parameters.settings.LbName)
                                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Responder Policy unbound successfully."
                                }
                            } catch {
                                Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Failed to unbind Responder. Exception Message: $($_.Exception.Message)"
                                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                            }
                        }
                    } catch {
                        Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Something went wrong while Retrieving data. Exception Message: $($_.Exception.Message)"
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    }
                    try {
                        Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Trying to remove the Responder Policy `"$($ResponderPolicy.name)`"."
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type responderpolicy -Resource "$($ResponderPolicy.name)"
                        Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Responder Policy removed successfully."
                    } catch {
                        Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Failed to remove the Responder Policy. Exception Message: $($_.Exception.Message)"
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    }
                }
        
            } else {
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "No Responder Policies found."
            }
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Checking if Responder Actions exists starting with `"$($Parameters.settings.RsaName)`"."
            try {
                $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderaction -Filter @{name = "/$($Parameters.settings.RsaName)/" }
            } catch {
                Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Failed to retrieve Responder Actions. Exception Message: $($_.Exception.Message)"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            }
            if (-Not([String]::IsNullOrEmpty($($response.responderaction)))) {
                Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "Responder Actions found:"
                $response.responderaction | Select-Object name, target | ForEach-Object {
                    Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                }
                ForEach ($ResponderAction in $response.responderaction) {
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    try {
                        Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Trying to remove the Responder Action `"$($ResponderAction.name)`""
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type responderaction -Resource "$($ResponderAction.name)"
                        Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Responder Action removed successfully."
                    } catch {
                        Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Failed to remove the Responder Action. Exception Message: $($_.Exception.Message)"
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    }
                }
            } else {
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "No Responder Actions found."
            }
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "Creating a test Responder Action."
            $payload = @{"name" = "$($($Parameters.settings.RsaName))_test"; "type" = "respondwith"; "target" = '"HTTP/1.0 200 OK" +"\r\n\r\n" + "XXXX"'; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type responderaction -Payload $payload -Action add
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "Responder Action created, creating a test Responder Policy."
            $payload = @{"name" = "$($($Parameters.settings.RspName))_test"; "action" = "$($($Parameters.settings.RsaName))_test"; "rule" = 'HTTP.REQ.URL.CONTAINS(".well-known/acme-challenge/XXXX")'; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type responderpolicy -Payload $payload -Action add
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "Responder Policy created, binding Responder Policy `"$($($Parameters.settings.RspName))_test`" to Load Balance VIP: `"$($Parameters.settings.LbName)`"."
            $payload = @{"name" = "$($Parameters.settings.LbName)"; "policyname" = "$($($Parameters.settings.RspName))_test"; "priority" = 5; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type lbvserver_responderpolicy_binding -Payload $payload -Resource $($Parameters.settings.LbName)
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            if (-not $CertRequest.UseLbVip) {
                try {
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Responder Policy bound successfully, check if Content Switch Policy exists."
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type cspolicy -Resource $($Parameters.settings.CspName)
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Content Switch Policy exists, continuing."
                    if (-not($response.cspolicy.rule -eq "HTTP.REQ.URL.CONTAINS(`"well-known/acme-challenge/`")")) {
                        $payload = @{"policyname" = "$($Parameters.settings.CspName)"; "rule" = "HTTP.REQ.URL.CONTAINS(`"well-known/acme-challenge/`")"; }
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type cspolicy -Payload $payload
                        Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "Response: $($response | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    }
                } catch {
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Create Content Switch Policy."
                    $payload = @{"policyname" = "$($Parameters.settings.CspName)"; "rule" = 'HTTP.REQ.URL.CONTAINS("well-known/acme-challenge/")'; }
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type cspolicy -Payload $payload -Action add
                }
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Content Switch Policy created successfully, bind Load Balancer `"$($Parameters.settings.LbName)`" to Content Switch `"$($CertRequest.CsVipName)`" with prio: $($Parameters.settings.CsVipBinding)"
                $payload = @{"name" = "$($CertRequest.CsVipName)"; "policyname" = "$($Parameters.settings.CspName)"; "priority" = "$($Parameters.settings.CsVipBinding)"; "targetlbvserver" = "$($Parameters.settings.LbName)"; "gotopriorityexpression" = "END"; }
                $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type csvserver_cspolicy_binding -Payload $payload
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Binding created successfully!"
            } else {
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "NO Content Switch Policy created, UseLbVip was configured"
            }
            Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Finished configuring the ADC"
        } catch {
            Write-DisplayText -ForeGroundColor Red " Error"
            Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Could not configure the ADC. Exception Message: $($_.Exception.Message)"
            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            Write-Error "Could not configure the ADC!"
            TerminateScript 1 "Could not configure the ADC!"
        }
        Start-Sleep -Seconds 2
        Write-DisplayText -ForeGroundColor Green " Ready"        
    }
    
}

function Invoke-CheckDNS {
    [CmdletBinding()]
    param (
    )
    process {
        Write-DisplayText -ForeGroundColor Yellow "`r`nNOTE: Executing some tests, can take a couple of seconds/minutes..."
        Write-DisplayText -ForeGroundColor Yellow "Should a DNS test fail, the script will try to continue!"
        Write-DisplayText -Title "DNS Validation & Verifying ADC config"
        Write-ToLogFile -I -C Invoke-CheckDNS -M "DNS Validation & Verifying ADC config."
        ForEach ($DNSObject in $SessionRequestObject.DNSObjects ) {
            Write-DisplayText -Line "DNS Hostname"
            Write-DisplayText -ForeGroundColor Cyan "$($DNSObject.DNSName) [$($DNSObject.IPAddress)]"
            $TestURL = "http://$($DNSObject.DNSName)/.well-known/acme-challenge/XXXX"
            Write-ToLogFile -I -C Invoke-CheckDNS -M "Testing if the Citrix ADC (Content Switch) is configured successfully by accessing URL: `"$TestURL`" (via internal DNS)."
            try {
                Write-ToLogFile -D -C Invoke-CheckDNS -M "Retrieving data"
                $result = Invoke-WebRequest -Uri $TestURL -TimeoutSec 10 -UseBasicParsing -ErrorAction Stop
                Write-ToLogFile -I -C Invoke-CheckDNS -M "Retrieved successfully."
                Write-ToLogFile -D -C Invoke-CheckDNS -M "output: $($result | Select-Object StatusCode,StatusDescription,RawContent | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
            } catch {
                $result = $null
                Write-ToLogFile -E -C Invoke-CheckDNS -M "Internal check failed. Exception Message: $($_.Exception.Message)"
            }
            Write-DisplayText -Line "Internal DNS Test"
            if ($result.RawContent -eq "HTTP/1.0 200 OK`r`n`r`nXXXX") {
                Write-DisplayText -ForeGroundColor Green "OK"
                Write-ToLogFile -I -C Invoke-CheckDNS -M "Internal DNS Test: OK"
            } else {
                Write-DisplayText -ForeGroundColor Yellow "Not successful, maybe not resolvable internally?"
                Write-ToLogFile -W -C Invoke-CheckDNS -M "Internal DNS Test: Not successful, maybe not resolvable externally?"
                Write-ToLogFile -D -C Invoke-CheckDNS -M "Output: $($result | Select-Object StatusCode,StatusDescription,RawContent | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
            }
    
            try {
                Write-ToLogFile -I -C Invoke-CheckDNS -M "Checking if Public IP is available for external DNS testing."
                [ref]$ValidIP = [IPAddress]::None
                if (([IPAddress]::TryParse("$($DNSObject.IPAddress)", $ValidIP)) -and (-not ($($CertRequest.DisableIPCheck)))) {
                    Write-ToLogFile -I -C Invoke-CheckDNS -M "Testing if the Citrix ADC (Content Switch) is configured successfully by accessing URL: `"$TestURL`" (via external DNS)."
                    $TestURL = "http://$($DNSObject.IPAddress)/.well-known/acme-challenge/XXXX"
                    $Headers = @{"Host" = "$($DNSObject.DNSName)" }
                    Write-ToLogFile -D -C Invoke-CheckDNS -M "Retrieving data with the following headers: $($Headers | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    $result = Invoke-WebRequest -Uri $TestURL -Headers $Headers -TimeoutSec 10 -UseBasicParsing
                    Write-ToLogFile -I -C Invoke-CheckDNS -M "Success"
                    Write-ToLogFile -D -C Invoke-CheckDNS -M "Output: $($result | Select-Object StatusCode,StatusDescription,RawContent | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                } else {
                    Write-ToLogFile -I -C Invoke-CheckDNS -M "Public IP is not available for external DNS testing"
                }
            } catch {
                $result = $null
                Write-ToLogFile -E -C Invoke-CheckDNS -M "External check failed. Exception Message: $($_.Exception.Message)"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            }
            [ref]$ValidIP = [IPAddress]::None
            if (([IPAddress]::TryParse("$($DNSObject.IPAddress)", $ValidIP)) -and (-not $CertRequest.DisableIPCheck)) {
                Write-DisplayText -Line "External DNS Test"
                if ($result.RawContent -eq "HTTP/1.0 200 OK`r`n`r`nXXXX") {
                    Write-DisplayText -ForeGroundColor Green "OK"
                    Write-ToLogFile -I -C Invoke-CheckDNS -M "External DNS Test: OK"
                } else {
                    Write-DisplayText -ForeGroundColor Yellow "Not successful, maybe not resolvable externally?"
                    Write-ToLogFile -W -C Invoke-CheckDNS -M "External DNS Test: Not successful, maybe not resolvable externally?"
                    Write-ToLogFile -D -C Invoke-CheckDNS -M "Output: $($result | Select-Object StatusCode,StatusDescription,RawContent | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                }
                if (-Not [String]::IsNullOrEmpty($($DNSObject.DNSType))) {
                    Write-DisplayText -Line "External DNS Record Type"
                    if ([String]::IsNullOrEmpty($($DNSObject.DNSCNAMEDetails))) {
                        Write-DisplayText -ForeGroundColor Cyan "$($DNSObject.DNSType -Join '-Record, ')-Record"
                    } else {
                        Write-DisplayText -ForeGroundColor Cyan "$($DNSObject.DNSType)-Record => $($DNSObject.DNSCNAMEDetails.Type -Join '-Record, ')-Record to $($DNSObject.DNSCNAMEDetails.Record -Join ', ') [$($DNSObject.DNSCNAMEDetails.IP -Join ', ')]"
                    }
                }
            } else {
                Write-ToLogFile -D -C Invoke-CheckDNS -M "Not a valid IP Address [$([IPAddress]::TryParse("$($DNSObject.IPAddress)", $ValidIP))] or DisableIPCheck [$($CertRequest.DisableIPCheck)]"
            }
        }
        Write-DisplayText -Title -ForeGroundColor Cyan "Finished the tests, script will continue"
        Write-ToLogFile -I -C Invoke-CheckDNS -M "Finished the tests, script will continue."        
    }
}

function ConvertTo-EncryptedPassword {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [Object]$Object
    )
    process {
        try {
            $IsEncrypted = $false
            if ([String]::IsNullOrEmpty($Object) -Or ($Object.Length -eq 0)) {
                $encrypted = "<null>"
                $IsEncrypted = $true
            } elseif ($Object -is [SecureString]) {
                $encrypted = ConvertFrom-SecureString -k (0..15) $Object
                $IsEncrypted = $true
            } elseif ($Object -is [String]) {
                $encrypted = ConvertFrom-SecureString -k (0..15) (ConvertTo-SecureString $Object -AsPlainText -Force)
                $IsEncrypted = $true
            } elseif ($Object -is [System.Management.Automation.PSCredential]) {
                if (([String]::IsNullOrEmpty($($Object.GetNetworkCredential().Password))) -or ($Object.Password.Length -eq 0)) {
                    $encrypted = "<null>"
                    $IsEncrypted = $true
                } else {
                    $encrypted = ConvertFrom-SecureString -k (0..15) $Object.Password
                    $IsEncrypted = $true
                }
            } else {
                Throw "The object type is unknown, must be String, SecureString or a PSCredential type."
            }
        } catch {
            $encrypted = "<null>"
            Throw "Could not convert the passed Object"
        }
        $result = [PSCustomObject]@{
            Password    = $encrypted
            IsEncrypted = $IsEncrypted
        }
        return $result
    }
}
function ConvertFrom-EncryptedPassword {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [PSCustomObject]$Object,

        [Switch]$AsClearText
    )
    process {
        try {    
            if (($Object.Password -eq "<null>") -Or ([String]::IsNullOrEmpty($Object.Password))) {
                if ($AsClearText) {
                    [String]$decodedString = ""
                } else {
                    [SecureString]$decodedString = [SecureString]::new()
                }                       
            } else {
                if ($Object.IsEncrypted) {
                    if ($AsClearText) {
                        [String]$decodedString = ""
                        [String]$decodedString = (New-Object System.Management.Automation.PSCredential(" ", (ConvertTo-SecureString -k (0..15) $Object.Password))).GetNetworkCredential().Password
                    } else {
                        [SecureString]$decodedString = [SecureString]::new()
                        [SecureString]$decodedString = (New-Object System.Management.Automation.PSCredential(" ", (ConvertTo-SecureString -k (0..15) $Object.Password))).Password
                    }
                } else {
                    if ($AsClearText) {
                        [String]$decodedString = $Object.Password
                    } else {
                        [SecureString]$decodedString = ConvertTo-SecureString $Object.Password -AsPlainText -Force
                    }
                }
            }
        } catch {
            if ($AsClearText) {
                [String]$decodedString = ""
            } else {
                [SecureString]$decodedString = [SecureString]::new()
            }
        }
        return $decodedString
    } 
}

function Invoke-AddUpdateParameter {
    [CmdletBinding()]
    param (
        [PSCustomObject]$Object,

        [String]$Name,

        [Object]$Value
    )
    process {
        if (($Value -is [SecureString]) -or ($Value -is [System.Management.Automation.PSCredential])) {
            $Value = ConvertTo-EncryptedPassword -Object $Value
        }
        if ([String]::IsNullOrEmpty($($Object | Get-Member -Name $Name -ErrorAction SilentlyContinue))) {
            $Object | Add-Member -MemberType NoteProperty -Name $Name -Value $Value
        } else {
            $Object."$Name" = $Value
        }
    }
}

function Write-DisplayText {
    [cmdletbinding(DefaultParameterSetName = "Line")]
    param(
        [Parameter(ParameterSetName = "Title", Position = 0)]
        [Parameter(ParameterSetName = "Line", Position = 0)]
        [Parameter(ParameterSetName = "Message", Position = 0)]
        [String]$Message,
        
        [Parameter(ParameterSetName = "Title")]
        [Switch]$Title,
        
        [Parameter(ParameterSetName = "Line")]
        [Switch]$Line,
        
        [Parameter(ParameterSetName = "Line")]
        [Int]$Length = 30,
        
        [Parameter(ParameterSetName = "Title")]
        [Parameter(ParameterSetName = "Line")]
        [Parameter(ParameterSetName = "Message")]
        [Switch]$NoConsoleOutput = $Script:NoConsoleOutput,
        
        [Parameter(ParameterSetName = "Message")]
        [Parameter(ParameterSetName = "Line")]
        [Switch]$NoNewLine,
        
        [Parameter(ParameterSetName = "Title")]
        [Parameter(ParameterSetName = "Line")]
        [Parameter(ParameterSetName = "Message")]
        [System.ConsoleColor]$ForeGroundColor = "White",
        
        [Parameter(ParameterSetName = "Line")]
        [Parameter(ParameterSetName = "Message")]
        [Parameter(ParameterSetName = "Blank")]
        [Switch]$PreBlank,

        [Parameter(ParameterSetName = "Line")]
        [Parameter(ParameterSetName = "Message")]
        [Parameter(ParameterSetName = "Blank")]
        [Switch]$Blank,

        [Parameter(ParameterSetName = "Title")]
        [Parameter(ParameterSetName = "Line")]
        [Parameter(ParameterSetName = "Message")]
        [Switch]$PostBlank
    )
    if ($NoConsoleOutput -eq $false) {
        if ($PreBlank) {
            Write-Host ""
        }
        if ($Blank) {
            Write-Host ""
        } elseif ($Title) {
            Write-Host ""
            Write-Host -ForegroundColor $ForeGroundColor "$Message"
        } elseif ($Line) {
            $NoNewLine = $true
            if ($Message.Length -ge $($Length - 5)) {
                $Message = $Message.substring(0, $($Length - 5))
            }
            Write-Host -ForegroundColor $ForeGroundColor -NoNewline:$NoNewLine " -$($Message.PadRight($($Length -4), ".")): "
        } elseif ([String]::IsNullOrEmpty($Message)) {
            Write-Host -ForegroundColor $ForeGroundColor -NoNewline:$NoNewLine "<none>"
        } elseif (-Not [String]::IsNullOrEmpty($Message)) {
            Write-Host -ForegroundColor $ForeGroundColor -NoNewline:$NoNewLine "$Message"
        }
        if ($PostBlank) {
            Write-Host ""
        } 
    }
}

function Get-ExceptionDetails {
    [CmdletBinding(DefaultParameterSetName = "Default")]
    param(
        [Parameter(ParameterSetName = "Default", Position = 0, Mandatory)]
        [Parameter(ParameterSetName = "Full", Position = 0, Mandatory)]
        [Parameter(ParameterSetName = "Summary", Position = 0, Mandatory)]
        [Object]$Exception,

        [Parameter(ParameterSetName = "Full")]
        [Switch]$Full,

        [Parameter(ParameterSetName = "Summary")]
        [Switch]$Summary
    )
    $ErrorLines = [System.Text.StringBuilder]::new()
    if ($Summary) {
        try { [void]$ErrorLines.AppendLine($($Exception | Format-List * -Force | Out-String).Trim()) } catch { }
    } else {
        [void]$ErrorLines.AppendLine("======================: Exception")
        try { [void]$ErrorLines.AppendLine($($Exception | Format-List * -Force | Out-String).Trim()) } catch { }
        [void]$ErrorLines.AppendLine($("======================: InvocationInfo"))
        try { [void]$ErrorLines.AppendLine($($Exception.InvocationInfo | Format-List * -Force | Out-String).Trim()) } catch { }
        if ($Full) {
            try { 
                for ($i = 0; $Exception; $i++, ($Exception = $Exception.InnerException)) {
                    [void]$ErrorLines.AppendLine($("======================: InnerException - $i"))
                    [void]$ErrorLines.AppendLine($($Exception | Format-List * -Force | Out-String ).Trim())
                }
            } catch { }
        }
        [void]$ErrorLines.AppendLine("=======================")
    }
    return $ErrorLines.ToString()
}

#endregion Functions

#region Help

if ($Help -Or ($PSBoundParameters.Count -eq 0)) {
    Get-Help $MyInvocation.InvocationName -Detailed
    
}
#endregion Help

#region ScriptBasics

if ((($PSCmdlet.ParameterSetName -eq 'LECertificatesDNS') -or ($PSCmdlet.ParameterSetName -eq 'LECertificatesHTTP') -or ($PSCmdlet.ParameterSetName -eq 'CommandPolicy')) -and (-Not $UseLbVip.ToBool()) -and [String]::IsNullOrEmpty($CsVipName)) {
    Throw "The `"-CsVipName`" parameter may not be empty! Only when specifying the `"-UseLbVip`" parameter."
}

$PreLogLines = @()

if ($MyInvocation.Line -like "*-CleanNS*" ) { 
    Write-Warning "Parameter `"-CleanNS`" is deprecated, please use `"-CleanADC`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-CleanNS`" is deprecated, please use `"-CleanADC`" instead." 
}
if ($MyInvocation.Line -like "*-NSManagementURL*" ) { 
    Write-Warning "Parameter `"-NSManagementURL`" is deprecated, please use `"-ManagementURL`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-NSManagementURL`" is deprecated, please use `"-ManagementURL`" instead." 
}
if ($MyInvocation.Line -like "*-NSUsername*" ) { 
    Write-Warning "Parameter `"-NSUsername`" is deprecated, please use `"-Username`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-NSUsername`" is deprecated, please use `"-Username`" instead." 
}
if ($MyInvocation.Line -like "*-NSPassword*" ) { 
    Write-Warning "Parameter `"-NSPassword`" is deprecated, please use `"-Password`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-NSPassword`" is deprecated, please use `"-Password`" instead." 
}
if ($MyInvocation.Line -like "*-NSCredential*" ) { 
    Write-Warning "Parameter `"-NSCredential`" is deprecated, please use `"-Credential`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-NSCredential`" is deprecated, please use `"-Credential`" instead." 
}
if ($MyInvocation.Line -like "*-NSCertNameToUpdate*" ) { 
    Write-Warning "Parameter `"-NSCertNameToUpdate`" is deprecated, please use `"-CertKeyNameToUpdate`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-NSCertNameToUpdate`" is deprecated, please use `"-CertKeyNameToUpdate`" instead." 
}
if ($MyInvocation.Line -like "*-LogLocation*" ) { 
    Write-Warning "Parameter `"-LogLocation`" is deprecated, please use `"-LogFile`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-LogLocation`" is deprecated, please use `"-LogFile`" instead." 
}
if ($MyInvocation.Line -like "*-SaveNSConfig*" ) { 
    Write-Warning "Parameter `"-SaveNSConfig`" is deprecated, please use `"-SaveADCConfig`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-SaveNSConfig`" is deprecated, please use `"-SaveADCConfig`" instead." 
}
if ($MyInvocation.Line -like "*-NSCsVipName*" ) { 
    Write-Warning "Parameter `"-NSCsVipName`" is deprecated, please use `"-CsVipName`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-NSCsVipName`" is deprecated, please use `"-CsVipName`" instead." 
}
if ($MyInvocation.Line -like "*-NSCspName*" ) { 
    Write-Warning "Parameter `"-NSCspName`" is deprecated, please use `"-CspName`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-NSCspName`" is deprecated, please use `"-CspName`" instead." 
}
if ($MyInvocation.Line -like "*-NSCsVipBinding*" ) { 
    Write-Warning "Parameter `"-NSCsVipBinding`" is deprecated, please use `"-CsVipBinding`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-NSCsVipBinding`" is deprecated, please use `"-CsVipBinding`" instead." 
}
if ($MyInvocation.Line -like "*-NSSvcName*" ) { 
    Write-Warning "Parameter `"-NSSvcName`" is deprecated, please use `"-SvcName`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-NSSvcName`" is deprecated, please use `"-SvcName`" instead." 
}
if ($MyInvocation.Line -like "*-NSSvcDestination*" ) { 
    Write-Warning "Parameter `"-NSSvcDestination`" is deprecated, please use `"-SvcDestination`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-NSSvcDestination`" is deprecated, please use `"-SvcDestination`" instead." 
}
if ($MyInvocation.Line -like "*-NSLbName*" ) { 
    Write-Warning "Parameter `"-NSLbName`" is deprecated, please use `"-LbName`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-NSLbName`" is deprecated, please use `"-LbName`" instead." 
}
if ($MyInvocation.Line -like "*-NSRspName*" ) { 
    Write-Warning "Parameter `"-NSRspName`" is deprecated, please use `"-RspName`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-NSRspName`" is deprecated, please use `"-RspName`" instead." 
}
if ($MyInvocation.Line -like "*-NSRsaName*" ) { 
    Write-Warning "Parameter `"-NSRsaName`" is deprecated, please use `"-RsaName`" instead." 
    $PreLogLines += "W;PARAMETERS;Parameter `"-NSRsaName`" is deprecated, please use `"-RsaName`" instead." 
}

if ("default" -notin $Partitions) {
    $Partitions += "default"
}

$CertificateActions = $true
$ADCActionsRequired = $true
if ($CleanADC -or $RemoveTestCertificates -or $CreateApiUser -or $CreateUserPermissions -or $help) {
    $CertificateActions = $false
} elseif ($CleanAllExpiredCertsOnDisk) {
    $CertificateActions = $false
    $ADCActionsRequired = $false
    $CertDir = $CertDir.TrimEnd("\")
}

##ToDo - Can be deleted after successful replacement
if ($IPv6 -and $CertificateActions) {
    Write-DisplayText -Title "IPv6"
    Write-DisplayText -Line "IPv6 checks"
    Write-Warning "IPv6 Checks are experimental"
    $PreLogLines += "W;INITIAL;IPv6 Checks are experimental"
    $PublicDnsServerv6 = "2606:4700:4700::1111"
}

$PublicDnsServer = "1.1.1.1"
##End ToDo

if (-Not [String]::IsNullOrEmpty($ManagementURL)) {
    $ManagementURL = $ManagementURL.TrimEnd('/')
}

$SessionRequestObjects = @()
$Script:MailData = @()
$Script:MailLog = @()

if (-Not [String]::IsNullOrEmpty($SAN)) {
    if ($SAN -is [Array]) {
        [String]$SAN = $SAN -Join ","
    } else {
        [String]$SAN = $($SAN.Split(",").Split(" ") -Join ",")
    }
}

$ScriptRoot = $(if ($psISE) { Split-Path -Path $psISE.CurrentFile.FullPath } else { $(if ($global:PSScriptRoot.Length -gt 0) { $global:PSScriptRoot } else { $global:pwd.Path }) })

if ($PSCmdlet.ParameterSetName -eq 'LECertificatesDNS') {
    $ValidationMethod = "dns"
}

if (-Not [String]::IsNullOrEmpty($DNSParams)) { 
    if ($DNSParams -is [Array]) {
        [String]$DNSParams = $DNSParams -Join "`r`n"
        [hashtable]$DNSParams = ConvertFrom-StringData -StringData $DNSParams
    } elseif ($DNSParams -is [String]) {
        [String]$DNSParams = ($DNSParams -Split (";") | ForEach-Object { "$($_.Trim())" }) -Join "`r`n"
        [hashtable]$DNSParams = ConvertFrom-StringData -StringData $DNSParams
    } elseif ($DNSParams -is [hashtable]) {
        if ($DNSParams.count -eq 0) {
            $DNSPlugin = "Manual"
        }
    } else {
        $DNSPlugin = "Manual"
        [hashtable]$DNSParams = @{ }
    }
}

try {
    if ((-Not $AutoRun) -and (-Not $CleanAllExpiredCertsOnDisk)) {
        if (($Password -is [String]) -and ($Password.Length -gt 0)) {
            [SecureString]$Password = ConvertTo-SecureString -String $Password -AsPlainText -Force
        }
        if ((($Password.Length -gt 0) -and ($Username.Length -gt 0))) {
            [PSCredential]$Credential = New-Object System.Management.Automation.PSCredential ($Username, $Password)
        }
        if (([PSCredential]::Empty -eq $Credential) -Or ([String]::IsNullOrEmpty($Credential))) {
            $Credential = Get-Credential -UserName nsroot -Message "Citrix ADC Credentials"
        }
        if (([PSCredential]::Empty -eq $Credential) -Or ([String]::IsNullOrEmpty($Credential))) {
            throw "No valid credential found, -Username & -Password or -Credential not specified!"
        } else {
            $ADCCredentialUsername = $Credential.Username
            $ADCCredentialPassword = $Credential.Password
        }
        if (($PfxPassword -is [String]) -and ($PfxPassword.Length -gt 0)) {
            [SecureString]$PfxPassword = ConvertTo-SecureString -String $PfxPassword -AsPlainText -Force
        }
    }
} catch {
    throw "Could not convert to Secure Values! Exception Message: $($_.Exception.Message)"
}

try {
    Write-DisplayText -Title "Script"
    if ($AutoRun -and (-Not (Test-Path -Path $ConfigFile -ErrorAction SilentlyContinue))) {
        Throw "Config File NOT found! This is required when specifying the AutoRun parameter!"
    }
    
    $Parameters = [PSCustomObject]@{
        settings     = [PSCustomObject]@{ }
        certrequests = @()
    }
    $SaveConfig = $false
    if (-Not [String]::IsNullOrEmpty($ConfigFile)) {
        $ConfigPath = try { Split-Path -Path $ConfigFile -Parent -ErrorAction SilentlyContinue } catch { $null }
        if ([String]::IsNullOrEmpty($ConfigPath) -Or $ConfigPath -eq ".") {
            $ConfigFile = Join-Path -Path $ScriptRoot -ChildPath $(Split-Path -Path $ConfigFile -Leaf -ErrorAction SilentlyContinue ) -ErrorAction SilentlyContinue
        }
        Write-DisplayText -Line "Config File"
        Write-DisplayText -ForeGroundColor Cyan -NoNewLine "$(if ($PSScriptRoot) {$ConfigFile.Replace("$PSScriptRoot\",$null)} else {$ConfigFile})"
        if (Test-Path -Path $ConfigFile) {
            $PreLogLines += "I;CONFIGFILE;Config File `"$ConfigFile`" was found!"
            Write-DisplayText -ForeGroundColor Green " (found)"
            try {
                if ($AutoRun) {
                    Write-DisplayText -Line "Reading Config File"
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    $Parameters = Get-Content -Path $ConfigFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                } else {
                    Write-DisplayText -Line "Creating Config"
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                }
                try { if (-Not $Parameters.GetType().Name -eq "PSCustomObject") { $Parameters = New-Object -TypeName PSCustomObject } } catch { $Parameters = New-Object -TypeName PSCustomObject }
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                if ([String]::IsNullOrEmpty($($Parameters | Get-Member -Name "settings" -ErrorAction SilentlyContinue))) { $Parameters | Add-Member -MemberType NoteProperty -Name "settings" -Value $(New-Object -TypeName PSCustomObject) }
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                if ([String]::IsNullOrEmpty($($Parameters | Get-Member -Name "certrequests" -ErrorAction SilentlyContinue))) { $Parameters | Add-Member -MemberType NoteProperty -Name "certrequests" -Value @() }
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                try { if (-Not ($Parameters.settings.GetType().Name -eq "PSCustomObject")) { $Parameters.settings = $(New-Object -TypeName PSCustomObject) } } Catch { $Parameters.settings = $(New-Object -TypeName PSCustomObject) }
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                if (-Not ($Parameters.certrequests -is [Array])) { $Parameters.certrequests = @() }
                try { $Parameters.ScriptVersion = $ScriptVersion } catch {}
            } catch {
                Write-DisplayText -ForeGroundColor Red "Error, Maybe the JSON file is invalid.`r`n$($_.Exception.Message)"
            }
            Write-DisplayText -ForeGroundColor Green " Done"
        } else {
            Write-DisplayText -Blank
            Write-DisplayText -Line "Status"
            Write-DisplayText -ForeGroundColor Cyan "Not Found, creating new ConfigFile"
            $PreLogLines += "I;CONFIGFILE;`"$ConfigFile`" not Found, creating new ConfigFile"
            if ($AutoRun) {
                Write-DisplayText -ForeGroundColor Red "No valid certificate requests found! This is required when specifying the AutoRun parameter!"
                Throw "No valid certificate requests found! This is required when specifying the AutoRun parameter!"
            }
        }
        if ($Parameters.certrequests.Count -le 0) {
            $Parameters.certrequests += New-Object -TypeName PSCustomobject
            if ($AutoRun) {
                Write-DisplayText -ForeGroundColor Red "No valid certificate requests found! This is required when specifying the AutoRun parameter!"
                Throw "No valid certificate requests found! This is required when specifying the AutoRun parameter!"
            }
        }
    } elseif ($ADCActionsRequired -eq $false) {
        Write-DisplayText -ForeGroundColor Yellow "Skipped"
    } elseif ($AutoRun) {
        Write-DisplayText -ForeGroundColor Red "Not Found! This is required when specifying the AutoRun parameter!"
        Throw "Config File NOT found! This is required when specifying the AutoRun parameter!`r`n$($_.Exception.Message)"
    } elseif ($CertificateActions) {
        if ($Parameters.certrequests.Count -le 0) {
            $Parameters.certrequests += New-Object -TypeName PSCustomobject
        }
    }
} catch {
    Write-DisplayText -ForeGroundColor Yellow "Could not load the Config File`r`n$($_.Exception.Message)"
    if ($AutoRun) {
        Throw "Could not load the Config File!`r`n$($_.Exception.Message)"
    }
}

if (-Not ($CreateUserPermissions) -and ($CsVipName -is [Array])) {
    [String]$CsVipName = $CsVipName[0]
}

Write-DisplayText -Line "Defining parameters"
Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
$PreLogLines += "I;PARAMETERS;Defining parameters"
if ($AutoRun) {
    $PreLogLines += "I;PARAMETERS;AutoRun active, defining the SMTPCredential."
    try {
        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
        $ADCCredentialUsername = $Parameters.settings.ADCCredentialUsername
        $ADCCredentialPassword = ConvertFrom-EncryptedPassword -Object $($Parameters.settings.ADCCredentialPassword)
        $Credential = New-Object -TypeName PSCredential -ArgumentList $ADCCredentialUsername, $ADCCredentialPassword
        $PreLogLines += "D;PARAMETERS;ADCCredential ready. Username:$($Credential.UserName)"
        if (-Not $Parameters.settings.ADCCredentialPassword.IsEncrypted) {
            Invoke-AddUpdateParameter -Object $Parameters.settings -Name ADCCredentialPassword -Value $(ConvertTo-EncryptedPassword -Object $ADCCredentialPassword)
            $SaveConfig = $true
        }
    } catch {
        $PreLogLines += "E;PARAMETERS;Could not read the ADCCredential. ERROR:$($_.Exception.Message)"
        Throw "Could not read ADC credentials. ERROR:$($_.Exception.Message)"
    }
    try {
        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
        $PreLogLines += "I;PARAMETERS;Defining the SMTPCredential."
        $SMTPCredentialUsername = $Parameters.settings.SMTPCredentialUsername
        $SMTPCredentialPassword = ConvertFrom-EncryptedPassword -Object $($Parameters.settings.SMTPCredentialPassword)
        $SMTPCredential = New-Object -TypeName PSCredential -ArgumentList $SMTPCredentialUsername, $SMTPCredentialPassword
        $PreLogLines += "D;PARAMETERS;SMTPCredential ready. Username:$($SMTPCredential.UserName)"
        if (-Not $Parameters.settings.SMTPCredentialPassword.IsEncrypted) {
            Invoke-AddUpdateParameter -Object $Parameters.settings -Name SMTPCredentialPassword -Value $(ConvertTo-EncryptedPassword -Object $SMTPCredentialPassword)
            $SaveConfig = $true
        }

    } catch {
        $PreLogLines += "E;PARAMETERS;Could not read the SMTPCredential, setting EmptyCredential. ERROR:$($_.Exception.Message)"
        $SMTPCredential = [PSCredential]::Empty
    }
    $Global:LogLevel = $Parameters.settings.LogLevel
    Write-DisplayText -ForeGroundColor Green " Done"
} else {
    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
    $PreLogLines += "I;PARAMETERS;AutoRun NOT active, parsing/updating the parameters."
    $SMTPCredentialUsername = $SMTPCredential.Username
    $SMTPCredentialPassword = $SMTPCredential.Password
    if ($SMTPTo -like "*,*") {
        [String[]]$SMTPTo = $SMTPTo.Split(",") | ForEach-Object { $_.Trim() }
    }
    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name ManagementURL -Value $ManagementURL
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name ADCCredentialUsername -Value $ADCCredentialUsername
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name ADCCredentialPassword -Value $ADCCredentialPassword
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name DisableLogging -Value $([bool]::Parse($DisableLogging))
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name LogFile -Value $LogFile
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name LogLevel -Value $LogLevel
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name SaveADCConfig -Value $([bool]::Parse($SaveADCConfig))
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name SendMail -Value $([bool]::Parse($SendMail))
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name SMTPTo -Value $SMTPTo
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name SMTPFrom -Value $SMTPFrom
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name SMTPCredentialUsername -Value $SMTPCredentialUsername
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name SMTPCredentialPassword -Value $SMTPCredentialPassword
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name SMTPServer -Value $SMTPServer
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name SMTPPort -Value $SMTPPort
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name SMTPUseSSL -Value $([bool]::Parse($SMTPUseSSL))
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name LogAsAttachment -Value $([bool]::Parse($LogAsAttachment))
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name SvcName -Value $SvcName
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name SvcDestination -Value $SvcDestination
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name LbName -Value $LbName
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name RspName -Value $RspName
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name RsaName -Value $RsaName
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name CspName -Value $CspName
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name TrafficDomain -Value $TrafficDomain
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name CsVipBinding -Value $CsVipBinding
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name ScriptVersion -Value $ScriptVersion
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name DNSParams -Value $DNSParams
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name DNSPlugin -Value $DNSPlugin
    if (($Parameters.certrequests.Count -eq 1) -and (-Not $AutoRun )) {
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name Enabled -Value $true
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name CN -Value $CN
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name SANs -Value $SAN
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name FriendlyName -Value $FriendlyName
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name CsVipName -Value $CsVipName
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name UseLbVip -Value $([bool]::Parse($UseLbVip))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name CertKeyNameToUpdate -Value $CertKeyNameToUpdate
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name RemovePrevious -Value $([bool]::Parse($RemovePrevious))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name CertDir -Value $CertDir
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name EmailAddress -Value $EmailAddress
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name KeyLength -Value $KeyLength
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name ValidationMethod -Value $ValidationMethod
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name CertExpires -Value $null
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name RenewAfter -Value $null
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name Partitions -Value $Partitions
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name ForceCertRenew -Value $([bool]::Parse($ForceCertRenew))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name DisableIPCheck -Value $([bool]::Parse($DisableIPCheck))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name PfxPassword -Value $PfxPassword
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name UpdateIIS -Value $([bool]::Parse($UpdateIIS))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name IISSiteToUpdate -Value $IISSiteToUpdate
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name PostPoSHScriptFilename -value $PostPoSHScriptFilename
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name PostPoSHScriptExtraParameters -value $PostPoSHScriptExtraParameters
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name CleanExpiredCertsOnDisk -Value $([bool]::Parse($CleanExpiredCertsOnDisk))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name CleanExpiredCertsOnDiskDays -Value $CleanExpiredCertsOnDiskDays
        ##ToDo
        #Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name Production -Value $([bool]::Parse($Production))
    }
    $SaveConfig = $true
    Write-DisplayText -ForeGroundColor Green " Done"
    $PreLogLines += "I;PARAMETERS;Finished."
}

if ($Parameters.settings.DisableLogging) {
    $Script:LoggingEnabled = $false
    $Global:LogLevel = "None"
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name LogLevel -Value $Global:LogLevel
} else {
    $Script:LoggingEnabled = $true
    if ($Parameters.settings.LogFile -like "*<DEFAULT>*") {
        $Parameters.settings.LogFile = Join-Path -Path $ScriptRoot -ChildPath $($MyInvocation.MyCommand -Replace '.ps1', '.txt' )
    }
    Write-Verbose "Log $($Parameters.settings.LogFile)"
    if (((Split-Path -Path $Parameters.settings.LogFile -Parent -ErrorAction SilentlyContinue) -eq ".") -or ([String]::IsNullOrEmpty($(Split-Path -Path $Parameters.settings.LogFile -Parent -ErrorAction SilentlyContinue)))) {
        $Parameters.settings.LogFile = Join-Path -Path $ScriptRoot -ChildPath $(Split-Path -Path $Parameters.settings.LogFile -Leaf )
        Write-Verbose "Log: $($Parameters.settings.LogFile)"
    }
    $Global:LogLevel = $Parameters.settings.LogLevel
    $Script:LogLevel = $Parameters.settings.LogLevel
    $Global:LogFile = $Parameters.settings.LogFile
    $Script:LogFile = $Parameters.settings.LogFile
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name LogFile -Value $LogFile
    
    $ExtraHeaderInfo = @"
ScriptBase: $ScriptRoot
Script Version: $ScriptVersion
PoSH ACME Version: $PoshACMEVersion
PSBoundParameters:
$($PSBoundParameters | Out-String)
"@
    Write-ToLogFile -I -C ScriptBasics -M "Starting a new log" -NewLog -ExtraHeaderInfo $ExtraHeaderInfo
    Write-DisplayText -Line "Log File"
    Write-DisplayText -ForeGroundColor Cyan "$(if ($PSScriptRoot) {$Parameters.settings.LogFile.Replace("$PSScriptRoot\",$null)} else {$Parameters.settings.LogFile})"
    Write-DisplayText -Line "Log Level"
    if ($Parameters.settings.LogLevel -eq "Debug") {
        Write-DisplayText -ForeGroundColor Yellow "$($Parameters.settings.LogLevel) - WARNING: Passwords may be visible in the log!"
    } else {
        Write-DisplayText -ForeGroundColor Cyan "$($Parameters.settings.LogLevel)"
    }
}

try {
    Write-ToLogFile -I -C LOG-CATCH-UP -M "Filling log with previously gathered log entries"
    Foreach ($line in $PreLogLines) {
        $lLevel, $lComponent, $lMessage = $line -split ';'
        $lExpression = 'Write-ToLogFile -{0} -C {1} -M "{2}"' -f $lLevel, $lComponent, $(($lMessage -Join ';').Replace('"', '`"'))
        Invoke-Expression $lExpression
    }
    Write-ToLogFile -I -C LOG-CATCH-UP -M "Finished catching-up"
} catch {
    Write-ToLogFile -E -C LOG-CATCH-UP -M "Caught an error! ERROR: $($_.Exception.Message)"
}

#endregion Logging

#region CleanPoshACMEStorage

$ACMEStorage = Join-Path -Path $($env:LOCALAPPDATA) -ChildPath "Posh-ACME"
if ($CleanPoshACMEStorage) {
    Write-ToLogFile -I -C CleanPoshACMEStorage -M "Parameter CleanPoshACMEStorage was specified, removing `"$ACMEStorage`"."
    Remove-Item -Path $ACMEStorage -Recurse -Force -ErrorAction SilentlyContinue
}

#endregion CleanPoshACMEStorage

#region LoadModule

if ($CertificateActions) {
    Write-ToLogFile -I -C DOTNETCheck -M "Checking if .NET Framework 4.7.2 or higher is installed."
    $NetRelease = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release).Release
    if ($NetRelease -lt 461808) {
        Write-ToLogFile -W -C DOTNETCheck -M ".NET Framework 4.7.2 or higher is NOT installed."
        Write-DisplayText -NoNewLine -ForeGroundColor RED "`n`nWARNING: "
        Write-DisplayText ".NET Framework 4.7.2 or higher is not installed, please install before continuing!"
        Start-Process https://www.microsoft.com/net/download/dotnet-framework-runtime
        TerminateScript 1 ".NET Framework 4.7.2 or higher is not installed, please install before continuing!"
    } else {
        Write-ToLogFile -I -C DOTNETCheck -M ".NET Framework 4.7.2 or higher is installed."
    }
    Write-DisplayText -Line "Loading Modules"
    Write-ToLogFile -I -C LoadModule -M "Try loading the Posh-ACME v$PoshACMEVersion Modules."
    $modules = Get-Module -ListAvailable -Verbose:$false | Where-Object { ($_.Name -like "*Posh-ACME*") -and ($_.Version -ge [System.Version]$PoshACMEVersion) }
    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
    if ([String]::IsNullOrEmpty($modules)) {
        Write-ToLogFile -D -C LoadModule -M "Checking for PackageManagement."
        if ([String]::IsNullOrWhiteSpace($(Get-Module -ListAvailable -Verbose:$false | Where-Object { $_.Name -eq "PackageManagement" }))) {
            Write-DisplayText -ForegroundColor Red " Failed"
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
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                }
                $installationPolicy = (Get-PSRepository -Name PSGallery).InstallationPolicy
                if (-not ($installationPolicy.ToLower() -eq "trusted")) {
                    Write-ToLogFile -D -C LoadModule -M "Defining PSGallery PSRepository as trusted."
                    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                }
                Write-ToLogFile -I -C LoadModule -M "Installing Posh-ACME v$PoshACMEVersion"
                try {
                    Install-Module -Name Posh-ACME -Scope AllUsers -RequiredVersion $PoshACMEVersion -Force -AllowClobber
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                } catch {
                    Write-ToLogFile -D -C LoadModule -M "Installing Posh-ACME again but without the -AllowClobber option."
                    Install-Module -Name Posh-ACME -Scope AllUsers -RequiredVersion $PoshACMEVersion -Force
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                }
                if (-not ((Get-PSRepository -Name PSGallery).InstallationPolicy -eq $installationPolicy)) {
                    Write-ToLogFile -D -C LoadModule -M "Returning the PSGallery PSRepository InstallationPolicy to previous value."
                    Set-PSRepository -Name "PSGallery" -InstallationPolicy $installationPolicy | Out-Null
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                }
                Write-ToLogFile -D -C LoadModule -M "Try loading module Posh-ACME."
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                Import-Module Posh-ACME -ErrorAction Stop
                Write-DisplayText -ForeGroundColor Green " OK"
            } catch {
                Write-DisplayText -ForeGroundColor Red " Failed"
                Write-ToLogFile -E -C LoadModule -M "Error while loading and/or installing module. Exception Message: $($_.Exception.Message)"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                Write-Error "Error while loading and/or installing module"
                Write-Warning "PackageManagement is not available please install this first or manually install Posh-ACME"
                Write-Warning "Visit `"https://docs.microsoft.com/en-us/powershell/gallery/psget/get_psget_module`" to download Package Management"
                Write-Warning "Posh-ACME: https://www.powershellgallery.com/packages/Posh-ACME/$PoshACMEVersion"
                Start-Process "https://www.powershellgallery.com/packages/Posh-ACME/$PoshACMEVersion"
                Write-ToLogFile -W -C LoadModule -M "PackageManagement is not available please install this first or manually install Posh-ACME."
                Write-ToLogFile -W -C LoadModule -M "Visit `"https://docs.microsoft.com/en-us/powershell/gallery/psget/get_psget_module`" to download Package Management."
                Write-ToLogFile -W -C LoadModule -M "Posh-ACME: https://www.powershellgallery.com/packages/Posh-ACME/$PoshACMEVersion"
                TerminateScript 1 "PackageManagement is not available please install this first or manually install Posh-ACME."
            }
        }
    } else {
        Write-ToLogFile -I -C LoadModule -M "v$PoshACMEVersion of Posh-ACME is installed, loading module."
        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
        try {
            Import-Module Posh-ACME -ErrorAction Stop
            Write-DisplayText -ForeGroundColor Green " OK"
        } catch {
            Write-DisplayText -ForeGroundColor Red " Failed"
            Write-ToLogFile -E -C LoadModule -M "Importing module Posh-ACME failed."
            Write-Error "Importing module Posh-ACME failed"
            TerminateScript 1 "Importing module Posh-ACME failed"
        }
    }
    Write-DisplayText -Line "Posh-ACME Version"
    Write-DisplayText -ForeGroundColor Cyan "v$PoshACMEVersion"
    Write-ToLogFile -I -C LoadModule -M "Posh-ACME loaded successfully."
}

#endregion LoadModule

#region VersionInfo

Write-DisplayText -Line "Script Version"
Write-DisplayText -ForeGroundColor Cyan "v$ScriptVersion"
Write-ToLogFile -I -C VersionInfo -M "Current script version: v$ScriptVersion, checking if a new version is available."
$Script:MailLog += "Script version: v$ScriptVersion"
$Script:MailLog += "PoshACME version: v$PoshACMEVersion"
try {
    $AvailableVersions = Invoke-CheckScriptVersions -URI $VersionURI
    if ([version]$AvailableVersions.master -gt [version]$ScriptVersion) {
        Write-DisplayText -Line "New Production Note"
        Write-DisplayText -ForeGroundColor Cyan "$($AvailableVersions.masternote)"
        Write-ToLogFile -I -C VersionInfo -M "Note: $($AvailableVersions.masternote)"
        Write-DisplayText -Line "New Production Version"
        Write-DisplayText -ForeGroundColor Cyan "v$($AvailableVersions.master)"
        Write-ToLogFile -I -C VersionInfo -M "Version: v$($AvailableVersions.master)"
        Write-DisplayText -Line "New Production URL"
        Write-DisplayText -ForeGroundColor Cyan "$($AvailableVersions.masterurl)"
        Write-ToLogFile -I -C VersionInfo -M "URL: $($AvailableVersions.masterurl)"
        $Script:MailLog += "New version available: v$($AvailableVersions.master), $($AvailableVersions.masterurl)"
        if (-Not [String]::IsNullOrEmpty($($AvailableVersions.masterimportant))) {
            Write-DisplayText -Blank
            Write-DisplayText -Line "IMPORTANT Note"
            Write-DisplayText -ForeGroundColor Yellow "$($AvailableVersions.masterimportant)"
            Write-ToLogFile -I -C VersionInfo -M "IMPORTANT Note: $($AvailableVersions.masterimportant)"
            $Script:MailLog += "IMPORTANT Note: $($AvailableVersions.masterimportant)"
        }
        $Script:MailLog += "$($AvailableVersions.masternote)`r`nVersion: v$($AvailableVersions.master)`r`nURL:$($AvailableVersions.masterurl)"
    } else {
        Write-ToLogFile -I -C VersionInfo -M "No new Master version available"
    }
    if ([version]$AvailableVersions.dev -gt [version]$ScriptVersion) {
        Write-DisplayText -Line "New Develop Note"
        Write-DisplayText -ForeGroundColor Cyan "$($AvailableVersions.devnote)"
        Write-ToLogFile -I -C VersionInfo -M "Note: $($AvailableVersions.devnote)"
        Write-DisplayText -Line "New Develop Version"
        Write-DisplayText -ForeGroundColor Cyan "v$($AvailableVersions.dev)"
        Write-ToLogFile -I -C VersionInfo -M "Version: v$($AvailableVersions.dev)"
        Write-DisplayText -Line "New Develop URL"
        Write-DisplayText -ForeGroundColor Cyan "$($AvailableVersions.devurl)"
        Write-ToLogFile -I -C VersionInfo -M "URL: $($AvailableVersions.devurl)"
        if (-Not [String]::IsNullOrEmpty($($AvailableVersions.devimportant))) {
            Write-DisplayText -Blank
            Write-DisplayText -Line "IMPORTANT Note"
            Write-DisplayText -ForeGroundColor Yellow "$($AvailableVersions.devimportant)"
            Write-ToLogFile -I -C VersionInfo -M "IMPORTANT Note: $($AvailableVersions.devimportant)"
        }
    } else {
        Write-ToLogFile -I -C VersionInfo -M "No new Development version available"
    }
} catch {
    Write-ToLogFile -E -C VersionInfo -M "Caught an error while retrieving version info. Exception Message: $($_.Exception.Message)"
    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
}
Write-ToLogFile -I -C VersionInfo -M "Version check finished."
#endregion VersionInfo

#region ADC-Check
if ($ADCActionsRequired) {
    Write-ToLogFile -I -C ADC-Check -M "Trying to login into the Citrix ADC."
    Write-DisplayText -Title "Citrix ADC Connection"
    Write-DisplayText -Line "Connecting"
    try {
        $ADCSession = Connect-ADC -ManagementURL $Parameters.settings.ManagementURL -Credential $Credential -PassThru
        Write-DisplayText -ForegroundColor Green "Connected"
    } catch {
        Write-DisplayText -ForegroundColor Red "NOT Connected!"
        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
        TerminateScript 1 "Could not connect, $($_.Exception.Message)"
    }
    Write-DisplayText -Line "URL"
    Write-DisplayText -ForeGroundColor Cyan "$($Parameters.settings.ManagementURL)"
    Write-DisplayText -Line "Username"
    Write-DisplayText -ForeGroundColor Cyan "$($ADCSession.Username)"
    Write-DisplayText -Line "Password"
    Write-DisplayText -ForeGroundColor Cyan "**ENCRYPTED**"
    try {
        $hanode = (Invoke-ADCGetHanode -ADCSession $ADCSession).hanode | Select-Object -First 1
        Write-DisplayText -Line "Node"
        if ($hanode.state -like "primary") {
            Write-DisplayText -ForeGroundColor Cyan $hanode.state
            Write-ToLogFile -I -C ADC-Check -M "You are connected to the $($hanode.state) node."
        } else {
            Write-DisplayText -ForeGroundColor Yellow $hanode.state
            Write-DisplayText -Blank
            Write-Warning "You are connected to the $($hanode.state) node, http certificate request will fail!"
            Write-ToLogFile -W -C ADC-Check -M "You are connected to the $($hanode.state) node, http certificate request will fail!"
            Write-DisplayText -Blank
            Start-Sleep -Seconds 5
        }
    } catch {
        Write-ToLogFile -E -C ADC-Check -M "Caught an error while retrieving the HA NOde info, $($_.Exception.message)"
        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
    }
    Write-DisplayText -Line "Version"
    Write-DisplayText -ForeGroundColor Cyan "$($ADCSession.Version)"
    try {
        $ADCVersion = [double]$($ADCSession.version.split(" ")[1].Replace("NS", "").Replace(":", ""))
        if ($ADCVersion -lt 11) {
            Write-DisplayText -ForeGroundColor RED -NoNewLine "ERROR: "
            Write-DisplayText -ForeGroundColor White "Only ADC version 11 and up is supported, please use an older version (v1-api) of this script!"
            Write-ToLogFile -E -C ADC-Check -M "Only ADC version 11 and up is supported, please use an older version (v1-api) of this script!"
            Start-Process "https://github.com/j81blog/GenLeCertForNS/tree/master-v1-api"
            TerminateScript 1 "Only ADC version 11 and up is supported, please use an older version (v1-api) of this script!"
        }
    } catch {
        Write-ToLogFile -E -C ADC-Check -M "Caught an error while retrieving the version! Exception Message: $($_.Exception.Message)"
        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
    }

    if ($CreateUserPermissions -and ([String]::IsNullOrEmpty($($CsVipName)) -or ($CsVipName.Count -eq 0)) ) {
        Write-DisplayText -Line "Content Switch"
        Write-DisplayText -ForeGroundColor Red "NOT Found! This is required for Command Policy creation!"
        TerminateScript 1 "No Content Switch VIP name defined, this is required for Command Policy creation!"
    }
}
#endregion ADC-Check

#region ApiUserPermissions

if ($CreateUserPermissions -Or $CreateApiUser) {
    Write-DisplayText -Blank
    if ($CsVipName -like "*,*") {
        $CsVipName = $CsVipName.Split(",")
    }
    $CSVipString = ""
    Write-Warning "When you want to use own names instead of the default values for VIPs, Policies, Actions, etc."
    Write-Warning "Please run the script with the optional parameters. These names will be defined in the Command Policy."
    Write-Warning "Only those configured are allowed to be used by the members of the Command Policy `"$NSCPName`"!"
    Write-Warning "You can rerun this script with the changed parameters at any time to update an existing Command Policy"
    Write-ToLogFile -I -C ApiUserPermissions -M "CreateUserPermissions parameter specified, create or update Command Policy `"$($NSCPName)`""
    Write-DisplayText -Title "Api User Permissions Group (Command Policy)"
    Write-DisplayText -Line "Command Policy Name"
    Write-DisplayText -ForeGroundColor Cyan "$NSCPName "
    Write-DisplayText -Line "CS VIP Name"
    if (-Not $UseLbVip -or [String]::IsNullOrEmpty($CsVipName)) {
        ForEach ($VipName in $CsVipName) {
            $CSVipString += "|(^(set|show|bind|unbind)\s+cs\s+vserver\s+$($VipName).*)"
        }
        Write-DisplayText -ForeGroundColor Cyan $($CsVipName -Join ", ")
    } else {
        Write-DisplayText -ForeGroundColor Cyan "none"
    }
    Write-DisplayText -Line "LB VIP Name"
    Write-DisplayText -ForeGroundColor Cyan $($Parameters.settings.LbName)
    Write-DisplayText -Line "Service Name"
    Write-DisplayText -ForeGroundColor Cyan $($Parameters.settings.SvcName)
    Write-DisplayText -Line "Traffic Domain"
    Write-DisplayText -ForeGroundColor Cyan $($Parameters.settings.TrafficDomain)
    Write-DisplayText -Line "Responder Action Name"
    Write-DisplayText -ForeGroundColor Cyan $($Parameters.settings.RsaName)
    Write-DisplayText -Line "Responder Policy Name"
    Write-DisplayText -ForeGroundColor Cyan $($Parameters.settings.RspName)
    Write-DisplayText -Line "CS Policy Name"
    Write-DisplayText -ForeGroundColor Cyan $($Parameters.settings.CspName)
    Write-DisplayText -Line "Action"

    $CmdSpec = "(^show\s+ns\s+license)|(^show\s+ns\s+license\s+.*)|(^(create|show)\s+system\s+backup)|(^(create|show)\s+system\s+backup\s+.*)|(^convert\s+ssl\s+pkcs12)|(^show\s+ns\s+feature)|(^show\s+ns\s+feature\s+.*)|(^show\s+responder\s+action)|(^show\s+responder\s+policy)|(^(add|rm)\s+system\s+file.*-fileLocation.*nsconfig.*ssl.*)|(^show\s+ssl\s+certKey)|(^(add|link|unlink|update)\s+ssl\s+certKey\s+.*)|(^show\s+HA\s+node)|(^show\s+HA\s+node\s+.*)|(^(save|show)\s+ns\s+config)|(^(save|show)\s+ns\s+config\s+.*)|(^show\s+ns\s+trafficDomain)|(^show\s+ns\s+trafficDomain\s+.*)|(^show\s+ns\s+version)$CSVipString|(^\S+\s+Service\s+$($Parameters.settings.SvcName).*)|(^\S+\s+lb\s+vserver\s+$($Parameters.settings.LbName).*)|(^\S+\s+responder\s+action\s+$($Parameters.settings.RsaName).*)|(^\S+\s+responder\s+policy\s+$($Parameters.settings.RspName).*)|(^\S+\s+cs\s+policy\s+$($Parameters.settings.CspName).*)"
    #ToDo Partition "|(^(show|switch)\s+ns\s+partition)|(^(show|switch)\s+ns\s+partition\s+.*)"
    #$otherPartitions = @( $Parameters.settings.Partitions | Where-Object { $_ -ne "default"} )
    #if ($otherPartitions.Count -gt 0 ) {
    #    
    #}
    
    try {
        $Filters = @{ policyname = "$NSCPName" }
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type systemcmdpolicy -Filters $Filters
        if ($response.systemcmdpolicy.count -eq 1) {
            Write-ToLogFile -I -C ApiUserPermissions -M "Existing found, updating Command Policy"
            Write-DisplayText -NoNewLine -ForeGroundColor Yellow "Existing found, "
            $payload = @{ policyname = $NSCPName; action = "Allow"; cmdspec = $CmdSpec }
            Write-ToLogFile -D -C ApiUserPermissions -M "Putting: $($payload | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type systemcmdpolicy -Payload $payload
            Write-DisplayText -ForeGroundColor Green "Changed"
            
        } elseif ($response.systemcmdpolicy.count -gt 1) {
            Write-DisplayText -ForeGroundColor Red "ERROR: Multiple Command Policies found!"
            Write-ToLogFile -I -C ApiUserPermissions -M "Multiple Command Policies found."
            $response.systemcmdpolicy | ForEach-Object {
                Write-ToLogFile -D -C ApiUserPermissions -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
            }
        } else {
            Write-ToLogFile -I -C ApiUserPermissions -M "None found, creating new Command Policy"
            $payload = @{ policyname = $NSCPName; action = "Allow"; cmdspec = $CmdSpec }
            Write-ToLogFile -D -C ApiUserPermissions -M "Posting: $($payload | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type systemcmdpolicy -Payload $payload
            Write-DisplayText -ForeGroundColor Green "Created"
        }
    } catch {
        Write-DisplayText -ForeGroundColor Red "Error"
        Write-ToLogFile -E -C ApiUserPermissions -M "Caught an error! Exception Message: $($_.Exception.Message)"
        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
    }
}

#endregion ApiUserPermissions

#region ApiUser

if ($CreateApiUser) {
    $CertificateActions = $false
    Write-ToLogFile -I -C ApiUser -M "CreateApiUser parameter specified, create or update user `"$ApiUsername`""
    Write-DisplayText -Title "Api (System) User"
    Write-DisplayText -Line "Api User Name"
    Write-DisplayText -ForeGroundColor Cyan "$ApiUsername "
    Write-DisplayText -Line "Action"
    if (($ApiPassword -is [String]) -and ($ApiPassword.Length -gt 0)) {
        [SecureString]$ApiPassword = ConvertTo-SecureString -String $ApiPassword -AsPlainText -Force
        Write-ToLogFile -D -C ApiUser -M "Secure password created"
    }
    if ((($ApiPassword.Length -gt 0) -and ($ApiUsername.Length -gt 0))) {
        $ApiCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $ApiUsername, $ApiPassword
        Write-ToLogFile -D -C ApiUser -M "Credential created"
    }
    if (([PSCredential]::Empty -eq $ApiCredential) -Or ($null -eq $ApiCredential)) {
        Write-DisplayText -ForeGroundColor Red "No valid credentials found!"
        Write-ToLogFile -E -C ApiUser -M "No valid Api Credential found, -ApiUsername or -ApiPassword not specified!"
        TerminateScript 1 "No valid Api Credential found, -ApiUsername or -ApiPassword not specified!"
    }
    Write-ToLogFile -D -C ApiUser -M "Basics ready, continuing"
    try {
        $Filters = @{ username = "$ApiUsername" }
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type systemuser -Filters $Filters
        if ($response.systemuser.count -eq 1) {
            Write-ToLogFile -I -C ApiUser -M "Existing found, updating User"
            Write-DisplayText -NoNewLine -ForeGroundColor Cyan "Updating Existing "
            try {
                Write-ToLogFile -D -C ApiUser -M "Trying the preferred (API) method"
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                $payload = @{ username = $ApiUsername; password = $($ApiCredential.GetNetworkCredential().password); externalauth = "Disabled"; allowedmanagementinterface = @("API") }
                Write-ToLogFile -D -C ApiUser -M "Putting: $($payload | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type systemuser -Payload $payload
                Write-ToLogFile -D -C ApiUser -M "Succeeded"
            } catch {
                Write-ToLogFile -D -C ApiUser -M "Failed, trying the method without API"
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                $payload = @{ username = $ApiUsername; password = $($ApiCredential.GetNetworkCredential().password); externalauth = "Disabled" }
                Write-ToLogFile -D -C ApiUser -M "Putting: $($payload | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type systemuser -Payload $payload
                Write-ToLogFile -D -C ApiUser -M "Succeeded"
            }
            Write-DisplayText -ForeGroundColor Green " Changed"
        } elseif ($response.systemuser.count -gt 1) {
            Write-DisplayText -ForeGroundColor Red "ERROR: Multiple users found!"
            Write-ToLogFile -I -C ApiUser -M "Multiple Command Policies found."
            $response.systemuser | ForEach-Object {
                Write-ToLogFile -D -C ApiUser -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
            }
        } else {
            Write-ToLogFile -I -C ApiUser -M "None found, creating new Users"
            try {
                Write-ToLogFile -D -C ApiUser -M "Trying to create the user"
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                $payload = @{ username = $ApiUsername; password = $($ApiCredential.GetNetworkCredential().password); externalauth = "Disabled" }
                Write-ToLogFile -D -C ApiUser -M "Posting: $($payload | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type systemuser -Payload $payload
                try {
                    Write-ToLogFile -D -C ApiUser -M "Trying to set the preferred (API) method"
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    $payload = @{ username = $ApiUsername; externalauth = "Disabled"; allowedmanagementinterface = @("API") }
                    Write-ToLogFile -D -C ApiUser -M "Posting: $($payload | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type systemuser -Payload $payload
                } catch {
                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    Write-ToLogFile -D -C ApiUser -M "Could not set API Command Line Interface only (Feature not supported on this version), $($_.Exception.Message)"
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine " API Interface setting not possible."
                }

                Write-ToLogFile -I -C ApiUser -M "API User created successfully."
                Write-DisplayText -ForeGroundColor Green " Created"
            } catch {
                Write-DisplayText -ForeGroundColor Red " Error"
                Write-ToLogFile -E -C ApiUser -M "Caught an error while creating user. $($_.Exception.Message)"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            }

        }
        Write-ToLogFile -I -C ApiUser -M "Bind Command Policy"
        Write-DisplayText -Line "User Policy Binding"
        Write-DisplayText -ForeGroundColor Cyan "$NSCPName "
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type systemuser_systemcmdpolicy_binding -Resource $ApiUsername
        if ($response.systemuser_systemcmdpolicy_binding.policyname.Count -gt 1) {
            Write-ToLogFile -I -C ApiUser -M "Multiple found ($($response.systemuser_systemcmdpolicy_binding.policyname -join ", "))"
            Write-DisplayText -ForeGroundColor Yellow "Multiple found ($($response.systemuser_systemcmdpolicy_binding.policyname -join ", "))"
            $BindingsToRemove = $response.systemuser_systemcmdpolicy_binding.policyname | Where-Object { $_ -ne $NSCPName }
            foreach ($Binding in $BindingsToRemove) {
                Write-ToLogFile -D -C ApiUser -M "Removing `"$Binding`""
                Write-DisplayText -Line "Binding"
                Write-DisplayText -ForeGroundColor Cyan -NoNewLine "[$Binding] "
                try {
                    $Arguments = @{ policyname = $Binding }
                    Write-ToLogFile -D -C ApiUser -M "Deleting: $($Arguments | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type systemuser_systemcmdpolicy_binding -Resource $ApiUsername -Arguments $Arguments -ErrorAction Stop
                    Write-DisplayText -ForeGroundColor Green "Removed"
                } catch {
                    Write-DisplayText -ForeGroundColor Red "Error"
                    Write-ToLogFile -D -C ApiUser -M "Error $($_.Exception.Message)"
                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                }
            }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type systemuser_systemcmdpolicy_binding -Resource $ApiUsername
        }
        Write-DisplayText -Line "User Policy Binding"
        if ($response.systemuser_systemcmdpolicy_binding.policyname | Where-Object { $_ -eq $NSCPName }) {
            Write-DisplayText -ForeGroundColor Cyan "Present"
            Write-ToLogFile -I -C ApiUser -M "A binding is already present"
        } else {
            Write-ToLogFile -I -C ApiUser -M "Creating a new binding"
            $payload = @{ username = $ApiUsername; policyname = $NSCPName; priority = 10 }
            Write-ToLogFile -D -C ApiUser -M "Putting: $($payload | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type systemuser_systemcmdpolicy_binding -Payload $payload
            Write-DisplayText -ForeGroundColor Green "Bound"
        }
    } catch {
        Write-DisplayText -ForeGroundColor Red "Error"
        Write-ToLogFile -E -C ApiUser -M "Caught an error! Exception Message: $($_.Exception.Message)"
        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
    }
}


if (($CreateUserPermissions) -Or ($CreateApiUser)) {
    Save-ADCConfig -SaveADCConfig:$($Parameters.settings.SaveADCConfig)
    TerminateScript 0
}

#endregion ApiUser

#region EmailSetup

if ($Parameters.settings.SendMail) {
    $SMTPError = @()
    Write-DisplayText -Title "Email Details"
    Write-DisplayText -Line "Email To Address"
    if ($Parameters.settings.SMTPTo -like "*,*") {
        [String[]]$Parameters.settings.SMTPTo = $Parameters.settings.SMTPTo.Split(",") | ForEach-Object { $_.Trim() }
    }
    if ([String]::IsNullOrEmpty($($Parameters.settings.SMTPTo)) -or ($Parameters.settings.SMTPTo.Count -eq 0)) {
        Write-DisplayText -ForeGroundColor Red "None"
        Write-ToLogFile -E -C EmailSettings -M "No To Address specified (-SMTPTo)"
        $SMTPError += "No To Address specified (-SMTPTo)"
    } else {
        Write-DisplayText -ForeGroundColor Cyan "$($Parameters.settings.SMTPTo -Join "; ")"
        Write-ToLogFile -I -C EmailSettings -M "Email To Address: $($Parameters.settings.SMTPTo -Join "; "))"
    }
    Write-DisplayText -Line "Email From Address"
    if ([String]::IsNullOrEmpty($($Parameters.settings.SMTPFrom))) {
        Write-DisplayText -ForeGroundColor Red "None"
        Write-ToLogFile -E -C EmailSettings -M "No From Address specified (-SMTPFrom)"
        $SMTPError += "No From Address specified (-SMTPFrom)"
    } else {
        Write-DisplayText -ForeGroundColor Cyan "$($Parameters.settings.SMTPFrom)"
        Write-ToLogFile -I -C EmailSettings -M "Email From Address: $($Parameters.settings.SMTPFrom)"
    }
    Write-DisplayText -Line "Email Server"
    if ([String]::IsNullOrEmpty($($Parameters.settings.SMTPServer))) {
        Write-DisplayText -ForeGroundColor Red "None"
        Write-ToLogFile -E -C EmailSettings -M "No Email (SMTP) Server specified (-SMTPServer)"
        $SMTPError += "No Email (SMTP) Server specified (-SMTPServer)"
    } if (-Not [String]::IsNullOrEmpty($($Parameters.settings.SMTPPort))) {
        Write-DisplayText -ForeGroundColor Cyan "$($Parameters.settings.SMTPServer):$($Parameters.settings.SMTPPort)"
        Write-ToLogFile -I -C EmailSettings -M "Email Server: $($Parameters.settings.SMTPServer):$($Parameters.settings.SMTPPort)"
    } else {
        Write-DisplayText -ForeGroundColor Cyan "$($Parameters.settings.SMTPServer)"
        Write-ToLogFile -I -C EmailSettings -M "Email Server: $($Parameters.settings.SMTPServer)"
    }
    Write-DisplayText -Line "Email Use SSL"
    if ($Parameters.settings.SMTPUseSSL) {
        Write-DisplayText -ForeGroundColor Green $($Parameters.settings.SMTPUseSSL)
        Write-ToLogFile -I -C EmailSettings -M "Use SSL for sending mail"
    } else {
        Write-DisplayText -ForeGroundColor Cyan "False"
    }
    Write-DisplayText -Line "Email Credentials"
    if ($SMTPCredential -eq [PSCredential]::Empty) {
        Write-DisplayText -ForeGroundColor Cyan "(Optional) None"
        Write-ToLogFile -I -C EmailSettings -M "No Email Credential specified, this is optional"
    } else {
        Write-DisplayText -ForeGroundColor Cyan "$($Parameters.settings.SMTPCredentialUserName) (Credential)"
        Write-ToLogFile -I -C EmailSettings -M "Email Credential: $($Parameters.settings.SMTPCredentialUserName)"
    }
    if (-Not [String]::IsNullOrEmpty($SMTPError)) {
        $Parameters.settings.SendMail = $false
        TerminateScript 1 "Incorrect values, check mail settings.`r`n$($SMTPError | Out-String)"
    }
}

#endregion MailSetup

#endregion ScriptBasics

if ($CertificateActions) {
    #region Services
    if ($Production) {
        $BaseService = "LE_PROD"
        $LEText = "Production Certificates"
    } else {
        $BaseService = "LE_STAGE"
        $LEText = "Test Certificates (Staging)"
        $Script:MailLog += "IMPORTANT: This is a test certificate!`r`n"
    }
    Posh-ACME\Set-PAServer $BaseService 6>$null
    $PAServer = Posh-ACME\Get-PAServer -Refresh
    Write-DisplayText -Title "Let's Encrypt Preparation"
    Write-DisplayText -Line "Note"
    Write-DisplayText -ForeGroundColor Yellow "IMPORTANT, By running this script you agree with the terms specified by Let's Encrypt."
    Write-ToLogFile -I -C Services -M "By running this script you agree with the terms specified by Let's Encrypt."
    Write-DisplayText -Line "Terms Of Service"
    Write-DisplayText -ForeGroundColor Yellow "$($PAServer.meta.termsOfService)"
    Write-ToLogFile -I -C Services -M "Terms Of Service: $($PAServer.meta.termsOfService)"
    Write-DisplayText -Line "Website"
    Write-DisplayText -ForeGroundColor Yellow "$($PAServer.meta.website)"
    Write-ToLogFile -I -C Services -M "Website: $($PAServer.meta.website)"
    Write-DisplayText -Line "LE Certificate Usage"
    Write-DisplayText -ForeGroundColor Cyan $LEText
    Write-ToLogFile -I -C Services -M "LE Certificate Usage: $LEText"
    Write-DisplayText -Line "LE Account Storage"
    Write-DisplayText -ForeGroundColor Cyan $ACMEStorage
    Write-ToLogFile -I -C Services -M "LE Account Storage: $ACMEStorage"

    #endregion Services

    if ($Parameters.certrequests.Count -gt 1) {
        Write-DisplayText -Line "Nr Cert. Requests"
        Write-DisplayText -ForeGroundColor Cyan "$($Parameters.certrequests.Count)"
    }
    
    $round = 0
    $TotalRounds = $Parameters.certrequests.Count
    Write-ToLogFile -I -C CertLoop -M "$TotalRounds required for all requests."
    ForEach ($CertRequest in $Parameters.certrequests) {
        $round++
        $PfxPasswordGenerated = $false
        if ((-Not [String]::IsNullOrEmpty($($CertRequest.CN))) -and (-Not ($CertRequest.ValidationMethod -eq "dns"))) {
            $CertRequest.ValidationMethod = "http"
        }
        if (-Not ($CertRequest | Get-Member -Name "Enabled" -ErrorAction SilentlyContinue -MemberType NoteProperty)) {
            $CertRequest | Add-Member -Name "Enabled" -MemberType NoteProperty -Value $true
            $SaveConfig = $true
        }
        if (-Not ($CertRequest | Get-Member -Name "ForceCertRenew" -ErrorAction SilentlyContinue -MemberType NoteProperty)) {
            $CertRequest | Add-Member -Name "ForceCertRenew" -MemberType NoteProperty -Value $false
            $SaveConfig = $true
        }
        if (-Not ($CertRequest | Get-Member -Name "CurrentCertIsProduction" -ErrorAction SilentlyContinue -MemberType NoteProperty)) {
            $CertRequest | Add-Member -Name "CurrentCertIsProduction" -MemberType NoteProperty -Value $null
            $SaveConfig = $true
        } else {
            if ($CertRequest.CurrentCertIsProduction -eq $true) {
                $currentCertificateType = "Production"
                $newCertificateType = "Staging (Test)"
            } 
            if ($CertRequest.CurrentCertIsProduction -eq $false) {
                $currentCertificateType = "Staging (Test)"
                $newCertificateType = "Production"
            }
        }
        $Script:MailData += [PSCustomObject]@{ID = $round; Code = "FAILED"; Result = ""; CN = ""; Text = ""; SAN = ""; Location = ""; CertKeyName = ""; CertExpiresDays = "NA" }
        $mailDataItem = $Script:MailData | Where-Object ID -EQ $round
        $mailDataItem.CN = $($CertRequest.CN)
        if ($TotalRounds -gt 1) {
            Write-ToLogFile -I -C "CertLoop-$($round.ToString('000'))" -M "**************************************** $($round.ToString('000'))  / $($TotalRounds.ToString('000')) ****************************************" 
            Write-DisplayText -Title " ============================"
            Write-DisplayText -Title "Request $($round.ToString('000')) / $($TotalRounds.ToString('000'))"
        }
        $SkipThisCertRequest = $false
        try {
            $renewAfterDays = 0
            if ($CertRequest.CertExpires -match '[0-9-]{8,10}T[0-9:]{6,8}Z') {
                $renewAfterDays = [Int]([datetime]$CertRequest.RenewAfter - (Get-Date)).TotalDays
            }
        } catch {
            $renewAfterDays = 0
        }
        try {
            $expireDays = 0
            if ($CertRequest.CertExpires -match '[0-9-]{8,10}T[0-9:]{6,8}Z') {
                $expireDays = [Int]([datetime]$CertRequest.CertExpires - (Get-Date)).TotalDays
                $mailDataItem.CertExpiresDays = $expireDays
            }
        } catch {
            $expireDays = 0
        }
        if ($CertRequest.Enabled -eq $false) {
            Write-DisplayText -Title "Current Certificate"
            Write-DisplayText -Line "CN"
            Write-DisplayText -ForeGroundColor Cyan "$($CertRequest.CN)"
            Write-DisplayText -Line "Request"
            Write-DisplayText -ForeGroundColor Yellow "Skipped"
            Write-ToLogFile -I -C CheckCertRenewal -M "$($CertRequest.CN) skipped Enabled:False"
            $mailDataItem.Text = "$($CertRequest.CN) skipped, Enabled:False"
            $mailDataItem.Code = "Skipped"
            $SkipThisCertRequest = $true
        } elseif ($null -ne $CertRequest.CurrentCertIsProduction -and $CertRequest.CurrentCertIsProduction -ne $Production) {
            Write-DisplayText -Title "Current Certificate"
            Write-DisplayText -Line "CN"
            Write-DisplayText -ForeGroundColor Cyan "$($CertRequest.CN)"
            Write-DisplayText -Line "Valid until"
            Write-DisplayText -ForeGroundColor Cyan "$($CertRequest.CertExpires) [$expireDays days]"
            Write-DisplayText -Line "Renew after"
            Write-DisplayText -ForeGroundColor Cyan "$($CertRequest.RenewAfter) [$renewAfterDays days]"
            Write-DisplayText -Line "Status"
            Write-DisplayText -ForeGroundColor Cyan "Still valid, but request is diffrent! Current: `"$currentCertificateType`" New: `"$newCertificateType`". Certificate will be renewed."
            $mailDataItem.Text = "Still valid, but request is diffrent! Current: `"$currentCertificateType`" New: `"$newCertificateType`". Certificate will be renewed."
        } elseif (-Not [String]::IsNullOrEmpty($($CertRequest.RenewAfter)) -and ($CertRequest.ForceCertRenew -eq $false) -and ($ForceCertRenew -eq $false)) {
            try {
                $RenewAfterDate = [DateTime]$CertRequest.RenewAfter
                if ((Get-Date) -lt $RenewAfterDate) {
                    Write-DisplayText -Title "Current Certificate"
                    Write-DisplayText -Line "CN"
                    Write-DisplayText -ForeGroundColor Cyan "$($CertRequest.CN)"
                    Write-DisplayText -Line "Valid until"
                    Write-DisplayText -ForeGroundColor Cyan "$($CertRequest.CertExpires) [$expireDays days]"
                    Write-DisplayText -Line "Renew after"
                    Write-DisplayText -ForeGroundColor Cyan "$($CertRequest.RenewAfter) [$renewAfterDays days]"
                    Write-DisplayText -Line "Status"
                    Write-DisplayText -ForeGroundColor Cyan "Still valid, request will be skipped"
                    Write-ToLogFile -I -C CheckCertRenewal -M "$($CertRequest.CN) is still valid for $expireDays days ($($CertRequest.CertExpires)). Can be replaced after $renewAfterDays days (after $($CertRequest.RenewAfter))"
                    $mailDataItem.Text = "Still valid for $expireDays days ($($CertRequest.CertExpires)).`r`nCan be replaced after $renewAfterDays days (after $($CertRequest.RenewAfter))"
                    $mailDataItem.Code = "Still Valid"
                    $SkipThisCertRequest = $true
                }
            } catch {
                Write-ToLogFile -E -C CheckCertRenewal -M "Caught an error while validating dates, $($_.Exception.Message)"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            }
        }
        if ($SkipThisCertRequest) {
            Write-ToLogFile -D -C CheckCertRenewal -M "Certificate Request was skipped."
        } else {
            Write-ToLogFile -D -C CertReqVariables -M "Setting session DATE/TIME variable."
            [DateTime]$ScriptDateTime = Get-Date
            [String]$SessionDateTime = $ScriptDateTime.ToString("yyyyMMdd-HHmmss")
            $SessionID = "$($SessionDateTime)_$($CertRequest.CN.Replace('.','_').ToLower())"
            Write-ToLogFile -D -C CertReqVariables -M "Session DATE/TIME variable value: `"$SessionDateTime`"."
            Write-ToLogFile -D -C CertReqVariables -M "Session ID value: `"$SessionID`"."
        
            $SessionRequestObjects += [PSCustomObject]@{
                SessionID     = $SessionID
                DateTime      = $ScriptDateTime
                CN            = $CertRequest.CN
                DNSObjects    = @()
                ExitCode      = 0
                ErrorOccurred = 0
                Messages      = @()
            }
            $SessionRequestObject = $SessionRequestObjects | Where-Object { $_.SessionID -eq $SessionID }

            #region DNSPreCheck
            [regex]$fqdnExpression = "^((?!-)[A-Za-z0-9-]{1,63}(?<!-).)+[A-Za-z]{2,63}$"
            if (($($CertRequest.CN) -match "\*") -Or ($CertRequest.SANs -match "\*")) {
                $SaveConfig = $false
                Write-DisplayText -ForeGroundColor Yellow "`r`nNOTE: -CN or -SAN contains a wildcard entry, continuing with the `"dns`" validation method!"
                Write-ToLogFile -I -C DNSPreCheck -M "-CN or -SAN contains a wildcard entry, continuing with the `"dns`" validation method!"
                Write-DisplayText -Line "CN"
                Write-DisplayText -ForeGroundColor Yellow "$($CertRequest.CN)"
                Write-ToLogFile -I -C DNSPreCheck -M "CN: $($CertRequest.CN)"
                Write-DisplayText -Line "SAN(s)"
                Write-DisplayText -ForeGroundColor Yellow "$($CertRequest.SANs)"
                Write-ToLogFile -I -C DNSPreCheck -M "SAN(s): $($CertRequest.SANs | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                $CertRequest.ValidationMethod = "dns"
                $CertRequest.DisableIPCheck = $true
                Write-ToLogFile -I -C DNSPreCheck -M "Continuing with the `"$($CertRequest.ValidationMethod)`" validation method!"
            } elseif ($CertRequest.ValidationMethod -eq "dns") {
                $SaveConfig = $false
                $CertRequest.DisableIPCheck = $true
                Write-ToLogFile -I -C DNSPreCheck -M "Continuing with the `"$($CertRequest.ValidationMethod)`" validation method!"
                Write-DisplayText -Line "CN"
                Write-DisplayText -ForeGroundColor Yellow "$($CertRequest.CN)"
                Write-ToLogFile -I -C DNSPreCheck -M "CN: $($CertRequest.CN)"
                Write-DisplayText -Line "SAN(s)"
                Write-DisplayText -ForeGroundColor Yellow "$($CertRequest.SANs)"
                Write-ToLogFile -I -C DNSPreCheck -M "SAN(s): $($CertRequest.SANs | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
            } else {
                $CertRequest.ValidationMethod = $CertRequest.ValidationMethod.ToLower()
                if (([String]::IsNullOrWhiteSpace($($CertRequest.CsVipName))) -and ($CertRequest.ValidationMethod -eq "http") -and (-Not $CertRequest.UseLbVip)) {
                    Write-DisplayText -ForeGroundColor Red "ERROR: The `"-CsVipName`" cannot be empty!" -PostBlank -PreBlank
                    Write-ToLogFile -E -C DNSPreCheck -M "The `"-CsVipName`" cannot be empty!"
                    Invoke-RegisterError 1 "The `"-CsVipName`" cannot be empty!"
                    Continue
                }
                Write-DisplayText -Title "Certificate Request"
                Write-DisplayText -Line "CN"
                Write-DisplayText -ForeGroundColor Yellow -NoNewline "$($CertRequest.CN)"
                if ($CertRequest.CN -match $fqdnExpression) {
                    Write-DisplayText -ForeGroundColor Green " $([Char]8730)"
                    Write-ToLogFile -I -C DNSPreCheck -M "CN: $($CertRequest.CN) is a valid record"
                } else {
                    Write-DisplayText -ForeGroundColor Red " NOT a valid fqdn!"
                    Invoke-RegisterError 1 "`"$($CertRequest.CN)`" is NOT a valid fqdn!"
                    Continue
                }
                Write-DisplayText -Line "SAN(s)"
                $CheckedSANs = @()
                if (-Not [String]::IsNullOrEmpty($($CertRequest.SANs))) {
                    ForEach ($record in $CertRequest.SANs.Split(",")) {
                        if ($CheckedSANs.Count -eq 0) {
                            Write-DisplayText -ForeGroundColor Yellow -NoNewline "$record"
                        } else {
                            Write-DisplayText -ForeGroundColor Yellow -NoNewline ", $record"
                        }
                        if ($record -match $fqdnExpression) {
                            Write-DisplayText -ForeGroundColor Green -NoNewline " $([Char]8730)"
                            Write-ToLogFile -I -C DNSPreCheck -M "SAN Entry: $record is a valid record"
                            $CheckedSANs += $record
                        } else {
                            Write-DisplayText -ForeGroundColor Red -NoNewline " NOT a valid fqdn!"
                            Write-DisplayText -ForeGroundColor Yellow -NoNewline " SKIPPED"
                            Write-ToLogFile -W -C DNSPreCheck -M "SAN Entry: $record is NOT valid record"
                        }
                    }
                } else {
                    Write-DisplayText -ForeGroundColor Green -NoNewline "none"
                }
                Write-DisplayText -Blank
                $CertRequest.SANs = $CheckedSANs -Join ","
                $mailDataItem.SAN = "$($CheckedSANs -Join ", ")"
            }

            Write-ToLogFile -D -C DNSPreCheck -M "ValidationMethod is set to: `"$($CertRequest.ValidationMethod)`"."
    
            if ($CertRequest.ValidationMethod -eq "dns" -and ($AutoRun)) {
                Write-ToLogFile -E -C DNSPreCheck -M "You cannot use the dns validation method with the -AutoRun parameter!"
                Write-DisplayText -Line "Wildcard"
                Write-DisplayText -ForeGroundColor RED "A wildcard was found while also using the -AutoRun parameter. Only HTTP validation (no Wildcard) is allowed!"
                Break
            }
        
            $ResponderPrio = 10
            $SessionRequestObject.DNSObjects += [PSCustomObject]@{
                DNSName         = [String]$($CertRequest.CN)
                IPAddress       = $null
                DNSType         = $null
                DNSCNAMEDetails = $null
                Status          = $null
                Match           = $null
                SAN             = $false
                Challenge       = $null
                ResponderPrio   = $ResponderPrio
                Done            = $false
            }
            if (-not ([String]::IsNullOrEmpty($($CertRequest.SANs)))) {
                Write-ToLogFile -I -C DNSPreCheck -M "Checking for double SAN values."
                $SANRecords = $CertRequest.SANs.Split(",").Split(" ")
                $SANCount = $SANRecords.Count
                $SANRecords = $SANRecords | Select-Object -Unique
                $CertRequest.SANs = $SANRecords -Join ","

                if (-Not ($SANCount -eq $SANRecords.Count)) {
                    Write-DisplayText -Line "Double Records"
                    Write-DisplayText -ForeGroundColor Yellow "WARNING: There were $($SANCount - $SANRecords.Count) double SAN values, only continuing with unique ones."
                    Write-ToLogFile -W -C DNSPreCheck -M "There were $($SANCount - $SANRecords.Count) double SAN values, only continuing with unique ones."
                } else {
                    Write-ToLogFile -I -C DNSPreCheck -M "No double SAN values found."
                }
                Foreach ($SANEntry in $SANRecords) {
                    $ResponderPrio += 10
                    if (-Not ($SANEntry -eq $($CertRequest.CN))) {
                        $SessionRequestObject.DNSObjects += [PSCustomObject]@{
                            DNSName         = [String]$SANEntry
                            IPAddress       = $null
                            DNSType         = $null
                            DNSCNAMEDetails = $null
                            Status          = $null
                            Match           = $null
                            SAN             = $true
                            Challenge       = $null
                            ResponderPrio   = [int]$ResponderPrio
                            Done            = $false
                        }
                    } else {
                        Write-DisplayText -Blank
                        Write-Warning "Double record found, SAN value `"$SANEntry`" is the same as CN value `"$($CertRequest.CN)`".`r`n         Removed double SAN entry."
                        Write-ToLogFile -W -C DNSPreCheck -M "Double record found, SAN value `"$SANEntry`" is the same as CN value `"$($CertRequest.CN)`". Removed double SAN entry."
                    }
                }
            }
            Write-ToLogFile -D -C DNSPreCheck -M "DNS Data:"
            $SessionRequestObject.DNSObjects | Select-Object DNSName, SAN | ForEach-Object {
                Write-ToLogFile -D -C DNSPreCheck -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
            }
    
            #endregion DNSPreCheck

            Write-DisplayText -Title "Citrix ADC Content Switch"
            if ($CertRequest.ValidationMethod -eq "dns") {
                Write-DisplayText -Line "Connection"
                Write-DisplayText -ForeGroundColor Yellow "Skipped"
            } elseif ($AutoRun -Or (-Not [String]::IsNullOrEmpty($($Parameters.settings.ManagementURL)))) {
                if ($CertRequest.UseLbVip) {
                    Write-DisplayText -Line "Content Switch"
                    Write-DisplayText -ForeGroundColor Yellow "Skipped, -UseLbVip specified!"
                    Write-DisplayText -Line "Connection"
                    if (-Not [String]::IsNullOrEmpty($($ADCSession.Version))) {
                        Write-DisplayText -ForeGroundColor Green "OK"
                        Write-ToLogFile -I -C ADC-CS-Validation -M "Connection OK."
                    } else {
                        Write-Warning "Could not verify the Citrix ADC Connection!"
                        Write-Warning "Script will continue but uploading of certificates will probably Fail"
                        Write-ToLogFile -W -C ADC-CS-Validation -M "Could not verify the Citrix ADC Connection! Script will continue but uploading of certificates will probably Fail."
                    }
                } elseif (-Not [String]::IsNullOrEmpty($($CertRequest.CsVipName))) {
                    $CsVipError = $false
                    try {
                        Write-ToLogFile -I -C ADC-CS-Validation -M "Verifying Content Switch."
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csvserver -Resource $($CertRequest.CsVipName)
                    } catch {
                        $ExceptMessage = $_.Exception.Message
                        Write-ToLogFile -E -C ADC-CS-Validation -M "Error Verifying Content Switch. Details: $ExceptMessage"
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    } finally {
                        if (($response.errorcode -eq "0") -and `
                            ($response.csvserver.type -eq "CONTENT") -and `
                            ($response.csvserver.curstate -eq "UP") -and `
                            ($response.csvserver.servicetype -eq "HTTP") -and `
                            ($response.csvserver.port -eq "80") ) {
                            Write-DisplayText -Line "Content Switch"
                            Write-DisplayText -ForeGroundColor Cyan -NoNewLine "$($CertRequest.CsVipName)"
                            Write-DisplayText -ForeGroundColor Green " (found)"
                            Write-DisplayText -Line "Connection"
                            Write-DisplayText -ForeGroundColor Green "OK"
                            Write-ToLogFile -I -C ADC-CS-Validation -M "Content Switch OK"
                        } elseif ($ExceptMessage -like "*(404) Not Found*") {
                            Write-DisplayText -Line "Content Switch"
                            Write-DisplayText -ForeGroundColor Red "ERROR: The Content Switch `"$($CertRequest.CsVipName)`" does NOT exist!"
                            Write-DisplayText -Line "Error message"
                            Write-DisplayText -ForeGroundColor Red "`"$ExceptMessage`"" -PostBlank
                            Write-DisplayText -ForeGroundColor Yellow "  IMPORTANT: Please make sure a HTTP Content Switch is available" -PostBlank
                            Write-DisplayText -Line "Connection"
                            Write-DisplayText -ForeGroundColor Red "FAILED! Exiting now" -PostBlank
                            Write-ToLogFile -E -C ADC-CS-Validation -M "The Content Switch `"$($CertRequest.CsVipName)`" does NOT exist! Please make sure a HTTP Content Switch is available."
                            $CsVipError = $true
                            Invoke-RegisterError 1 "The Content Switch `"$($CertRequest.CsVipName)`" does NOT exist! Please make sure a HTTP Content Switch is available."
                        } elseif ($ExceptMessage -like "*The remote server returned an error*") {
                            Write-DisplayText -Line "Content Switch"
                            Write-DisplayText -ForeGroundColor Red "ERROR: Unknown error found while checking the Content Switch"
                            Write-DisplayText -Line "Error message"
                            Write-DisplayText -ForeGroundColor Red "`"$ExceptMessage`"" -PostBlank
                            Write-DisplayText -Line "Connection"
                            Write-DisplayText -ForeGroundColor Red "FAILED! Exiting now" -PostBlank
                            Write-ToLogFile -E -C ADC-CS-Validation -M "Unknown error found while checking the Content Switch"
                            $CsVipError = $true
                            Invoke-RegisterError 1 "Unknown error found while checking the Content Switch"
                        } elseif (($response.errorcode -eq "0") -and (-not ($response.csvserver.servicetype -eq "HTTP"))) {
                            Write-DisplayText -Line "Content Switch"
                            Write-DisplayText -ForeGroundColor Red "ERROR: Content Switch `"$($CertRequest.CsVipName)`" is $($response.csvserver.servicetype) and NOT HTTP"
                            if (-not ([String]::IsNullOrWhiteSpace($ExceptMessage))) {
                                Write-DisplayText -Line "Error message"
                                Write-DisplayText -ForeGroundColor Red "`"$ExceptMessage`""
                            }
                            Write-DisplayText -ForeGroundColor Yellow "  IMPORTANT: Please use a HTTP (Port 80) Content Switch!`r`n  This is required for the validation." -PreBlank -PostBlank
                            Write-DisplayText -Line "Connection"
                            Write-DisplayText -ForeGroundColor Red "FAILED! Exiting now" -PostBlank
                            Write-ToLogFile -E -C ADC-CS-Validation -M "Content Switch `"$($CertRequest.CsVipName)`" is $($response.csvserver.servicetype) and NOT HTTP. Please use a HTTP (Port 80) Content Switch! This is required for the validation."
                            $CsVipError = $true
                            Invoke-RegisterError 1 "Content Switch `"$($CertRequest.CsVipName)`" is $($response.csvserver.servicetype) and NOT HTTP. Please use a HTTP (Port 80) Content Switch! This is required for the validation."
                        } elseif ($response.csvserver.td -ne $Parameters.settings.TrafficDomain) {
                            Write-DisplayText -Line "Content Switch"
                            Write-DisplayText -ForeGroundColor Red "ERROR: Content Switch `"$($CertRequest.CsVipName)`" has a diffrent TrafficDomain $($response.csvserver.td) than specified $($Parameters.settings.TrafficDomain)!"
                            Write-DisplayText -ForeGroundColor Yellow "  IMPORTANT: Run the script with the `"-TrafficDomain $($response.csvserver.td)`" additional parameter." -PreBlank -PostBlank
                            Write-DisplayText -Line "Connection"
                            Write-DisplayText -ForeGroundColor Red "FAILED! Exiting now" -PostBlank
                            Write-ToLogFile -E -C ADC-CS-Validation -M "Content Switch `"$($CertRequest.CsVipName)`" has a diffrent TrafficDomain $($response.csvserver.td) than specified $($Parameters.settings.TrafficDomain)! Run the script with the `"-TrafficDomain $($response.csvserver.td)`" additional parameter."
                            $CsVipError = $true
                            Invoke-RegisterError 1 "Content Switch `"$($CertRequest.CsVipName)`" has a diffrent TrafficDomain $($response.csvserver.td) than specified $($Parameters.settings.TrafficDomain)!"
                        } else {
                            Write-DisplayText -Line "Content Switch"
                            Write-DisplayText -ForeGroundColor Green "Found"
                            Write-ToLogFile -I -C ADC-CS-Validation -M "Content Switch Found"
                            Write-DisplayText -Line "State"
                            if ($response.csvserver.curstate -eq "UP") {
                                Write-DisplayText -ForeGroundColor Green "UP"
                                Write-ToLogFile -I -C ADC-CS-Validation -M "Content Switch is UP"
                            } else {
                                Write-DisplayText -ForeGroundColor RED "$($response.csvserver.curstate)"
                                Write-ToLogFile -I -C ADC-CS-Validation -M "Content Switch Not OK, Current Status: $($response.csvserver.curstate)."
                            }
                            Write-DisplayText -Line "Type"
                            if ($response.csvserver.type -eq "CONTENT") {
                                Write-DisplayText -ForeGroundColor Green "CONTENT"
                                Write-ToLogFile -I -C ADC-CS-Validation -M "Content Switch type OK, Type: $($response.csvserver.type)"
                            } else {
                                Write-DisplayText -ForeGroundColor RED "$($response.csvserver.type)"
                                Write-ToLogFile -I -C ADC-CS-Validation -M "Content Switch type Not OK, Type: $($response.csvserver.type)"
                            }
                            if (-not ([String]::IsNullOrWhiteSpace($ExceptMessage))) {
                                Write-DisplayText -Line "Error message"
                                Write-DisplayText -ForeGroundColor Red "`"$ExceptMessage`""
                            }
                            Write-DisplayText -Line "Data"
                            Write-DisplayText -ForeGroundColor Yellow $($response.csvserver | Format-List -Property * | Out-String)
                            Write-DisplayText -Line "Connection"
                            Write-DisplayText -ForeGroundColor Red "FAILED! Exiting now" -PostBlank
                            Write-ToLogFile -E -C ADC-CS-Validation -M "Content Switch verification failed."
                            $CsVipError = $true
                            Invoke-RegisterError 1 "Content Switch verification failed."
                        }
                    }
                } else {
                    Write-DisplayText -Line "Connection"
                    if (-Not [String]::IsNullOrEmpty($($ADCSession.Version))) {
                        Write-DisplayText -ForeGroundColor Green "OK"
                        Write-ToLogFile -I -C ADC-CS-Validation -M "Connection OK."
                    } else {
                        Write-Warning "Could not verify the Citrix ADC Connection!"
                        Write-Warning "Script will continue but uploading of certificates will probably Fail"
                        Write-ToLogFile -W -C ADC-CS-Validation -M "Could not verify the Citrix ADC Connection! Script will continue but uploading of certificates will probably Fail."
                    }
                }
            }
            if ($CsVipError) {
                Continue
            }
    
            #region Registration
    
            if ($CertRequest.ValidationMethod -in "http", "dns") {
                Write-DisplayText -Title "Let's Encrypt Account & Registration"
                Write-DisplayText -Line "Registration"
                try {
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    Write-ToLogFile -I -C Registration -M "Try to retrieve the existing Registration."
                    $PARegistrations = Posh-ACME\Get-PAAccount -List -Contact $CertRequest.EmailAddress -Refresh | Where-Object { ($_.status -eq "valid") -and ($_.KeyLength -eq $CertRequest.KeyLength) }
                    if ($PARegistrations -is [system.array]) {
                        $PARegistration = $PARegistrations | Sort-Object id | Select-Object -Last 1
                        Write-ToLogFile -I -C Registration -M "Found multiple Accounts"
                        $PARegistrations | ForEach-Object { Write-ToLogFile -D -C Registration -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)" }
                    } else {
                        $PARegistration = $PARegistrations
                    }
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    if ($PARegistration.Contact -contains "mailto:$($CertRequest.EmailAddress)") {
                        Write-ToLogFile -I -C Registration -M "Existing registration found, no changes necessary."
                    } else {
                        if ([String]::IsNullOrEmpty($($PARegistration.Contact))) {
                            Write-ToLogFile -I -C Registration -M "Current registration is not equal to `"$($CertRequest.EmailAddress)`", currently empty! Setting new registration."
                        } else {
                            Write-ToLogFile -I -C Registration -M "Current registration `"$($PARegistration.Contact)`" is not equal to `"$($CertRequest.EmailAddress)`", setting new registration."
                        }
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                        $PARegistration = Posh-ACME\New-PAAccount -Contact $($CertRequest.EmailAddress) -KeyLength $CertRequest.KeyLength -AcceptTOS
                    }
                } catch {
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    Write-ToLogFile -I -C Registration -M "Setting new registration to `"$($CertRequest.EmailAddress)`"."
                    try {
                        $PARegistration = Posh-ACME\New-PAAccount -Contact $($CertRequest.EmailAddress) -KeyLength $CertRequest.KeyLength -AcceptTOS
                        Write-ToLogFile -I -C Registration -M "New registration successful."
                    } catch {
                        Write-ToLogFile -E -C Registration -M "Error New registration failed! Exception Message: $($_.Exception.Message)"
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                        Write-DisplayText -ForeGroundColor Red "`nError New registration failed!"
                    }
                }
                try {
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    Set-PAAccount -ID $PARegistration.id -Force | Out-Null
                    Write-ToLogFile -I -C Registration -M "Account $($PARegistration.id) set as default."
                } catch {
                    Write-ToLogFile -E -C Registration -M "Could not set default account. Exception Message: $($_.Exception.Message)."
                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                }
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"


                $PARegistration = Get-PAAccount -ID $PARegistration.ID -Refresh
                #$PARegistrations = Posh-ACME\Get-PAAccount -List -Contact $($CertRequest.EmailAddress) -Refresh | Where-Object { ($_.status -eq "valid") -and ($_.KeyLength -eq $CertRequest.KeyLength) }
                #Write-ToLogFile -D -C Registration -M "Registration: $($PARegistrations | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)."

                if (-not ($PARegistration.Contact -contains "mailto:$($CertRequest.EmailAddress)")) {
                    Write-DisplayText -ForeGroundColor Red " Error"
                    Write-ToLogFile -E -C Registration -M "User registration failed."
                    Write-Error "User registration failed"
                    Invoke-RegisterError 1 "User registration failed"
                    Continue
                }
                if ($PARegistration.status -ne "valid") {
                    Write-DisplayText -ForeGroundColor Red " Error"
                    Write-ToLogFile -E -C Registration -M "Account status is $($Account.status)."
                    Write-Error  "Account status is $($Account.status)"
                    Invoke-RegisterError 1 "Account status is $($Account.status)"
                    Continue
                } 
                Write-DisplayText -ForeGroundColor Green " Ready [$($PARegistration.Contact)]"
            }
    
            #endregion Registration
    
            #region Order
    
            if (($CertRequest.ValidationMethod -in "http", "dns") -and ($SessionRequestObject.ExitCode -eq 0)) {
                if ([String]::IsNullOrEmpty($($CertRequest.FriendlyName))) {
                    $CertRequest.FriendlyName = $CertRequest.CN
                }
                if ($CertRequest.ForceCertRenew) {
                    Write-DisplayText -Line "Removing previous cert"
                    try {
                        $CertStoragePath = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Posh-ACME" -ErrorAction Stop
                        $CertStoragePath = Join-Path -Path $CertStoragePath -ChildPath ([uri]$PARegistration.location).Authority -ErrorAction Stop
                        $CertStoragePath = Join-Path -Path $CertStoragePath -ChildPath $PARegistration.id -ErrorAction Stop
                        $CertStoragePath = Join-Path -Path $CertStoragePath -ChildPath $CertRequest.CN -ErrorAction Stop
                        Write-ToLogFile -D -C Order -M "CertStoragePath: $CertStoragePath"
                        $CertStorageFilePath = Join-Path -Path $CertStoragePath -ChildPath "order.json" -ErrorAction Stop
                        Write-ToLogFile -D -C Order -M "CertStorageFilePath: CertStorageFilePath"
                        if (Test-Path -Path  $CertStorageFilePath) {
                            Write-ToLogFile -I -C Order -M "Old certificate found, trying to remove (ForceCertRenew was set)"
                            Remove-Item -Path $CertStoragePath -Force -Recurse -ErrorAction Stop
                            Write-DisplayText -ForeGroundColor Green "Done"
                            Write-ToLogFile -I -C Order -M "Old certificate removed"
                        } else {
                            Write-ToLogFile -I -C Order -M "Old certificate NOT found (ForceCertRenew was set)"
                            Write-DisplayText -ForeGroundColor Yellow "Not Found"
                        }
                    } catch {
                        Write-DisplayText -ForeGroundColor Red "Failed"
                        Write-ToLogFile -E -C Order -M "Caught an error, $($_.Exception.Message)"
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    }
                    
                }
                Add-Type -AssemblyName System.Web | Out-Null
                $length = 20
                [SecureString]$GeneratedPassword = ConvertTo-SecureString -String $(New-Password -Length $length) -AsPlainText -Force
                if (-Not [String]::IsNullOrEmpty($($Parameters.settings.PfxPassword))) {
                    $PfxPassword = ConvertFrom-EncryptedPassword -Object $($Parameters.settings.PfxPassword)
                    Write-ToLogFile -I -C Order -M "PfxPassword retrieved from the settings"
                    try {
                        $Parameters.settings.PSObject.Properties.Remove('PfxPassword')
                        Write-ToLogFile -I -C Order -M "PfxPassword deleted from the settings"
                    } catch {
                        Write-ToLogFile -E -C Order -M "Could not delete PfxPassword from settings"
                    }
                }
                if (-Not [String]::IsNullOrEmpty($($CertRequest.PfxPassword))) {
                    $PfxPassword = ConvertFrom-EncryptedPassword -Object $($CertRequest.PfxPassword)
                    Write-ToLogFile -I -C Order -M "PfxPassword retrieved from the cert request"
                }
                if ([String]::IsNullOrEmpty($($PfxPassword))) {
                    $PfxPassword = $GeneratedPassword
                    $PfxPasswordGenerated = $true
                    Write-ToLogFile -I -C Order -M "New PfxPassword generated"
                }
                Invoke-AddUpdateParameter -Object $CertRequest -Name PfxPassword -Value $PfxPassword
                Write-DisplayText -Line "Order"
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                try {
                    Write-ToLogFile -I -C Order -M "Trying to create a new order."
                    $domains = $SessionRequestObject.DNSObjects | Select-Object DNSName -ExpandProperty DNSName
                    $PAOrder = Posh-ACME\New-PAOrder -Domain $domains -KeyLength $CertRequest.KeyLength -Force -FriendlyName $CertRequest.FriendlyName -PfxPass $(ConvertTo-PlainText -SecureString $PfxPassword)
                    Start-Sleep -Seconds 1
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    Write-ToLogFile -D -C Order -M "Order data:"
                    $PAOrder | Select-Object MainDomain, FriendlyName, SANs, status, expires, KeyLength | ForEach-Object {
                        Write-ToLogFile -D -C Order -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    }
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    $PAChallenges = $PAOrder | Posh-ACME\Get-PAOrder -Refresh | Posh-ACME\Get-PAAuthorizations
                    Write-ToLogFile -D -C Order -M "Challenge status: "
                    $PAChallenges | Select-Object DNSId, status, HTTP01Status, DNS01Status | ForEach-Object {
                        Write-ToLogFile -D -C Order -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    }
                    Write-ToLogFile -I -C Order -M "Order created successfully."
                } catch {
                    Write-DisplayText -ForeGroundColor Red " Error"
                    if ($_.Exception.Message -like "*rate*limit*") {
                        Write-DisplayText -PreBlank -Line -ForeGroundColor Yellow "Rate-Limit WARNING"
                        Write-DisplayText -ForeGroundColor Yellow "$($_.Exception.Message)"
                        $mailDataItem.Text = "Rate-Limit WARNING, ERROR: $($_.Exception.Message)"
                        Invoke-RegisterError 1 "Could not create the order. $($_.Exception.Message)"
                    } else {
                        Write-ToLogFile -E -C Order -M "Could not create the order. You can retry with specifying the `"-CleanPoshACMEStorage`" parameter. "
                        Write-ToLogFile -E -C Order -M "Exception Message: $($_.Exception.Message)"
                        Write-DisplayText -ForeGroundColor Red "ERROR: Could not create the order. You can retry with specifying the `"-CleanPoshACMEStorage`" parameter."
                        Invoke-RegisterError 1 "Could not create the order. You can retry with specifying the `"-CleanPoshACMEStorage`" parameter."
                        $mailDataItem.Text = "Could not create the order, ERROR: $($_.Exception.Message)"
                    }
                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    Continue
                }
                Write-DisplayText -ForeGroundColor Green " Ready"
            }
    
            #endregion Order
    
            #region DNS-Validation
    
            if (($CertRequest.ValidationMethod -in "http", "dns") -and ($SessionRequestObject.ExitCode -eq 0)) {
                Write-DisplayText -Title "DNS - Validate Records"
                Write-DisplayText -Line "Checking records"
                Write-ToLogFile -I -C DNS-Validation -M "Validate DNS record(s)."
                $DNSTypes = '[{"Type":"A","TypeId":1},{"Type":"AAAA","TypeId":28},{"Type":"CNAME","TypeId":5},{"Type":"TXT","TypeId":16}]' | ConvertFrom-Json
                $DNSValidationError = $false
                Foreach ($DNSObject in $SessionRequestObject.DNSObjects) {
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    if ($IPv6) {
                        $DNSObject.IPAddress = "::"
                    } else {
                        $DNSObject.IPAddress = "0.0.0.0"
                    }
                    $DNSObject.Status = $false
                    $DNSObject.Match = $false
                    try {
                        $PAChallenge = $PAChallenges | Where-Object { $_.fqdn -eq $DNSObject.DNSName }
                        if ([String]::IsNullOrWhiteSpace($PAChallenge)) {
                            Write-DisplayText -ForeGroundColor Red " Error [$($DNSObject.DNSName)]"
                            Write-ToLogFile -E -C DNS-Validation -M "No valid Challenge found."
                            Write-Error "No valid Challenge found"
                            $DNSValidationError = $true
                            Invoke-RegisterError 1 "No valid Challenge found"
                            Break
                        } else {
                            $DNSObject.Challenge = $PAChallenge
                        }
                        if ($($CertRequest.DisableIPCheck) -Or $($Parameters.settings.DisableIPCheck)) {
                            $DNSObject.IPAddress = "NoIPCheck"
                            $DNSObject.Match = $true
                            $DNSObject.Status = $true
                            Write-ToLogFile -I -C DNS-Validation -M "Skip IP Checking!"
                        } else {
                            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                            Write-ToLogFile -I -C DNS-Validation -M "Using public DNS server (dns.google) to verify dns records."
                            Write-ToLogFile -D -C DNS-Validation -M "Trying to get IP Address."
                            try {
                                $DNSResult = Invoke-RestMethod -Method Get -Uri "https://dns.google/resolve?name=$($DNSObject.DNSName)"
                                $PublicIP = $DNSResult.Answer | Where-Object { $_.type -eq 1 } | Select-Object -ExpandProperty "data"
                                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                                Write-ToLogFile -I -C DNS-Validation -M "Resolved the following address: $($PublicIP -Join ', ')"
                            } catch {
                                $PublicIP = $null
                                Write-ToLogFile -E -C DNS-Validation -M "Could not resolve the IP. $($_.Exception.Message)"
                                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                            }
                            $RecordType = $null
                            try {
                                $RecordTypeID = $DNSResult.Answer | Where-Object { $_.name -like "$($DNSObject.DNSName)." } | Select-Object -ExpandProperty "type"
                                $RecordType = $DNSTypes | Where-Object { $_.TypeID -like $RecordTypeID } | Select-Object -ExpandProperty Type
                                Write-ToLogFile -D -C DNS-Validation -M "Got a $RecordType Record"
                                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                            } catch {
                                $RecordTypeID = $null
                                $RecordType = $null
                                Write-ToLogFile -E -C DNS-Validation -M "Could not determine the Record Type. $($_.Exception.Message)"
                                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                            }   
                            try {
                                $DNSCNAMEDetails = $null
                                if ($RecordTypeID -like "5") {
                                    $DNSCNAMEDetails = $DNSResult.Answer | Where-Object { $_.type -notlike $RecordTypeID } | Select-Object -Property `
                                    @{ Name = 'Record'; Expression = { $_.name.TrimEnd(".") } },
                                    @{ Name = 'Type'; Expression = { $Type = $_.type; $DNSTypes | Where-Object { $_.TypeID -like "$Type" } | Select-Object -ExpandProperty "type" } },
                                    @{ Name = 'IP'; Expression = { $_.data } }
                                }
                                Write-ToLogFile -D -C DNS-Validation -M "The CNAME record details collected."
                                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                            } catch {
                                $DNSCNAMEDetails = $null
                                Write-ToLogFile -E -C DNS-Validation -M "Could not retrieve CNAME details. $($_.Exception.Message)"
                                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                            }   
                            $DNSObject.DNSType = $RecordType
                            $DNSObject.DNSCNAMEDetails = $DNSCNAMEDetails

                            if ([String]::IsNullOrWhiteSpace($PublicIP)) {
                                Write-DisplayText -PostBlank -ForeGroundColor Red " Error [$($DNSObject.DNSName)] - NO valid IP - Try running the script with the `"-DisableIPCheck`" parameter."
                                Write-ToLogFile -E -C DNS-Validation -M "No valid (public) IP Address found for DNSName:`"$($DNSObject.DNSName)`". Try running the script with the `"-DisableIPCheck`" parameter."
                                Write-Error "No valid (public) IP Address found for DNSName:`"$($DNSObject.DNSName)`""
                                $DNSValidationError = $true
                                Invoke-RegisterError 1 "No valid (public) IP Address found for DNSName:`"$($DNSObject.DNSName)`". Try running the script with the `"-DisableIPCheck`" parameter."
                                Break

                            } elseif ($PublicIP -is [system.array]) {
                                Write-ToLogFile -W -C DNS-Validation -M "More than one ip address found:"
                                $PublicIP | ForEach-Object {
                                    Write-ToLogFile -D -C DNS-Validation -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
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
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                        Write-DisplayText -ForeGroundColor Red -NoNewLine "Error while retrieving IP Address,"
                        if ($DNSObject.SAN) {
                            Write-DisplayText -ForeGroundColor Red "you can try to re-run the script with the -DisableIPCheck parameter."
                            Write-DisplayText -ForeGroundColor Red "The script will continue but `"$DNSRecord`" will be skipped"
                            Write-ToLogFile -E -C DNS-Validation -M "You can try to re-run the script with the -DisableIPCheck parameter. The script will continue but `"$DNSRecord`" will be skipped."
                            $DNSObject.IPAddress = "Skipped"
                            $DNSObject.Match = $true
                        } else {
                            Write-DisplayText -ForeGroundColor Red " Error [$($DNSObject.DNSName)]"
                            Write-DisplayText -ForeGroundColor Red "you can try to re-run the script with the -DisableIPCheck parameter."
                            Write-ToLogFile -E -C DNS-Validation -M "You can try to re-run the script with the -DisableIPCheck parameter."
                            $DNSValidationError = $true
                            Invoke-RegisterError 1 "You can try to re-run the script with the -DisableIPCheck parameter."
                            Break
                        }
                    }
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    if ($DNSObject.SAN) {
                        $CNObject = $SessionRequestObject.DNSObjects | Where-Object { $_.SAN -eq $false }
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
                }
                if ($DNSValidationError) {
                    continue
                }
                Write-ToLogFile -D -C DNS-Validation -M "SAN Objects:"
                $SessionRequestObject.DNSObjects | Select-Object DNSName, IPAddress, DNSType, Status, Match | ForEach-Object {
                    Write-ToLogFile -D -C DNS-Validation -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                }
                Write-DisplayText -ForeGroundColor Green " Ready"
            }
            if (($CertRequest.ValidationMethod -eq "http") -and ($SessionRequestObject.ExitCode -eq 0)) {
                Write-DisplayText -Line "Checking for errors"
                Write-ToLogFile -I -C DNS-Validation -M "Checking for invalid DNS Records."
                $InvalidDNS = $SessionRequestObject.DNSObjects | Where-Object { $_.Status -eq $false }
                $SkippedDNS = $SessionRequestObject.DNSObjects | Where-Object { $_.IPAddress -eq "Skipped" }
                if ($InvalidDNS) {
                    Write-DisplayText -ForeGroundColor Red "Error"
                    Write-ToLogFile -E -C DNS-Validation -M "Invalid DNS object(s):"
                    $InvalidDNS | Select-Object DNSName, IPAddress, Status | ForEach-Object {
                        Write-ToLogFile -D -C DNS-Validation -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                        Write-DisplayText -ForeGroundColor Red -Line "Record with Error"
                        Write-DisplayText -ForeGroundColor Red "$($_.DNSName) [$($_.IPAddress)]"
                    }
                    Write-DisplayText -Blank
                    Write-Error -Message "Invalid (not registered?) DNS Record(s) found!"
                    Invoke-RegisterError 1 "Invalid (not registered?) DNS Record(s) found!"
                    Continue
                } else {
                    Write-ToLogFile -I -C DNS-Validation -M "None found, continuing"
                }
                if ($SkippedDNS) {
                    Write-Warning "The following DNS object(s) will be skipped:`n$($SkippedDNS | Select-Object DNSName | Format-List | Out-String)"
                    Write-ToLogFile -W -C DNS-Validation -M "The following DNS object(s) will be skipped:"
                    $SkippedDNS | Select-Object DNSName | ForEach-Object {
                        Write-ToLogFile -D -C DNS-Validation -M "Skipped: $($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    }
                }
                Write-ToLogFile -I -C DNS-Validation -M "Checking non-matching DNS Records"
                $DNSNoMatch = $SessionRequestObject.DNSObjects | Where-Object { $_.Match -eq $false }
                if ($DNSNoMatch -and (-not $($CertRequest.DisableIPCheck))) {
                    Write-DisplayText -ForeGroundColor Red "Error"
                    Write-ToLogFile -E -C DNS-Validation -M "Non-matching records found, must match to `"$($SessionRequestObject.DNSObjects[0].DNSName)`" ($($SessionRequestObject.DNSObjects[0].IPAddress))"
                    $DNSNoMatch | Select-Object DNSName, IPAddress, Match | ForEach-Object {
                        Write-ToLogFile -D -C DNS-Validation -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                        Write-DisplayText -ForeGroundColor Red -Line "Record with Error"
                        Write-DisplayText -ForeGroundColor Red "$($_.DNSName) [$($_.IPAddress)]"
                    }
                    Write-DisplayText ""
                    Write-Error "Non-matching records found, must match to `"$($SessionRequestObject.DNSObjects[0].DNSName)`" ($($SessionRequestObject.DNSObjects[0].IPAddress))."
                    Invoke-RegisterError 1 "Non-matching records found, must match to `"$($SessionRequestObject.DNSObjects[0].DNSName)`" ($($SessionRequestObject.DNSObjects[0].IPAddress))."
                    Continue
                } elseif ($($CertRequest.DisableIPCheck)) {
                    Write-ToLogFile -I -C DNS-Validation -M "IP Addresses checking was skipped."
                } else {
                    Write-ToLogFile -I -C DNS-Validation -M "All IP Addresses match."
                }
                Write-DisplayText -ForeGroundColor Green "Done"
            }
    
            #endregion DNS-Validation
    
            #region CheckOrderValidation
    
            if (($CertRequest.ValidationMethod -eq "http") -and ($SessionRequestObject.ExitCode -eq 0)) {
                Write-ToLogFile -I -C CheckOrderValidation -M "Checking if validation is required."
                $PAOrderItems = Posh-ACME\Get-PAOrder -Refresh -MainDomain $($CertRequest.CN) | Posh-ACME\Get-PAAuthorizations
                $ValidationRequired = $PAOrderItems | Where-Object { $_.status -ne "valid" }
                Write-ToLogFile -D -C CheckOrderValidation -M "$($ValidationRequired.Count) validations required:"
                $ValidationRequired | Select-Object fqdn, status, HTTP01Status, Expires | ForEach-Object {
                    Write-ToLogFile -D -C CheckOrderValidation -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
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
            if (($ADCActionsRequired -and ($CertRequest.ValidationMethod -eq "http")) -and ($SessionRequestObject.ExitCode -eq 0)) {
                try {
                    Invoke-AddInitialADCConfig
                } catch {
                    Write-Error -Message "Cannot pre-configure the Citrix ADC, please validate your settings!"
                    Invoke-RegisterError 1 "Cannot pre-configure the Citrix ADC, please validate your settings!"
                }
            }
            #endregion ConfigureADC
    
            #region CheckDNS
            if (($ADCActionsRequired) -and ($CertRequest.ValidationMethod -eq "http") -and ($SessionRequestObject.ExitCode -eq 0)) {
                try {
                    Invoke-CheckDNS
                } catch {
                    Write-Error -Message "Cannot Check the DNS, please validate your settings!"
                    Invoke-RegisterError 1 "Cannot Check the DNS, please validate your settings!"
                }
            }
            #endregion CheckDNS
            #region OrderValidation

            if (($CertRequest.ValidationMethod -eq "http") -and ($SessionRequestObject.ExitCode -eq 0)) {
                Write-ToLogFile -I -C OrderValidation -M "Configuring the ADC Responder Policies/Actions required for the validation."
                Write-ToLogFile -D -C OrderValidation -M "PAOrderItems:"
                $PAOrderItems | Select-Object fqdn, status, Expires, HTTP01Status, DNS01Status | ForEach-Object {
                    Write-ToLogFile -D -C OrderValidation -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                }
                Write-DisplayText -Title "ADC - Order Validation"
                foreach ($DNSObject in $SessionRequestObject.DNSObjects) {
                    $ADCKeyAuthorization = $null
                    $PAOrderItem = $PAOrderItems | Where-Object { $_.fqdn -eq $DNSObject.DNSName }
                    Write-DisplayText -Line "DNS Hostname"
                    Write-DisplayText -ForeGroundColor Cyan "$($DNSObject.DNSName)"
                    Write-DisplayText -Line "Ready for Validation"
                    if ($PAOrderItem.status -eq "valid") {
                        Write-DisplayText -ForeGroundColor Green "=> N/A, Still valid"
                        Write-ToLogFile -I -C OrderValidation -M "`"$($DNSObject.DNSName)`" is valid, nothing to configure."
                    } else {
                        Write-ToLogFile -I -C OrderValidation -M "New validation required for `"$($DNSObject.DNSName)`", Start configuring the ADC."
                        $PAToken = ".well-known/acme-challenge/$($PAOrderItem.HTTP01Token)"
                        $KeyAuth = Posh-ACME\Get-KeyAuthorization -Token $($PAOrderItem.HTTP01Token) -Account $PAAccount
                        $ADCKeyAuthorization = "HTTP/1.0 200 OK\r\n\r\n$($KeyAuth)"
                        $RspName = "{0}_{1}" -f $($Parameters.settings.RspName), $DNSObject.ResponderPrio
                        $RsaName = "{0}_{1}" -f $($Parameters.settings.RsaName), $DNSObject.ResponderPrio
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                        try {
                            Write-ToLogFile -I -C OrderValidation -M "Add Responder Action `"$RsaName`" to return `"$ADCKeyAuthorization`"."
                            $payload = @{"name" = "$RsaName"; "type" = "respondwith"; "target" = "`"$ADCKeyAuthorization`""; }
                            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type responderaction -Payload $payload -Action add
                            Write-ToLogFile -I -C OrderValidation -M "Responder Action added successfully."
                            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                            try {
                                Write-ToLogFile -I -C OrderValidation -M "Add Responder Policy `"$RspName`" to: `"HTTP.REQ.URL.CONTAINS(`"$PAToken`")`""
                                $payload = @{"name" = "$RspName"; "action" = "$RsaName"; "rule" = "HTTP.REQ.URL.CONTAINS(`"$PAToken`")"; }
                                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type responderpolicy -Payload $payload -Action add
                                Write-ToLogFile -I -C OrderValidation -M "Responder Policy added successfully."
                                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                                try {
                                    Write-ToLogFile -I -C OrderValidation -M "Trying to bind the Responder Policy `"$RspName`" to LoadBalance VIP: `"$($Parameters.settings.LbName)`""
                                    $payload = @{"name" = "$($Parameters.settings.LbName)"; "policyname" = "$RspName"; "priority" = "$($DNSObject.ResponderPrio)"; }
                                    $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type lbvserver_responderpolicy_binding -Payload $payload -Resource $($Parameters.settings.LbName)
                                    Write-ToLogFile -I -C OrderValidation -M "Responder Policy successfully bound to Load Balance VIP."
                                    try {
                                        Write-ToLogFile -I -C OrderValidation -M "Sending acknowledgment to Let's Encrypt."
                                        Send-ChallengeAck -ChallengeUrl $($PAOrderItem.HTTP01Url) -Account $PAAccount -ErrorAction Stop
                                        Write-ToLogFile -I -C OrderValidation -M "Successfully send."
                                    } catch {
                                        Write-ToLogFile -E -C OrderValidation -M "Error while submitting the Challenge. Exception Message: $($_.Exception.Message)"
                                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                        Write-DisplayText -ForegroundColor Red "`r`nERROR: Error while submitting the Challenge."
                                        Invoke-RegisterError 1 "Error while submitting the Challenge."
                                        Break
                                    }
                                    Write-DisplayText -ForeGroundColor Green " Ready"
                                } catch {
                                    Write-ToLogFile -E -C OrderValidation -M "Failed to bind Responder Policy to Load Balance VIP. Exception Message: $($_.Exception.Message)"
                                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                    Write-DisplayText -ForeGroundColor Red " ERROR  [Responder Policy Binding - $RspName]"
                                    Write-DisplayText -ForegroundColor Red "`r`nERROR: $($_.Exception.Message)"
                                    Invoke-RegisterError 1 "Failed to bind Responder Policy to Load Balance VIP"
                                    Break
                                }
                            } catch {
                                Write-ToLogFile -E -C OrderValidation -M "Failed to add Responder Policy. Exception Message: $($_.Exception.Message)"
                                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                Write-DisplayText -ForeGroundColor Red " ERROR  [Responder Policy - $RspName]"
                                Write-DisplayText -ForegroundColor Red "`r`nERROR: $($_.Exception.Message)"
                                Invoke-RegisterError 1 "Failed to add Responder Policy"
                                Break
                            }
                        } catch {
                            Write-ToLogFile -E -C OrderValidation -M "Failed to add Responder Action. Error Details: $($_.Exception.Message)"
                            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                            Write-DisplayText -ForeGroundColor Red " ERROR  [Responder Action - $RsaName]"
                            Write-DisplayText -ForegroundColor Red "`r`nERROR: $($_.Exception.Message)"
                            Invoke-RegisterError 1 "Failed to add Responder Action"
                            Break
                        }
                    }
                }

                if ($SessionRequestObject.ExitCode -eq 0) {
                    Write-DisplayText -Title "Waiting for Order completion"
                    Write-DisplayText -Line "Completion"
                    Write-ToLogFile -I -C OrderValidation -M "Retrieving validation status."
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    $PAOrderItems = Posh-ACME\Get-PAOrder -Refresh -MainDomain $($CertRequest.CN) | Posh-ACME\Get-PAAuthorizations
                    Write-ToLogFile -D -C OrderValidation -M "Listing PAOrderItems"
                    $PAOrderItems | Select-Object fqdn, status, Expires, HTTP01Status, DNS01Status | ForEach-Object {
                        Write-ToLogFile -D -C OrderValidation -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    }
                    $WaitLoop = 10
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    Write-ToLogFile -D -C OrderValidation -M "Items still pending: $(($PAOrderItems | Where-Object { $_.status -eq "pending" }).Count -gt 0)"
                    while ($true) {
                        Start-Sleep -Seconds 10
                        $PAOrderItems = Posh-ACME\Get-PAOrder -Refresh -MainDomain $($CertRequest.CN) | Posh-ACME\Get-PAAuthorizations
                        Write-ToLogFile -I -C OrderValidation -M "Still $((($PAOrderItems | Where-Object {$_.status -eq "pending"})| Measure-Object).Count) `"pending`" items left. Waiting an extra 5 seconds."
                        if ($WaitLoop -eq 0) {
                            Write-ToLogFile -D -C OrderValidation -M "Loop ended, max reties reached!"
                            break
                        } elseif ($((($PAOrderItems | Where-Object { $_.status -eq "pending" }) | Measure-Object).Count) -eq 0) {
                            Write-ToLogFile -D -C OrderValidation -M "Loop ended no pending items left."
                            break
                        }
                        $WaitLoop--
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    }
                    $PAOrderItems = Posh-ACME\Get-PAOrder -Refresh -MainDomain $($CertRequest.CN) | Posh-ACME\Get-PAAuthorizations
                    Write-ToLogFile -D -C OrderValidation -M "Listing PAOrderItems"
                    $PAOrderItems | Select-Object fqdn, status, Expires, HTTP01Status, DNS01Status | ForEach-Object {
                        Write-ToLogFile -D -C OrderValidation -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    }
                    if ($PAOrderItems | Where-Object { $_.status -ne "valid" }) {
                        Write-DisplayText -ForeGroundColor Red "Failed"
                        Write-ToLogFile -E -C OrderValidation -M "Unfortunately there are invalid items. Failed Records:"
                        $PAOrderItems | Where-Object { $_.status -ne "valid" } | Select-Object fqdn, status, Expires, HTTP01Status, DNS01Status | ForEach-Object {
                            Write-ToLogFile -D -C OrderValidation -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                        }
                        Write-DisplayText -Title "Invalid items:"
                        ForEach ($Item in $($PAOrderItems | Where-Object { $_.status -ne "valid" })) {
                            Write-DisplayText -Line "DNS Hostname"
                            Write-DisplayText -ForeGroundColor Cyan "$($Item.fqdn)"
                            Write-DisplayText -Line "Status"
                            Write-DisplayText -ForeGroundColor Red "ERROR [$($Item.status)]"
                            Write-DisplayText -ForeGroundColor Red -Line "Error Status"
                            Write-DisplayText -ForeGroundColor Red "$($Item.challenges.error.status)"
                            Write-DisplayText -ForeGroundColor Red -Line "Type"
                            Write-DisplayText -ForeGroundColor Red "$($Item.challenges.error.type)"
                            Write-DisplayText -ForeGroundColor Red -Line "Details"
                            Write-DisplayText -ForeGroundColor Red "$($Item.challenges.error.detail)"
                            $mailDataItem.Text = "Status: $($Item.challenges.error.status) | Type: $($Item.challenges.error.type)`r`nDetail: $($Item.challenges.error.detail)"
                            Write-DisplayText -ForeGroundColor Red -Line "Hostname | Port"
                            Write-DisplayText -ForeGroundColor Red "$($Item.challenges.validationRecord.hostname) | $($Item.challenges.validationRecord.port)"
                            Write-DisplayText -ForeGroundColor Red -Line "IPAddress Used | Resolved"
                            Write-DisplayText -ForeGroundColor Red "$($Item.challenges.validationRecord.addressUsed) | $($Item.challenges.validationRecord.addressesResolved -join ', ')"
                            Write-ToLogFile -E -C OrderValidation -M "Error: $($Item.challenges.error | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress -ErrorAction SilentlyContinue)"
                            Write-ToLogFile -E -C OrderValidation -M "ValidationRecord: $($Item.challenges.validationRecord | ForEach-Object {$_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress -ErrorAction SilentlyContinue})"
                        }
                        Write-DisplayText -ForegroundColor Red "`r`nERROR: There are some invalid items"
                        Invoke-RegisterError 1 "There are some invalid items"
                        Continue
                    } else {
                        Write-DisplayText -ForeGroundColor Green " Completed"
                        Write-ToLogFile -I -C OrderValidation -M "Validation status finished."
                    }
                } else {
                    Write-ToLogFile -D -C OrderValidation -M "Skipped Order Completion, Exit Code: $($SessionRequestObject.ExitCode)"
                }
                #endregion OrderValidation

                #region CleanupADC

                if ($CertRequest.ValidationMethod -in "http", "dns") {
                    Invoke-ADCCleanup -Full
                }

                #endregion CleanupADC
            }
    
            #region DNSChallenge
    
            if (($CertRequest.ValidationMethod -eq "dns") -and ($SessionRequestObject.ExitCode -eq 0)) {
                $PAOrderItems = Posh-ACME\Get-PAOrder -Refresh -MainDomain $($CertRequest.CN) | Posh-ACME\Get-PAAuthorizations
                $TXTRecords = $PAOrderItems | Select-Object fqdn, `
                @{L = 'TXTName'; E = { "_acme-challenge.$($_.fqdn.Replace('*.',''))" } }, `
                @{L = 'TXTValue'; E = { (Get-KeyAuthorization $_.DNS01Token -ForDNS) } }, `
                @{L = 'SanitizedFqdn'; E = { "$($_.fqdn.Replace('*.',''))" } }, `
                @{L = 'Token'; E = { $_.DNS01Token } }
                $PoshACMEPluginUsed = $false
                if ([String]::IsNullOrEmpty($DNSParams) -or [String]::IsNullOrEmpty($DNSPlugin) -or ($DNSParams.Count -eq 0) -or ($DNSPlugin -like "Manual")) {
                    Write-DisplayText -ForeGroundColor Magenta "`r`n********************************************************************"
                    Write-DisplayText -ForeGroundColor Magenta "* Make sure the following TXT records are configured at your DNS   *"
                    Write-DisplayText -ForeGroundColor Magenta "* provider before continuing! If not, DNS validation will fail!    *"
                    Write-DisplayText -ForeGroundColor Magenta "********************************************************************"
                    Write-ToLogFile -I -C DNSChallenge -M "Make sure the following TXT records are configured at your DNS provider before continuing! If not, DNS validation will fail!"
                    foreach ($Record in $TXTRecords) {
                        Write-DisplayText -Blank
                        Write-DisplayText -Line "DNS Hostname"
                        Write-DisplayText -ForeGroundColor Cyan "$($Record.fqdn)"
                        Write-DisplayText -Line "TXT Record Name."
                        Write-DisplayText -ForeGroundColor Yellow "$($Record.TXTName)"
                        Write-DisplayText -Line "TXT Record Value"
                        Write-DisplayText -ForeGroundColor Yellow "$($Record.TXTValue)"
                        Write-ToLogFile -I -C DNSChallenge -M "DNS Hostname: `"$($Record.fqdn)`" => TXT Record Name: `"$($Record.TXTName)`", Value: `"$($Record.TXTValue)`"."
                    }
                    Write-DisplayText -Blank
                    Write-DisplayText -ForeGroundColor Magenta "********************************************************************"
                    $($TXTRecords | Format-List | Out-String).Trim() | clip.exe
                    Write-DisplayText -ForegroundColor Yellow "`r`nINFO: Data is copied tot the clipboard"
                    $answer = Read-Host -Prompt "Enter `"yes`" when ready to continue"
                    if (-not ($answer.ToLower() -eq "yes")) {
                        Write-DisplayText -ForegroundColor Yellow "You've entered `"$answer`", last chance to continue"
                        $answer = Read-Host -Prompt "Enter `"yes`" when ready to continue, or something else to stop and exit"
                        if (-not ($answer.ToLower() -eq "yes")) {
                            Write-DisplayText -ForegroundColor Yellow "You've entered `"$answer`", ending now!"
                            Exit (0)
                        }
                    }
                } else {
                    Write-ToLogFile -I -C DNSChallenge -M "Using the Posh-ACME Plugin: `"$DNSPlugin`""
                    foreach ($Record in $TXTRecords) {
                        try {
                            Write-ToLogFile -I -C DNSChallenge -M "DNS Hostname: `"$($Record.fqdn)`" adding using plugin. Record: $($Record.fqdn) TXTValue: $($Record.TXTValue)"
                            Write-ToLogFile -D -C DNSChallenge -M "DNS Arguments: $($DNSParams | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                            Write-ToLogFile -D -C DNSChallenge -M "Domain: $($Record.SanitizedFqdn) Token: $($Record.Token) -Plugin: $DNSPlugin"
                            Publish-Challenge -Domain $Record.SanitizedFqdn -Account $PARegistration -Token $Record.Token -Plugin $DNSPlugin -PluginArgs $DNSParams
                        } catch {
                            try {
                                Write-ToLogFile -E -C DNSChallenge -M "Caught an error, $($_.Exception.Message)"
                                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                Unpublish-Challenge -Domain $Record.SanitizedFqdn -Account $PARegistration -Token $Record.Token -Plugin $DNSPlugin -PluginArgs $DNSParams
                            } catch {
                                Write-ToLogFile -E -C DNSChallenge -M "Caught an error, $($_.Exception.Message)"
                                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                            }
                        }    

                    }
                    $PoshACMEPluginUsed = $true
                }
                Write-DisplayText "Continuing, Waiting 30 seconds for the records to settle"
                Start-Sleep -Seconds 30
                Write-ToLogFile -I -C DNSChallenge -M "Start verifying the TXT records."
                $issues = $false
                try {
                    Write-DisplayText -Title "Pre-Checking the TXT records"
                    Foreach ($Record in $TXTRecords) {
                        Write-DisplayText -Line "DNS Hostname"
                        Write-DisplayText -ForeGroundColor Cyan "$($Record.fqdn)"
                        Write-DisplayText -Line "TXT Record check"
                        Write-ToLogFile -I -C DNSChallenge -M "Trying to retrieve the TXT record for `"$($Record.fqdn)`"."
                        $result = $null
                        if ($IPv6) {
                            $dnsserver = Resolve-DnsName -Name $Record.TXTName -Server $PublicDnsServerv6 -DnsOnly
                        } else {
                            $dnsserver = Resolve-DnsName -Name $Record.TXTName -Server $PublicDnsServer -DnsOnly
                        }
                        if ([String]::IsNullOrWhiteSpace($dnsserver.PrimaryServer)) {
                            Write-ToLogFile -D -C DNSChallenge -M "Using DNS Server `"$PublicDnsServer`" for resolving the TXT records."
                            $result = Resolve-DnsName -Name $Record.TXTName -Type TXT -Server $PublicDnsServer -DnsOnly
                        } else {
                            Write-ToLogFile -D -C DNSChallenge -M "Using DNS Server `"$($dnsserver.PrimaryServer)`" for resolving the TXT records."
                            $result = Resolve-DnsName -Name $Record.TXTName -Type TXT -Server $dnsserver.PrimaryServer -DnsOnly
                        }
                        Write-ToLogFile -D -C DNSChallenge -M "Output: $($result | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                        if ([String]::IsNullOrWhiteSpace($result.Strings -like "*$($Record.TXTValue)*")) {
                            Write-DisplayText -ForegroundColor Yellow "Could not determine"
                            $issues = $true
                            Write-ToLogFile -W -C DNSChallenge -M "Could not determine."
                        } else {
                            Write-DisplayText -ForegroundColor Green "OK"
                            Write-ToLogFile -I -C DNSChallenge -M "Check OK."
                        }
                    }
                } catch {
                    Write-ToLogFile -E -C DNSChallenge -M "Caught an error. Exception Message: $($_.Exception.Message)"
                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    $issues = $true
                }
                if ($issues) {
                    Write-DisplayText -Blank
                    Write-Warning "Found issues during the initial test. TXT validation might fail. Waiting an additional 30 seconds before continuing..."
                    Write-ToLogFile -W -C DNSChallenge -M "Found issues during the initial test. TXT validation might fail."
                    Start-Sleep -Seconds 20
                }
            }
    
            #endregion DNSChallenge
    
            #region FinalizingOrder
    
            if (($CertRequest.ValidationMethod -eq "dns") -and ($SessionRequestObject.ExitCode -eq 0)) {
                Write-ToLogFile -I -C FinalizingOrder -M "Check if DNS Records need to be validated."
                Write-DisplayText -Title "Sending Acknowledgment"
                $DNSValidationError = $false
                Foreach ($DNSObject in $SessionRequestObject.DNSObjects) {
                    Write-DisplayText -Line "DNS Hostname"
                    Write-DisplayText -ForeGroundColor Cyan "$($DNSObject.DNSName)"
                    Write-ToLogFile -I -C FinalizingOrder -M "Validating item: `"$($DNSObject.DNSName)`"."
                    Write-DisplayText -Line "Send Ack"
                    $PAOrderItem = Posh-ACME\Get-PAOrder -MainDomain $($CertRequest.CN) | Posh-ACME\Get-PAAuthorizations | Where-Object { $_.fqdn -eq $DNSObject.DNSName }
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    Write-ToLogFile -D -C FinalizingOrder -M "OrderItem:"
                    $PAOrderItem | Select-Object fqdn, status, DNS01Status, expires | ForEach-Object {
                        Write-ToLogFile -D -C FinalizingOrder -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    }
                    if (($PAOrderItem.DNS01Status -notlike "valid") -and ($PAOrderItem.DNS01Status -notlike "invalid")) {
                        try {
                            Write-ToLogFile -I -C FinalizingOrder -M "Validation required, start submitting Challenge."
                            Posh-ACME\Send-ChallengeAck -ChallengeUrl $($PAOrderItem.DNS01Url) -Account $PAAccount
                            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                            Write-ToLogFile -I -C FinalizingOrder -M "Submitted the Challenge successfully."
                        } catch {
                            Write-DisplayText -ForeGroundColor Red " ERROR"
                            Write-ToLogFile -E -C FinalizingOrder -M "Caught an error. Exception Message: $($_.Exception.Message)"
                            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                            Write-Error "Error while submitting the Challenge"
                            $DNSValidationError = $true
                            Invoke-RegisterError 1 "Error while submitting the Challenge"
                            Break
                        }
                        Write-DisplayText -ForeGroundColor Green " Sent Successfully"
                    } elseif ($PAOrderItem.DNS01Status -like "valid") {
                        Write-ToLogFile -I -C FinalizingOrder -M "The item is valid."
                        $DNSObject.Done = $true
                        Write-DisplayText -ForeGroundColor Green " Still valid"
                    } else {
                        Write-ToLogFile -W -C FinalizingOrder -M "Unexpected status: $($PAOrderItem.DNS01Status)"
                    }
                    $PAOrderItem = $null
                }
                if ($DNSValidationError) {
                    Continue
                }
                $i = 1
                Write-DisplayText -Title "Validation"
                Write-ToLogFile -I -C FinalizingOrder -M "Start validation."
                $ValidationError = $false
                while ($i -le 20) {
                    Write-DisplayText -Line "Attempt"
                    Write-DisplayText "$i"
                    Write-ToLogFile -I -C FinalizingOrder -M "Validation attempt: $i"
                    $PAOrderItems = Posh-ACME\Get-PAOrder -MainDomain $($CertRequest.CN) | Posh-ACME\Get-PAAuthorizations
                    Foreach ($DNSObject in $SessionRequestObject.DNSObjects) {
                        if ($DNSObject.Done -eq $false -And (-Not $ValidationError)) {
                            Write-DisplayText -Line "DNS Hostname"
                            Write-DisplayText -ForeGroundColor Cyan "$($DNSObject.DNSName)"
                            try {
                                $PAOrderItem = $PAOrderItems | Where-Object { $_.fqdn -eq $DNSObject.DNSName }
                                Write-ToLogFile -D -C FinalizingOrder -M "OrderItem:"
                                $PAOrderItem | Select-Object fqdn, status, DNS01Status, expires | ForEach-Object {
                                    Write-ToLogFile -D -C FinalizingOrder -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                                }
                                Write-DisplayText -Line "Status"
                                switch ($PAOrderItem.DNS01Status.ToLower()) {
                                    "pending" {
                                        Write-DisplayText -ForeGroundColor Yellow "$($PAOrderItem.DNS01Status)"
                                    }
                                    "invalid" {
                                        $DNSObject.Done = $true
                                        Write-DisplayText -ForeGroundColor Red "$($PAOrderItem.DNS01Status)"
                                        Write-DisplayText -Line "DNS Hostname"
                                        Write-DisplayText -ForeGroundColor Cyan "$($PAOrderItem.fqdn)"
                                        Write-DisplayText -Line "Status"
                                        Write-DisplayText -ForeGroundColor Red "ERROR [$($PAOrderItem.status)]"
                                        Write-DisplayText -ForeGroundColor Red -Line "Error Status"
                                        Write-DisplayText -ForeGroundColor Red "$($PAOrderItem.challenges.error.status)"
                                        Write-DisplayText -ForeGroundColor Red -Line "Type"
                                        Write-DisplayText -ForeGroundColor Red "$($PAOrderItem.challenges.error.type)"
                                        Write-DisplayText -ForeGroundColor Red -Line "Details"
                                        Write-DisplayText -ForeGroundColor Red "$($PAOrderItem.challenges.error.detail)"
                                        $mailDataItem.Text = "Status: $($PAOrderItem.challenges.error.status) | Type: $($PAOrderItem.challenges.error.type)`r`nDetail: $($PAOrderItem.challenges.error.detail)"
                                        Write-ToLogFile -E -C OrderValidation -M "Error: $($PAOrderItem.challenges.error | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress -ErrorAction SilentlyContinue)"
                                        Write-ToLogFile -E -C OrderValidation -M "ValidationRecord: $($PAOrderItem.challenges.validationRecord | ForEach-Object {$_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress -ErrorAction SilentlyContinue})"
                                    }
                                    "valid" {
                                        $DNSObject.Done = $true
                                        Write-DisplayText -ForeGroundColor Green "$($PAOrderItem.DNS01Status)"
                                    }
                                    default {
                                        Write-DisplayText -ForeGroundColor Red "UNKNOWN [$($PAOrderItem.DNS01Status)]"
                                    }
                                }
                                Write-ToLogFile -I -C FinalizingOrder -M "$($DNSObject.DNSName): $($PAOrderItem.DNS01Status)"
                            } catch {
                                Write-ToLogFile -E -C FinalizingOrder -M "Error while Retrieving validation status. Exception Message: $($_.Exception.Message)"
                                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                Write-Error "Error while Retrieving validation status"
                                $ValidationError = $true
                                Invoke-RegisterError 1 "Error while Retrieving validation status"
                                Break
                            }
                            $PAOrderItem = $null
                        }
                    }
                    if ($ValidationError) {
                        Break
                    }
                    if (-NOT ($SessionRequestObject.DNSObjects | Where-Object { $_.Done -eq $false })) {
                        Write-ToLogFile -I -C FinalizingOrder -M "All items validated."
                        if ($PAOrderItems | Where-Object { $_.DNS01Status -eq "invalid" }) {
                            Write-DisplayText -ForegroundColor Red "`r`nERROR: Validation Failed, invalid items found! Exiting now!"
                            Write-ToLogFile -E -C FinalizingOrder -M "Validation Failed, invalid items found!"
                            $ValidationError = $true
                            Invoke-RegisterError 1 "Validation Failed, invalid items found!"
                        }
                        if ($PAOrderItems | Where-Object { $_.DNS01Status -eq "pending" }) {
                            Write-DisplayText -ForegroundColor Red "`r`nERROR: Validation Failed, still pending items left! Exiting now!"
                            Write-ToLogFile -E -C FinalizingOrder -M "Validation Failed, still pending items left!"
                            $ValidationError = $true
                            Invoke-RegisterError 1 "Validation Failed, still pending items left!"
                        }
                        break
                    }
                    Write-ToLogFile -I -C FinalizingOrder -M "Waiting, round: $i"
                    Start-Sleep -Seconds 15
                    $i++
                    Write-DisplayText -Blank
                }
            }
            if ($ValidationError) {
                Continue
            }
            if (($CertRequest.ValidationMethod -in "http", "dns") -and ($SessionRequestObject.ExitCode -eq 0)) {
                Write-DisplayText -Title "Certificates"
                Write-DisplayText -Line "Status"
                Write-ToLogFile -I -C FinalizingOrder -M "Checking if order is ready."
                $PAOrder = Posh-ACME\Get-PAOrder -Refresh -MainDomain $($CertRequest.CN)
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                Write-ToLogFile -D -C FinalizingOrder -M "Order state: $($PAOrder.status)"
                if ($PAOrder.status -eq "ready") {
                    Write-ToLogFile -I -C FinalizingOrder -M "Order is ready."
                } else {
                    Invoke-RegisterError 1 "Order not ready! Order state: $($PAOrder.status)"
                    Write-DisplayText -ForeGroundColor Red " Error, order not ready! Order state: $($PAOrder.status)"
                    Write-ToLogFile -E -C FinalizingOrder -M "Order is still not ready, validation failed?"
                }
                if ($SessionRequestObject.ExitCode -eq 0) {
                    Write-ToLogFile -I -C FinalizingOrder -M "Requesting certificate."
                    try {
                        if ($CertRequest.ForceCertRenew) {
                            $NewCertificates = New-PACertificate -Domain $($SessionRequestObject.DNSObjects.DNSName) -Force -DirectoryUrl $BaseService -PfxPass $(ConvertTo-PlainText -SecureString $PfxPassword) -CertKeyLength $CertRequest.KeyLength -FriendlyName $CertRequest.FriendlyName -ErrorAction stop
                        } else {
                            $NewCertificates = New-PACertificate -Domain $($SessionRequestObject.DNSObjects.DNSName) -DirectoryUrl $BaseService -PfxPass $(ConvertTo-PlainText -SecureString $PfxPassword) -CertKeyLength $CertRequest.KeyLength -FriendlyName $CertRequest.FriendlyName -ErrorAction stop
                        }
                        Write-ToLogFile -D -C FinalizingOrder -M "$($NewCertificates | Select-Object Subject,NotBefore,NotAfter,KeyLength | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                        Write-ToLogFile -I -C FinalizingOrder -M "Certificate requested successfully."
                    } catch {
                        Write-ToLogFile -I -C FinalizingOrder -M "Failed to request certificate."
                    }
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    Start-Sleep -Seconds 1
                }
            }
    
            #endregion FinalizingOrder
    
            #region CertFinalization
    
            if (($CertRequest.ValidationMethod -in "http", "dns") -and ($SessionRequestObject.ExitCode -eq 0)) {
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                $CertificateAlias = "LECRT-$SessionDateTime-$($CertRequest.CN.Replace('*.',''))"
                $CertificateDirectory = Join-Path -Path $($CertRequest.CertDir) -ChildPath "$CertificateAlias"
                Write-ToLogFile -I -C CertFinalization -M "Create directory `"$CertificateDirectory`" for storing the new certificates."
                New-Item $CertificateDirectory -ItemType directory -Force | Out-Null
                $CertificateName = "$($ScriptDateTime.ToString("yyyyMMddHHmm"))-$($CertRequest.CN.Replace('*.',''))"
                if (Test-Path $CertificateDirectory) {
                    Write-ToLogFile -I -C CertFinalization -M "Retrieving certificate info."
                    $PACertificate = Posh-ACME\Get-PACertificate -MainDomain $($CertRequest.CN)
                    Write-ToLogFile -I -C CertFinalization -M "Retrieved successfully."
                    if ([String]::IsNullOrEmpty($($PACertificate.ChainFile))) {
                        Write-DisplayText -ForeGroundColor Red " Error, certificate not found!"
                        Write-ToLogFile -E -C CertFinalization -M "No Certificate Found!"
                        Invoke-RegisterError 1 "No Certificate Found!"
                        Continue
                    }
                    $ChainFile = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 "$($PACertificate.ChainFile)"
                    Write-ToLogFile -D -C CertFinalization -M $($ChainFile | Select-Object DnsNameList, Subject, @{ Name = 'NotBefore'; Expression = { $_.NotBefore.ToString('yyyy-MM-dd HH:mm:ss') } }, @{ Name = 'NotAfter'; Expression = { $_.NotAfter.ToString('yyyy-MM-dd HH:mm:ss') } }, SerialNumber, Thumbprint, Issuer | ConvertTo-Json -WarningAction SilentlyContinue -Compress -Depth 8)
                    $IntermediateCACertName = $ChainFile.Subject.Split(",")[0].Replace('CN=', $null).Replace("'", $null).Replace('(', $null).Replace(')', $null)
                    $IntermediateCACertKeyName = $IntermediateCACertName
                    if ($IntermediateCACertKeyName.length -gt 26) {
                        $IntermediateCACertKeyName = $IntermediateCACertKeyName -Replace '(?sm)\W', $null
                        Write-ToLogFile -D -C CertFinalization -M "Intermediate certificate to long, new name: `"$IntermediateCACertKeyName`"."
                    }
                    if ($IntermediateCACertKeyName.length -gt 26) {
                        $IntermediateCACertKeyName = "$($IntermediateCACertKeyName.subString(0,26))"
                        Write-ToLogFile -D -C CertFinalization -M "Intermediate certificate STILL to long, new name: `"$IntermediateCACertKeyName`"."
                    }
                    $IntermediateCAFileName = "$($IntermediateCACertKeyName)-$($ChainFile.NotAfter.ToString('yyyy')).crt"
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
                            $CertificateKeyFileName = "$($CertificateAlias.subString(0,59)).key"
                            $CertificatePfxFileName = "$($CertificateAlias.subString(0,59)).pfx"
                            $CertificatePemFileName = "$($CertificateAlias.subString(0,59)).pem"
                        } else {
                            $CertificateFileName = "$($CertificateAlias).crt"
                            $CertificateKeyFileName = "$($CertificateAlias).key"
                            $CertificatePfxFileName = "$($CertificateAlias).pfx"
                            $CertificatePemFileName = "$($CertificateAlias).pem"
                        }
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
                            $CertificateKeyFileName = "TST-$($CertificateAlias.subString(0,55)).key"
                            $CertificatePfxFileName = "TST-$($CertificateAlias.subString(0,55)).pfx"
                            $CertificatePemFileName = "TST-$($CertificateAlias.subString(0,55)).pem"
                        } else {
                            $CertificateFileName = "TST-$($CertificateAlias).crt"
                            $CertificateKeyFileName = "TST-$($CertificateAlias).key"
                            $CertificatePfxFileName = "TST-$($CertificateAlias).pfx"
                            $CertificatePemFileName = "TST-$($CertificateAlias).pem"
                        }
                        $CertificatePfxWithChainFileName = "TST-$($CertificateAlias)-WithChain.pfx"
                    }
                    Write-ToLogFile -D -C CertFinalization -M "Crt: `"$CertificateFileName`"($($CertificateFileName.length) max 63)"
                    Write-ToLogFile -D -C CertFinalization -M "Key: `"$CertificateKeyFileName`"($($CertificateKeyFileName.length) max 63)"
                    Write-ToLogFile -D -C CertFinalization -M "Pfx: `"$CertificatePfxFileName`"($($CertificatePfxFileName.length) max 63)"
                    Write-ToLogFile -D -C CertFinalization -M "Pem: `"$CertificatePemFileName`"($($CertificatePemFileName.length) max 63)"
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    $CertificateFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificateFileName
                    $CertificateKeyFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificateKeyFileName
                    $CertificatePfxFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificatePfxFileName
                    $CertificatePfxWithChainFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificatePfxWithChainFileName
                    Copy-Item $PACertificate.CertFile -Destination $CertificateFullPath -Force
                    Copy-Item $PACertificate.KeyFile -Destination $CertificateKeyFullPath -Force
                    Copy-Item $PACertificate.PfxFullChain -Destination $CertificatePfxWithChainFullPath -Force
                    $certificate = Get-PfxData -FilePath $CertificatePfxWithChainFullPath -Password $PfxPassword
                    $NewCertificates = Export-PfxCertificate -PFXData $certificate -FilePath $CertificatePfxFullPath -Password $PfxPassword -ChainOption EndEntityCertOnly -Force
                    Write-ToLogFile -I -C CertFinalization -M "Certificates Finished."
                    if ($CertRequest.ForceCertRenew) {
                        $CertRequest.ForceCertRenew = $false
                        Write-ToLogFile -D -C CertFinalization -M "ForceCertRenew was reset to `"false`""
                    }
                    
                } else {
                    Write-ToLogFile -E -C CertFinalization -M "Could not test Certificate directory."
                }
            }
    
            #endregion CertFinalization
    
            #region ADC-CertUpload
    
            if (($CertRequest.ValidationMethod -in "http", "dns") -and ($SessionRequestObject.ExitCode -eq 0)) {
                try {
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    Write-ToLogFile -I -C ADC-CertUpload -M "Uploading the certificate to the Citrix ADC."
                    Write-ToLogFile -D -C ADC-CertUpload -M "Retrieving existing CA Intermediate Certificate."
                    $Filters = @{"serial" = "$($ChainFile.SerialNumber)" }
                    $ADCIntermediateCA = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey -Filters $Filters -ErrorAction SilentlyContinue
                    if ([String]::IsNullOrEmpty($($ADCIntermediateCA.sslcertkey.certkey))) {
                        Write-ToLogFile -D -C ADC-CertUpload -M "Second attempt, trying without leading zero's."
                        $Filters = @{"serial" = "$($ChainFile.SerialNumber.TrimStart("00"))" }
                        $ADCIntermediateCA = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey -Filters $Filters -ErrorAction SilentlyContinue
                    }
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    Write-ToLogFile -D -C ADC-CertUpload -M "Details:"
                    $ADCIntermediateCA.sslcertkey | Select-Object certkey, serial, clientcertnotbefore, clientcertnotafter, issuer, subject, cert | ForEach-Object {
                        Write-ToLogFile -D -C ADC-CertUpload -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    }
                    Write-ToLogFile -D -C ADC-CertUpload -M "Checking if IntermediateCA `"$IntermediateCACertKeyName`" already exists."
                    if ([String]::IsNullOrEmpty($($ADCIntermediateCA.sslcertkey.certkey))) {
                        try {
                            Write-ToLogFile -I -C ADC-CertUpload -M "Uploading `"$IntermediateCAFileName`" to the ADC."
                            if ('PSEdition' -notin $PSVersionTable.Keys -or $PSVersionTable.PSEdition -eq 'Desktop') {
                                $IntermediateCABase64 = [System.Convert]::ToBase64String($(Get-Content $IntermediateCAFullPath -Encoding "Byte"))
                            } else {
                                $IntermediateCABase64 = [System.Convert]::ToBase64String($(Get-Content $IntermediateCAFullPath -AsByteStream))
                            }
                            $payload = @{"filename" = "$IntermediateCAFileName"; "filecontent" = "$IntermediateCABase64"; "filelocation" = "/nsconfig/ssl/"; "fileencoding" = "BASE64"; }
                            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type systemfile -Payload $payload
                            Write-ToLogFile -I -C ADC-CertUpload -M "Succeeded, Add the certificate to the ADC config."
                            $payload = @{"certkey" = "$IntermediateCACertKeyName"; "cert" = "/nsconfig/ssl/$($IntermediateCAFileName)"; }
                            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload
                            Write-ToLogFile -I -C ADC-CertUpload -M "Certificate added."
                        } catch {
                            Write-DisplayText -Blank
                            Write-Warning "Could not upload or get the Intermediate CA `"$($IntermediateCACertName)`",`r`n         manual action may be required"
                            Write-ToLogFile -W -C ADC-CertUpload -M "Could not upload or get the Intermediate CA ($($IntermediateCACertName)), manual action may be required."
                            Write-DisplayText -Blank
                            Write-DisplayText -Line "Status"
                        }
                    } else {
                        $IntermediateCACertKeyName = $ADCIntermediateCA.sslcertkey.certkey
                        Write-ToLogFile -D -C ADC-CertUpload -M "IntermediateCA exists, saving existing name `"$IntermediateCACertKeyName`" (Serial:$($ADCIntermediateCA.sslcertkey.serial)) for later use."
                    }
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    if ([String]::IsNullOrEmpty($($CertRequest.CertKeyNameToUpdate))) {
                        Write-ToLogFile -I -C ADC-CertUpload -M "CertKeyNameToUpdate variable was not configured."
                        $ExistingCertificateDetails = $Null
                    } else {
                        Write-ToLogFile -D -C ADC-CertUpload -M "CertKeyNameToUpdate: `"$($CertRequest.CertKeyNameToUpdate)`""

                        Write-ToLogFile -I -C ADC-CertUpload -M "CertKeyNameToUpdate variable was configured, trying to retrieve data."
                        $Filters = @{"certkey" = "$($CertRequest.CertKeyNameToUpdate)" }
                        $ExistingCertificateDetails = try { Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey -Resource $($CertRequest.CertKeyNameToUpdate) -Filters $Filters -ErrorAction SilentlyContinue } catch { $null }
                    }
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    if (-Not [String]::IsNullOrEmpty($($ExistingCertificateDetails.sslcertkey.certkey))) {
                        $CertificateCertKeyName = $($ExistingCertificateDetails.sslcertkey.certkey)
                        Write-ToLogFile -I -C ADC-CertUpload -M "Existing certificate `"$CertificateCertKeyName`" found on the ADC, start updating."
                        try {
                            Write-ToLogFile -D -C ADC-CertUpload -M "Unlinking certificate."
                            try {
                                Write-ToLogFile -D -C ADC-CertUpload -M "Linked details (before-unlink)"
                                $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type "sslcertchain_binding" -Resource $CertificateCertKeyName
                                $response.sslcertchain_binding.sslcertchain_sslcertkey_binding | ForEach-Object {
                                    Write-ToLogFile -D -C ADC-CertUpload -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                                }
                            } catch {
                                Write-ToLogFile -D -C ADC-CertUpload -M "Could not determine linked details"
                            }
                            $payload = @{"certkey" = "$CertificateCertKeyName"; }
                            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action unlink
                            try {
                                Write-ToLogFile -D -C ADC-CertUpload -M "Linked details (after-unlink)"
                                $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type "sslcertchain_binding" -Resource $CertificateCertKeyName
                                $response.sslcertchain_binding.sslcertchain_sslcertkey_binding | ForEach-Object {
                                    Write-ToLogFile -D -C ADC-CertUpload -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                                }
                            } catch {
                                Write-ToLogFile -D -C ADC-CertUpload -M "Could not determine linked details"
                            }
                        } catch {
                            Write-ToLogFile -D -C ADC-CertUpload -M "Certificate was not linked."
                        }
                        $ADCCertKeyUpdating = $true
                    } else {
                        Write-ToLogFile -I -C ADC-CertUpload -M "No existing certificate found on the ADC that needs to be updated."
                        if ([String]::IsNullOrEmpty($($CertRequest | Get-Member -Name RemovePrevious))) {
                            $CertRequest | Add-Member -MemberType NoteProperty -Name "RemovePrevious" -Value $false
                        } else {
                            $CertRequest.RemovePrevious = $false
                        }
                        if (-Not [String]::IsNullOrEmpty($($CertRequest.CertKeyNameToUpdate))) {
                            $CertificateCertKeyName = $($CertRequest.CertKeyNameToUpdate)
                            Write-ToLogFile -I -C ADC-CertUpload -M "Adding new certificate as `"$($CertRequest.CertKeyNameToUpdate)`""
                        } else {
                            $CertificateCertKeyName = $CertificateName
                            $ExistingCertificateDetails = try { Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey -Resource $CertificateName -ErrorAction SilentlyContinue } catch { $null }
                            if (-Not [String]::IsNullOrEmpty($($ExistingCertificateDetails.sslcertkey.certkey))) {
                                Write-Warning "Certificate `"$CertificateCertKeyName`" already exists, please update manually! Or if you need to update an existing Certificate, specify the `"-CertKeyNameToUpdate`" Parameter."
                                Write-ToLogFile -W -C ADC-CertUpload -M "Certificate `"$CertificateCertKeyName`" already exists, please update manually! Or if you need to update an existing Certificate, specify the `"-CertKeyNameToUpdate`" Parameter."
                                Invoke-RegisterError 1 "Certificate `"$CertificateCertKeyName`" already exists, please update manually! Or if you need to update an existing Certificate, specify the `"-CertKeyNameToUpdate`" Parameter."
                                Continue
                            }
                        }
                        $ADCCertKeyUpdating = $false
                    }
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    Write-ToLogFile -D -C ADC-CertUpload -M "CertificateName: $CertificateName"
                    Write-ToLogFile -D -C ADC-CertUpload -M "CertificateCertKeyName: $CertificateCertKeyName"
                    if ('PSEdition' -notin $PSVersionTable.Keys -or $PSVersionTable.PSEdition -eq 'Desktop') {
                        $CertificatePfxBase64 = [System.Convert]::ToBase64String($(Get-Content $CertificatePfxFullPath -Encoding "Byte"))
                    } else {
                        $CertificatePfxBase64 = [System.Convert]::ToBase64String($(Get-Content $CertificatePfxFullPath -AsByteStream))
                    }
                    Write-ToLogFile -I -C ADC-CertUpload -M "Uploading the Pfx certificate."
                    $payload = @{"filename" = "$CertificatePfxFileName"; "filecontent" = "$CertificatePfxBase64"; filelocation = "/nsconfig/ssl/"; fileencoding = "BASE64"; }
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type systemfile -Payload $payload
    
                    if ($ADCVersion -lt 12) {
                        Write-ToLogFile -D -C ADC-CertUpload -M "ADC verion is lower than 12, converting the Pfx certificate to a pem file ($CertificatePemFileName)"
                        $payload = @{"outfile" = "$CertificatePemFileName"; "Import" = "true"; "pkcs12file" = "$CertificatePfxFileName"; "des3" = "true"; "password" = "$(ConvertTo-PlainText -SecureString $PfxPassword)"; "pempassphrase" = "$(ConvertTo-PlainText -SecureString $PfxPassword)" }
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslpkcs12 -Payload $payload -Action convert
                        $payload = @{certkey = "$CertificateCertKeyName"; cert = "$CertificatePemFileName"; key = $CertificatePemFileName; password = "true"; inform = "PEM"; passplain = "$(ConvertTo-PlainText -SecureString $PfxPassword)" }
                    } else {
                        Write-ToLogFile -D -C ADC-CertUpload -M "ADC verion is higher than 12, using Pfx certificates"
                        $payload = @{certkey = $CertificateCertKeyName; cert = $CertificatePfxFileName; key = $CertificatePfxFileName; password = "true"; inform = "PFX"; passplain = "$(ConvertTo-PlainText -SecureString $PfxPassword)" }
                    }
                    try {
                        if ($ADCCertKeyUpdating) {
                            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                            Write-ToLogFile -I -C ADC-CertUpload -M "Update the certificate and key to the ADC config."
                            try {
                                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action update
                                Write-ToLogFile -I -C ADC-CertUpload -M "Certificate updated successfully."
                            } catch {
                                Write-ToLogFile -E -C ADC-RemovePrevious -M "Could not update certificate at first atempt, $($_.Exception.Message)"
                                try {
                                    Write-ToLogFile -I -C ADC-CertUpload -M "Certificate update second atempt (nodomaincheck=true)"
                                    $payload.nodomaincheck = $true
                                    $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action update
                                    Write-ToLogFile -I -C ADC-CertUpload -M "Certificate updated successfully!"
                                } catch {
                                    Write-ToLogFile -E -C ADC-RemovePrevious -M "Could not remove previous files, $($_.Exception.Message)"
                                    Throw "Certificate update failed!"
                                }
                            }
                            if ($CertRequest.RemovePrevious) {
                                try {
                                    Write-ToLogFile -I -C ADC-RemovePrevious -M "-RemovePrevious parameter was specified, retrieving files."
                                    $Arguments = @{ filename = "$($ExistingCertificateDetails.sslcertkey.cert)"; filelocation = "/nsconfig/ssl/" }
                                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type systemfile -Arguments $Arguments
                                    $PreviousCertFileName = $response.systemfile.filename
                                    Write-ToLogFile -D -C ADC-RemovePrevious -M "PreviousCertFileName: `"$PreviousCertFileName`""
                                    $Arguments = @{ filename = "$($ExistingCertificateDetails.sslcertkey.key)"; filelocation = "/nsconfig/ssl/" }
                                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type systemfile -Arguments $Arguments
                                    $PreviousKeyFileName = $response.systemfile.filename
                                    Write-ToLogFile -D -C ADC-RemovePrevious -M "PreviousKeyFileName: `"$PreviousKeyFileName`""
                                    $Arguments = @{ filelocation = "/nsconfig/ssl/" }
                                    if (-Not [String]::IsNullOrEmpty($PreviousCertFileName)) {
                                        Write-ToLogFile -I -C ADC-RemovePrevious -M "Removing file: `"/nsconfig/ssl/$PreviousCertFileName`""
                                        $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type systemfile -Resource $PreviousCertFileName -Arguments $Arguments
                                        Write-ToLogFile -I -C ADC-RemovePrevious -M "Success"
                                    }
                                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                                    if ((-Not [String]::IsNullOrEmpty($PreviousKeyFileName)) -And ($PreviousCertFileName -ne $PreviousKeyFileName)) {
                                        Write-ToLogFile -I -C ADC-RemovePrevious -M "Removing file: `"/nsconfig/ssl/$PreviousKeyFileName`""
                                        $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type systemfile -Resource $PreviousKeyFileName -Arguments $Arguments
                                        Write-ToLogFile -I -C ADC-RemovePrevious -M "Success"
                                    } else {
                                        Write-ToLogFile -I -C ADC-RemovePrevious -M "Same file, `"/nsconfig/ssl/$PreviousKeyFileName`" was already removed."
                                    }
                                } catch {
                                    Write-ToLogFile -E -C ADC-RemovePrevious -M "Could not remove previous files, $($_.Exception.Message)"
                                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                }
                            } else {
                                Write-ToLogFile -I -C ADC-RemovePrevious -M "-RemovePrevious parameter was NOT specified, not removing previous files."
                            }
                        } else {
                            Write-ToLogFile -I -C ADC-CertUpload -M "Add the certificate and key to the ADC config."
                            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload
                            Write-ToLogFile -I -C ADC-CertUpload -M "Added successfully."
                        }
                    } catch {
                        Write-Warning "Caught an error, certificate not added to the ADC Config"
                        Write-Warning "Details: $($_.Exception.Message | Out-String)"
                        Write-ToLogFile -E -C ADC-CertUpload -M "Caught an error, certificate not added to the ADC Config. Exception Message: $($_.Exception.Message)"
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                        Write-DisplayText -Line "Status"
                    }
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    Write-ToLogFile -I -C ADC-CertUpload -M "Link `"$CertificateCertKeyName`" to `"$IntermediateCACertKeyName`""
                    try {
                        $payload = @{"certkey" = "$CertificateCertKeyName"; "linkcertkeyname" = "$IntermediateCACertKeyName"; }
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action link -ErrorAction Stop
                        Write-ToLogFile -I -C ADC-CertUpload -M "Link successfully."
                        Write-ToLogFile -D -C ADC-CertUpload -M "Response: $($response | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    } catch {
                        Write-DisplayText -Blank
                        Write-Warning -Message "Could not link the certificate`"$CertificateCertKeyName`"`r`n         to Intermediate `"$IntermediateCACertKeyName`""
                        Write-ToLogFile -E -C ADC-CertUpload -M "Could not link the certificate `"$CertificateCertKeyName`" to Intermediate `"$IntermediateCACertKeyName`"."
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                        Write-DisplayText -Blank
                        Write-DisplayText -Line "Status"
                    }
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    try {
                        Write-ToLogFile -D -C ADC-CertUpload -M "Linked details (after-link)"
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type "sslcertchain_binding" -Resource $CertificateCertKeyName
                        $response.sslcertchain_binding.sslcertchain_sslcertkey_binding | ForEach-Object {
                            Write-ToLogFile -D -C ADC-CertUpload -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                        }
                    } catch {
                        Write-ToLogFile -D -C ADC-CertUpload -M "Could not determine linked details"
                    }
                    Write-DisplayText -ForeGroundColor Green " Ready"

                    if ($PfxPasswordGenerated) {
                        Write-DisplayText -Blank
                        Write-Warning "No Password was specified, so a random password was generated!"
                        Write-ToLogFile -W -C ADC-CertUpload -M "No Password was specified, so a random password was generated! (Password not saved in Log)"
                        Write-DisplayText -ForeGroundColor Magenta "`r`n********************************************************************"
                        Write-DisplayText -Blank
                        Write-DisplayText -Line "PFX Password"
                        Write-DisplayText -ForeGroundColor Yellow $(ConvertTo-PlainText -SecureString $PfxPassword)
                        Write-DisplayText -ForeGroundColor Magenta "`r`n********************************************************************"
                    }
                    Write-DisplayText -Line "Certificate Usage" 
                    if ($Production) {
                        Write-DisplayText -ForeGroundColor Cyan "Production"
                    } else {
                        Write-DisplayText -ForeGroundColor Yellow "!! Test !!"
                    }
                    try {
                        $PAOrder = Posh-ACME\Get-PAOrder -Refresh -MainDomain $($CertRequest.CN)
                        if (-Not ($CertRequest | Get-Member -Name "CertExpires" -ErrorAction SilentlyContinue -MemberType NoteProperty)) {
                            $CertRequest | Add-Member -MemberType NoteProperty -Name "CertExpires" -Value $PAOrder.CertExpires
                        } else {
                            $CertRequest.CertExpires = $PAOrder.CertExpires
                        }
                        if (-Not ($CertRequest | Get-Member -Name "RenewAfter" -ErrorAction SilentlyContinue -MemberType NoteProperty)) {
                            $CertRequest | Add-Member -MemberType NoteProperty -Name "RenewAfter" -Value $PAOrder.RenewAfter
                        } else {
                            $CertRequest.RenewAfter = $PAOrder.RenewAfter
                        }
                        $CertRequest.CurrentCertIsProduction = [bool]::Parse($Production)
                        Write-ToLogFile -D -C ADC-CertUpload -M "CertExpires: $($CertRequest.CertExpires) | RenewAfter: $($CertRequest.RenewAfter)"
                        $SaveConfig = $true
                    } catch {
                        Write-ToLogFile -E -C ADC-CertUpload -M "Error while retrieving expiration details, $($_.Exception.Message)"
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    }
                    $FinalCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 "$(Join-Path -Path $CertificateDirectory -ChildPath $CertificateFileName)"
                    try {
                        $renewAfterDays = 0
                        if ($CertRequest.CertExpires -match '[0-9-]{8,10}T[0-9:]{6,8}Z') {
                            $renewAfterDays = [Int]([datetime]$CertRequest.RenewAfter - (Get-Date)).TotalDays
                        }
                    } catch {
                        $renewAfterDays = 0
                    }
                    try {
                        $expireDays = 0
                        if ($CertRequest.CertExpires -match '[0-9-]{8,10}T[0-9:]{6,8}Z') {
                            $expireDays = [Int]([datetime]$CertRequest.CertExpires - (Get-Date)).TotalDays
                            $mailDataItem.CertExpiresDays = $expireDays
                        }
                    } catch {
                        $expireDays = 0
                    }
            
                    Write-DisplayText -Line "Certificate expires in" 
                    Write-DisplayText -ForeGroundColor Cyan "$expireDays days ($($CertRequest.CertExpires))"
                    Write-DisplayText -Line "Renew after" 
                    Write-DisplayText -ForeGroundColor Cyan "$renewAfterDays days ($($CertRequest.RenewAfter))"
                    Write-DisplayText -Line "Public Key Size"
                    Write-DisplayText -ForeGroundColor Cyan "$($FinalCertificate.PublicKey.key.KeySize)"
                    Write-DisplayText -Line "Certkey Name" 
                    Write-DisplayText -ForeGroundColor Cyan $CertificateCertKeyName
                    Write-DisplayText -Line "Intermediate" 
                    Write-DisplayText -ForeGroundColor Cyan "$($IntermediateCACertName)  [$($ChainFile.NotAfter.ToString('yyyy-MM-dd'))]"
                    Write-DisplayText -Line "Intermediate Certkey Name"
                    Write-DisplayText -ForeGroundColor Cyan $IntermediateCACertKeyName
                    Write-DisplayText -Line "Cert Dir" 
                    Write-DisplayText -ForeGroundColor Cyan $CertificateDirectory
                    Write-DisplayText -Line "CRT Filename"
                    Write-DisplayText -ForeGroundColor Cyan $CertificateFileName
                    Write-DisplayText -Line "KEY Filename"
                    Write-DisplayText -ForeGroundColor Cyan $CertificateKeyFileName
                    Write-DisplayText -Line "PFX Filename"
                    Write-DisplayText -ForeGroundColor Cyan $CertificatePfxFileName
                    Write-DisplayText -Line "PFX (with Chain)"
                    Write-DisplayText -ForeGroundColor Cyan $CertificatePfxWithChainFileName
                    Write-DisplayText -Line "Certificate State"
                    Write-DisplayText -ForeGroundColor Green "Finished with the certificate for CN: $($CertRequest.CN)!"
                    Write-ToLogFile -I -C ADC-CertUpload -M "Keysize: $($CertRequest.KeyLength)"
                    Write-ToLogFile -I -C ADC-CertUpload -M "Cert Dir: $CertificateDirectory"
                    Write-ToLogFile -I -C ADC-CertUpload -M "Certkey Name: $CertificateCertKeyName"
                    Write-ToLogFile -I -C ADC-CertUpload -M "Intermediate: $($IntermediateCACertName)  [$($ChainFile.NotAfter.ToString('yyyy-MM-dd'))]"
                    Write-ToLogFile -I -C ADC-CertUpload -M "Intermediate Certkey Name: $IntermediateCACertKeyName"
                    Write-ToLogFile -I -C ADC-CertUpload -M "CRT Filename: $CertificateFileName"
                    Write-ToLogFile -I -C ADC-CertUpload -M "KEY Filename: $CertificateKeyFileName"
                    Write-ToLogFile -I -C ADC-CertUpload -M "PFX Filename: $CertificatePfxFileName"
                    Write-ToLogFile -I -C ADC-CertUpload -M "PFX (with Chain): $CertificatePfxWithChainFileName"
                    Write-ToLogFile -I -C ADC-CertUpload -M "Finished with the certificate for CN: $($CertRequest.CN)!"
                    $mailDataItem.Location = $CertificateDirectory
                    $mailDataItem.CertKeyName = $CertificateCertKeyName

                    try {
                        $mailDataItem.Text += "Valid for: $expireDays days ($($CertRequest.CertExpires))`r`n"
                        $mailDataItem.Text += "Renew after: $renewAfterDays days ($($CertRequest.RenewAfter))`r`n"
                        $mailDataItem.Text += "Public Key Size: $($FinalCertificate.PublicKey.key.KeySize)`r`n"
                        $mailDataItem.Text += "Issued by CA: $($IntermediateCACertName)  [$($ChainFile.NotAfter.ToString('yyyy-MM-dd'))] - (ADC SSL Certkey Name: $IntermediateCACertKeyName)"
                        $mailDataItem.Code = "OK"
                    } catch {
                        Write-ToLogFile -D -C ADC-CertUpload-Mail -M "Error while gathering data for mail, Error: $($_.Exception.Message)"
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                        $mailDataItem.Text += "`r`nError while gathering data for mail, Error: $($_.Exception.Message)"
                    }

                    ##Saving Config if required    
                    Save-ADCConfig -SaveADCConfig:$($Parameters.settings.SaveADCConfig)

                    #region IISActions
    
                    if ($CertRequest.UpdateIIS) {
                        Write-DisplayText -Title "IIS"
                        try {
                            Import-Module WebAdministration -ErrorAction Stop
                            $WebAdministrationModule = $true
                        } catch {
                            $WebAdministrationModule = $false
                        }
                        if ($WebAdministrationModule) {
                            try {
                                Write-DisplayText -Line "IIS Site" 
                                Write-DisplayText -ForeGroundColor Cyan $($CertRequest.IISSiteToUpdate)
                                $ImportedCertificate = Import-PfxCertificate -FilePath $CertificatePfxFullPath -CertStoreLocation Cert:\LocalMachine\My -Password $PfxPassword
                                Write-ToLogFile -D -C IISActions -M "ImportedCertificate $($ImportedCertificate | Select-Object Thumbprint,Subject | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                                Write-DisplayText -Line "Binding" 
                                $CurrentWebBinding = Get-WebBinding -Name $CertRequest.IISSiteToUpdate -Protocol https
                                if ($CurrentWebBinding) {
                                    Write-ToLogFile -I -C IISActions -M "Current binding exists."
                                    Write-DisplayText -ForeGroundColor Green "Current [$($CurrentWebBinding.bindingInformation)]"
                                    $CurrentCertificateBinding = Get-Item IIS:\SslBindings\0.0.0.0!443 -ErrorAction SilentlyContinue
                                    Write-ToLogFile -D -C IISActions -M "CurrentCertificateBinding $($CurrentCertificateBinding | Select-Object IPAddress,Port,Host,Store,@{ name="Sites"; expression={$_.Sites.Value} } | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                                    Write-DisplayText -Line "Unbinding Current Cert" 
                                    Write-ToLogFile -I -C IISActions -M "Unbinding Current Certificate, $($CurrentCertificateBinding.Thumbprint)"
                                    $CurrentCertificateBinding | Remove-Item -ErrorAction SilentlyContinue
                                    Write-DisplayText -ForeGroundColor Yellow "Removed [$($CurrentCertificateBinding.Thumbprint)]"
                                } else {
                                    Write-ToLogFile -I -C IISActions -M "No current binding exists, trying to add one."
                                    try {
                                        New-WebBinding -Name $CertRequest.IISSiteToUpdate -IPAddress "*" -Port 443 -Protocol https
                                        $CurrentWebBinding = Get-WebBinding -Name $CertRequest.IISSiteToUpdate -Protocol https
                                        Write-DisplayText -ForeGroundColor Green "New, created [$($CurrentWebBinding.bindingInformation)]"
                                        Write-ToLogFile -D -C IISActions -M "CurrentCertificateBinding $($CurrentCertificateBinding | Select-Object IPAddress,Port,Host,Store,@{ name="Sites"; expression={$_.Sites.Value} } | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                                    } catch {
                                        Write-DisplayText -ForeGroundColor Red "Failed"
                                        Write-ToLogFile -E -C IISActions -M "Failed. Exception Message: $($_.Exception.Message)"
                                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                    }
                                }
                                try {
                                    Write-ToLogFile -I -C IISActions -M "Binding new certificate, $($ImportedCertificate.Thumbprint)"
                                    Write-DisplayText -Line "Binding New Cert" 
                                    New-Item -Path IIS:\SSLBindings\0.0.0.0!443 -Value $ImportedCertificate -ErrorAction Stop | Out-Null
                                    Write-DisplayText -ForeGroundColor Green "Bound [$($ImportedCertificate.Thumbprint)]"
                                    $mailDataItem.Text += "IIS Binding updated for site `"$($CertRequest.IISSiteToUpdate)`": $($ImportedCertificate.Thumbprint)"
                                } catch {
                                    Write-DisplayText -ForeGroundColor Red "Could not bind"
                                    Write-ToLogFile -E -C IISActions -M "Could not bind. Exception Message: $($_.Exception.Message)"
                                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                }
                            } catch {
                                Write-DisplayText -ForeGroundColor Red "Caught an error while updating"
                                Write-ToLogFile -E -C IISActions -M "Caught an error while updating. Exception Message: $($_.Exception.Message)"
                                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                            }
                        } else {
                            Write-DisplayText -Line "Module" 
                            Write-DisplayText -ForeGroundColor Red "WebAdministration Module could not be found, please install feature!"
                        }
                    }
    
                    #endregion IISActions

                    if ($CertRequest.ValidationMethod -eq "dns") {
                        if ($PoshACMEPluginUsed -ne $true) {
                            Write-DisplayText -ForegroundColor Magenta "`r`n********************************************************************"
                            Write-DisplayText -ForegroundColor Magenta "* IMPORTANT: Don't forget to delete the created DNS records!!      *"
                            Write-DisplayText -ForegroundColor Magenta "********************************************************************"
                            Write-ToLogFile -I -C ADC-CertUpload -M "Don't forget to delete the created DNS records!!"
                            foreach ($Record in $TXTRecords) {
                                Write-DisplayText -Blank
                                Write-DisplayText -Line "DNS Hostname"
                                Write-DisplayText -ForeGroundColor Cyan "$($Record.fqdn)"
                                Write-DisplayText -Line "TXT Record Name"
                                Write-DisplayText -ForeGroundColor Yellow "$($Record.TXTName)"
                                Write-ToLogFile -I -C ADC-CertUpload -M "TXT Record: `"$($Record.TXTName)`""
                            }
                            Write-DisplayText -Blank
                            Write-DisplayText -ForegroundColor Magenta "********************************************************************"
                        } else {
                            Write-ToLogFile -I -C ADC-CertUpload -M "Using the Posh-ACME Plugin: `"$DNSPlugin`""
                            foreach ($Record in $TXTRecords) {
                                try {
                                    Write-ToLogFile -I -C ADC-CertUpload -M "Removing DNS record for $($Record.fqdn)"
                                    Write-ToLogFile -D -C DNSChallenge -M "DNS Arguments: $($DNSParams | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                                    Write-ToLogFile -D -C DNSChallenge -M "Domain: $($Record.SanitizedFqdn) Token: $($Record.Token) -Plugin: $DNSPlugin"
                                    Unpublish-Challenge -Domain $Record.SanitizedFqdn -Account $PARegistration -Token $Record.Token -Plugin $DNSPlugin -PluginArgs $DNSParams
                                } catch {
                                    Write-ToLogFile -E -C ADC-CertUpload -M "Caught an error, $($_.Exception.Message)"
                                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                }
                            }
                        }

                    }
                    if (-not $Production) {
                        Write-DisplayText -ForeGroundColor Yellow "`r`nYou are now ready for the Production version!"
                        Write-DisplayText -ForeGroundColor Yellow "Add the `"-Production`" parameter and rerun the same script." -PostBlank
                        Write-ToLogFile -I -C ADC-CertUpload -M "You are now ready for the Production version! Add the `"-Production`" parameter and rerun the same script."
                    }
                } catch {
                    Write-ToLogFile -E -C ADC-CertUpload -M "Certificate completion failed. Exception Message: $($_.Exception.Message)"
                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    Write-Error "Certificate completion failed. Exception Message: $($_.Exception.Message)"
                    Invoke-RegisterError 1 "Certificate completion failed. Exception Message: $($_.Exception.Message)"
                    Continue
                }
                if ($SessionRequestObject.ErrorOccurred -gt 0 ) {
                    Write-DisplayText -Blank
                    Write-Warning "There were $($SessionRequestObject.ErrorOccurred) errors during this request, please check logs!"
                    $mailDataItem.Text += "`r`nThere were $($SessionRequestObject.ErrorOccurred) errors during this request, please check logs!`r`n"
                }

            }
    
            #endregion ADC-CertUpload

            #region PostPoSHScriptFilename
            Write-ToLogFile -I -C PostPoSHScript -M "Checking if parameter `"PostPoSHScriptFilename`" was defined."
            
            if ($CertRequest | Get-Member -Name  PostPoSHScriptFilename -ErrorAction SilentlyContinue) {
                $CertRequest.PostPoSHScriptFilename = try { (Resolve-Path -Path $CertRequest.PostPoSHScriptFilename).Path } catch { $null }

                if ((-Not [String]::IsNullOrEmpty($($CertRequest.PostPoSHScriptFilename))) -and (Test-Path -Path $($CertRequest.PostPoSHScriptFilename))) {
                    Write-DisplayText -Title "Post PowerShell Script"
                    Write-ToLogFile -I -C PostPoSHScript -M "Post PowerShell Script defined, Filename: `"$($CertRequest.PostPoSHScriptFilename)`""
                    $pfxCertificateFilename = Join-Path -Path $CertificateDirectory -ChildPath $CertificatePfxWithChainFileName
                    if (-Not [String]::IsNullOrEmpty($($FinalCertificate.Thumbprint)) -and (Test-Path $pfxCertificateFilename)) {
                        Write-DisplayText -Line "Script Path" 
                        Write-DisplayText -ForeGroundColor Cyan $CertRequest.PostPoSHScriptFilename
                        Write-DisplayText -Line "Executing script" 
                        try {
                            Write-ToLogFile -I -C PostPoSHScript -M "Post Script Starting"
                            $output = Invoke-Command -ScriptBlock {
                                param (
                                    $poshScript,
                                    $Thumbprint,
                                    $PFXfilename,
                                    $PFXPassword,
                                    $extraParams
                                )
                                Write-ToLogFile -D -C PoSHScript -M "Post Script Starting"
                                & "$poshScript" -Thumbprint $Thumbprint -PFXfilename $PFXfilename -PFXPassword $PFXPassword @extraParams *>&1
                                Write-ToLogFile -D -C PoSHScript -M "Post Script Ended [$LastExitCode]"
                            } -ArgumentList $CertRequest.PostPoSHScriptFilename, $FinalCertificate.Thumbprint, $pfxCertificateFilename, $PfxPassword, $CertRequest.PostPoSHScriptExtraParameters
                            $postPoSHScriptResult = $LastExitCode
                            Write-ToLogFile -D -C PostPoSHScript -M "Post Script Finished [ExitCode:$postPoSHScriptResult]"
                            if ($null -ne $output) {
                                Write-ToLogFile -D -C PostPoSHScript -M "======== Script output ======== "
                                Write-ToLogFile -D -B $output
                                Write-ToLogFile -D -C PostPoSHScript -M "======== Script output ======== "
                            }
                        } catch {
                            $postPoSHScriptResult = 1
                            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                        }
                        switch ($postPoSHScriptResult) {
                            0 {
                                Write-DisplayText -ForeGroundColor Green "Success"
                                Write-ToLogFile -I -C PostPoSHScript -M "Post PowerShell script executed successfully"
                                $mailDataItem.Text += "Post PowerShell script executed successfully"
                            }
                            1 {
                                Write-DisplayText -ForeGroundColor Red "Failed!"
                                Invoke-RegisterError 1 "Failed to execute Post PowerShell script"
                            }
                            Default {
                                Write-DisplayText -ForeGroundColor Yellow "Unknown Result! [$postPoSHScriptResult]"
                                Write-ToLogFile -W -C PostPoSHScript -M "Unknown Result while executing post PowerShell Script! [ $output.ExitCode / $postPoSHScriptResult ]"
                                $mailDataItem.Text += "Unknown Result while executing post PowerShell Script! [ $output.ExitCode / $postPoSHScriptResult ]"
                            }
                        }
                    } else {
                        Write-DisplayText -ForeGroundColor Yellow "SKIPPED! Not a valid certificate found!"
                        Write-ToLogFile -W -C PostPoSHScript -M "Not a valid certificate found! Skipped the execution."
                    }
                } elseif ((-Not [String]::IsNullOrEmpty($($CertRequest.PostPoSHScriptFilename))) -and (-Not (Test-Path -Path $($CertRequest.PostPoSHScriptFilename)))) {
                    Write-DisplayText -Title "Post PowerShell Script"
                    Write-DisplayText -Line "Script Path" 
                    Write-DisplayText -NoNewLine -ForeGroundColor Cyan $CertRequest.PostPoSHScriptFilename
                    Write-DisplayText -ForeGroundColor Red " NOT FOUND!"
                    Write-ToLogFile -E -C PostPoSHScript -M "PoSH Script `"$($CertRequest.PostPoSHScriptFilename)`" NOT found!"
                } else {
                    Write-ToLogFile -I -C PostPoSHScript -M "No Post PowerShell Script defined"
                }
            }
            #endregion PostPoSHScriptFilename

        }
        if ($CertRequest.CleanExpiredCertsOnDisk -eq $true) {
            Write-ToLogFile -i -C RemoveExpiredCerts -M "Removing expired certificates on disk (`"*.$($CertRequest.CN.Replace('*.',''))`")"
            Write-DisplayText -Title "Removing expired certificates on disk (`"$($CertRequest.CertDir)\*.$($CertRequest.CN.Replace('*.',''))`")"
            Write-DisplayText -Line "Removing files older than"
            Write-DisplayText -ForeGroundColor Cyan "$($CertRequest.CleanExpiredCertsOnDiskDays) Day(s)"
            Write-DisplayText -Line "Removing files"
            try {
                $RegEx = '(?>CRT-SAN|LECRT)-[0-9]{8}-[0-9]{6}-' + $CertRequest.CN.Replace('*.', '')
                $FoldersWithExpiredCertificates = Get-ChildItem -Path $CertRequest.CertDir | Where-Object { ($_.Name -match $RegEx) -and ($_.CreationTime -lt (Get-Date).AddDays( - $($CertRequest.CleanExpiredCertsOnDiskDays))) }
                $FoldersWithExpiredCertificates | Remove-Item -Force -Recurse -ErrorAction Stop
                Write-DisplayText -ForeGroundColor Green "$($FoldersWithExpiredCertificates.Count) file(s) removed!"
                Write-ToLogFile -I -C RemoveExpiredCerts -M "$($FoldersWithExpiredCertificates.Count) file(s) removed!"
            } catch {
                Write-DisplayText -ForeGroundColor Red "Failed, $($_.Exception.Message)"
                Write-ToLogFile -E -C RemoveExpiredCerts -M "Error while cleaning expired certificate files. Exception Message: $($_.Exception.Message)"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            }
        }
    } #END Loop
}

#region CleanupADC
    
if ($CleanADC) {
    Invoke-ADCCleanup -Full
}
    
    
#endregion CleanupADC

#region RemoveTestCerts

if ($RemoveTestCertificates) {
    Write-DisplayText -Title "ADC - (Test) Certificate Cleanup"
    Write-ToLogFile -I -C RemoveTestCerts -M "Start removing the test certificates."
    Write-ToLogFile -I -C RemoveTestCerts -M "Trying to login into the Citrix ADC."
    $ADCSession = Connect-ADC -ManagementURL $Parameters.settings.ManagementURL -Credential $Credential -PassThru
    $IntermediateCACertKeyName = "Fake LE Intermediate X1"
    $IntermediateCASerial = "8be12a0e5944ed3c546431f097614fe5"
    Write-ToLogFile -I -C RemoveTestCerts -M "Retrieving existing certificates."
    $CertDetails = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey
    Write-ToLogFile -D -C RemoveTestCerts -M "Checking if IntermediateCA `"$IntermediateCACertKeyName`" already exists."
    $IntermediateCADetails = $CertDetails.sslcertkey | Where-Object { $_.serial -eq $IntermediateCASerial }
    $LinkedCertificates = $CertDetails.sslcertkey | Where-Object { $_.linkcertkeyname -eq $IntermediateCADetails.certkey }
    Write-ToLogFile -D -C RemoveTestCerts -M "The following certificates were found:"
    $LinkedCertificates | Select-Object certkey, linkcertkeyname, serial | ForEach-Object {
        Write-ToLogFile -D -C RemoveTestCerts -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
    }
    Write-DisplayText -Line "Linked Certkeys found"
    Write-DisplayText -ForeGroundColor Cyan "$(($LinkedCertificates | Measure-Object).Count)"
    ForEach ($LinkedCertificate in $LinkedCertificates) {
        $payload = @{"certkey" = "$($LinkedCertificate.certkey)"; }
        try {
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action unlink
            Write-DisplayText -Line "Unlinking Certkey"
            Write-DisplayText -ForeGroundColor Green "Done    [$($LinkedCertificate.certkey)]"
            Write-ToLogFile -I -C RemoveTestCerts -M "Unlinked: `"$($LinkedCertificate.certkey)`""
        } catch {
            Write-DisplayText -ForeGroundColor Yellow "WARNING, Could not unlink `"$($LinkedCertificate.certkey)`""
            Write-ToLogFile -E -C RemoveTestCerts -M "Could not unlink certkey `"$($LinkedCertificate.certkey)`". Exception Message: $($_.Exception.Message)"
            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
        }
    }
    $FakeCerts = $CertDetails.sslcertkey | Where-Object { $_.issuer -match $IntermediateCACertKeyName }
    Write-ToLogFile -D -C RemoveTestCerts -M "Test Cert data:"
    $FakeCerts | ForEach-Object {
        Write-ToLogFile -D -C RemoveTestCerts -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
    }
    Write-DisplayText -Line "Certificates found"
    Write-DisplayText -ForeGroundColor Cyan "$(($FakeCerts | Measure-Object).Count)"
    ForEach ($FakeCert in $FakeCerts) {
        try {
            Write-ToLogFile -I -C RemoveTestCerts -M "Trying to delete `"$($FakeCert.certkey)`"."
            Write-DisplayText -Line "SSL Certkey"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type sslcertkey -Resource $($FakeCert.certkey)
            Write-DisplayText -ForeGroundColor Green "Deleted [$($FakeCert.certkey)]"
        } catch {
            Write-DisplayText -ForeGroundColor Yellow "WARNING, could not remove certkey `"$($FakeCert.certkey)`""
            Write-ToLogFile -W -C RemoveTestCerts -M "Could not remove certkey `"$($FakeCert.certkey)`" from the ADC. Exception Message: $($_.Exception.Message)"
            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
        }
        Write-ToLogFile -W -C RemoveTestCerts -M "Getting Certificate details"
        try {
            $CertFilePath = (Split-Path $($FakeCert.cert) -Parent).Replace("\", "/")
            if ([String]::IsNullOrEmpty($CertFilePath)) {
                $CertFilePath = "/nsconfig/ssl/"
            }
        } catch {
            $CertFilePath = "/nsconfig/ssl/"
        }
        try {
            $CertFileName = Split-Path $($FakeCert.cert) -Leaf
        } catch {
            $CertFileName = $null
        }
        Write-ToLogFile -W -C RemoveTestCerts -M "Certificate name: `"$($CertFileName)`" in path: `"$($CertFilePath)`""
        Write-ToLogFile -W -C RemoveTestCerts -M "Getting Certificate Key details"
        try {
            $KeyFilePath = (Split-Path $($FakeCert.key) -Parent).Replace("\", "/")
            if ([String]::IsNullOrEmpty($KeyFilePath)) {
                $KeyFilePath = "/nsconfig/ssl/"
            }
        } catch {
            $KeyFilePath = "/nsconfig/ssl/"
        }
        try {
            $KeyFileName = Split-Path $($FakeCert.key) -Leaf
        } catch {
            $KeyFileName = $null
        }
        Write-ToLogFile -W -C RemoveTestCerts -M "Certificate name: `"$($KeyFileName)`" in path: `"$($KeyFilePath)`""
        Write-DisplayText -Line "SSL Certificate File"
        $Arguments = @{"filelocation" = "$CertFilePath"; }
        try {
            Write-ToLogFile -I -C RemoveTestCerts -M "Trying to delete `"$(Join-Path -Path $CertFilePath -ChildPath $CertFileName)`"."
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type systemfile -Resource $CertFileName -Arguments $Arguments
            Write-DisplayText -ForeGroundColor Green "Deleted [$(Join-Path -Path $CertFilePath -ChildPath $CertFileName)]"
            Write-ToLogFile -I -C RemoveTestCerts -M "File deleted."
        } catch {
            Write-DisplayText -ForeGroundColor Yellow "WARNING, could not delete file `"$(Join-Path -Path $CertFilePath -ChildPath $CertFileName)`""
            Write-ToLogFile -E -C RemoveTestCerts -M "Could not delete file `"$(Join-Path -Path $CertFilePath -ChildPath $CertFileName)`". Exception Message: $($_.Exception.Message)"
            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
        }
        if (-Not ($(Join-Path -Path $CertFilePath -ChildPath $CertFileName) -eq $(Join-Path -Path $KeyFilePath -ChildPath $KeyFileName))) {
            Write-DisplayText -Line "SSL Key File"
            $Arguments = @{"filelocation" = "$KeyFilePath"; }
            try {
                Write-ToLogFile -I -C RemoveTestCerts -M "Trying to delete `"$(Join-Path -Path $KeyFilePath -ChildPath $KeyFileName)`"."
                $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type systemfile -Resource $KeyFileName -Arguments $Arguments
                Write-DisplayText -ForeGroundColor Green "Deleted [$(Join-Path -Path $KeyFilePath -ChildPath $KeyFileName)]"
                Write-ToLogFile -I -C RemoveTestCerts -M "File deleted."
            } catch {
                Write-DisplayText -ForeGroundColor Yellow "WARNING, could not delete file `"$(Join-Path -Path $KeyFilePath -ChildPath $KeyFileName)`""
                Write-ToLogFile -E -C RemoveTestCerts -M "Could not delete file `"$(Join-Path -Path $KeyFilePath -ChildPath $KeyFileName)`". Exception Message: $($_.Exception.Message)"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            }
        }
    }
    $Arguments = @{"filelocation" = "/nsconfig/ssl"; }
    $CertFiles = Invoke-ADCRestApi -Session $ADCSession -Method Get -Type systemfile -Arguments $Arguments
    $CertFilesToRemove = $CertFiles.systemfile | Where-Object { $_.filename -match "TST-" }
    Write-DisplayText -Line "Misc. Files Found"
    Write-DisplayText -ForeGroundColor Cyan "$(($CertFilesToRemove | Measure-Object).Count)"
    ForEach ($CertFileToRemove in $CertFilesToRemove) {
        Write-DisplayText -Line "File"
        $Arguments = @{"filelocation" = "$($CertFileToRemove.filelocation)"; }
        try {
            Write-ToLogFile -I -C RemoveTestCerts -M "Trying to delete `"$(Join-Path -Path $CertFileToRemove.filelocation -ChildPath $CertFileToRemove.filename)`"."
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type systemfile -Resource $($CertFileToRemove.filename) -Arguments $Arguments
            Write-DisplayText -ForeGroundColor Green "Deleted [$(Join-Path -Path $CertFileToRemove.filelocation -ChildPath $CertFileToRemove.filename)]"
            Write-ToLogFile -I -C RemoveTestCerts -M "File deleted."
        } catch {
            Write-DisplayText -ForeGroundColor Yellow "WARNING, could not delete file [$(Join-Path -Path $CertFileToRemove.filelocation -ChildPath $CertFileToRemove.filename)]"
            Write-ToLogFile -E -C RemoveTestCerts -M "Could not delete file: `"$(Join-Path -Path $CertFileToRemove.filelocation -ChildPath $CertFileToRemove.filename)`". Exception Message: $($_.Exception.Message)"
            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
        }
    }
}

#endregion RemoveTestCerts

#region Final Actions

if ($CleanAllExpiredCertsOnDisk) {
    Write-ToLogFile -I -C RemoveExpiredCerts -M "Removing expired certificates on disk ($($CertDir)\*)"
    Write-DisplayText -Title "Removing expired certificates on disk ($($CertDir)\*)"
    Write-DisplayText -Line "Removing files older than"
    Write-DisplayText -ForeGroundColor Cyan "$($CleanExpiredCertsOnDiskDays) Day(s)"
    try {
        Write-DisplayText -Line "Removing files"
        $RegEx = '(?>CRT-SAN|LECRT)-[0-9]{8}-[0-9]{6}-\w+\.\w+'
        $FoldersWithExpiredCertificates = Get-ChildItem -Path $CertDir | Where-Object { ($_.Name -match $RegEx) -and ($_.CreationTime -lt (Get-Date).AddDays( - $($CleanExpiredCertsOnDiskDays))) }
        $FoldersWithExpiredCertificates | Remove-Item -Force -Recurse -ErrorAction Stop
        Write-DisplayText -ForeGroundColor Green "$($FoldersWithExpiredCertificates.Count) file(s) removed!"
        Write-ToLogFile -I -C RemoveExpiredCerts -M "$($FoldersWithExpiredCertificates.Count) file(s) removed!"
    } catch {
        Write-DisplayText -ForeGroundColor Red "Failed, $($_.Exception.Message)"
        Write-ToLogFile -E -C RemoveExpiredCerts -M "Error while cleaning expired certificate files. Exception Message: $($_.Exception.Message)"
        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
    }
}

if ($SaveConfig -and (-Not [String]::IsNullOrEmpty($ConfigFile))) {
    try {
        Write-ToLogFile -I -C Final-Actions -M "Saving parameters to file `"$ConfigFile`""
        $Parameters | ConvertTo-Json -Depth 7 -WarningAction SilentlyContinue | Out-File -FilePath $ConfigFile -Encoding unicode -Force -ErrorAction Stop | Out-Null
        Write-ToLogFile -I -C Final-Actions -M "Saving done"
    } catch {
        Write-ToLogFile -E -C Final-Actions -M "Saving failed! Exception Message: $($_.Exception.Message)"
        Write-DisplayText -ForegroundColor Red "Could not write the Parameters to `"$ConfigFile`"`r`nException Message: $($_.Exception.Message)"
        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
    }
} elseif ($SaveConfig -and ([String]::IsNullOrEmpty($ConfigFile))) {
    Write-ToLogFile -D -C Final-Actions -M "There were unsaved changes, but no ConfigFile was defined."
} else {
    Write-ToLogFile -D -C Final-Actions -M "No ConfigFile was defined, nothing will be saved."
}

$RequestsWithErrors = $SessionRequestObjects | Where-Object { $_.ErrorOccurred -gt 0 }
if (-Not [String]::IsNullOrEmpty($RequestsWithErrors)) {
    $ExitCode = 0
    ForEach ($FailedItem in $RequestsWithErrors) {
        Write-Error "There were $($FailedItem.ErrorOccurred) errors during the request for CN: `"$($FailedItem.CN)`"!"
        Write-ToLogFile -E -C Final-Actions -M "There were $($FailedItem.ErrorOccurred) errors during the request for CN: `"$($FailedItem.CN)`"!"
        $ExitCode = $FailedItem.ExitCode
    }
    if ($LogLevel -eq "Debug") {
        TerminateScript $ExitCode "There were one or more errors, please check the debug log for more info!"
    } else {
        TerminateScript $ExitCode "There were one or more errors, please check the log or rerun with the `"-LogLevel Debug`" option!"
    }
    
}

TerminateScript 0

# SIG # Begin signature block
# MIIknAYJKoZIhvcNAQcCoIIkjTCCJIkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAcD9V0pOxVw1eI
# Nm0NVTEQC9sjqri/Ya5idkZioZWSA6CCHl8wggTzMIID26ADAgECAhAsJ03zZBC0
# i/247uUvWN5TMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# ExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoT
# D1NlY3RpZ28gTGltaXRlZDEkMCIGA1UEAxMbU2VjdGlnbyBSU0EgQ29kZSBTaWdu
# aW5nIENBMB4XDTIxMDUwNTAwMDAwMFoXDTI0MDUwNDIzNTk1OVowWzELMAkGA1UE
# BhMCTkwxEjAQBgNVBAcMCVZlbGRob3ZlbjEbMBkGA1UECgwSSm9oYW5uZXMgQmls
# bGVrZW5zMRswGQYDVQQDDBJKb2hhbm5lcyBCaWxsZWtlbnMwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCsfgRG81keOHalHfCUgxOa1Qy4VNOnGxB8SL8e
# rjP9SfcF13McP7F1HGka5Be495pTZ+duGbaQMNozwg/5Dg9IRJEeBabeSSJJCbZo
# SNpmUu7NNRRfidQxlPC81LxTVHxJ7In0MEfCVm7rWcri28MRCAuafqOfSE+hyb1Z
# /tKyCyQ5RUq3kjs/CF+VfMHsJn6ZT63YqewRkwHuc7UogTTZKjhPJ9prGLTer8UX
# UgvsGRbvhYZXIEuy+bmx/iJ1yRl1kX4nj6gUYzlhemOnlSDD66YOrkLDhXPMXLym
# AN7h0/W5Bo//R5itgvdGBkXkWCKRASnq/9PTcoxW6mwtgU8xAgMBAAGjggGQMIIB
# jDAfBgNVHSMEGDAWgBQO4TqoUzox1Yq+wbutZxoDha00DjAdBgNVHQ4EFgQUZWMy
# gC0i1u2NZ1msk2Mm5nJm5AswDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEQYJYIZIAYb4QgEBBAQDAgQQMEoGA1UdIARD
# MEEwNQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGln
# by5jb20vQ1BTMAgGBmeBDAEEATBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3Js
# LnNlY3RpZ28uY29tL1NlY3RpZ29SU0FDb2RlU2lnbmluZ0NBLmNybDBzBggrBgEF
# BQcBAQRnMGUwPgYIKwYBBQUHMAKGMmh0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2Vj
# dGlnb1JTQUNvZGVTaWduaW5nQ0EuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2Nz
# cC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEARjv9ieRocb1DXRWm3XtY
# jjuSRjlvkoPd9wS6DNfsGlSU42BFd9LCKSyRREZVu8FDq7dN0PhD4bBTT+k6AgrY
# KG6f/8yUponOdxskv850SjN2S2FeVuR20pqActMrpd1+GCylG8mj8RGjdrLQ3QuX
# qYKS68WJ39WWYdVB/8Ftajir5p6sAfwHErLhbJS6WwmYjGI/9SekossvU8mZjZwo
# Gbu+fjZhPc4PhjbEh0ABSsPMfGjQQsg5zLFjg/P+cS6hgYI7qctToo0TexGe32DY
# fFWHrHuBErW2qXEJvzSqM5OtLRD06a4lH5ZkhojhMOX9S8xDs/ArDKgX1j1Xm4Tu
# DjCCBYEwggRpoAMCAQICEDlyRDr5IrdR19NsEN0xNZUwDQYJKoZIhvcNAQEMBQAw
# ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
# A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
# BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0xOTAzMTIwMDAwMDBaFw0y
# ODEyMzEyMzU5NTlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKTmV3IEplcnNl
# eTEUMBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1Qg
# TmV0d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1
# dGhvcml0eTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIASZRc2DsPb
# CLPQrFcNdu3NJ9NMrVCDYeKqIE0JLWQJ3M6Jn8w9qez2z8Hc8dOx1ns3KBErR9o5
# xrw6GbRfpr19naNjQrZ28qk7K5H44m/Q7BYgkAk+4uh0yRi0kdRiZNt/owbxiBhq
# kCI8vP4T8IcUe/bkH47U5FHGEWdGCFHLhhRUP7wz/n5snP8WnRi9UY41pqdmyHJn
# 2yFmsdSbeAPAUDrozPDcvJ5M/q8FljUfV1q3/875PbcstvZU3cjnEjpNrkyKt1ya
# tLcgPcp/IjSufjtoZgFE5wFORlObM2D3lL5TN5BzQ/Myw1Pv26r+dE5px2uMYJPe
# xMcM3+EyrsyTO1F4lWeL7j1W/gzQaQ8bD/MlJmszbfduR/pzQ+V+DqVmsSl8MoRj
# VYnEDcGTVDAZE6zTfTen6106bDVc20HXEtqpSQvf2ICKCZNijrVmzyWIzYS4sT+k
# OQ/ZAp7rEkyVfPNrBaleFoPMuGfi6BOdzFuC00yz7Vv/3uVzrCM7LQC/NVV0CUnY
# SVgaf5I25lGSDvMmfRxNF7zJ7EMm0L9BX0CpRET0medXh55QH1dUqD79dGMvsVBl
# CeZYQi5DGky08CVHWfoEHpPUJkZKUIGy3r54t/xnFeHJV4QeD2PW6WK61l9VLupc
# xigIBCU5uA4rqfJMlxwHPw1S9e3vL4IPAgMBAAGjgfIwge8wHwYDVR0jBBgwFoAU
# oBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYDVR0OBBYEFFN5v1qqK0rPVIDh2JvAnfKy
# A2bLMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MBEGA1UdIAQKMAgw
# BgYEVR0gADBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNv
# bS9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQwF
# AAOCAQEAGIdR3HQhPZyK4Ce3M9AuzOzw5steEd4ib5t1jp5y/uTW/qofnJYt7wNK
# fq70jW9yPEM7wD/ruN9cqqnGrvL82O6je0P2hjZ8FODN9Pc//t64tIrwkZb+/UNk
# fv3M0gGhfX34GRnJQisTv1iLuqSiZgR2iJFODIkUzqJNyTKzuugUGrxx8VvwQQuY
# AAoiAxDlDLH5zZI3Ge078eQ6tvlFEyZ1r7uq7z97dzvSxAKRPRkA0xdcOds/exgN
# Rc2ThZYvXd9ZFk8/Ub3VRRg/7UqO6AZhdCMWtQ1QcydER38QXYkqa4UxFMToqWpM
# gLxqeM+4f452cpkMnf7XkQgWoaNflTCCBfUwggPdoAMCAQICEB2iSDBvmyYY0ILg
# ln0z02owDQYJKoZIhvcNAQEMBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpO
# ZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVT
# RVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmlj
# YXRpb24gQXV0aG9yaXR5MB4XDTE4MTEwMjAwMDAwMFoXDTMwMTIzMTIzNTk1OVow
# fDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
# A1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSQwIgYDVQQD
# ExtTZWN0aWdvIFJTQSBDb2RlIFNpZ25pbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUA
# A4IBDwAwggEKAoIBAQCGIo0yhXoYn0nwli9jCB4t3HyfFM/jJrYlZilAhlRGdDFi
# xRDtsocnppnLlTDAVvWkdcapDlBipVGREGrgS2Ku/fD4GKyn/+4uMyD6DBmJqGx7
# rQDDYaHcaWVtH24nlteXUYam9CflfGqLlR5bYNV+1xaSnAAvaPeX7Wpyvjg7Y96P
# v25MQV0SIAhZ6DnNj9LWzwa0VwW2TqE+V2sfmLzEYtYbC43HZhtKn52BxHJAteJf
# 7wtF/6POF6YtVbC3sLxUap28jVZTxvC6eVBJLPcDuf4vZTXyIuosB69G2flGHNyM
# fHEo8/6nxhTdVZFuihEN3wYklX0Pp6F8OtqGNWHTAgMBAAGjggFkMIIBYDAfBgNV
# HSMEGDAWgBRTeb9aqitKz1SA4dibwJ3ysgNmyzAdBgNVHQ4EFgQUDuE6qFM6MdWK
# vsG7rWcaA4WtNA4wDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# HQYDVR0lBBYwFAYIKwYBBQUHAwMGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0g
# ADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNF
# UlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwdgYIKwYBBQUHAQEE
# ajBoMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVNFUlRy
# dXN0UlNBQWRkVHJ1c3RDQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVz
# ZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAE1jUO1HNEphpNveaiqMm/EA
# AB4dYns61zLC9rPgY7P7YQCImhttEAcET7646ol4IusPRuzzRl5ARokS9At3Wpwq
# QTr81vTr5/cVlTPDoYMot94v5JT3hTODLUpASL+awk9KsY8k9LOBN9O3ZLCmI2pZ
# aFJCX/8E6+F0ZXkI9amT3mtxQJmWunjxucjiwwgWsatjWsgVgG10Xkp1fqW4w2y1
# z99KeYdcx0BNYzX2MNPPtQoOCwR/oEuuu6Ol0IQAkz5TXTSlADVpbL6fICUQDRn7
# UJBhvjmPeo5N9p8OHv4HURJmgyYZSJXOSsnBf/M6BZv5b9+If8AjntIeQ3pFMcGc
# TanwWbJZGehqjSkEAnd8S0vNcL46slVaeD68u28DECV3FTSK+TbMQ5Lkuk/xYpMo
# JVcp+1EZx6ElQGqEV8aynbG8HArafGd+fS7pKEwYfsR7MUFxmksp7As9V1DSyt39
# ngVR5UR43QHesXWYDVQk/fBO4+L4g71yuss9Ou7wXheSaG3IYfmm8SoKC6W59J7u
# mDIFhZ7r+YMp08Ysfb06dy6LN0KgaoLtO0qqlBCk4Q34F8W2WnkzGJLjtXX4oemO
# CiUe5B7xn1qHI/+fpFGe+zmAEc3btcSnqIBv5VPU4OOiwtJbGvoyJi1qV3AcPKRY
# LqPzW0sH3DJZ84enGm1YMIIG7DCCBNSgAwIBAgIQMA9vrN1mmHR8qUY2p3gtuTAN
# BgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJz
# ZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNU
# IE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBB
# dXRob3JpdHkwHhcNMTkwNTAyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjB9MQswCQYD
# VQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdT
# YWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3Rp
# Z28gUlNBIFRpbWUgU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDIGwGv2Sx+iJl9AZg/IJC9nIAhVJO5z6A+U++zWsB21hoEpc5Hg7Xr
# xMxJNMvzRWW5+adkFiYJ+9UyUnkuyWPCE5u2hj8BBZJmbyGr1XEQeYf0RirNxFrJ
# 29ddSU1yVg/cyeNTmDoqHvzOWEnTv/M5u7mkI0Ks0BXDf56iXNc48RaycNOjxN+z
# xXKsLgp3/A2UUrf8H5VzJD0BKLwPDU+zkQGObp0ndVXRFzs0IXuXAZSvf4DP0REK
# V4TJf1bgvUacgr6Unb+0ILBgfrhN9Q0/29DqhYyKVnHRLZRMyIw80xSinL0m/9NT
# IMdgaZtYClT0Bef9Maz5yIUXx7gpGaQpL0bj3duRX58/Nj4OMGcrRrc1r5a+2kxg
# zKi7nw0U1BjEMJh0giHPYla1IXMSHv2qyghYh3ekFesZVf/QOVQtJu5FGjpvzdeE
# 8NfwKMVPZIMC1Pvi3vG8Aij0bdonigbSlofe6GsO8Ft96XZpkyAcSpcsdxkrk5WY
# nJee647BeFbGRCXfBhKaBi2fA179g6JTZ8qx+o2hZMmIklnLqEbAyfKm/31X2xJ2
# +opBJNQb/HKlFKLUrUMcpEmLQTkUAx4p+hulIq6lw02C0I3aa7fb9xhAV3PwcaP7
# Sn1FNsH3jYL6uckNU4B9+rY5WDLvbxhQiddPnTO9GrWdod6VQXqngwIDAQABo4IB
# WjCCAVYwHwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYE
# FBqh+GEZIA/DQXdFKI7RNV8GEgRVMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8E
# CDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0g
# ADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNF
# UlRydXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwdgYIKwYBBQUHAQEE
# ajBoMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVNFUlRy
# dXN0UlNBQWRkVHJ1c3RDQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVz
# ZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAG1UgaUzXRbhtVOBkXXfA3oy
# Cy0lhBGysNsqfSoF9bw7J/RaoLlJWZApbGHLtVDb4n35nwDvQMOt0+LkVvlYQc/x
# QuUQff+wdB+PxlwJ+TNe6qAcJlhc87QRD9XVw+K81Vh4v0h24URnbY+wQxAPjeT5
# OGK/EwHFhaNMxcyyUzCVpNb0llYIuM1cfwGWvnJSajtCN3wWeDmTk5SbsdyybUFt
# Z83Jb5A9f0VywRsj1sJVhGbks8VmBvbz1kteraMrQoohkv6ob1olcGKBc2NeoLvY
# 3NdK0z2vgwY4Eh0khy3k/ALWPncEvAQ2ted3y5wujSMYuaPCRx3wXdahc1cFaJqn
# yTdlHb7qvNhCg0MFpYumCf/RoZSmTqo9CfUFbLfSZFrYKiLCS53xOV5M3kg9mzSW
# mglfjv33sVKRzj+J9hyhtal1H3G/W0NdZT1QgW6r8NDT/LKzH7aZlib0PHmLXGTM
# ze4nmuWgwAxyh8FuTVrTHurwROYybxzrF06Uw3hlIDsPQaof6aFBnf6xuKBlKjTg
# 3qj5PObBMLvAoGMs/FwWAKjQxH/qEZ0eBsambTJdtDgJK0kHqv3sMNrxpy/Pt/36
# 0KOE2See+wFmd7lWEOEgbsausfm2usg1XTN2jvF8IAwqd661ogKGuinutFoAsYyr
# 4/kKyVRd1LlqdJ69SK6YMIIG9jCCBN6gAwIBAgIRAJA5f5rSSjoT8r2RXwg4qUMw
# DQYJKoZIhvcNAQEMBQAwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIg
# TWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBMB4X
# DTIyMDUxMTAwMDAwMFoXDTMzMDgxMDIzNTk1OVowajELMAkGA1UEBhMCR0IxEzAR
# BgNVBAgTCk1hbmNoZXN0ZXIxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoG
# A1UEAwwjU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBTaWduZXIgIzMwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCQsnE/eeHUuYoXzMOXwpCUcu1aOm8B
# Q39zWiifJHygNUAG+pSvCqGDthPkSxUGXmqKIDRxe7slrT9bCqQfL2x9LmFR0IxZ
# Nz6mXfEeXYC22B9g480Saogfxv4Yy5NDVnrHzgPWAGQoViKxSxnS8JbJRB85XZyw
# lu1aSY1+cuRDa3/JoD9sSq3VAE+9CriDxb2YLAd2AXBF3sPwQmnq/ybMA0QfFijh
# anS2nEX6tjrOlNEfvYxlqv38wzzoDZw4ZtX8fR6bWYyRWkJXVVAWDUt0cu6gKjH8
# JgI0+WQbWf3jOtTouEEpdAE/DeATdysRPPs9zdDn4ZdbVfcqA23VzWLazpwe/Opw
# feZ9S2jOWilh06BcJbOlJ2ijWP31LWvKX2THaygM2qx4Qd6S7w/F7KvfLW8aVFFs
# M7ONWWDn3+gXIqN5QWLP/Hvzktqu4DxPD1rMbt8fvCKvtzgQmjSnC//+HV6k8+4W
# OCs/rHaUQZ1kHfqA/QDh/vg61MNeu2lNcpnl8TItUfphrU3qJo5t/KlImD7yRg1p
# sbdu9AXbQQXGGMBQ5Pit/qxjYUeRvEa1RlNsxfThhieThDlsdeAdDHpZiy7L9GQs
# Qkf0VFiFN+XHaafSJYuWv8at4L2xN/cf30J7qusc6es9Wt340pDVSZo6HYMaV38c
# AcLOHH3M+5YVxQIDAQABo4IBgjCCAX4wHwYDVR0jBBgwFoAUGqH4YRkgD8NBd0Uo
# jtE1XwYSBFUwHQYDVR0OBBYEFCUuaDxrmiskFKkfot8mOs8UpvHgMA4GA1UdDwEB
# /wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEoG
# A1UdIARDMEEwNQYMKwYBBAGyMQECAQMIMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8v
# c2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEAjBEBgNVHR8EPTA7MDmgN6A1hjNodHRw
# Oi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29SU0FUaW1lU3RhbXBpbmdDQS5jcmww
# dAYIKwYBBQUHAQEEaDBmMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnNlY3RpZ28u
# Y29tL1NlY3RpZ29SU0FUaW1lU3RhbXBpbmdDQS5jcnQwIwYIKwYBBQUHMAGGF2h0
# dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqGSIb3DQEBDAUAA4ICAQBz2u1ocsvC
# uUChMbu0A6MtFHsk57RbFX2o6f2t0ZINfD02oGnZ85ow2qxp1nRXJD9+DzzZ9cN5
# JWwm6I1ok87xd4k5f6gEBdo0wxTqnwhUq//EfpZsK9OU67Rs4EVNLLL3OztatcH7
# 14l1bZhycvb3Byjz07LQ6xm+FSx4781FoADk+AR2u1fFkL53VJB0ngtPTcSqE4+X
# rwE1K8ubEXjp8vmJBDxO44ISYuu0RAx1QcIPNLiIncgi8RNq2xgvbnitxAW06IQI
# kwf5fYP+aJg05Hflsc6MlGzbA20oBUd+my7wZPvbpAMxEHwa+zwZgNELcLlVX0e+
# OWTOt9ojVDLjRrIy2NIphskVXYCVrwL7tNEunTh8NeAPHO0bR0icImpVgtnyughl
# A+XxKfNIigkBTKZ58qK2GpmU65co4b59G6F87VaApvQiM5DkhFP8KvrAp5eo6rWN
# es7k4EuhM6sLdqDVaRa3jma/X/ofxKh/p6FIFJENgvy9TZntyeZsNv53Q5m4aS18
# YS/to7BJ/lu+aSSR/5P8V2mSS9kFP22GctOi0MBk0jpCwRoD+9DtmiG4P6+mslFU
# 1UzFyh8SjVfGOe1c/+yfJnatZGZn6Kow4NKtt32xakEnbgOKo3TgigmCbr/j9re8
# ngspGGiBoZw/bhZZSxQJCZrmrr9gFd2G9TGCBZMwggWPAgEBMIGQMHwxCzAJBgNV
# BAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1Nh
# bGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEkMCIGA1UEAxMbU2VjdGln
# byBSU0EgQ29kZSBTaWduaW5nIENBAhAsJ03zZBC0i/247uUvWN5TMA0GCWCGSAFl
# AwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJ
# KoZIhvcNAQkEMSIEIBYIC94TEbiUAs7fgePyvVp853E6xrtVULoxje4Zoso8MA0G
# CSqGSIb3DQEBAQUABIIBAFE7OcOX5w47GYG6ILP7MnWQpxRptDRX3LLmfbwibguQ
# ShXrEXhpqXJt8ahh/qaXQz0ltaYN7aFTc+kVrATeJNG6EeoQxw5qybwhQWlBTdVC
# ieTVhrdgVRdGdhUkuIP2eP0nVhEBVDTiQRrIvh2zDeYnA6hcNwauSft+FAqihKza
# HcUlVZmd0rvZlb1X6skaZFo+Npx/hAq9Ernxeh+Y1ap8qU08IZdFRZskn998E37g
# tfbM1LYEoC9VSb/iyB+iNKzDdCcx5s36aNehEkDMddYfpNlihXyyXjgU9aI1aGaV
# fqXV7TGggRFoTT1fRP5fjhg8e8L0LCCWF+J2tTMTd2uhggNMMIIDSAYJKoZIhvcN
# AQkGMYIDOTCCAzUCAQEwgZIwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0
# ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGln
# byBMaW1pdGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENB
# AhEAkDl/mtJKOhPyvZFfCDipQzANBglghkgBZQMEAgIFAKB5MBgGCSqGSIb3DQEJ
# AzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIzMDMxMjIwMTYxNFowPwYJ
# KoZIhvcNAQkEMTIEMGtALXZ/BVVC17KZ/x0OIzjNm2EsaqkviRbIYFzWWs5Zb8pM
# xhpjQEh+IBrtlBn4JDANBgkqhkiG9w0BAQEFAASCAgBt7b1PIrJUKWkVxFFQP3e+
# OwMQKZK18d0X7gPLh59QNdSC+Ul8ht6JcfY6LeBdYZT6LQAWOiHK3D6gjEBIbw1g
# NF/rp6CRdoFpZs1culrzIKpY3TJenJUCtv+yGlbkHIET5Kf/k+QxqV6b0elnI2L2
# V9Iv32WkbSw7c19NnCVgoHjBoewlj3NNIrL/AWjrYgf+EP8G388qKGLMtm4PzbcF
# bCor50HBxu6deIYA0iqBTNx5De+DGj4lKojt7BtVajZNJERKHEOob0HVrzYbM0Yy
# I0Ec1VqVTqnkFLOShm5+J2bxVWrmWk0neFe1Mahnvb3PsefLqpiD+i3KoMAR2r2D
# RBK0iWTwxwUE/geMS/lBxnpPDeKyKu0ZtpfHKsvz/au0Svk0Sv1COsC4gxArLqya
# Aty0bjfwmhMBWPTZEdfo69Q+Iej7Q6v8VFodv1hBb4hbzKtG4vDbrJIydXr1iA5E
# HzszWyeIYbYOtQFjaPx0F/2q0ds9vq8wyDjTPkT9XKgTxow1rPkTZySGlh2ugHu0
# uKUQIXQwy+GHLZkE85uaMz9QW6O2iHoHgQO8HAZMrraog12PSuFI9TvN+hL69saN
# Nco3OjKhrvB/3Us3lA0c8IyXqvswRbb6oMLKnGiiNKJz5s06j3udOATUDE6nMm2I
# DBmchZuk2xQSTo4w7wPhlA==
# SIG # End signature block
