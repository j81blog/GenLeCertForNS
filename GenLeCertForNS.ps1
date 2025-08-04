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
.PARAMETER CsaName
    ADC Content Switch Action name
    Default: "csa_letsencrypt"
.PARAMETER CspName
    ADC Content Switch Policy name
    Default: "csp_letsencrypt"
.PARAMETER EnableVipBefore
    Enable the VIP before requesting a new certificate.
.PARAMETER DisableVipAfter
    Disable the VIP after requesting a new certificate.
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
.PARAMETER DNSWaitTime
    Define the DNS Wait Time, time in seconds that this script needs to wait for after setting the TXT records and before continuing submitting the request to Let's Encrypt.
    Some providers need extra time for records to settle and be replicated among the peers.
    Default: 30 seconds
.PARAMETER Production
    Use the production Let's encrypt server, without this parameter the staging (test) server will be used
.PARAMETER CreateUserPermissions
    When this parameter is configured, a User Group (Command Policy) will be created with a limited set of permissions required to run this script.
    Also specify all VIP, LB svc names if you want other than default values.
    Mandatory parameter is the CsVipName (Except when -UseLbVip parameter is used).
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
.PARAMETER UpdateGlobalVPNCertBinding
    If specified, the script will try to update the Global VPN Certificate Binding with the new certificate
.PARAMETER GlobalVPNCertBindingIncludeCA
    If specified, the script will include the CA certificate in the Global VPN Certificate Binding
    Only used when the UpdateGlobalVPNCertBinding parameter is specified
.PARAMETER GlobalVPNCertBindingCrlCheck
    Specify the CRL Check for the Global VPN Certificate Binding
    Options: 'Mandatory' or 'Optional'
    Only used when the UpdateGlobalVPNCertBinding parameter is specified
.PARAMETER GlobalVPNCertBindingOcspCheck
    Specify the OCSP Check for the Global VPN Certificate Binding
    Options: 'Mandatory' or 'Optional'
    Only used when the UpdateGlobalVPNCertBinding parameter is specified
.PARAMETER AlternateDNSValidationDomain
    Specify an alternate domain to be used for DNS validation. This is useful when the domain you are requesting a certificate for is a CNAME to another domain.
    The domain you are requesting a certificate for must be a CNAME to the alternate domain.
    This parameter is only used when the DNS validation method is used.
.PARAMETER AlternateDNSValidationDomainSkipCheck
    Specify this parameter if you want to skip manual steps for the alternate domain when using the AlternateDNSValidationDomain parameter.
.PARAMETER UseNetScalerDNS
    Specify this parameter if you want to use the NetScaler DNS service for DNS validation.
    This parameter is only used when the DNS validation method is used with the -AlternateDNSValidationDomain parameter.
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
    Be sure to run the script next with the same parameters as specified when running this command, the same for -SvcName (Default "svc_letsencrypt_cert_dummy"), -LbName (Default: "lb_letsencrypt_cert"), -RspName (Default: "rsp_letsencrypt"), -RsaName (Default: "rsa_letsencrypt"), -CspName (Default: "csp_letsencrypt")
    Next time you want to generate certificates you can specify the new user  -Username le-user -Password "LEP@ssw0rd"
.EXAMPLE
    .\GenLeCertForNS.ps1 -CreateUserPermissions -CreateApiUser -UseLbVip -LbName "HTTP-LBVIPName" -ApiUsername "le-user" -ApiPassword "LEP@ssw0rd" -NSCPName "MinLePermissionGroup" -Username nsroot -Password "nsroot" -ManagementURL https://citrixadc.domain.local
    This command will create a Command Policy with the minimum set of permissions, you need to run this once to create (or when you want to change something).
    Specify a LoadBalance VIP Name for the -LbName parameter when using the "-UseLbVip" parameter if you don't have a CSVip (E.G. when using a Gateway Edition license).
    Be sure to run the script next with the same parameters as specified when running this command, the same for -SvcName (Default "svc_letsencrypt_cert_dummy"), -RspName (Default: "rsp_letsencrypt"), -RsaName (Default: "rsa_letsencrypt"), -CspName (Default: "csp_letsencrypt")
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
    Version   : v2.32.0
    Author    : John Billekens
    Requires  : PowerShell v5.1 and up
                ADC 12.1 and higher
                Run As Administrator
                Posh-ACME 4.28.0 (Will be installed via this script) Thank you @rmbolger for providing the HTTP validation method!
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

    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Int]$DNSWaitTime = 30,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [alias("NSCertNameToUpdate")]
    [String]$CertKeyNameToUpdate,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$RemovePrevious,

    [Parameter(ParameterSetName = "LECertificatesHTTP", Mandatory = $true)]
    [Parameter(ParameterSetName = "LECertificatesDNS", Mandatory = $true)]
    [Parameter(ParameterSetName = "CleanExpiredCerts", Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^(?:[a-zA-Z]:\\|\\\\[^\\\/]+\\[^\\\/]+)(?:[^\\\/:*?"<>|\r\n]+\\?)*$')]
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

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [String]$EmailAddress,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [ValidateScript( {
            if ($_ -lt 2048 -or $_ -gt 4096 -or ($_ % 128) -ne 0) {
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

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$UpdateGlobalVPNCertBinding,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$GlobalVPNCertBindingIncludeCA,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [ValidateSet('Mandatory', 'Optional', IgnoreCase = $true)]
    [String]$GlobalVPNCertBindingCrlCheck,

    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [ValidateSet('Mandatory', 'Optional', IgnoreCase = $true)]
    [String]$GlobalVPNCertBindingOcspCheck,

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

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Parameter(ParameterSetName = "CleanADC")]
    [String]$CsaName = "csa_letsencrypt",

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

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$EnableVipBefore,

    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [String]$AlternateDNSValidationDomain,

    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$AlternateDNSValidationDomainSkipCheck,

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$UseNetScalerDNS,

    [Parameter(ParameterSetName = "CommandPolicy")]
    [Parameter(ParameterSetName = "CommandPolicyUser")]
    [Parameter(ParameterSetName = "LECertificatesHTTP")]
    [Parameter(ParameterSetName = "LECertificatesDNS")]
    [Switch]$DisableVipAfter,

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
$ScriptVersion = "2.32.0"
$PoshACMEVersion = "4.28.0"
$VersionURI = "https://drive.google.com/uc?export=download&id=1WOySj40yNHEza23b7eZ7wzWKymKv64JW"

#region Functions

function Write-ToLogFile {
    <#
.SYNOPSIS
    Logs messages or large blocks of data to a specified logfile with support for log rotation,
    sensitive data masking, customizable headers, and multi-level log filtering.

.DESCRIPTION
    Writes detailed log entries to a file or displays them on the console. The function supports:
      • Multiple message types: Error, Warning, Informational, Debug.
      • Writing large blocks of text.
      • Log rotation based on file size.
      • Sensitive data replacement.
      • Customizable header information with metadata.
      • Global/default variable overrides for LogFile, LogLevel, and sensitive words.

.PARAMETER Message
    One or more string messages to log. If multiple messages are provided and the -SeparateMessages
    switch is used, each message is written on a new line.

.PARAMETER SeparateMessages
    When set, writes each message from the Message parameter on a separate line in the log file.

.PARAMETER Block
    A block of data (can be non-string) to log without including date or component tags.
    Use the BlockIndent switch to indent each line of the block if desired.

.PARAMETER BlockIndent
    When logging a block, indent every line to visually separate the block content.

.PARAMETER E
    Indicates the Message is an error type. Only logs if the current LogLevel permits errors.

.PARAMETER W
    Indicates the Message is a warning type. Only logs if the current LogLevel permits warnings.

.PARAMETER I
    Indicates the Message is informational. This is the default if no other type is specified.

.PARAMETER D
    Indicates the Message or Block is for debug purposes. Only logs if LogLevel is set to Debug.

.PARAMETER Component
    Specifies a component name to include in the log entry.
    Default: The calling script's name or "LOG" if unavailable.

.PARAMETER NoDate
    When set, no timestamp is prepended to the log entry.

.PARAMETER DateFormat
    Defines the date/time format to be used in the log entry.
    Default: "yyyy-MM-dd HH:mm:ss:ffff"

.PARAMETER Show
    Displays the generated log entry to the console instead of writing it to a file.

.PARAMETER LogFile
    Specifies the path to the log file. If a global or script-level $LogFile variable exists,
    that value is used unless overridden.
    Default: "<ScriptRoot>\Log.txt" or ".\Log.txt" where PSScriptRoot is unavailable.

.PARAMETER Delimiter
    Custom delimiter used in formatting the log file.
    Default: TAB character

.PARAMETER LogLevel
    Defines the minimum log level to process. Accepted values are:
      • None: No logging.
      • Error: Only errors.
      • Warning: Errors and warnings.
      • Info: Errors, warnings, and informational entries.
      • Debug: All types.
    Global or script-level $LogLevel variables are also considered.
    Default: Info

.PARAMETER NoLogHeader
    When specified, does not add a header to a new logfile.

.PARAMETER WriteHeader
    Forces writing only the log header (with metadata) to the log file.

.PARAMETER ExtraHeaderInfo
    Adds additional user-defined information to the log header.

.PARAMETER NewLog
    Forces creation of a new logfile by removing any pre-existing file at the LogFile path.

.PARAMETER ReplaceSensitive
    An array of strings specifying sensitive words to be replaced in the log entry.
    Global or script-level values can also be used.

.PARAMETER SensitiveMask
    The string used to replace any detected sensitive data.
    Default: "**SENSITIVE**"

.PARAMETER Encoding
    Specifies the file encoding to use when writing to the log file.
    Accepted values: Unicode, UTF8, UTF7, UTF32, ASCII, BigEndianUnicode, Default.
    Default: UTF8

.PARAMETER MaxLogSize
    Maximum allowed file size in bytes before log rotation occurs.

.PARAMETER LogHistoryCount
    The number of rotated log files to keep. Older files beyond this count will be removed.

.EXAMPLE
    Write-ToLogFile "This is an informational log message."
    Logs a single informational message to the default log file.

.EXAMPLE
    Write-ToLogFile -E "This is an error log entry." -LogFile "C:\Logs\AppError.txt"
    Logs an error message to a specific log file.

.EXAMPLE
    Write-ToLogFile -Block (Get-Content "C:\Temp\Report.txt") -BlockIndent
    Logs the content of a file as a block with each line indented.

.NOTES
    Function Name  : Write-ToLogFile
    Version      : v2.1
    Author       : John Billekens Consultancy (Updated)
    Requirements : PowerShell v3 or later
    More Info    : https://blog.j81.nl
#>
    [CmdletBinding(DefaultParameterSetName = "Info")]
    param (
        [Parameter(ParameterSetName = "Error", Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName = "Warning", Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName = "Info", Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName = "Debug", Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("M")]
        [string[]]$Message,

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Alias("Separate", "SM")]
        [switch]$SeparateMessages,

        [Parameter(ParameterSetName = "Block", Mandatory = $true, ValueFromPipeline = $true)]
        [Alias("B")]
        [object[]]$Block,

        [Parameter(ParameterSetName = "Block")]
        [Alias("BI")]
        [Switch]$BlockIndent,

        [Parameter(ParameterSetName = "Error")]
        [Alias("Err")]
        [Switch]$E,

        [Parameter(ParameterSetName = "Warning")]
        [Alias("Warning", "Warn")]
        [Switch]$W,

        [Parameter(ParameterSetName = "Info")]
        [Alias("Info", "Information", "Inf")]
        [Switch]$I,

        [Parameter(ParameterSetName = "Block")]
        [Parameter(ParameterSetName = "Debug")]
        [Alias("Dbg")]
        [Switch]$D,

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Alias("C")]
        [String]$Component,

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [ValidateNotNullOrEmpty()]
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

        [Parameter(ParameterSetName = "Head")]
        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Parameter(ParameterSetName = "Block")]
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
        [ValidateSet("Error", "Warning", "Info", "Debug", "None", IgnoreCase = $true)]
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

        [Parameter(ParameterSetName = "Head")]
        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Parameter(ParameterSetName = "Block")]
        [Alias("HI")]
        [String]$ExtraHeaderInfo = $null,

        [Parameter(ParameterSetName = "Head")]
        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Parameter(ParameterSetName = "Block")]
        [Alias("NL")]
        [Switch]$NewLog,

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Parameter(ParameterSetName = "Block")]
        [String[]]$ReplaceSensitive = @(),

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Parameter(ParameterSetName = "Block")]
        [String]$SensitiveMask = "**SENSITIVE**",


        [Parameter(ParameterSetName = "Head")]
        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Parameter(ParameterSetName = "Block")]
        [ValidateSet("Unicode", "UTF8", "UTF7", "UTF32", "ASCII", "BigEndianUnicode", "Default")]
        [String]$Encoding = "UTF8",

        [Parameter(ParameterSetName = "Head")]
        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Parameter(ParameterSetName = "Block")]
        [int]$MaxLogSize,

        [Parameter(ParameterSetName = "Head")]
        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Parameter(ParameterSetName = "Block")]
        [int]$LogHistoryCount
    )

    begin {
        Write-Verbose "Initializing message and block collections"
        $messageCollection = [System.Collections.Generic.List[string]]::new()
        $blockCollection = [System.Collections.Generic.List[object]]::new()
    }

    process {
        Write-Verbose "Processing [$($PSCmdlet.ParameterSetName)] parameter set"
        switch ($PSCmdlet.ParameterSetName) {
            { $_ -in "Error", "Warning", "Info", "Debug" } {
                if ($Message) {
                    Write-Verbose "Adding $($Message.Count) message(s) to collection"
                    $messageCollection.AddRange($Message)
                }
            }
            "Block" {
                if ($Block) {
                    Write-Verbose "Adding $($Block.Count) block item(s) to collection"
                    $blockCollection.AddRange($Block)
                }
            }
        }
    }

    end {
        # Use collections if they have items
        if ($messageCollection.Count -gt 0) {
            $Message = $messageCollection
            Write-Verbose "Using collected messages ($($Message.Count) items)"
        }
        if ($blockCollection.Count -gt 0) {
            $Block = $blockCollection
            Write-Verbose "Using collected block items ($($Block.Count) items)"
        }

        # Component initialization
        if (-not $PSBoundParameters.ContainsKey('Component')) {
            if ($MyInvocation.ScriptName) {
                $Component = [System.IO.Path]::GetFileName($MyInvocation.ScriptName)
                Write-Verbose "Component set from script name: $Component"
            } else {
                $Component = "LOG"
                Write-Verbose "Component defaulted to LOG"
            }
        }

        # Root path determination
        $RootPath = if ($PSScriptRoot) {
            $PSScriptRoot
        } elseif ($psISE) {
            Split-Path -Path $psISE.CurrentFile.FullPath
        } else {
            $pwd.Path
        }
        Write-Verbose "Root path: $RootPath"

        # Check for global log file variable
        foreach ($scope in @('Global', 'Script')) {
            try {
                $LogFileVar = Get-Variable -Scope $scope -Name LogFile -ValueOnly -ErrorAction SilentlyContinue
                if (-not [String]::IsNullOrWhiteSpace($LogFileVar)) {
                    $LogFile = $LogFileVar
                    Write-Verbose "LogFile set from $scope scope: $LogFile"
                    break
                }
            } catch {
                Write-Verbose "No LogFile variable found in $scope scope"
            }
        }

        # Check for global log level
        if ([String]::IsNullOrEmpty($LogLevel) -and (-not $WriteHeader)) {
            foreach ($scope in @('Global', 'Script')) {
                try {
                    $LogLevelVar = Get-Variable -Scope $scope -Name LogLevel -ValueOnly -ErrorAction SilentlyContinue
                    if (-not [String]::IsNullOrEmpty($LogLevelVar)) {
                        $LogLevel = $LogLevelVar
                        Write-Verbose "LogLevel set from $scope scope: $LogLevel"
                        break
                    }
                } catch {
                    Write-Verbose "No LogLevel variable found in $scope scope"
                }
            }
            if ([String]::IsNullOrEmpty($LogLevel)) {
                $LogLevel = "Info"
                Write-Verbose "LogLevel defaulted to Info"
            }
        }

        # Check for global sensitive words
        foreach ($scope in @('Global', 'Script')) {
            try {
                $sensitiveVar = Get-Variable -Scope $scope -Name ReplaceSensitive -ValueOnly -ErrorAction SilentlyContinue
                if ($sensitiveVar -and $sensitiveVar.Count -gt 0) {
                    $ReplaceSensitive = $sensitiveVar
                    Write-Verbose "ReplaceSensitive set from $scope scope ($($sensitiveVar.Count) words)"
                    break
                }
            } catch {
                Write-Verbose "No ReplaceSensitive variable found in $scope scope"
            }
        }

        # Regex caching for sensitive words
        if ($ReplaceSensitive.Count -gt 0) {
            if (-not $script:sensitiveRegex -or $script:sensitiveWords -ne $ReplaceSensitive) {
                $WholeWordOnly = $true
                Write-Verbose "Building regex for $($ReplaceSensitive.Count) sensitive words"
                $script:sensitiveWords = $ReplaceSensitive
                $escaped = $ReplaceSensitive | ForEach-Object { [regex]::Escape($_) }

                $escaped = $ReplaceSensitive |
                    ForEach-Object { $_.Trim() } |
                    Where-Object { $_ -ne "" } |
                    Sort-Object Length -Descending |
                    ForEach-Object {
                        $escaped = [regex]::Escape($_)
                        if ($WholeWordOnly) {
                            "\b$escaped\b"  # wrap in word boundaries
                        } else {
                            $escaped
                        }
                    }

                $pattern = ($escaped -join '|')
                $script:sensitiveRegex = [regex]::new($pattern, 'IgnoreCase')
            }
            $regex = $script:sensitiveRegex
        }

        # Resolve log file path
        if (-not [String]::IsNullOrWhiteSpace($LogFile)) {
            $ParentPath = Split-Path -Path $LogFile -Parent -ErrorAction SilentlyContinue
            if ([String]::IsNullOrEmpty($ParentPath) -or ($ParentPath -eq "\")) {
                $LogFile = Join-Path -Path $RootPath -ChildPath (Split-Path -Path $LogFile -Leaf)
                Write-Verbose "Resolved log path: $LogFile"
            }
        }

        # Warn about default log name
        if ($LogFile -like "*\Log.txt" -or $LogFile -like "Log.txt") {
            Write-Warning "Default log file name (Log.txt) in use. Consider specifying a unique name."
        }

        # Log rotation
        if (-not [String]::IsNullOrWhiteSpace($LogFile) -and
            $MaxLogSize -gt 0 -and
            (Test-Path -Path $LogFile -ErrorAction SilentlyContinue)) {

            $logFileItem = Get-Item -Path $LogFile
            if ($logFileItem.Length -ge $MaxLogSize) {
                $logDir = $logFileItem.DirectoryName
                $logBaseName = $logFileItem.BaseName
                $logExtension = $logFileItem.Extension
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $newLogName = "${logBaseName}_${timestamp}${logExtension}"
                $newLogPath = Join-Path -Path $logDir -ChildPath $newLogName

                Write-Verbose "Rotating log (size: $($logFileItem.Length) > max: $MaxLogSize)"
                Move-Item -Path $LogFile -Destination $newLogPath -Force

                if ($LogHistoryCount -gt 0) {
                    $oldLogs = Get-ChildItem -Path $logDir -Filter "${logBaseName}_*${logExtension}" |
                        Sort-Object -Property CreationTime -Descending |
                        Select-Object -Skip $LogHistoryCount

                    if ($oldLogs) {
                        Write-Verbose "Removing $($oldLogs.Count) old log file(s)"
                        $oldLogs | Remove-Item -Force
                    }
                }
            }
        }

        # Define log header
        $LogHeader = $null
        $writeHeader = $false
        if (-not ($LogLevel -eq "None") -and -not $Show) {
            $writeHeader = (-not $NoLogHeader) -and (
                (-not (Test-Path -Path $LogFile -ErrorAction SilentlyContinue)) -or
                $NewLog -or
                $WriteHeader
            )

            if ($writeHeader) {
                Write-Verbose "Generating log header"
                $headerInfo = @{
                    LogFile              = $LogFile
                    StartTime            = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Username             = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                    IsAdmin              = (New-Object Security.Principal.WindowsPrincipal(
                            [Security.Principal.WindowsIdentity]::GetCurrent()
                        )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                    Machine              = "$($Env:COMPUTERNAME) ($([System.Environment]::OSVersion.VersionString))"
                    PSCulture            = $PSCulture
                    PSVersion            = $PSVersionTable.PSVersion
                    PSEdition            = $PSVersionTable.PSEdition
                    PSCompatibleVersions = $PSVersionTable.PSCompatibleVersions -join ', '
                    BuildVersion         = $PSVersionTable.BuildVersion
                    PSCommandPath        = $PSCommandPath
                    LanguageMode         = $ExecutionContext.SessionState.LanguageMode
                }

                $LogHeader = "**********************`r`n"
                $LogHeader += "LogFile: $($headerInfo.LogFile)`r`n"
                $LogHeader += "Start time: $($headerInfo.StartTime)`r`n"
                $LogHeader += "Username: $($headerInfo.Username)`r`n"
                $LogHeader += "RunAs Admin: $($headerInfo.IsAdmin)`r`n"
                $LogHeader += "Machine: $($headerInfo.Machine)`r`n"
                $LogHeader += "PSCulture: $($headerInfo.PSCulture)`r`n"
                $LogHeader += "PSVersion: $($headerInfo.PSVersion)`r`n"
                $LogHeader += "PSEdition: $($headerInfo.PSEdition)`r`n"
                $LogHeader += "PSCompatibleVersions: $($headerInfo.PSCompatibleVersions)`r`n"
                $LogHeader += "BuildVersion: $($headerInfo.BuildVersion)`r`n"
                $LogHeader += "PSCommandPath: $($headerInfo.PSCommandPath)`r`n"
                $LogHeader += "LanguageMode: $($headerInfo.LanguageMode)`r`n"

                if (-not [String]::IsNullOrEmpty($ExtraHeaderInfo)) {
                    $LogHeader += "$($ExtraHeaderInfo.TrimEnd("`r`n"))`r`n"
                }
                $LogHeader += "`r`n**********************`r`n`r`n"
            }
        }

        # Handle new log creation
        if ($NewLog -and (Test-Path -Path $LogFile -ErrorAction SilentlyContinue)) {
            Write-Verbose "Removing existing log file (NewLog requested)"
            Remove-Item -Path $LogFile -Force -ErrorAction SilentlyContinue
        }

        # Set default message type
        if (-not $I -and -not $W -and -not $E -and -not $D -and -not $Block -and -not $WriteHeader) {
            Write-Verbose "Defaulting to Info message type"
            $I = $true
        }

        # Date string handling
        if (-not ($LogLevel -eq "None") -and -not $NoDate -and -not $Block -and -not $WriteHeader) {
            $DateString = "{0}{1}" -f (Get-Date -Format $DateFormat), $Delimiter
        } else {
            $DateString = $null
        }

        # Component formatting
        if (-not [String]::IsNullOrEmpty($Component) -and -not $Block -and -not $WriteHeader) {
            $Component = " {0}[{1}]{0}" -f $Delimiter, $Component.ToUpper()
        } else {
            $Component = $null
        }

        # Determine message type and logging eligibility
        $WriteLog = $false
        $MessageType = $null

        if ($WriteHeader) {
            $WriteLog = $true
            Write-Verbose "Writing header to log"
        } elseif ($Block) {
            $WriteLog = $true
            if ($D -and ($LogLevel -ine "Debug")) {
                $WriteLog = $false
                Write-Verbose "Skipping debug block due to log level"
            }
        } else {
            switch ($true) {
                $E {
                    $MessageType = "ERROR"
                    $WriteLog = $LogLevel -iin @("Error", "Debug")
                }
                $W {
                    $MessageType = "WARN "
                    $WriteLog = $LogLevel -iin @("Error", "Warning", "Debug")
                }
                $I {
                    $MessageType = "INFO "
                    $WriteLog = $LogLevel -iin @("Error", "Warning", "Info", "Debug")
                }
                $D {
                    $MessageType = "DEBUG"
                    $WriteLog = $LogLevel -ieq "Debug"
                }
            }
            if ($WriteLog) {
                Write-Verbose "Logging [$MessageType] message"
            }
        }

        # Generate log content
        if ($WriteLog) {
            if ($WriteHeader) {
                $LogString = $LogHeader
            } elseif ($Block) {
                $BlockLineStart = if ($BlockIndent) { "$Delimiter$Delimiter$Delimiter" } else { "" }

                $content = if ($Block -is [string]) { $Block } else { $Block | Out-String }

                $LogString = $content -replace "(?m)^", $BlockLineStart -replace "`r`n$"
                $LogString += "`r`n"
            } else {
                if ($SeparateMessages.ToBool() -eq $true) {
                    $lines = $Message | ForEach-Object {
                        "$DateString$MessageType$Component$_"
                    }

                    $LogString = $lines -join "`r`n"
                    $LogString += "`r`n"
                } else {
                    $logMessage = if ($Message.Count -gt 1) {
                        $Message -join "`r`n"
                    } else {
                        $Message[0]
                    }
                    $LogString = "$DateString$MessageType$Component$logMessage`r`n"
                }
            }

            # Apply sensitive data replacement
            if ($regex -and $ReplaceSensitive.Count -gt 0) {
                Write-Verbose "Applying sensitive data replacement"
                $LogString = $regex.Replace($LogString, $SensitiveMask)
            }

            # Output to console or file
            if ($Show) {
                $LogString.TrimEnd("`r`n")
                Write-Verbose "Displayed log content in console"
            } else {
                if ($LogHeader -and $writeHeader -and -not $WriteHeader) {
                    $LogString = $LogHeader + $LogString
                }

                # Select encoding
                $enc = switch ($Encoding) {
                    "Unicode" { [System.Text.Encoding]::Unicode }
                    "UTF8" { [System.Text.Encoding]::UTF8 }
                    "UTF7" { [System.Text.Encoding]::UTF7 }
                    "UTF32" { [System.Text.Encoding]::UTF32 }
                    "ASCII" { [System.Text.Encoding]::ASCII }
                    "BigEndianUnicode" { [System.Text.Encoding]::BigEndianUnicode }
                    default { [System.Text.Encoding]::Default }
                }

                try {
                    [System.IO.File]::AppendAllText($LogFile, $LogString, $enc)
                    Write-Verbose "Logged $($LogString.Length) characters to $LogFile"
                } catch {
                    Write-Error "Log write failed: $($_.Exception.Message)"
                }
            }
        } else {
            Write-Verbose "No log entry created (log level or parameter constraints)"
        }
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
        $Script:ADCCleanRequired = $true
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
        if ($Script:LoggingEnabled) { Write-ToLogFile -D -C Invoke-ADCRestApi -M "JSON Payload: $($jsonPayload)" }
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
            if ($Script:LoggingEnabled) { Write-ToLogFile -D -C Invoke-ADCRestApi -M "Response: $($response | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)" }
            if ($Method -eq "GET") {
                if ($Clean -and (-not ([String]::IsNullOrEmpty($Type)))) {
                    return $response | Select-Object -ExpandProperty $Type -ErrorAction SilentlyContinue
                } else {
                    return $response
                }
            }
        }
    } catch [Exception] {
        $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($Type -eq 'reboot' -and $restError[0].Message -eq 'The underlying connection was closed: The connection was closed unexpectedly.') {
            if ($Script:LoggingEnabled) { Write-ToLogFile -I -C Invoke-ADCRestApi -M "Connection closed due to reboot." }
        } else {
            if (-not [String]::IsNullOrEmpty($($errorDetails.message))) {
                $errorMessage = '{0} [{2}]: {1}' -f $errorDetails.severity, $errorDetails.message, $errorDetails.errorcode
                if ($Script:LoggingEnabled) { Write-ToLogFile -E -C Invoke-ADCRestApi -M "Caught an error. NetScaler message: $errorMessage" }
                throw $errorMessage
            } else {
                if ($Script:LoggingEnabled) { Write-ToLogFile -E -C Invoke-ADCRestApi -M "Caught an error. Exception Message: $($_.Exception.Message)" }
                throw $_
            }
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
            if (-not ("TrustAllCertsPolicy" -as [type])) {
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
                Username = $Credential.Username
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
        $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        if (-not [String]::IsNullOrEmpty($($errorDetails.message))) {
            $errorMessage = '{0} [{2}]: {1}' -f $errorDetails.severity, $errorDetails.message, $errorDetails.errorcode
            if ($Script:LoggingEnabled) { Write-ToLogFile -E -C Invoke-ADCRestApi -M "Caught an error. NetScaler message: $errorMessage" }
            throw $errorMessage
        } else {
            if ($Script:LoggingEnabled) { Write-ToLogFile -E -C Invoke-ADCRestApi -M "Caught an error. Exception Message: $($_.Exception.Message)" }
            throw $_
        }
    }
    $session = [PSObject]@{
        ManagementURL = $ManagementURL.ToString().TrimEnd('/')
        WebSession    = [Microsoft.PowerShell.Commands.WebRequestSession]$saveSession
        Username      = $Credential.Username
        Version       = "UNKNOWN"
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
    process {
        $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        try {
            $result = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
        } finally {
            [Runtime.InteropServices.Marshal]::FreeBSTR($BSTR)

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
    if (-not $ExitNow) {
        Write-ToLogFile -E -C Invoke-RegisterError -M "Registering error only, continuing to cleanup."
        $Script:SessionRequestObject.ErrorOccurred++
        $Script:SessionRequestObject.ExitCode = $ExitCode
        if (-not [String]::IsNullOrEmpty($ErrorMessage)) {
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
    if (-not [String]::IsNullOrEmpty($ExitMessage)) {
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
        if (-not ($ExitCode -eq 0)) {
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
            if (-not ($Script:SMTPCredential -eq [PSCredential]::Empty)) {
                Write-ToLogFile -D -C SendMail -M "Setting SMTP Credentials, Username: $($Script:SMTPCredential.Username)"
                $smtp.Credentials = $Script:SMTPCredential
            }
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            if (-not ([String]::IsNullOrEmpty(($Script:Parameters.settings.SMTPPort)))) {
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
    Write-DisplayText -Title "NS Configuration"
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
            Write-ToLogFile -E -C SaveADCConfig -M "ERROR, NS configuration NOT Saved! $($_.Exception.Message)"
        }
    } else {
        Write-DisplayText -ForeGroundColor Yellow "NOT Saved! (`"-SaveADCConfig`" Parameter not defined)"
        Write-ToLogFile -I -C SaveADCConfig -M "NetScaler configuration NOT Saved! (`"-SaveADCConfig`" Parameter not defined)"
        $Script:MailLog += "`r`nIMPORTANT: Your Citrix NetScaler configuration was NOT saved!`r`n"
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
        if ($Script:ADCCleanRequired) {
            Write-DisplayText -Line "Cleanup type"
            #ToDo - Create two options, for now only Full
            if ($Full) {
                Write-DisplayText -ForegroundColor Cyan "Full"
            } else {
                Write-DisplayText -ForegroundColor Cyan "Full"
            }
            Write-ToLogFile -I -C Invoke-ADCCleanup -M "Trying to login into the Citrix ADC."
            $ADCSession = Connect-ADC -ManagementURL $Parameters.settings.ManagementURL -Credential $Credential -PassThru
            if (-not $CertRequest.UseLbVip) {
                Write-DisplayText -Line "Cleanup CS Vip"
                try {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if a binding exists for `"$($Parameters.settings.CspName)`"."
                    try {
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type cspolicy_csvserver_binding -Resource $($Parameters.settings.CspName) -ErrorAction SilentlyContinue
                    } catch { }
                    if ($response.cspolicy_csvserver_binding.Count -gt 0) {
                        foreach ($item in $response.cspolicy_csvserver_binding) {
                            Write-ToLogFile -I -C Invoke-ADCCleanup -M "Binding exists for `"$($item.policyname)`", removing Content Switch CSPolicy Binding for CS VIP: `"$($item.boundto)`", Prio: `"$($($item.priority))`"."
                            $Arguments = @{"policyname" = "$($item.policyname)"; "priority" = "$($item.priority)"; }
                            try {
                                $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type csvserver_cspolicy_binding -Arguments $Arguments -Resource $($item.boundto)
                                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                            } catch {
                                Write-ToLogFile -E -C Invoke-ADCCleanup -M "Not able to remove the Content Switch CSPolicy Binding. Exception Message: $($_.Exception.Message)"
                                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                Write-DisplayText -ForeGroundColor Yellow " WARNING: Not able to remove the Content Switch CSPolicy Binding for CS VIP: $($item.domain), Prio: $($($item.priority))."
                            }
                        }
                    } else {
                        Write-ToLogFile -I -C Invoke-ADCCleanup -M "No binding found."
                    }
                    Write-DisplayText -ForeGroundColor Green " OK"
                } catch {
                    Write-ToLogFile -E -C Invoke-ADCCleanup -M "Not able to remove the Content Switch CSPolicy Binding. Exception Message: $($_.Exception.Message)"
                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    Write-DisplayText -ForeGroundColor Yellow " WARNING: Not able to remove the Content Switch CSPolicy Binding"
                }
                Write-DisplayText -Line "Cleanup CS Policy"
                try {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if Content Switch Policy `"$($Parameters.settings.CspName)`" exists."
                    try {
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type cspolicy -Resource "$($Parameters.settings.CspName)"
                    } catch { }
                    if ($response.cspolicy.policyname -eq $($Parameters.settings.CspName)) {
                        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Content Switch Policy exist, removing Content Switch Policy."
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                        $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type cspolicy -Resource "$($Parameters.settings.CspName)"
                        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Removed Content Switch Policy successfully."
                    } else {
                        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Content Switch Policy not found."
                    }
                    Write-DisplayText -ForeGroundColor Green " OK"
                } catch {
                    Write-ToLogFile -E -C Invoke-ADCCleanup -M "Not able to remove the Content Switch Policy. Exception Message: $($_.Exception.Message)"
                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    Write-DisplayText -ForeGroundColor Yellow " WARNING: Not able to remove the Content Switch Policy"
                }
                Write-DisplayText -Line "Cleanup CS Action"
                try {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if Content Switch Action `"$($Parameters.settings.CsaName)`" exists."
                    try {
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csaction -Resource "$($Parameters.settings.CsaName)"
                    } catch { }
                    if ($response.csaction.name -eq $($Parameters.settings.CsaName)) {
                        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Content Switch Action exist, removing Content Switch Action."
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                        $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type csaction -Resource "$($Parameters.settings.CsaName)"
                        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Removed Content Switch Action successfully."
                    } else {
                        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Content Switch Action not found."
                    }
                    Write-DisplayText -ForeGroundColor Green " OK"
                } catch {
                    Write-ToLogFile -E -C Invoke-ADCCleanup -M "Not able to remove the Content Switch Action. Exception Message: $($_.Exception.Message)"
                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    Write-DisplayText -ForeGroundColor Yellow " WARNING: Not able to remove the Content Switch Action"
                }
                Write-DisplayText -Line "Cleanup LB Vip"
                try {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if Load Balance VIP `"$($Parameters.settings.LbName)`" exists."
                    try {
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type lbvserver -Resource "$($Parameters.settings.LbName)"
                    } catch { }
                    if ($response.lbvserver.name -eq $($Parameters.settings.LbName)) {
                        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance VIP exist, removing the Load Balance VIP."
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                        $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type lbvserver -Resource "$($Parameters.settings.LbName)"
                    } else {
                        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance VIP not found."
                    }
                    Write-DisplayText -ForeGroundColor Green " OK"
                } catch {
                    Write-ToLogFile -E -C Invoke-ADCCleanup -M "Not able to remove the Load Balance VIP. Exception Message: $($_.Exception.Message)"
                    Write-DisplayText -ForeGroundColor Yellow " WARNING: Not able to remove the Load Balance VIP"
                }
            } else {
                Write-DisplayText -Line "Cleanup LB Svc Binding"
                try {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if service `"$($Parameters.settings.SvcName)`" is bound to Load Balance VIP `"$($Parameters.settings.LbName)`"."
                    try {
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type lbvserver_service_binding -Resource "$($Parameters.settings.LbName)"
                    } catch { }
                    if ($response.lbvserver_service_binding.servicename -eq $($Parameters.settings.SvcName)) {
                        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance VIP binding with Service exists, removing the Load Balance VIP-Service binding."
                        $Arguments = @{"servicename" = "$($Parameters.settings.SvcName)" }
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                        $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type lbvserver_service_binding -Resource "$($Parameters.settings.LbName)" -Arguments $arguments
                        Write-DisplayText -ForeGroundColor Green " OK"
                    } else {
                        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance VIP - Service binding not found."
                    }
                } catch {
                    Write-ToLogFile -E -C Invoke-ADCCleanup -M "Not able to remove the Load Balance VIP - Service binding. Exception Message: $($_.Exception.Message)"
                    Write-DisplayText -ForeGroundColor Yellow " WARNING: Not able to remove the Load Balance VIP - Service binding"
                }
            }
            Write-DisplayText -Line "Cleanup LB Service"
            try {
                Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if Load Balance Service `"$($Parameters.settings.SvcName)`" exists."
                try {
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type service -Resource "$($Parameters.settings.SvcName)"
                } catch { }
                if ($response.service.name -eq $($Parameters.settings.SvcName)) {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance Service exist, removing Service `"$($Parameters.settings.SvcName)`"."
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type service -Resource "$($Parameters.settings.SvcName)"
                } else {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance Service not found."
                }
                Write-DisplayText -ForeGroundColor Green " OK"
            } catch {
                Write-ToLogFile -E -C Invoke-ADCCleanup -M "Not able to remove the Service. Exception Message: $($_.Exception.Message)"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                Write-DisplayText -ForeGroundColor Yellow " WARNING: Not able to remove the Service"
            }
            Write-DisplayText -Line "Cleanup LB Server"
            try {
                Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if Load Balance Server `"$($Parameters.settings.SvcDestination)`" exists."
                try {
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type server -Resource "$($Parameters.settings.SvcDestination)"
                } catch { }
                if ($response.server.name -eq $($Parameters.settings.SvcDestination)) {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance Server exist, removing Load Balance Server `"$($Parameters.settings.SvcDestination)`"."
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type server -Resource "$($Parameters.settings.SvcDestination)"
                } else {
                    Write-ToLogFile -I -C Invoke-ADCCleanup -M "Load Balance Server not found."
                }
                Write-DisplayText -ForeGroundColor Green " OK"
            } catch {
                Write-ToLogFile -E -C Invoke-ADCCleanup -M "Not able to remove the Server. Exception Message: $($_.Exception.Message)"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                Write-DisplayText -ForeGroundColor Yellow " WARNING: Not able to remove the Server"
            }
            Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if there are Responder Policies starting with the name `"$($Parameters.settings.RspName)`"."
            Write-DisplayText -Line "Cleanup Responder Policy"
            try {
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderpolicy -Filter @{name = "/$($Parameters.settings.RspName)/" }
            } catch {
                Write-ToLogFile -E -C Invoke-ADCCleanup -M "Failed to retrieve Responder Policies. Exception Message: $($_.Exception.Message)"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            }
            if (-not([String]::IsNullOrEmpty($($response.responderpolicy)))) {
                Write-ToLogFile -D -C Invoke-ADCCleanup -M "Responder Policies found:"
                $response.responderpolicy | Select-Object name, action, rule | ForEach-Object {
                    Write-ToLogFile -D -C Invoke-ADCCleanup -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                }
                foreach ($ResponderPolicy in $response.responderpolicy) {
                    try {
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                        Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if policy `"$($ResponderPolicy.name)`" is bound to Load Balance VIP."
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderpolicy_binding -Resource "$($ResponderPolicy.name)"
                        foreach ($ResponderBinding in $response.responderpolicy_binding) {
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
            Write-DisplayText -ForeGroundColor Green " OK"
            Write-ToLogFile -I -C Invoke-ADCCleanup -M "Checking if there are Responder Actions starting with the name `"$($Parameters.settings.RsaName)`"."
            Write-DisplayText -Line "Cleanup Responder Action"
            try {
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderaction -Filter @{name = "/$($Parameters.settings.RsaName)/" }
            } catch {
                Write-ToLogFile -E -C Invoke-ADCCleanup -M "Failed to retrieve Responder Actions. Exception Message: $($_.Exception.Message)"
                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            }
            if (-not([String]::IsNullOrEmpty($($response.responderaction)))) {
                Write-ToLogFile -D -C Invoke-ADCCleanup -M "Responder Actions found:"
                $response.responderaction | Select-Object name, target | ForEach-Object {
                    Write-ToLogFile -D -C Invoke-ADCCleanup -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                }
                foreach ($ResponderAction in $response.responderaction) {
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
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
            Write-DisplayText -ForeGroundColor Green " OK"

            if ($Full) {

            }
            Write-DisplayText -Line "Cleanup"
            Write-DisplayText -ForeGroundColor Green " Completed"
            Write-ToLogFile -I -C Invoke-ADCCleanup -M "Finished cleaning up."
        } else {
            Write-DisplayText -Line "Cleanup"
            Write-DisplayText -ForeGroundColor Green "Nothing to clean"
            Write-ToLogFile -I -C Invoke-ADCCleanup -M "Not required, nothng to clean."
        }
        $Script:ADCCleanRequired = $false
    }
}

function Invoke-NSPublishTXTRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]$DomainName,

        [Parameter(Mandatory = $true)]
        [String]$TXTValue,

        [Parameter()]
        [Int]$TTL = 300
    )

    $payload = @{
        domain = $DomainName
        string = $TXTValue
        ttl    = $TTL
    }
    try {
        Write-ToLogFile -I -C Invoke-ADCPublishTXTRecord -M "Adding NS TXT Record for Domain: $DomainName"
        Write-DisplayText -Line "Adding NS TXT Record"
        $filters = @{
            domain = $DomainName
            string = $TXTValue
        }
        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type dnstxtrec -Filters $filters
        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
        if ($response.dnstxtrec) {
            Write-DisplayText -ForeGroundColor Yellow " already exists"
            Write-ToLogFile -I -C Invoke-ADCPublishTXTRecord -M "TXT Record already exists."
        } else {
            Write-ToLogFile -I -C Invoke-ADCPublishTXTRecord -M "Adding TXT Record for Domain: $DomainName"
            Write-DisplayText -ForeGroundColor Cyan -NoNewLine " $DomainName"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type dnstxtrec -Payload $payload
            Write-DisplayText -ForeGroundColor Green " OK"
            Write-ToLogFile -I -C Invoke-ADCPublishTXTRecord -M "TXT Record added successfully."
        }
    } catch {
        Write-DisplayText -ForeGroundColor Red " Error"
        Write-ToLogFile -E -C Invoke-ADCPublishTXTRecord -M "Could not add TXT Record. Exception Message: $($_.Exception.Message)"
        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
        throw "Could not add TXT Record. Exception Message: $($_.Exception.Message)"
    }
}

function Invoke-NSRemoveTXTRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]$DomainName,

        [Parameter(Mandatory = $true)]
        [String]$TXTValue
    )

    try {
        Write-ToLogFile -I -C Invoke-NSRemoveTXTRecord -M "Removing NS TXT Record for Domain: $DomainName"
        Write-DisplayText -Line "Remove NS TXT Record"
        Write-DisplayText -ForeGroundColor Cyan -NoNewLine "$DomainName"
        $filters = @{
            domain = $DomainName
            string = $TXTValue
        }
        Write-DisplayText -ForeGroundColor Yellow -NoNewLine " *"
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type dnstxtrec -Filters $filters
        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
        if ($response.dnstxtrec) {
            Write-ToLogFile -I -C Invoke-NSRemoveTXTRecord -M "Record found, removing TXT Record for Domain: $DomainName"
            $arguments = @{
                "recordid" = $response.dnstxtrec.recordid
            }
            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
            $response = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type dnstxtrec -Resource "$($DomainName)" -Arguments $arguments
            Write-DisplayText -ForeGroundColor Green " OK"
            Write-ToLogFile -I -C Invoke-NSRemoveTXTRecord -M "TXT Record removed successfully."
        } else {
            Write-DisplayText -ForeGroundColor Yellow " Record not found"
            Write-ToLogFile -I -C Invoke-NSRemoveTXTRecord -M "TXT Record not found."
        }
    } catch {
        if ($_.Exception.Message -match "404") {
            Write-DisplayText -ForeGroundColor Yellow " Record not found"
            Write-ToLogFile -I -C Invoke-NSRemoveTXTRecord -M "TXT Record not found."
        } else {

            Write-DisplayText -ForeGroundColor Red " Error"
            Write-ToLogFile -E -C Invoke-NSRemoveTXTRecord -M "Could not remove TXT Record. Exception Message: $($_.Exception.Message)"
            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            throw "Could not remove TXT Record. Exception Message: $($_.Exception.Message)"
        }
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
                throw $_
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
            Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Features enabled, verifying Content Switch."
            if (-not $CertRequest.UseLbVip) {
                foreach ($csVip in $CertRequest.CsVipName) {
                    try {
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csvserver -Resource $csVip
                        Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Content Switch is OK, check if Load Balance Service exists."
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    } catch {
                        $ExceptMessage = $_.Exception.Message
                        Write-DisplayText -ForeGroundColor Red " Error"
                        Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Could not find/read out the content switch `"$csVip`" not available? Exception Message: $ExceptMessage"
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                        Write-Error "Could not find/read out the content switch `"$csVip`" not available?"
                        TerminateScript 1 "Could not find/read out the content switch `"$csVip`" not available?"
                        if ($ExceptMessage -like "*(404) Not Found*") {
                            Write-DisplayText -ForeGroundColor Red "The Content Switch `"$csVip`" does NOT exist!"
                            Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "The Content Switch `"$csVip`" does NOT exist!"
                            TerminateScript 1 "The Content Switch `"$csVip`" does NOT exist!"
                        } elseif ($ExceptMessage -like "*The remote server returned an error*") {
                            Write-DisplayText -ForeGroundColor Red "Unknown error found while checking the Content Switch: `"$csVip`"."
                            Write-DisplayText -ForeGroundColor Red "Error message: `"$ExceptMessage`""
                            Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Unknown error found while checking the Content Switch: `"$csVip`". Exception Message: $ExceptMessage"
                            TerminateScript 1 "Unknown error found while checking the Content Switch: `"$csVip`". Exception Message: $ExceptMessage"
                        } elseif (-not [String]::IsNullOrEmpty($ExceptMessage)) {
                            Write-DisplayText -ForeGroundColor Red "Unknown Error, `"$ExceptMessage`""
                            Write-ToLogFile -E -C Invoke-AddInitialADCConfig -M "Caught an unknown error. Exception Message: $ExceptMessage"
                            TerminateScript 1 "Caught an unknown error. Exception Message: $ExceptMessage"
                        }
                    }
                }
            } else {
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Skipped, UseLbVip parameter was configured."
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Check if Load Balance Service exists."
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
            if (-not([String]::IsNullOrEmpty($($response.responderpolicy)))) {
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Responder Policies found"
                $response.responderpolicy | Select-Object name, action, rule | ForEach-Object {
                    Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                }
                foreach ($ResponderPolicy in $response.responderpolicy) {
                    try {
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                        Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Checking if policy `"$($ResponderPolicy.name)`" is bound to Load Balance VIP."
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderpolicy_binding -Resource "$($ResponderPolicy.name)"
                        foreach ($ResponderBinding in $response.responderpolicy_binding) {
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
            if (-not([String]::IsNullOrEmpty($($response.responderaction)))) {
                Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "Responder Actions found:"
                $response.responderaction | Select-Object name, target | ForEach-Object {
                    Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                }
                foreach ($ResponderAction in $response.responderaction) {
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
            $payload = @{"name" = "$($($Parameters.settings.RsaName))_test"; "type" = "respondwith"; "target" = '"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\nXXXX"'; }
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
            Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Responder Policy bound successfully."
            if (-not $CertRequest.UseLbVip) {

                try {
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Check if Content Switch Action exists with Load Balance VIP $($Parameters.settings.LbName) as target."
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csaction -Resource $($Parameters.settings.CsaName)
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Content Switch Action exists, validating current settings..."
                    Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "Response: $($response | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    if (-not($response.csaction.targetlbvserver -eq $Parameters.settings.LbName)) {
                        Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Update required, making changes"
                        $payload = @{ "name" = "$($Parameters.settings.CsaName)"; "targetlbvserver" = "$($Parameters.settings.LbName)"; "comment" = "Let's Encrypt Temp Action"; }
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type csaction -Payload $payload
                        Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "Response: $($response | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    }
                } catch {
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Create Content Switch Action."
                    $payload = @{ "name" = "$($Parameters.settings.CsaName)"; "targetlbvserver" = "$($Parameters.settings.LbName)"; "comment" = "Let's Encrypt Temp Action"; }
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type csaction -Payload $payload -Action add
                    Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "Response: $($response | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                }
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Content Switch Action is OK"
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                try {
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Check if Content Switch Policy exists."
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type cspolicy -Resource $($Parameters.settings.CspName)
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Content Switch Policy exists, validating current settings..."
                    Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "Response: $($response | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    if ((-not($response.cspolicy.rule -eq "HTTP.REQ.URL.CONTAINS(`"well-known/acme-challenge/`")")) -or (-not ($response.cspolicy.action -eq $($Parameters.settings.CsaName)))) {
                        Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Update required, making changes"
                        $payload = @{"policyname" = "$($Parameters.settings.CspName)"; "rule" = "HTTP.REQ.URL.CONTAINS(`"well-known/acme-challenge/`")"; "action" = "$($Parameters.settings.CsaName)" ; }
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type cspolicy -Payload $payload
                        Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "Response: $($response | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    }
                } catch {
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Create Content Switch Policy."
                    $payload = @{"policyname" = "$($Parameters.settings.CspName)"; "rule" = 'HTTP.REQ.URL.CONTAINS("well-known/acme-challenge/")'; "action" = "$($Parameters.settings.CsaName)"; }
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type cspolicy -Payload $payload -Action add
                    Write-ToLogFile -D -C Invoke-AddInitialADCConfig -M "Response: $($response | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                }
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Content Switch Policy is OK"
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                foreach ($csVip in $CertRequest.CsVipName) {
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Bind Content Switch Policy `"$($Parameters.settings.CspName)`" to Content Switch `"$csVip`" with prio: $($Parameters.settings.CsVipBinding)"
                    $payload = @{ "name" = "$csVip"; "policyname" = "$($Parameters.settings.CspName)"; "priority" = "$($Parameters.settings.CsVipBinding)"; "gotopriorityexpression" = "END"; }
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type csvserver_cspolicy_binding -Payload $payload
                    Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "Binding created successfully!"
                }
            } else {
                Write-ToLogFile -I -C Invoke-AddInitialADCConfig -M "NO Content Switch Action & Policy created, UseLbVip parameter was configured"
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
        foreach ($DNSObject in $SessionRequestObject.DNSObjects ) {
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
            if ($result.RawContent -like "HTTP/1.0 200 OK`r`nContent-Type: text/html`r`n`r`nXXXX") {
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
                if ($result.RawContent -like "HTTP/1.0 200 OK`r`nContent-Type: text/html`r`n`r`nXXXX") {
                    Write-DisplayText -ForeGroundColor Green "OK"
                    Write-ToLogFile -I -C Invoke-CheckDNS -M "External DNS Test: OK"
                } else {
                    Write-DisplayText -ForeGroundColor Yellow "Not successful, maybe not resolvable externally?"
                    Write-ToLogFile -W -C Invoke-CheckDNS -M "External DNS Test: Not successful, maybe not resolvable externally?"
                    Write-ToLogFile -D -C Invoke-CheckDNS -M "Output: $($result | Select-Object StatusCode,StatusDescription,RawContent | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                }
                if (-not [String]::IsNullOrEmpty($($DNSObject.DNSType))) {
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
    [OutputType([PSCustomObject], [string])]
    param (
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [Object]$Object,

        [Switch]$AsJson,

        [Switch]$IncludeUserName
    )
    process {
        try {
            $username = ""
            $IsEncrypted = $false

            if ([String]::IsNullOrEmpty($Object) -or ($Object.Length -eq 0)) {
                $encrypted = "<null>"
                $IsEncrypted = $true
            } elseif ($Object -is [SecureString]) {
                $encrypted = ConvertFrom-SecureString -Key (0..15) $Object
                $IsEncrypted = $true
            } elseif ($Object -is [String]) {
                $encrypted = ConvertFrom-SecureString -Key (0..15) (ConvertTo-SecureString $Object -AsPlainText -Force)
                $IsEncrypted = $true
            } elseif ($Object -is [System.Management.Automation.PSCredential]) {
                $plainText = $Object.GetNetworkCredential().Password
                if ([String]::IsNullOrEmpty($plainText)) {
                    $encrypted = "<null>"
                    $IsEncrypted = $true
                } else {
                    $encrypted = ConvertFrom-SecureString -Key (0..15) $Object.Password
                    $IsEncrypted = $true
                }
                $username = $Object.UserName
            } else {
                throw "Unsupported object type '$($Object.GetType().FullName)'. Must be String, SecureString, or PSCredential."
            }
        } catch {
            throw "Could not convert the provided object to an encrypted password. $_"
        }

        $result = [PSCustomObject]@{
            Password    = $encrypted
            IsEncrypted = $IsEncrypted
        }

        if ($IncludeUserName) {
            $result | Add-Member -MemberType NoteProperty -Name UserName -Value $username
        }

        if ($AsJson) {
            $result = $result | ConvertTo-Json -Compress -Depth 5 -ErrorAction SilentlyContinue
        }

        return $result
    }
}

function ConvertFrom-EncryptedPassword {
    [CmdletBinding(DefaultParameterSetName = "SecureString")]
    [OutputType([PSCustomObject], [string], [SecureString], [PSCredential])]
    param (
        [Parameter(ParameterSetName = "SecureString", Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName = "ClearText", Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName = "Credential", Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [PSCustomObject]$Object,

        [Parameter(ParameterSetName = "ClearText")]
        [Switch]$AsClearText,

        [Parameter(ParameterSetName = "Credential")]
        [Switch]$AsCredential
    )
    process {
        try {
            if (($object | Get-Member -Name Password -MemberType NoteProperty) -and ($object | Get-Member -Name IsEncrypted -MemberType NoteProperty)) {
                #Encrypted password object
            } elseif ($Object -is [string] -and (-not [String]::IsNullOrEmpty($Object))) {
                $tryConvert = $Object | ConvertFrom-Json -ErrorAction SilentlyContinue
                if (-not [String]::IsNullOrEmpty($tryConvert)) {
                    $Object = $tryConvert
                }
            }

            if (-not $Object.Password -or $Object.Password -eq "<null>") {
                if ($AsClearText) {
                    return ""
                } else {
                    return [SecureString]::new()
                }
            }

            if ($Object.IsEncrypted) {
                if ($AsClearText) {
                    return (New-Object System.Management.Automation.PSCredential(" ", (ConvertTo-SecureString -Key (0..15) $Object.Password))).GetNetworkCredential().Password
                } elseif ($AsCredential) {
                    $username = $Object.UserName
                    return New-Object System.Management.Automation.PSCredential($username, (ConvertTo-SecureString -Key (0..15) $Object.Password))
                } else {
                    return (New-Object System.Management.Automation.PSCredential(" ", (ConvertTo-SecureString -Key (0..15) $Object.Password))).Password
                }
            } else {
                if ($AsClearText) {
                    return "$($Object.Password)"
                } elseif ($AsCredential) {
                    $username = $Object.UserName
                    return New-Object System.Management.Automation.PSCredential($username, (ConvertTo-SecureString -AsPlainText -Force -String "$($Object.Password)"))
                } else {
                    return ConvertTo-SecureString -AsPlainText -Force -String "$($Object.Password)"
                }
            }
        } catch {
            if ($AsClearText) {
                return ""
            } else {
                return [SecureString]::new()
            }
        }
    }
}

function ConvertTo-Base64 {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$String
    )
    process {
        if (-not [string]::IsNullOrEmpty($String)) {
            return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($String))
        }
        return $null
    }
}

function ConvertFrom-Base64 {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]$String
    )
    process {
        if (-not [string]::IsNullOrEmpty($String)) {
            try {
                return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($String))
            } catch {
                throw "Invalid Base64 input: $String"
            }
        }
        return $null
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
        } elseif (-not [String]::IsNullOrEmpty($Message)) {
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

if ($Help -or ($PSBoundParameters.Count -eq 0)) {
    Get-Help $MyInvocation.InvocationName -Detailed
    exit 0
}
#endregion Help

#region ScriptBasics

# Check the -CSVIPName parameter
if ((($PSCmdlet.ParameterSetName -eq 'LECertificatesDNS') -or ($PSCmdlet.ParameterSetName -eq 'LECertificatesHTTP') -or ($PSCmdlet.ParameterSetName -eq 'CommandPolicy')) -and ($UseLbVip.ToBool() -eq $false) -and $CsVipName.Count -lt 1) {
    Write-Error -Exception ([System.Management.Automation.ParameterBindingException]::New("The `"-CsVipName`" parameter may not be empty! Only when specifying the `"-UseLbVip`" parameter.")) -ErrorAction Stop
}
[Version]$psVersionInfo = $PSVersionTable.PSVersion
$psEditionInfo = if ($PSVersionTable.ContainsKey('PSEdition')) { $PSVersionTable.PSEdition } else { 'Desktop' }

#Define the variable that will contain sensitive words like passwords that should not be logged
$Script:ReplaceSensitive = [String[]]@()

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

if (-not [String]::IsNullOrEmpty($ManagementURL)) {
    $ManagementURL = $ManagementURL.TrimEnd('/')
}

if ($CsVipName -like "*,*") {
    $CsVipName = $CsVipName.Split(",")
}

$SessionRequestObjects = @()
$Script:MailData = @()
$Script:MailLog = @()

if (-not [String]::IsNullOrEmpty($SAN)) {
    if ($SAN -is [Array]) {
        [String]$SAN = $SAN -join ","
    } else {
        [String]$SAN = $($SAN.Split(",").Split(" ") -join ",")
    }
}

$ScriptRoot = $(if ($psISE) { Split-Path -Path $psISE.CurrentFile.FullPath } else { $(if ($global:PSScriptRoot.Length -gt 0) { $global:PSScriptRoot } else { $global:pwd.Path }) })

if ($PSCmdlet.ParameterSetName -eq 'LECertificatesDNS') {
    $ValidationMethod = "dns"
}

if (-not [String]::IsNullOrEmpty($DNSParams)) {
    if ($DNSParams -is [Array]) {
        [String]$DNSParams = $DNSParams -join "`r`n"
        [hashtable]$DNSParams = ConvertFrom-StringData -StringData $DNSParams
    } elseif ($DNSParams -is [String]) {
        [String]$DNSParams = ($DNSParams -split (";") | ForEach-Object { "$($_.Trim())" }) -join "`r`n"
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
    if ((-not $AutoRun) -and (-not $CleanAllExpiredCertsOnDisk)) {
        if (($Password -is [String]) -and ($Password.Length -gt 0)) {
            $Script:ReplaceSensitive += @($Password)
            [SecureString]$Password = ConvertTo-SecureString -String $Password -AsPlainText -Force
        }
        if ((($Password.Length -gt 0) -and ($Username.Length -gt 0))) {
            [PSCredential]$Credential = New-Object System.Management.Automation.PSCredential ($Username, $Password)
            $Script:ReplaceSensitive += @($Credential.GetNetworkCredential().Password)
        }
        if (([PSCredential]::Empty -eq $Credential) -or ([String]::IsNullOrEmpty($Credential))) {
            if ([string]::IsNullOrEmpty($Username)) {
                $Credential = Get-Credential -UserName nsroot -Message "Citrix ADC Credentials"
            } else {
                $Credential = Get-Credential -UserName $Username -Message "Citrix ADC Credentials"
            }
            $Script:ReplaceSensitive += @($Credential.GetNetworkCredential().Password)
        }
        if (([PSCredential]::Empty -eq $Credential) -or ([String]::IsNullOrEmpty($Credential))) {
            throw "No valid credential found, -Username & -Password or -Credential not specified!"
        } else {
            $ADCCredentialUsername = $Credential.Username
            $ADCCredentialPassword = $Credential.Password
            $Script:ReplaceSensitive += @($Credential.GetNetworkCredential().Password)
        }
        if (($PfxPassword -is [String]) -and ($PfxPassword.Length -gt 0)) {
            $Script:ReplaceSensitive += @($PfxPassword)
            [SecureString]$PfxPassword = ConvertTo-SecureString -String $PfxPassword -AsPlainText -Force
        }
    }
} catch {
    throw "Could not convert to Secure Values! Exception Message: $($_.Exception.Message)"
}

try {
    Write-DisplayText -Title "Script"
    if ($AutoRun -and (-not (Test-Path -Path $ConfigFile -ErrorAction SilentlyContinue))) {
        throw "Config File NOT found! This is required when specifying the AutoRun parameter!"
    }
    Write-DisplayText -Line "PowerShell Version"
    Write-DisplayText -ForeGroundColor Cyan "$($PSVersionTable.PSVersion.ToString()) ($psEditionInfo)"
    Write-DisplayText -Line "PowerShell Edition"
    Write-DisplayText -ForeGroundColor Cyan "$psEditionInfo"

    $Parameters = [PSCustomObject]@{
        settings     = [PSCustomObject]@{ }
        certrequests = @()
    }
    $SaveConfig = $false
    if (-not [String]::IsNullOrEmpty($ConfigFile)) {
        $ConfigPath = try { Split-Path -Path $ConfigFile -Parent -ErrorAction SilentlyContinue } catch { $null }
        if ([String]::IsNullOrEmpty($ConfigPath) -or $ConfigPath -eq ".") {
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
                try { if (-not $Parameters.GetType().Name -eq "PSCustomObject") { $Parameters = New-Object -TypeName PSCustomObject } } catch { $Parameters = New-Object -TypeName PSCustomObject }
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                if ([String]::IsNullOrEmpty($($Parameters | Get-Member -Name "settings" -ErrorAction SilentlyContinue))) { $Parameters | Add-Member -MemberType NoteProperty -Name "settings" -Value $(New-Object -TypeName PSCustomObject) }
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                if ([String]::IsNullOrEmpty($($Parameters | Get-Member -Name "certrequests" -ErrorAction SilentlyContinue))) { $Parameters | Add-Member -MemberType NoteProperty -Name "certrequests" -Value @() }
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                try { if (-not ($Parameters.settings.GetType().Name -eq "PSCustomObject")) { $Parameters.settings = $(New-Object -TypeName PSCustomObject) } } catch { $Parameters.settings = $(New-Object -TypeName PSCustomObject) }
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                if (-not ($Parameters.certrequests -is [Array])) { $Parameters.certrequests = @() }
                try {
                    if ($Parameters.settings.ScriptVersion -ne $ScriptVersion) {
                        if ( $Parameters.settings | Get-Member -Name ScriptVersion ) {
                            $Parameters.settings.ScriptVersion = $ScriptVersion
                        } else {
                            $Parameters.settings | Add-Member -MemberType NoteProperty -Name ScriptVersion -Value $ScriptVersion
                        }
                        $SaveConfig = $true
                    }
                } catch { }

                try {
                    $Script:ReplaceSensitive += @(ConvertFrom-EncryptedPassword -Object $($Parameters.settings.ADCCredentialPassword) -AsClearText)
                } catch {
                    $PreLogLines += "E;CONFIGFILE;Could not read the ADCCredential. ERROR: $($_.Exception.Message)"
                }
                try {
                    $Script:ReplaceSensitive += @(ConvertFrom-EncryptedPassword -Object $($Parameters.settings.SMTPCredentialPassword) -AsClearText)
                } catch {
                    $PreLogLines += "W;CONFIGFILE;Could not read the SMTPCredential. ERROR:$($_.Exception.Message)"
                }
                if ($Parameters.certrequests.Count -gt 0) {
                    $Parameters.certrequests | ForEach-Object {
                        try {
                            $Script:ReplaceSensitive += @(ConvertFrom-EncryptedPassword -Object $_.PfxPassword -AsClearText)
                        } catch {
                            $PreLogLines += "E;CONFIGFILE;Could not read the PfxPassword. ERROR:$($_.Exception.Message)"
                        }
                    }
                }
            } catch {
                Write-DisplayText -ForeGroundColor Red "Error, Maybe the JSON file is invalid.`r`n$($_.Exception.Message)"
                $PreLogLines += "E;CONFIGFILE;Error, Maybe the JSON file is invalid.`r`n$($_.Exception.Message)"
                $PreLogLines += "I;CONFIGFILE;Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
            }
            Write-DisplayText -ForeGroundColor Green " Done"
        } else {
            Write-DisplayText -Blank
            Write-DisplayText -Line "Status"
            Write-DisplayText -ForeGroundColor Cyan "Not Found, creating new ConfigFile"
            $PreLogLines += "I;CONFIGFILE;`"$ConfigFile`" not Found, creating new ConfigFile"
            if ($AutoRun) {
                Write-DisplayText -ForeGroundColor Red "No valid certificate requests found! This is required when specifying the AutoRun parameter!"
                throw "No valid certificate requests found! This is required when specifying the AutoRun parameter!"
            }
        }
        if ($Parameters.certrequests.Count -le 0) {
            $Parameters.certrequests += New-Object -TypeName PSCustomobject
            if ($AutoRun) {
                Write-DisplayText -ForeGroundColor Red "No valid certificate requests found! This is required when specifying the AutoRun parameter!"
                throw "No valid certificate requests found! This is required when specifying the AutoRun parameter!"
            }
        }
    } elseif ($ADCActionsRequired -eq $false) {
        Write-DisplayText -ForeGroundColor Yellow "Skipped"
    } elseif ($AutoRun) {
        Write-DisplayText -ForeGroundColor Red "Not Found! This is required when specifying the AutoRun parameter!"
        throw "Config File NOT found! This is required when specifying the AutoRun parameter!`r`n$($_.Exception.Message)"
    } elseif ($CertificateActions) {
        if ($Parameters.certrequests.Count -le 0) {
            $Parameters.certrequests += New-Object -TypeName PSCustomobject
        }
    }
} catch {
    Write-DisplayText -ForeGroundColor Yellow "Could not load the Config File`r`n$($_.Exception.Message)"
    if ($AutoRun) {
        throw "Could not load the Config File!`r`n$($_.Exception.Message)"
    }
}

Write-DisplayText -Line "Initializing parameters"
Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
$PreLogLines += "I;PARAMETERS;Initializing parameters"
if ($AutoRun) {
    $PreLogLines += "D;PARAMETERS;AutoRun active, Initialize the ADCCredential."
    try {
        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
        $ADCCredentialUsername = $Parameters.settings.ADCCredentialUsername
        $ADCCredentialPassword = ConvertFrom-EncryptedPassword -Object $($Parameters.settings.ADCCredentialPassword)
        $Script:ReplaceSensitive += @(ConvertFrom-EncryptedPassword -Object $($Parameters.settings.ADCCredentialPassword) -AsClearText)
        $Credential = New-Object -TypeName PSCredential -ArgumentList $ADCCredentialUsername, $ADCCredentialPassword
        $PreLogLines += "D;PARAMETERS;ADCCredential ready. Username:$($Credential.UserName)"
        if (-not $Parameters.settings.ADCCredentialPassword.IsEncrypted) {
            Invoke-AddUpdateParameter -Object $Parameters.settings -Name ADCCredentialPassword -Value $(ConvertTo-EncryptedPassword -Object $ADCCredentialPassword)
            $SaveConfig = $true
        }
    } catch {
        $PreLogLines += "E;PARAMETERS;Could not read the ADCCredential. ERROR:$($_.Exception.Message)"
        throw "Could not read ADC credentials. ERROR:$($_.Exception.Message)"
    }
    try {
        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
        $PreLogLines += "D;PARAMETERS;Initialize the SMTPCredential."
        $SMTPCredentialUsername = $Parameters.settings.SMTPCredentialUsername
        $SMTPCredentialPassword = ConvertFrom-EncryptedPassword -Object $($Parameters.settings.SMTPCredentialPassword)
        if ($SMTPCredentialPassword.Length -gt 0) {
            try {
                $Script:ReplaceSensitive += @(ConvertFrom-EncryptedPassword -Object $SMTPCredentialPassword -AsClearText)
            } catch {
                $PreLogLines += "W;PARAMETERS;Could not read the SMTPCredentialPassword. ERROR:$($_.Exception.Message)"
            }
        } else {
            $SMTPCredentialPassword = [SecureString]::new()
        }
        if ([String]::IsNullOrEmpty($SMTPCredentialUsername)) {
            $SMTPCredentialUsername = $null
            $PreLogLines += "D;PARAMETERS;SMTPCredential not Initialized, skipped"
        } else {
            $SMTPCredential = New-Object -TypeName PSCredential -ArgumentList $SMTPCredentialUsername, $SMTPCredentialPassword
            $PreLogLines += "D;PARAMETERS;SMTPCredential ready. Username:$($SMTPCredential.UserName)"
        }
        if (-not $Parameters.settings.SMTPCredentialPassword.IsEncrypted) {
            Invoke-AddUpdateParameter -Object $Parameters.settings -Name SMTPCredentialPassword -Value $(ConvertTo-EncryptedPassword -Object $SMTPCredentialPassword)
            $SaveConfig = $true
        }
    } catch {
        $PreLogLines += "W;PARAMETERS;Could not read the SMTPCredential, setting EmptyCredential. ERROR:$($_.Exception.Message)"
        $SMTPCredential = [PSCredential]::Empty
    }
    $Global:LogLevel = $Parameters.settings.LogLevel
    Write-DisplayText -ForeGroundColor Green " Done"
    if ([String]::IsNullOrEmpty($($Parameters.settings.CsaName))) {
        Invoke-AddUpdateParameter -Object $Parameters.settings -Name CsaName -Value "csa_letsencrypt"
    }
    $PreLogLines += "I;PARAMETERS;Initialization done"
} else {
    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
    $PreLogLines += "I;PARAMETERS;AutoRun NOT active, parsing/updating the parameters."
    $SMTPCredentialUsername = $SMTPCredential.Username
    $SMTPCredentialPassword = $SMTPCredential.Password
    if ($SMTPCredentialPassword.Length -gt 0) {
        $Script:ReplaceSensitive += @(ConvertFrom-EncryptedPassword -Object $SMTPCredentialPassword -AsClearText)
    }
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
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name CsaName -Value $CsaName
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name TrafficDomain -Value $TrafficDomain
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name CsVipBinding -Value $CsVipBinding
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name ScriptVersion -Value $ScriptVersion
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name DNSParams -Value $DNSParams
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name DNSPlugin -Value $DNSPlugin
    if (($Parameters.certrequests.Count -eq 1) -and (-not $AutoRun )) {
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name Enabled -Value $true
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name CN -Value $CN
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name SANs -Value $SAN
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name FriendlyName -Value $FriendlyName
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name CsVipName -Value @($CsVipName)
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name UseLbVip -Value $([bool]::Parse($UseLbVip))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name EnableVipBefore -Value $([bool]::Parse($EnableVipBefore))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name DisableVipAfter -Value $([bool]::Parse($DisableVipAfter))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name CertKeyNameToUpdate -Value $CertKeyNameToUpdate
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name RemovePrevious -Value $([bool]::Parse($RemovePrevious))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name CertDir -Value $CertDir
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name EmailAddress -Value $EmailAddress
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name KeyLength -Value $KeyLength
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name ValidationMethod -Value $ValidationMethod
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name DNSWaitTime -Value $DNSWaitTime
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name CertExpires -Value $null
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name RenewAfter -Value $null
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name Partitions -Value $Partitions
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name ForceCertRenew -Value $([bool]::Parse($ForceCertRenew))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name DisableIPCheck -Value $([bool]::Parse($DisableIPCheck))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name AlternateDNSValidationDomain -Value $AlternateDNSValidationDomain
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name AlternateDNSValidationDomainSkipCheck -Value $([bool]::Parse($AlternateDNSValidationDomainSkipCheck))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name UseNetScalerDNS -Value $([bool]::Parse($UseNetScalerDNS))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name PfxPassword -Value $PfxPassword
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name UpdateIIS -Value $([bool]::Parse($UpdateIIS))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name IISSiteToUpdate -Value $IISSiteToUpdate
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name UpdateGlobalVPNCertBinding -Value $([bool]::Parse($UpdateGlobalVPNCertBinding))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name GlobalVPNCertBindingIncludeCA -Value $([bool]::Parse($GlobalVPNCertBindingIncludeCA))
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name GlobalVPNCertBindingCrlCheck -Value $GlobalVPNCertBindingCrlCheck
        Invoke-AddUpdateParameter -Object $Parameters.certrequests[0] -Name GlobalVPNCertBindingOcspCheck -Value $GlobalVPNCertBindingOcspCheck
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

if (-not [string]::IsNullOrEmpty($ApiPassword)) {
    $Script:ReplaceSensitive += @($ApiPassword)
}

# Get only the unique sensitive words
$Script:ReplaceSensitive = @($Script:ReplaceSensitive | Select-Object -Unique | Sort-Object Length -Descending)


# Ratelimit protection https://letsencrypt.org/docs/rate-limits/#new-registrations-per-ip-address
if ($Parameters.settings | Get-Member -Name NewRegistrationsAfter -ErrorAction SilentlyContinue) {
    $PreLogLines += "D;PARAMETERS;NewRegistrationsAfter already set to `"$($Parameters.settings.NewRegistrationsAfter)`"."
} else {
    $Parameters.settings | Add-Member -MemberType NoteProperty -Name NewRegistrationsAfter -Value (Get-Date)
    $PreLogLines += "D;PARAMETERS;NewRegistrationsAfter added and set to `"$($Parameters.settings.NewRegistrationsAfter)`"."
}

if ($Parameters.settings.DisableLogging) {
    $Script:LoggingEnabled = $false
    $Global:LogLevel = "None"
    Invoke-AddUpdateParameter -Object $Parameters.settings -Name LogLevel -Value $Global:LogLevel
    $PreLogLines += "D;PARAMETERS;LogLevel set to `"$($Parameters.settings.LogLevel)`"."
} else {
    $Script:LoggingEnabled = $true
    if ($Parameters.settings.LogFile -like "*<DEFAULT>*") {
        $Parameters.settings.LogFile = Join-Path -Path $ScriptRoot -ChildPath $($MyInvocation.MyCommand -replace '.ps1', '.txt' )
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
PowerShell Version: $($($PSVersionTable.PSVersion.ToString()))
Edition: $psEditionInfo
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
    foreach ($line in $PreLogLines) {
        $lLevel, $lComponent, $lMessage = $line -split ';'
        $lExpression = 'Write-ToLogFile -{0} -C {1} -M "{2}"' -f $lLevel, $lComponent, $(($lMessage -join ';').Replace('"', '`"'))
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
    Remove-Item -Path $ACMEStorage -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $ACMEStorage -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
}

#endregion CleanPoshACMEStorage

#region LoadModule

if ($CertificateActions) {
    Write-ToLogFile -I -C DOTNETCheck -M "Checking if .NET Framework 4.7.2 or higher is installed."
    $NetRelease = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release).Release
    if ($NetRelease -lt 461808 -and $psVersionInfo -gt [Version]"5.1" -and $psVersionInfo -lt [Version]"6.0") {
        Write-ToLogFile -W -C DOTNETCheck -M ".NET Framework 4.7.2 or higher is NOT installed. This is required to run the script on this version of PowerShell ($psVersionInfo)."
        Write-DisplayText -NoNewLine -ForeGroundColor RED "`n`nWARNING: "
        Write-DisplayText ".NET Framework 4.7.2 or higher is not installed, please install before continuing!"
        Start-Process https://www.microsoft.com/net/download/dotnet-framework-runtime
        TerminateScript 1 ".NET Framework 4.7.2 or higher is not installed, please install before continuing!"
    } elseif ($psVersionInfo -gt [Version]"6.0") {
        Write-ToLogFile -I -C DOTNETCheck -M ".NET Framework 4.7.2 is not required on this version of PowerShell ($psVersionInfo)."
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
        if (-not [String]::IsNullOrEmpty($($AvailableVersions.masterimportant))) {
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
        if (-not [String]::IsNullOrEmpty($($AvailableVersions.devimportant))) {
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
    Write-DisplayText -Title "Citrix NS Connection"
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
    Write-DisplayText -ForeGroundColor Cyan "**SENSITIVE**"
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
            TerminateScript 1 "You are connected to the $($hanode.state) node, http certificate request will fail!"
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

    if ($CreateUserPermissions -and $UseLbVip) {
        #Do Nothing, skip for CsVipName when using the -UseLbVip parameter
    } elseif ($CreateUserPermissions -and ([String]::IsNullOrEmpty($($CsVipName)) -or ($CsVipName.Count -lt 1)) ) {
        Write-DisplayText -Line "Content Switch"
        Write-DisplayText -ForeGroundColor Red "NOT Found! This is required for Command Policy creation!"
        TerminateScript 1 "No Content Switch VIP name defined, this is required for Command Policy creation!"
    }
}
#endregion ADC-Check

#region ApiUserPermissions

if ($CreateUserPermissions -or $CreateApiUser) {
    Write-DisplayText -Blank
    $CSVipString = ""
    Write-Information "INFO: When you want to use own names instead of the default values for VIPs, Policies, Actions, etc." -InformationAction Continue
    Write-Information "INFO: Please run the script with the optional parameters. These names will be defined in the Command Policy." -InformationAction Continue
    Write-Information "INFO: Only those configured are allowed to be used by the members of the Command Policy:" -InformationAction Continue
    if ($NSCPName.length -ge 24) {
        Write-Information "INFO: `"$($NSCPName.subString(0,24))-(Basics|LEBkEd|LEFtEd)`"!" -InformationAction Continue
    } else {
        Write-Information "INFO: `"$($NSCPName)-(Basics|LEBkEd|LEFtEd)`"!" -InformationAction Continue
    }
    Write-Information "INFO: You can rerun this script with the changed parameters at any time to update an existing Command Policy" -InformationAction Continue
    Write-ToLogFile -I -C ApiUserPermissions -M "CreateUserPermissions parameter specified, create or update Command Policy `"$($NSCPName)-(Basics|Custom)`""
    Write-DisplayText -Title "Api User Permissions Group (Command Policy)"
    Write-DisplayText -Line "Command Policy Name"
    Write-DisplayText -ForeGroundColor Cyan "$($NSCPName)-(Basics|LEBkEd|LEFtEd) "
    Write-DisplayText -Line "CS VIP Name"
    $csVipExtraActionsString = ""
    if ($EnableVipBefore -eq $true) {
        $csVipExtraActionsString = $csVipExtraActionsString += '|enable'
    }
    if ($DisableVipAfter -eq $true) {
        $csVipExtraActionsString = $csVipExtraActionsString += '|disable'
    }

    if (-not $UseLbVip -or [String]::IsNullOrEmpty($CsVipName)) {
        foreach ($VipName in $CsVipName) {
            $CSVipString += "|(^(set|show|bind|unbind$($csVipExtraActionsString))\s+cs\s+vserver(\s+$($VipName).*))|(^\S+\s+cs\s+(policy\s+$($Parameters.settings.CspName)|action\s+$($Parameters.settings.CsaName)).*)"
        }
        Write-DisplayText -ForeGroundColor Cyan $($CsVipName -join ", ")
        Write-DisplayText -Line "CS Policy Name"
        Write-DisplayText -ForeGroundColor Cyan $($Parameters.settings.CspName)
        Write-DisplayText -Line "CS Action Name"
        Write-DisplayText -ForeGroundColor Cyan $($Parameters.settings.CsaName)
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

    #Max length 991 each
    $cmdSpec = [ordered]@{
        Basics = "(^show\s+ns\s+license)|(^show\s+ns\s+license\s+.*)|(^(create|show)\s+system\s+backup)|(^(create|show)\s+system\s+backup\s+.*)|(^convert\s+ssl\s+pkcs12)|(^show\s+ns\s+feature)|(^show\s+ns\s+feature\s+.*)|(^show\s+responder\s+action)|(^show\s+responder\s+policy)|(^(show|add|rm)\s+system\s+file.*-fileLocation.*nsconfig.*ssl.*)|(^show\s+ssl\s+certKey)|(^(add|link|unlink|update)\s+ssl\s+certKey\s+.*)|(^show\s+HA\s+node)|(^show\s+HA\s+node\s+.*)|(^(save|show)\s+ns\s+config)|(^(save|show)\s+ns\s+config\s+.*)|(^show\s+ns\s+trafficDomain)|(^show\s+ns\s+trafficDomain\s+.*)|(^show\s+ssl\s+certChain)|(^show\s+ssl\s+certChain\s+.*)|(^add\s+ssl\s+certificateChain)|(^add\s+ssl\s+certificateChain\s+.*)|(^show\s+ssl\s+certificateChain)|(^show\s+ssl\s+certificateChain\s+.*)|(^show\s+ssl\s+certLink)|(^show\s+ssl\s+certLink\s+.*)"
        LEBkEd = "(^show\s+ns\s+version)|(^\S+\s+Service\s+$($Parameters.settings.SvcName).*)|(^\S+\s+lb\s+vserver\s+$($Parameters.settings.LbName).*)|(^\S+\s+responder\s+action\s+$($Parameters.settings.RsaName).*)|(^\S+\s+responder\s+policy\s+$($Parameters.settings.RspName).*)"
        LEFtEd = "(^show\s+ns\s+version)$CSVipString"
    }
    $cmdSpecPriority = @{
        Basics = 10
        LEBkEd = 20
        LEFtEd = 30
    }
    if ($UseNetScalerDNS) {
        $cmdSpec["LEFtEd"] += "|(^\S+\s+dns\s+txtRec)|(^\S+\s+dns\s+txtRec\s+.*)"
    }
    if ($UpdateGlobalVPNCertBinding) {
        $cmdSpec["LEBkEd"] += "|(^\S+\s+vpn\s+global)|(^\S+\s+vpn\s+global\s+.*)"
    }

    #ToDo Partition "|(^(show|switch)\s+ns\s+partition)|(^(show|switch)\s+ns\s+partition\s+.*)"
    #$otherPartitions = @( $Parameters.settings.Partitions | Where-Object { $_ -ne "default"} )
    #if ($otherPartitions.Count -gt 0 ) {
    #
    #}
    foreach ($item in $($cmdSpec.GetEnumerator())) {
        Write-DisplayText -Line "Command Spec $($item.Name)"
        try {
            $policyName = "$($NSCPName)-$($item.Name)"
            if ($policyName.length -ge 31) {
                Write-DisplayText -ForeGroundColor Yellow "Policy name: `"$policyName`" is longer than 31 characters!"
                $policyNameOld = $policyName
                $policyName = "$($NSCPName.subString(0,24))-$($item.Name)"
                Write-ToLogFile -D -C ApiUserPermissions -M "$($policyName) was longer that 31 char. New policy name: `"$policyName`""
                Write-DisplayText -Line "Command Policy (new) Name"
                Write-DisplayText -ForeGroundColor Cyan "$($policyNameOld) "
                Write-DisplayText -Line "Command Spec $($item.Name)"
            } else {
                $policyName = "$($NSCPName)-$($item.Name)"
                Write-ToLogFile -D -C ApiUserPermissions -M "Policy name: `"$policyName`""
            }
            $Filters = @{ policyname = $policyName }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type systemcmdpolicy -Filters $Filters
            if ($response.systemcmdpolicy.count -eq 1) {
                Write-ToLogFile -I -C ApiUserPermissions -M "Existing found, updating Command Policy ($($item.Name))"
                Write-DisplayText -NoNewLine -ForeGroundColor Yellow "Existing policy found ($policyName), "
                $payload = @{ policyname = $policyName; action = "Allow"; cmdspec = $item.Value }
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
                Write-ToLogFile -I -C ApiUserPermissions -M "None found, creating new Command Policy ($policyName)"
                $payload = @{ policyname = $policyName; action = "Allow"; cmdspec = $item.Value }
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
    if (([PSCredential]::Empty -eq $ApiCredential) -or ($null -eq $ApiCredential)) {
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
        $policyName = "$($NSCPName)"
        if ($policyName.length -ge 24) {
            $policyNameOld = $policyName
            $policyName = "$($NSCPName.subString(0,24))"
            Write-ToLogFile -D -C ApiUser -M "$($policyNameOld) was in total longer than 31 char. New policy name: `"$policyName`""
        } else {
            $policyName = "$($NSCPName)"
            Write-ToLogFile -D -C ApiUser -M "Policy name: `"$($policyName)-(Basics|LEBkEd|LEFtEd)`""
        }
        Write-DisplayText -ForeGroundColor Cyan "$($policyName)-(Basics|LEBkEd|LEFtEd) "
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type systemuser_systemcmdpolicy_binding -Resource $ApiUsername
        $bindingsToRemove = [String[]]($response.systemuser_systemcmdpolicy_binding.policyname | Where-Object { $_ -notin "$($policyName)-Basics", "$($policyName)-LEBkEd", "$($policyName)-LEFtEd" })
        foreach ($cmdSpecItem in $($cmdSpec.GetEnumerator())) {
            $bindingsToRemove += $response.systemuser_systemcmdpolicy_binding | Where-Object { $_.policyname -eq "$($policyName)-$($cmdSpecItem.Name)" -and $_.priority -ne $cmdSpecPriority[$cmdSpecItem.Name] } | Select-Object -ExpandProperty policyname
        }
        if ($bindingsToRemove.Count -gt 0) {
            Write-ToLogFile -I -C ApiUser -M "Unauthorized, legacy or wrongly bound CmdSpec policies found ($($bindingsToRemove -join ", "))"
            Write-Warning -Message "Unauthorized, legacy or wrongly bound CmdSpec policies found ($($bindingsToRemove -join ", "))"
            foreach ($binding in $bindingsToRemove) {
                Write-ToLogFile -D -C ApiUser -M "Remove the binding for `"$binding`""
                Write-DisplayText -Line "Binding"
                Write-DisplayText -ForeGroundColor Cyan -NoNewLine "[$($binding)] "
                try {
                    $Arguments = @{ policyname = $binding }
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
        foreach ($cmdSpecItem in $($cmdSpec.GetEnumerator())) {
            $itemPolicyName = "$($policyName)-$($cmdSpecItem.Name)"
            Write-DisplayText -Line "User Policy Binding"
            Write-DisplayText -ForeGroundColor Cyan -NoNewLine "[$itemPolicyName => $($cmdSpecPriority[$cmdSpecItem.Name])] "
            if ($response.systemuser_systemcmdpolicy_binding.policyname | Where-Object { $_ -ieq $itemPolicyName }) {
                Write-DisplayText -ForeGroundColor Green "Present"
                Write-ToLogFile -I -C ApiUser -M "A bindings for `"$itemPolicyName`" already present"
            } else {
                Write-ToLogFile -I -C ApiUser -M "Creating a new binding for `"$itemPolicyName`""
                $payload = @{ username = $ApiUsername; policyname = $itemPolicyName; priority = $cmdSpecPriority[$cmdSpecItem.Name] }
                Write-ToLogFile -D -C ApiUser -M "Putting: $($payload | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                $response = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type systemuser_systemcmdpolicy_binding -Payload $payload
                Write-DisplayText -ForeGroundColor Green "Bound"
            }
        }
    } catch {
        Write-DisplayText -ForeGroundColor Red "Error"
        Write-ToLogFile -E -C ApiUser -M "Caught an error! Exception Message: $($_.Exception.Message)"
        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
    }
}

if (($CreateUserPermissions) -or ($CreateApiUser)) {
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
    } if (-not [String]::IsNullOrEmpty($($Parameters.settings.SMTPPort))) {
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
    if (-not [String]::IsNullOrEmpty($SMTPError)) {
        $Parameters.settings.SendMail = $false
        TerminateScript 1 "Incorrect values, check mail settings.`r`n$($SMTPError | Out-String)"
    }
}

#endregion MailSetuprver

#endregion ScriptBasics

if ($CertificateActions) {
    #region Services
    Write-DisplayText -Title "Let's Encrypt Preparation"
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
    Write-ToLogFile -D -C Services -M "PSServer content: $($PAServer | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
    Write-ToLogFile -I -C Services -M "By running this script you agree with the terms specified by Let's Encrypt."
    Write-DisplayText -Line "Terms Of Service URL"
    Write-DisplayText -ForeGroundColor Yellow "$($PAServer.meta.termsOfService)"
    Write-DisplayText -Line "TOS agreement"
    Write-DisplayText -ForeGroundColor Yellow "IMPORTANT, By running this script you agree with the terms specified by Let's Encrypt."
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
    foreach ($CertRequest in $Parameters.certrequests) {
        $round++
        if ($CertRequest.CsVipName -like "*,*") {
            $CertRequest.CsVipName = [String[]]$CertRequest.CsVipName.Split(",")
        } elseif (-not ($CertRequest.CsVipName -is [Array])) {
            $CertRequest.CsVipName = [String[]]$CertRequest.CsVipName
        }
        $PfxPasswordGenerated = $false
        if ((-not [String]::IsNullOrEmpty($($CertRequest.CN))) -and (-not ($CertRequest.ValidationMethod -eq "dns"))) {
            $CertRequest.ValidationMethod = "http"
        }
        if (-not ($CertRequest | Get-Member -Name "Enabled" -ErrorAction SilentlyContinue -MemberType NoteProperty)) {
            $CertRequest | Add-Member -Name "Enabled" -MemberType NoteProperty -Value $true
            $SaveConfig = $true
        }
        if (-not ($CertRequest | Get-Member -Name "ForceCertRenew" -ErrorAction SilentlyContinue -MemberType NoteProperty)) {
            $CertRequest | Add-Member -Name "ForceCertRenew" -MemberType NoteProperty -Value $false
            $SaveConfig = $true
        }
        if (-not ($CertRequest | Get-Member -Name "CurrentCertIsProduction" -ErrorAction SilentlyContinue -MemberType NoteProperty)) {
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
        } elseif (-not [String]::IsNullOrEmpty($($CertRequest.RenewAfter)) -and ($CertRequest.ForceCertRenew -eq $false) -and ($ForceCertRenew -eq $false)) {
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
            if (($($CertRequest.CN) -match "\*") -or ($CertRequest.SANs -match "\*")) {
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
            }
            if ($CertRequest.ValidationMethod -eq "dns") {
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
                if (([String]::IsNullOrWhiteSpace($($CertRequest.CsVipName)) -or ($CertRequest.CsVipName.Count -lt 1)) -and ($CertRequest.ValidationMethod -eq "http") -and (-not $CertRequest.UseLbVip)) {
                    Write-DisplayText -ForeGroundColor Red "ERROR: The `"-CsVipName`" parameter cannot be empty!" -PostBlank -PreBlank
                    Write-ToLogFile -E -C DNSPreCheck -M "The `"-CsVipName`" cannot be empty!"
                    Invoke-RegisterError 1 "The `"-CsVipName`" cannot be empty!"
                    continue
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
                    continue
                }
                Write-DisplayText -Line "SAN(s)"
                $CheckedSANs = @()
                if (-not [String]::IsNullOrEmpty($($CertRequest.SANs))) {
                    foreach ($record in $CertRequest.SANs.Split(",")) {
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
                $CertRequest.SANs = $CheckedSANs -join ","
                $mailDataItem.SAN = "$($CheckedSANs -Join ", ")"
            }

            Write-ToLogFile -D -C DNSPreCheck -M "ValidationMethod is set to: `"$($CertRequest.ValidationMethod)`"."

            if ($UseNetScalerDNS -and -not [String]::IsNullOrEmpty($AlternateDNSValidationDomain) -and $AlternateDNSValidationDomainSkipCheck -and $AutoRun) {
                Write-ToLogFile -E -C DNSPreCheck -M "-AutoRun and -UseNetScalerDNS are defined, we will allow this"

            } elseif ($DNSPlugin -ine "Manual" -and $DNSParams.count -gt 0 -and $AutoRun) {
                Write-ToLogFile -E -C DNSPreCheck -M "-AutoRun and -DNSPlugin are defined, we will allow this"

            } elseif ($CertRequest.ValidationMethod -eq "dns" -and ($AutoRun)) {
                Write-ToLogFile -E -C DNSPreCheck -M "You cannot use the dns validation method with the -AutoRun parameter!"
                Write-DisplayText -Line "DNS Validation"
                Write-DisplayText -ForeGroundColor RED "(Manual) DNS validation is configured together with the -AutoRun parameter. Only HTTP validation or Automatic DNS validations are supported with -AutoRun"
                break
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
                $CertRequest.SANs = $SANRecords -join ","

                if (-not ($SANCount -eq $SANRecords.Count)) {
                    Write-DisplayText -Line "Double Records"
                    Write-DisplayText -ForeGroundColor Yellow "WARNING: There were $($SANCount - $SANRecords.Count) double SAN values, only continuing with unique ones."
                    Write-ToLogFile -W -C DNSPreCheck -M "There were $($SANCount - $SANRecords.Count) double SAN values, only continuing with unique ones."
                } else {
                    Write-ToLogFile -I -C DNSPreCheck -M "No double SAN values found."
                }
                foreach ($SANEntry in $SANRecords) {
                    $ResponderPrio += 10
                    if (-not ($SANEntry -eq $($CertRequest.CN))) {
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

            Write-DisplayText -Title "Citrix NS Content Switch"
            if ($CertRequest.ValidationMethod -eq "dns") {
                Write-DisplayText -Line "Connection"
                Write-DisplayText -ForeGroundColor Yellow "Skipped"
            } elseif ($AutoRun -or (-not [String]::IsNullOrEmpty($($Parameters.settings.ManagementURL)))) {
                if ($CertRequest.UseLbVip) {
                    Write-DisplayText -Line "Content Switch"
                    Write-DisplayText -ForeGroundColor Yellow "Skipped, -UseLbVip specified!"
                    Write-DisplayText -Line "Connection"
                    if (-not [String]::IsNullOrEmpty($($ADCSession.Version))) {
                        Write-DisplayText -ForeGroundColor Green "OK"
                        Write-ToLogFile -I -C ADC-CS-Validation -M "Connection OK."
                    } else {
                        Write-Warning "Could not verify the Citrix ADC Connection!"
                        Write-Warning "Script will continue but uploading of certificates will probably Fail"
                        Write-ToLogFile -W -C ADC-CS-Validation -M "Could not verify the Citrix ADC Connection! Script will continue but uploading of certificates will probably Fail."
                    }
                } elseif ($CertRequest.CsVipName.Count -gt 0) {
                    $CsVipError = $false
                    $loopCounter = 0
                    foreach ($csVip in $CertRequest.CsVipName) {
                        $loopCounter++
                        Write-DisplayText -Line "Content Switch $loopCounter/$($CertRequest.CsVipName.Count)"
                        Write-DisplayText "$csVip"
                        try {
                            Write-ToLogFile -I -C ADC-CS-Validation -M "Verifying Content Switch $loopCounter of $($CertRequest.CsVipName.Count)."
                            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csvserver -Resource $csVip
                            if ($CertRequest.EnableVipBefore -eq $true -and ($response.csvserver.curstate -like "OUT OF SERVICE")) {
                                Write-DisplayText -Line "State"
                                Write-DisplayText "$($response.csvserver.curstate), needs to be enabled first (EnableVipBefore was set)"
                                Write-ToLogFile -E -C ADC-CS-Validation -M "The CS Vip is disabled, enabling it now because of parameter EnableVipBefore is set."
                                $payload = @{"name" = "$csVip"; }
                                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type csvserver -Payload $payload -Action enable
                                Write-ToLogFile -I -C ADC-CS-Validation -M "Verifying Content Switch to get latest data after enabling."
                                $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csvserver -Resource $csVip
                                Write-DisplayText -Line "New State"
                                Write-DisplayText -ForeGroundColor Cyan "$($response.csvserver.curstate)"
                                Write-DisplayText -Line "Content Switch"
                            } else {
                                Write-DisplayText -Line "Content Switch"
                            }
                        } catch {
                            $ExceptMessage = $_.Exception.Message
                            Write-ToLogFile -E -C ADC-CS-Validation -M "Error Verifying Content Switch. Details: $ExceptMessage"
                            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                        } finally {
                            Write-DisplayText -ForeGroundColor Cyan -NoNewLine "VIP"
                            if (($response.errorcode -eq "0") -and `
                                ($response.csvserver.type -eq "CONTENT") -and `
                                ($response.csvserver.curstate -eq "UP") -and `
                                ($response.csvserver.servicetype -eq "HTTP") -and `
                                ($response.csvserver.port -eq "80") ) {
                                Write-DisplayText -ForeGroundColor Green " (found)"
                                Write-DisplayText -Line "Connection"
                                Write-DisplayText -ForeGroundColor Green "OK"
                                Write-ToLogFile -I -C ADC-CS-Validation -M "Content Switch OK"
                            } elseif ($ExceptMessage -like "*(404) Not Found*") {
                                Write-DisplayText -ForeGroundColor Red " ERROR => The Content Switch does NOT exist!"
                                Write-DisplayText -Line "Error message"
                                Write-DisplayText -ForeGroundColor Red "`"$ExceptMessage`"" -PostBlank
                                Write-DisplayText -ForeGroundColor Yellow "  IMPORTANT: Please make sure a HTTP Content Switch is available" -PostBlank
                                Write-DisplayText -Line "Connection"
                                Write-DisplayText -ForeGroundColor Red "FAILED! Exiting now" -PostBlank
                                Write-ToLogFile -E -C ADC-CS-Validation -M "The Content Switch `"$csVip`" does NOT exist! Please make sure a HTTP Content Switch is available."
                                $CsVipError = $true
                                Invoke-RegisterError 1 "The Content Switch `"$csVip`" does NOT exist! Please make sure a HTTP Content Switch is available."
                            } elseif ($ExceptMessage -like "*The remote server returned an error*") {
                                Write-DisplayText -ForeGroundColor Red " ERROR => Unknown error found while checking the Content Switch"
                                Write-DisplayText -Line "Error message"
                                Write-DisplayText -ForeGroundColor Red "`"$ExceptMessage`"" -PostBlank
                                Write-DisplayText -Line "Connection"
                                Write-DisplayText -ForeGroundColor Red "FAILED! Exiting now" -PostBlank
                                Write-ToLogFile -E -C ADC-CS-Validation -M "Unknown error found while checking the Content Switch"
                                $CsVipError = $true
                                Invoke-RegisterError 1 "Unknown error found while checking the Content Switch"
                            } elseif (($response.errorcode -eq "0") -and (-not ($response.csvserver.servicetype -eq "HTTP"))) {
                                Write-DisplayText -ForeGroundColor Red " ERROR => Content Switch `"$csVip`" is $($response.csvserver.servicetype) and NOT HTTP"
                                if (-not ([String]::IsNullOrWhiteSpace($ExceptMessage))) {
                                    Write-DisplayText -Line "Error message"
                                    Write-DisplayText -ForeGroundColor Red "`"$ExceptMessage`""
                                }
                                Write-DisplayText -ForeGroundColor Yellow "  IMPORTANT: Please use a HTTP (Port 80) Content Switch!`r`n  This is required for the validation." -PreBlank -PostBlank
                                Write-DisplayText -Line "Connection"
                                Write-DisplayText -ForeGroundColor Red "FAILED! Exiting now" -PostBlank
                                Write-ToLogFile -E -C ADC-CS-Validation -M "Content Switch `"$csVip`" is $($response.csvserver.servicetype) and NOT HTTP. Please use a HTTP (Port 80) Content Switch! This is required for the validation."
                                $CsVipError = $true
                                Invoke-RegisterError 1 "Content Switch `"$csVip`" is $($response.csvserver.servicetype) and NOT HTTP. Please use a HTTP (Port 80) Content Switch! This is required for the validation."
                            } elseif ($response.csvserver.td -ne $Parameters.settings.TrafficDomain) {
                                Write-DisplayText -ForeGroundColor Red " ERROR => Content Switch has a different TrafficDomain $($response.csvserver.td) than specified $($Parameters.settings.TrafficDomain)!"
                                Write-DisplayText -ForeGroundColor Yellow "  IMPORTANT: Run the script with the `"-TrafficDomain $($response.csvserver.td)`" additional parameter." -PreBlank -PostBlank
                                Write-DisplayText -Line "Connection"
                                Write-DisplayText -ForeGroundColor Red "FAILED! Exiting now" -PostBlank
                                Write-ToLogFile -E -C ADC-CS-Validation -M "Content Switch `"$csVip`" has a different TrafficDomain $($response.csvserver.td) than specified $($Parameters.settings.TrafficDomain)! Run the script with the `"-TrafficDomain $($response.csvserver.td)`" additional parameter."
                                $CsVipError = $true
                                Invoke-RegisterError 1 "Content Switch `"$csVip`" has a different TrafficDomain $($response.csvserver.td) than specified $($Parameters.settings.TrafficDomain)!"
                            } else {
                                Write-DisplayText -ForeGroundColor Green " (found)"
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
                    }
                } else {
                    Write-DisplayText -Line "Connection"
                    if (-not [String]::IsNullOrEmpty($($ADCSession.Version))) {
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
                continue
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
                        if ($Parameters.settings.NewRegistrationsAfter -gt (Get-Date)) {
                            Write-ToLogFile -W -C Registration -M "Too many new registrations detected, skipping registration for now."
                            Write-DisplayText -ForeGroundColor Red "`nERROR: Too many new registrations detected! We need to wait 20 minutes before we can register a new account."
                            Invoke-RegisterError 1 "Too many new registrations detected"
                            continue
                        }
                        $PARegistration = Posh-ACME\New-PAAccount -Contact $($CertRequest.EmailAddress) -KeyLength $CertRequest.KeyLength -AcceptTOS
                    }
                } catch {
                    if ($_.Exception.Message -like "*too many new registrations*") {
                        Write-ToLogFile -W -C Registration -M "Too many new registrations detected."
                        Write-DisplayText -ForeGroundColor Red "`nERROR: Too many new registrations detected! We need to wait 20 minutes before we can register a new account."
                        $Parameters.settings.NewRegistrationsAfter = (Get-Date).AddMinutes(20)
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                        Invoke-RegisterError 1 "Too many new registrations detected"
                        continue
                    }
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    Write-ToLogFile -I -C Registration -M "Setting new registration to `"$($CertRequest.EmailAddress)`"."
                    try {
                        if ($Parameters.settings.NewRegistrationsAfter -gt (Get-Date)) {
                            Write-ToLogFile -W -C Registration -M "Too many new registrations detected, skipping registration for now."
                            Write-DisplayText -ForeGroundColor Red "`nERROR: Too many new registrations detected! We need to wait 20 minutes before we can register a new account."
                            Invoke-RegisterError 1 "Too many new registrations detected"
                            continue
                        }
                        $PARegistration = Posh-ACME\New-PAAccount -Contact $($CertRequest.EmailAddress) -KeyLength $CertRequest.KeyLength -AcceptTOS
                        Write-ToLogFile -I -C Registration -M "New registration successful."
                    } catch {
                        if ($_.Exception.Message -like "*too many new registrations*") {
                            Write-ToLogFile -W -C Registration -M "Too many new registrations detected."
                            Write-DisplayText -ForeGroundColor Red "`nERROR: Too many new registrations detected! We need to wait 20 minutes before we can register a new account."
                            $Parameters.settings.NewRegistrationsAfter = (Get-Date).AddMinutes(20)
                            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                            Invoke-RegisterError 1 "Too many new registrations detected"
                            continue
                        }
                        Write-ToLogFile -E -C Registration -M "New registration failed! Exception Message: $($_.Exception.Message)"
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                        Write-DisplayText -ForeGroundColor Red "`nERROR: New registration failed!"
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
                # ToDo Cleanup
                #$PARegistrations = Posh-ACME\Get-PAAccount -List -Contact $($CertRequest.EmailAddress) -Refresh | Where-Object { ($_.status -eq "valid") -and ($_.KeyLength -eq $CertRequest.KeyLength) }
                #Write-ToLogFile -D -C Registration -M "Registration: $($PARegistrations | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)."

                # ToDo Cleanup
                #if (-not ($PARegistration.Contact -contains "mailto:$($CertRequest.EmailAddress)")) {
                #    Write-DisplayText -ForeGroundColor Red " Error"
                #    Write-ToLogFile -E -C Registration -M "User registration failed."
                #    Write-Error "User registration failed"
                #    Invoke-RegisterError 1 "User registration failed"
                #    Continue
                #}
                if ($PARegistration.status -ne "valid") {
                    Write-DisplayText -ForeGroundColor Red " Error"
                    Write-ToLogFile -E -C Registration -M "Account status is $($Account.status)."
                    Write-Error "Account status is $($Account.status)"
                    Invoke-RegisterError 1 "Account status is $($Account.status)"
                    continue
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
                    Write-DisplayText -Line "Cleaning cert storage"
                    try {
                        $CertStoragePath = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Posh-ACME" -ErrorAction Stop
                        $CertStoragePath = Join-Path -Path $CertStoragePath -ChildPath ([uri]$PARegistration.location).Authority -ErrorAction Stop
                        $CertStoragePath = Join-Path -Path $CertStoragePath -ChildPath $PARegistration.id -ErrorAction Stop
                        $CertStoragePath = Join-Path -Path $CertStoragePath -ChildPath $CertRequest.CN -ErrorAction Stop
                        Write-ToLogFile -D -C Order -M "CertStoragePath: $CertStoragePath"
                        $CertStorageFilePath = Join-Path -Path $CertStoragePath -ChildPath "order.json" -ErrorAction Stop
                        Write-ToLogFile -D -C Order -M "CertStorageFilePath: CertStorageFilePath"
                        if (Test-Path -Path $CertStorageFilePath) {
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
                if (-not [String]::IsNullOrEmpty($($Parameters.settings.PfxPassword))) {
                    $PfxPassword = ConvertFrom-EncryptedPassword -Object $($Parameters.settings.PfxPassword)
                    Write-ToLogFile -I -C Order -M "PfxPassword retrieved from the settings"
                    try {
                        $Parameters.settings.PSObject.Properties.Remove('PfxPassword')
                        Write-ToLogFile -I -C Order -M "PfxPassword deleted from the settings"
                    } catch {
                        Write-ToLogFile -E -C Order -M "Could not delete PfxPassword from settings"
                    }
                }
                if (-not [String]::IsNullOrEmpty($($CertRequest.PfxPassword))) {
                    $PfxPassword = ConvertFrom-EncryptedPassword -Object $($CertRequest.PfxPassword)
                    Write-ToLogFile -I -C Order -M "PfxPassword retrieved from the cert request"
                }
                if ([String]::IsNullOrEmpty($($PfxPassword))) {
                    $PfxPassword = $GeneratedPassword
                    $PfxPasswordGenerated = $true
                    Write-ToLogFile -I -C Order -M "New PfxPassword generated"
                }
                Invoke-AddUpdateParameter -Object $CertRequest -Name PfxPassword -Value $PfxPassword
                $Script:ReplaceSensitive += @(ConvertFrom-EncryptedPassword -Object $PfxPassword)
                Write-DisplayText -Line "Order"
                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                try {
                    Write-ToLogFile -I -C Order -M "Trying to create a new order."
                    $domains = $SessionRequestObject.DNSObjects | Select-Object DNSName -ExpandProperty DNSName
                    $PAOrder = Posh-ACME\New-PAOrder -Domain $domains -AlwaysNewKey -KeyLength $CertRequest.KeyLength -Force -FriendlyName $CertRequest.FriendlyName -PfxPassSecure $PfxPassword
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
                    continue
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
                foreach ($DNSObject in $SessionRequestObject.DNSObjects) {
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
                            break
                        } else {
                            $DNSObject.Challenge = $PAChallenge
                        }
                        if (-not [String]::IsNullOrEmpty($AlternateDNSValidationDomain)) {
                            $DNSObject.IPAddress = "NoIPCheck"
                            $DNSObject.Match = $true
                            $DNSObject.Status = $true
                            Write-ToLogFile -I -C DNS-Validation -M "Skipped IP Checking for alternate DNS Validation Domain."
                        } elseif ($($CertRequest.DisableIPCheck) -or $($Parameters.settings.DisableIPCheck)) {
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
                                break

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
                            break
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
                    continue
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
                    continue
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
                        $ADCKeyAuthorization = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n$($KeyAuth)"
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
                                        break
                                    }
                                    Write-DisplayText -ForeGroundColor Green " Ready"
                                } catch {
                                    Write-ToLogFile -E -C OrderValidation -M "Failed to bind Responder Policy to Load Balance VIP. Exception Message: $($_.Exception.Message)"
                                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                    Write-DisplayText -ForeGroundColor Red " ERROR  [Responder Policy Binding - $RspName]"
                                    Write-DisplayText -ForegroundColor Red "`r`nERROR: $($_.Exception.Message)"
                                    Invoke-RegisterError 1 "Failed to bind Responder Policy to Load Balance VIP"
                                    break
                                }
                            } catch {
                                Write-ToLogFile -E -C OrderValidation -M "Failed to add Responder Policy. Exception Message: $($_.Exception.Message)"
                                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                Write-DisplayText -ForeGroundColor Red " ERROR  [Responder Policy - $RspName]"
                                Write-DisplayText -ForegroundColor Red "`r`nERROR: $($_.Exception.Message)"
                                Invoke-RegisterError 1 "Failed to add Responder Policy"
                                break
                            }
                        } catch {
                            Write-ToLogFile -E -C OrderValidation -M "Failed to add Responder Action. Error Details: $($_.Exception.Message)"
                            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                            Write-DisplayText -ForeGroundColor Red " ERROR  [Responder Action - $RsaName]"
                            Write-DisplayText -ForegroundColor Red "`r`nERROR: $($_.Exception.Message)"
                            Invoke-RegisterError 1 "Failed to add Responder Action"
                            break
                        }
                    }
                }

                if ($SessionRequestObject.ExitCode -eq 0) {
                    $orderCompletionError = $false
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
                        foreach ($Item in $($PAOrderItems | Where-Object { $_.status -ne "valid" })) {
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
                        $orderCompletionError = $true
                    } else {
                        Write-DisplayText -ForeGroundColor Green " Completed"
                        Write-ToLogFile -I -C OrderValidation -M "Validation status finished."
                    }
                } else {
                    Write-ToLogFile -D -C OrderValidation -M "Skipped Order Completion, Exit Code: $($SessionRequestObject.ExitCode)"
                }

                #region CleanupADC

                if ($CertRequest.ValidationMethod -in "http", "dns") {
                    Invoke-ADCCleanup
                }
                #endregion CleanupADC

                if ($orderCompletionError) {
                    continue
                }
            }
            #endregion OrderValidation

            #region DNSChallenge

            if (($CertRequest.ValidationMethod -eq "dns") -and ($SessionRequestObject.ExitCode -eq 0)) {
                $PAOrderItems = Posh-ACME\Get-PAOrder -Refresh -MainDomain $($CertRequest.CN) | Posh-ACME\Get-PAAuthorizations

                $TXTRecords = $PAOrderItems | Select-Object fqdn, `
                @{L = 'TXTName'; E = { "_acme-challenge.$($_.fqdn.Replace('*.',''))" } }, `
                @{L = 'TXTValue'; E = { (Get-KeyAuthorization $_.DNS01Token -ForDNS) } }, `
                @{L = 'SanitizedFqdn'; E = { "$($_.fqdn.Replace('*.',''))" } }, `
                @{L = 'Token'; E = { $_.DNS01Token } }, `
                @{L = 'AlternateDNS'; E = { if ($AlternateDNSValidationDomain) { $true } else { $false } } }, `
                @{L = 'AlternateCNAMEName'; E = { "_acme-challenge.$($($_.fqdn.Replace('*.','')))" } }, `
                @{L = 'AlternateCNAMEValue'; E = { "$($AlternateDNSValidationDomain)" } }, `
                @{L = 'AlternateTXTName'; E = { "$($AlternateDNSValidationDomain)" } }
                $PoshACMEPluginUsed = $false
                Write-DisplayText -Title "DNS Challenge"
                Write-ToLogFile -I -C DNSChallenge -M "DNS Challenge requested."

                if (-not ([String]::IsNullOrEmpty($AlternateDNSValidationDomain))) {
                    Write-ToLogFile -I -C DNSChallenge -M "Alternate DNS Validation Domain is set."
                    Write-DisplayText -Line "Alt. DNS validation"
                    Write-DisplayText -ForeGroundColor Cyan "Enabled"
                    Write-DisplayText -Line "Alt. DNS Name"
                    Write-DisplayText -ForeGroundColor Cyan "$AlternateDNSValidationDomain"
                }

                if ($UseNetScalerDNS -and (-not [String]::IsNullOrEmpty($AlternateDNSValidationDomain) -and $AlternateDNSValidationDomainSkipCheck )) {
                    Write-ToLogFile -I -C DNSChallenge -M "Alternate DNS Validation Domain is set to `"$AlternateDNSValidationDomain`" and -AlternateDNSValidationDomainSkipCheck was configured, skipping DNS manual configuration."
                    Write-DisplayText -Line "Validation Skip"
                    Write-DisplayText -ForeGroundColor Cyan "Enabled"

                } elseif ([String]::IsNullOrEmpty($DNSParams) -or [String]::IsNullOrEmpty($DNSPlugin) -or ($DNSParams.Count -eq 0) -or ($DNSPlugin -like "Manual") ) {
                    Write-DisplayText -ForeGroundColor Magenta "`r`n********************************************************************"
                    if (-not [String]::IsNullOrEmpty($AlternateDNSValidationDomain)) {
                        Write-DisplayText -ForeGroundColor Magenta "* Make sure the following CNAME records are configured at your DNS *"
                        Write-DisplayText -ForeGroundColor Magenta "* provider before continuing! If not, DNS validation will fail!    *"
                        Write-DisplayText -ForeGroundColor Magenta "* You can leave the CNAME records after validation is completed.   *"
                    } else {
                        Write-DisplayText -ForeGroundColor Magenta "* Make sure the following TXT records are configured at your DNS   *"
                        Write-DisplayText -ForeGroundColor Magenta "* provider before continuing! If not, DNS validation will fail!    *"
                    }
                    Write-DisplayText -ForeGroundColor Magenta "********************************************************************"
                    Write-ToLogFile -I -C DNSChallenge -M "Make sure the following TXT records are configured at your DNS provider before continuing! If not, DNS validation will fail!"
                    foreach ($Record in $TXTRecords) {
                        Write-DisplayText -Blank
                        if ($Record.AlternateDNS) {
                            Write-DisplayText -Line "CNAME Record Name"
                            Write-DisplayText -ForeGroundColor Cyan "$($Record.AlternateCNAMEName)"
                            Write-DisplayText -Line "CNAME Record Value"
                            Write-DisplayText -ForeGroundColor Cyan "$($Record.AlternateCNAMEValue)"
                            Write-ToLogFile -I -C DNSChallenge -M "CNAME Record: `"$($Record.AlternateCNAMEName)`" => `"$($Record.AlternateCNAMEValue)`"."
                            if (-not $UseNetScalerDNS) {
                                Write-DisplayText -Line "TXT Record Name."
                                Write-DisplayText -ForeGroundColor Yellow "$($Record.AlternateTXTName)"
                                Write-DisplayText -Line "TXT Record Value"
                                Write-DisplayText -ForeGroundColor Yellow "$($Record.TXTValue)"
                            }
                        } else {
                            Write-DisplayText -Line "DNS Hostname"
                            Write-DisplayText -ForeGroundColor Cyan "$($Record.fqdn)"
                            Write-DisplayText -Line "TXT Record Name."
                            Write-DisplayText -ForeGroundColor Yellow "$($Record.TXTName)"
                            Write-DisplayText -Line "TXT Record Value"
                            Write-DisplayText -ForeGroundColor Yellow "$($Record.TXTValue)"
                            Write-ToLogFile -I -C DNSChallenge -M "DNS Hostname: `"$($Record.fqdn)`" => TXT Record Name: `"$($Record.TXTName)`", Value: `"$($Record.TXTValue)`"."
                        }
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
                            exit (0)
                        }
                        Write-DisplayText -Blank
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

                if ($UseNetScalerDNS -and (-not [String]::IsNullOrEmpty($AlternateDNSValidationDomain))) {
                    Write-ToLogFile -I -C DNSChallenge -M "Using the NetScaler DNS Plugin."
                    Write-DisplayText -Line "NetScaler DNS Plugin"
                    Write-DisplayText -ForeGroundColor Cyan "Enabled"
                    foreach ($record in $TXTRecords) {
                        Invoke-NSPublishTXTRecord -DomainName $record.AlternateTXTName -TXTValue $record.TXTValue
                    }
                } else {
                    Write-DisplayText -Blank
                    Write-DisplayText -ForeGroundColor Green -NoNewLine "Continuing"
                    Write-DisplayText ", Waiting $($CertRequest.DNSWaitTime) seconds for the records to settle"
                    Start-Sleep -Seconds $($CertRequest.DNSWaitTime)
                }
                Write-ToLogFile -I -C DNSChallenge -M "Start verifying the TXT records."
                $issues = $false
                try {
                    Write-DisplayText -Title "Pre-Checking the TXT records"
                    foreach ($Record in $TXTRecords) {
                        Write-DisplayText -Line "DNS Hostname"
                        Write-DisplayText -ForeGroundColor Cyan "$($Record.fqdn)"
                        Write-DisplayText -Line "TXT Record check"
                        Write-ToLogFile -I -C DNSChallenge -M "Trying to retrieve the TXT record for `"$($Record.fqdn)`"."
                        $result = $null
                        if ($IPv6) {
                            $dnsserver = Resolve-DnsName -Name $Record.TXTName -Server $PublicDnsServerv6 -DnsOnly -ErrorAction SilentlyContinue
                        } else {
                            $dnsserver = Resolve-DnsName -Name $Record.TXTName -Server $PublicDnsServer -DnsOnly -ErrorAction SilentlyContinue
                        }
                        if ([String]::IsNullOrWhiteSpace($dnsserver.PrimaryServer)) {
                            Write-ToLogFile -D -C DNSChallenge -M "Using DNS Server `"$PublicDnsServer`" for resolving the TXT records."
                            $result = Resolve-DnsName -Name $Record.TXTName -Type TXT -Server $PublicDnsServer -DnsOnly -ErrorAction SilentlyContinue
                        } else {
                            Write-ToLogFile -D -C DNSChallenge -M "Using DNS Server `"$($dnsserver.PrimaryServer)`" for resolving the TXT records."
                            $result = Resolve-DnsName -Name $Record.TXTName -Type TXT -Server $dnsserver.PrimaryServer -DnsOnly -ErrorAction SilentlyContinue
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
                foreach ($DNSObject in $SessionRequestObject.DNSObjects) {
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
                            break
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
                    continue
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
                    foreach ($DNSObject in $SessionRequestObject.DNSObjects) {
                        if ($DNSObject.Done -eq $false -and (-not $ValidationError)) {
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
                                break
                            }
                            $PAOrderItem = $null
                        }
                    }
                    if ($ValidationError) {
                        break
                    }
                    if (-not ($SessionRequestObject.DNSObjects | Where-Object { $_.Done -eq $false })) {
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
                continue
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
                        continue
                    }
                    $ChainFile = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 "$($PACertificate.ChainFile)"
                    Write-ToLogFile -D -C CertFinalization -M $($ChainFile | Select-Object DnsNameList, Subject, @{ Name = 'NotBefore'; Expression = { $_.NotBefore.ToString('yyyy-MM-dd HH:mm:ss') } }, @{ Name = 'NotAfter'; Expression = { $_.NotAfter.ToString('yyyy-MM-dd HH:mm:ss') } }, SerialNumber, Thumbprint, Issuer | ConvertTo-Json -WarningAction SilentlyContinue -Compress -Depth 8)
                    $intermediateCACertName = $ChainFile.Subject.Split(",")[0].Replace('CN=', $null).Replace("'", $null).Replace('(', $null).Replace(')', $null)
                    $intermediateCACertKeyName = $intermediateCACertName
                    #ToDo: Remove old code when no issues with the longer name
                    #if ($intermediateCACertKeyName.length -gt 26) {
                    #    $intermediateCACertKeyName = $intermediateCACertKeyName -Replace '(?sm)\W', $null
                    #    Write-ToLogFile -D -C CertFinalization -M "Intermediate certificate to long, new name: `"$intermediateCACertKeyName`"."
                    #}
                    #if ($intermediateCACertKeyName.length -gt 26) {
                    #    $intermediateCACertKeyName = "$($intermediateCACertKeyName.subString(0,26))"
                    #    Write-ToLogFile -D -C CertFinalization -M "Intermediate certificate STILL to long, new name: `"$intermediateCACertKeyName`"."
                    #}
                    $intermediateCAFileName = "$($intermediateCACertKeyName)-$($ChainFile.NotAfter.ToString('yyyy')).crt"
                    $intermediateCAFullPath = Join-Path -Path $CertificateDirectory -ChildPath $intermediateCAFileName

                    Write-ToLogFile -D -C CertFinalization -M "Intermediate: `"$intermediateCAFileName`"."
                    Copy-Item $PACertificate.ChainFile -Destination $intermediateCAFullPath -Force
                    if ($Production) {
                        #ToDo: Remove old code when no issues with the longer name
                        #if ($CertificateName.length -ge 31) {
                        #    $CertificateName = "$($CertificateName.subString(0,31))"
                        #    Write-ToLogFile -D -C CertFinalization -M "CertificateName (new name): `"$CertificateName`" ($($CertificateName.length) max 31)"
                        #} else {
                        $CertificateName = "$CertificateName"
                        Write-ToLogFile -D -C CertFinalization -M "CertificateName: `"$CertificateName`" ($($CertificateName.length) characters)"
                        #}
                        #if ($CertificateAlias.length -ge 59) {
                        #    $CertificateFileName = "$($CertificateAlias.subString(0,59)).crt"
                        #    $CertificateKeyFileName = "$($CertificateAlias.subString(0,59)).key"
                        #    $CertificatePfxFileName = "$($CertificateAlias.subString(0,59)).pfx"
                        #    $CertificatePemFileName = "$($CertificateAlias.subString(0,59)).pem"
                        #} else {
                        $CertificateFileName = "$($CertificateAlias).crt"
                        $CertificateKeyFileName = "$($CertificateAlias).key"
                        $CertificatePfxFileName = "$($CertificateAlias).pfx"
                        $CertificatePemFileName = "$($CertificateAlias).pem"
                        #}
                        $CertificatePfxWithChainFileName = "$($CertificateAlias)-WithChain.pfx"
                    } else {
                        #ToDo: Remove old code when no issues with the longer name
                        #if ($CertificateName.length -ge 27) {
                        #    $CertificateName = "TST-$($CertificateName.subString(0,27))"
                        #    Write-ToLogFile -D -C CertFinalization -M "CertificateName (new name): `"$CertificateName`" ($($CertificateName.length) max 31)"
                        #} else {
                        $CertificateName = "TST-$($CertificateName)"
                        Write-ToLogFile -D -C CertFinalization -M "CertificateName: `"$CertificateName`" ($($CertificateName.length) characters)"
                        #}
                        #if ($CertificateAlias.length -ge 55) {
                        #    $CertificateFileName = "TST-$($CertificateAlias.subString(0,55)).crt"
                        #    $CertificateKeyFileName = "TST-$($CertificateAlias.subString(0,55)).key"
                        #    $CertificatePfxFileName = "TST-$($CertificateAlias.subString(0,55)).pfx"
                        #    $CertificatePemFileName = "TST-$($CertificateAlias.subString(0,55)).pem"
                        #} else {
                        $CertificateFileName = "TST-$($CertificateAlias).crt"
                        $CertificateKeyFileName = "TST-$($CertificateAlias).key"
                        $CertificatePfxFileName = "TST-$($CertificateAlias).pfx"
                        $CertificatePemFileName = "TST-$($CertificateAlias).pem"
                        #}
                        $CertificatePfxWithChainFileName = "TST-$($CertificateAlias)-WithChain.pfx"
                    }
                    Write-ToLogFile -D -C CertFinalization -M "Crt: `"$CertificateFileName`"($($CertificateFileName.length) characters)"
                    Write-ToLogFile -D -C CertFinalization -M "Key: `"$CertificateKeyFileName`"($($CertificateKeyFileName.length) characters)"
                    Write-ToLogFile -D -C CertFinalization -M "Pfx: `"$CertificatePfxFileName`"($($CertificatePfxFileName.length) characters)"
                    Write-ToLogFile -D -C CertFinalization -M "Pem: `"$CertificatePemFileName`"($($CertificatePemFileName.length) characters)"
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    $CertificateFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificateFileName
                    $CertificateKeyFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificateKeyFileName
                    $CertificatePfxFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificatePfxFileName
                    $CertificatePfxWithChainFullPath = Join-Path -Path $CertificateDirectory -ChildPath $CertificatePfxWithChainFileName
                    Copy-Item $PACertificate.CertFile -Destination $CertificateFullPath -Force
                    if (-not [String]::IsNullOrEmpty($CertificateFullPath) -and (Test-Path -Path "$CertificateFullPath" -ErrorAction SilentlyContinue)) {
                        Write-ToLogFile -D -C CertFinalization -M "Certificate file copied successfully."
                    } else {
                        Write-ToLogFile -E -C CertFinalization -M "Certificate file not copied!"
                    }
                    Copy-Item $PACertificate.KeyFile -Destination $CertificateKeyFullPath -Force
                    if (-not [String]::IsNullOrEmpty($CertificateKeyFullPath) -and (Test-Path "$CertificateKeyFullPath" -ErrorAction SilentlyContinue)) {
                        Write-ToLogFile -D -C CertFinalization -M "Key file copied successfully."
                    } else {
                        Write-ToLogFile -E -C CertFinalization -M "Key file not copied!"
                    }
                    Copy-Item $PACertificate.PfxFullChain -Destination $CertificatePfxWithChainFullPath -Force
                    if (-not [String]::IsNullOrEmpty($CertificatePfxWithChainFullPath) -and (Test-Path "$CertificatePfxWithChainFullPath" -ErrorAction SilentlyContinue)) {
                        Write-ToLogFile -D -C CertFinalization -M "Pfx file (with full chain) copied successfully."
                    } else {
                        Write-ToLogFile -E -C CertFinalization -M "Pfx file (with full chain) not copied!"
                    }
                    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor `
                        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 `
                    ($CertificatePfxWithChainFullPath, $pfxPassword, $flags)
                    if (-not $cert.HasPrivateKey) {
                        Write-ToLogFile -E -C CertFinalization -M "Certificate does not have a private key!"
                        $CertificatePfxFullPath = $CertificatePfxWithChainFullPath
                        Write-ToLogFile -D -C CertFinalization -M "Using the Pfx file (with full chain) `"$CertificatePfxFullPath`"."
                    } else {
                        Write-ToLogFile -D -C CertFinalization -M "Exporting the certificate (withou chain) to `"$CertificatePfxFullPath`"."
                        $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                        $null = $collection.Add($cert)
                        $pfxBytes = $collection.Export(
                            [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
                            $((New-Object System.Management.Automation.PSCredential(" ", ($PfxPassword))).GetNetworkCredential().Password)
                        )
                        Write-ToLogFile -D -C CertFinalization -M "Saving the certificate to `"$CertificatePfxFullPath`"."
                        [System.IO.File]::WriteAllBytes($CertificatePfxFullPath, $pfxBytes)
                        if (-not [String]::IsNullOrEmpty($CertificatePfxFullPath) -and (Test-Path "$CertificatePfxFullPath" -ErrorAction SilentlyContinue)) {
                            Write-ToLogFile -D -C CertFinalization -M "Pfx file created successfully."
                        } else {
                            Write-ToLogFile -E -C CertFinalization -M "Pfx file not created!"
                        }
                    }
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

            #region UpdateGlobalVPNCertBinding-Removal

            if (($CertRequest.ValidationMethod -in "http", "dns") -and $CertRequest.UpdateGlobalVPNCertBinding -and ($SessionRequestObject.ExitCode -eq 0)) {
                $updateGlobalVPNCertBindingActionRequired = $false
                try {
                    Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding-Removal" -M "Retrieving current SSL Certificate Binding for VPN Global"
                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    if ($response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type vpnglobal_sslcertkey_binding | Select-Object -ExpandProperty vpnglobal_sslcertkey_binding -ErrorAction SilentlyContinue) {
                        Write-ToLogFile -D -C "UpdateGlobalVPNCertBinding-Removal" -M "Response: $($response | ConvertTo-Json -Compress)"
                        if ($currentBinding = $response | Where-Object { $_.certkeyname -ieq $($CertRequest.CertKeyNameToUpdate) } ) {
                            Write-ToLogFile -D -C "UpdateGlobalVPNCertBinding-Removal" -M "Current Binding: $($currentBinding | ConvertTo-Json -Compress)"
                            Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding-Removal" -M "Unbinding current certificate"
                            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                            $arguments = @{ certkeyname = $($CertRequest.CertKeyNameToUpdate) }
                            Write-DisplayText -ForeGroundColor Yellow "*"
                            Write-DisplayText -Line "Unbinding certificate"
                            try {
                                $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type vpnglobal_sslcertkey_binding -Arguments $arguments
                                Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding-Removal" -M "Successfully unbound certificate"
                                $updateGlobalVPNCertBindingActionRequired = $true
                                Write-DisplayText -ForeGroundColor Green "Unbound (VPN Global certificate) successfully"
                            } catch {
                                Write-ToLogFile -E -C "UpdateGlobalVPNCertBinding-Removal" -M "Failed to unbind certificate"
                                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                Write-DisplayText -ForeGroundColor Red "Failed to unbind certificate"
                            }
                            Write-DisplayText -Line "Status"
                        } else {
                            Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding-Removal" -M "Bindings found, but not the one we are looking for"
                            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                        }
                    } else {
                        Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding-Removal" -M "No current binding found"
                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                    }
                } catch {
                    Write-ToLogFile -E -C "UpdateGlobalVPNCertBinding-Removal" -M "Caught an error, $($_.Exception.Message)"
                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    Invoke-RegisterError 1 "Caught an error, $($_.Exception.Message)"
                }
            }

            #endregion UpdateGlobalVPNCertBinding-Removal

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
                    Write-ToLogFile -D -C ADC-CertUpload -M "Checking if IntermediateCA `"$intermediateCACertKeyName`" already exists."
                    $intermediateFileExists = $false
                    $intermediateFileLocation = "/nsconfig/ssl/"
                    if ([String]::IsNullOrEmpty($($ADCIntermediateCA.sslcertkey.certkey))) {
                        Write-ToLogFile -D -C ADC-CertUpload -M "Checking if IntermediateCA file exists on the ADC."
                        try {
                            $Arguments = @{"filename" = "$intermediateCAFileName"; "filelocation" = "$intermediateFileLocation" }
                            try {
                                $files = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type systemfile -Arguments $arguments
                            } catch {
                                $files = @{"systemfile" = @() }
                            }
                            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                            if ($files.systemfile.count -eq 1) {
                                Write-ToLogFile -I -C ADC-CertUpload -M "IntermediateCA file already exists on the ADC, trying to read it's properties."
                                $intermediateCertificateBytes = [Convert]::FromBase64String($files.systemfile[0].filecontent)
                                $intermediateCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($intermediateCertificateBytes)
                                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                                if ($intermediateCertificate.SerialNumber -ieq $ChainFile.SerialNumber -or "$($intermediateCertificate.SerialNumber)".TrimStart("00") -ieq $ChainFile.SerialNumber) {
                                    Write-ToLogFile -I -C ADC-CertUpload -M "IntermediateCA file already exists on the ADC, and is the same as the one we are trying to upload."
                                    $intermediateCACertKeyName = $files.systemfile[0].filename
                                    $intermediateFileLocation = "$($files.systemfile[0].filelocation.TrimEnd("/"))/"
                                    Write-ToLogFile -D -C ADC-CertUpload -M "IntermediateCACertKeyName: `"$($intermediateFileLocation)$($intermediateCACertKeyName)`""
                                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                                    $intermediateFileExists = $true
                                } else {
                                    Write-ToLogFile -I -C ADC-CertUpload -M "IntermediateCA file already exists on the ADC, but is not the same as the one we are trying to upload."
                                    Write-ToLogFile -D -C ADC-CertUpload -M "Trying new name with serialnumber in the name."
                                    $intermediateCACertKeyName = "$($intermediateCACertKeyName)-$($ChainFile.SerialNumber)"
                                    $Arguments = @{"filename" = "$intermediateCAFileName"; "filelocation" = "$intermediateFileLocation" }
                                    try {
                                        $files = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type systemfile -Arguments $arguments
                                    } catch {
                                        $files = @{"systemfile" = @() }
                                    }
                                    Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                                    if ($files.systemfile.count -eq 1) {
                                        $intermediateCertificateBytes = [Convert]::FromBase64String($files.systemfile[0].filecontent)
                                        $intermediateCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($intermediateCertificateBytes)
                                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                                        if ($intermediateCertificate.SerialNumber -ieq $ChainFile.SerialNumber -or "$($intermediateCertificate.SerialNumber)".TrimStart("00") -ieq $ChainFile.SerialNumber) {
                                            Write-ToLogFile -I -C ADC-CertUpload -M "IntermediateCA file already exists on the ADC, and is the same as the one we are trying to upload."
                                            $intermediateCACertKeyName = $files.systemfile[0].filename
                                            $intermediateFileLocation = "$($files.systemfile[0].filelocation.TrimEnd("/"))/"
                                            Write-ToLogFile -D -C ADC-CertUpload -M "IntermediateCACertKeyName: `"$($intermediateFileLocation)$($intermediateCACertKeyName)`""
                                            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                                            $intermediateFileExists = $true
                                        } else {
                                            Write-ToLogFile -E -C ADC-CertUpload -M "IntermediateCA file already exists on the ADC, but is not the same as the one we are trying to upload. Manual action may be required."
                                            Write-ToLogFile -D -C ADC-CertUpload -M "IntermediateCACertKeyName: `"$intermediateCACertKeyName`""
                                            Write-DisplayText -ForeGroundColor Red " ERROR: IntermediateCA file already exists on the ADC, but is not the same as the one we are trying to upload. Manual action may be required."
                                        }
                                    } else {
                                        Write-ToLogFile -I -C ADC-CertUpload -M "IntermediateCA file does not exist on the ADC."
                                    }
                                }
                            } else {
                                Write-ToLogFile -I -C ADC-CertUpload -M "IntermediateCA file does not exist on the ADC."
                            }
                        } catch {
                            Write-DisplayText -Blank
                            Write-ToLogFile -E -C ADC-CertUpload -M "Could not determine if IntermediateCA file exists on the ADC."
                            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                            Write-Warning "Could not determine if IntermediateCA file exists on the ADC."
                            Write-DisplayText -Blank
                            Write-DisplayText -Line "Status"
                        }
                        if ($intermediateFileExists) {
                            Write-ToLogFile -I -C ADC-CertUpload -M "IntermediateCA file already exists on the ADC, skipping upload."
                            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                            #ToDo: Remove
                            #$intermediateCACertKeyName = $ADCIntermediateCA.sslcertkey.certkey
                        } else {
                            Write-ToLogFile -I -C ADC-CertUpload -M "IntermediateCA does not exist, start uploading."
                            try {
                                Write-ToLogFile -I -C ADC-CertUpload -M "Uploading `"$intermediateCAFileName`" to the ADC."
                                if ('PSEdition' -notin $PSVersionTable.Keys -or $PSVersionTable.PSEdition -eq 'Desktop') {
                                    $intermediateCABase64 = [System.Convert]::ToBase64String($(Get-Content $intermediateCAFullPath -Encoding "Byte"))
                                } else {
                                    $intermediateCABase64 = [System.Convert]::ToBase64String($(Get-Content $intermediateCAFullPath -AsByteStream))
                                }
                                $payload = @{"filename" = "$intermediateCAFileName"; "filecontent" = "$intermediateCABase64"; "filelocation" = "$intermediateFileLocation"; "fileencoding" = "BASE64"; }
                                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type systemfile -Payload $payload
                                Write-ToLogFile -I -C ADC-CertUpload -M "Succeeded, Add the certificate to the ADC config."
                                $payload = @{"certkey" = "$intermediateCACertKeyName"; "cert" = "$($intermediateFileLocation)$($intermediateCAFileName)"; }
                                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload
                                Write-ToLogFile -I -C ADC-CertUpload -M "Certificate added."
                            } catch {
                                Write-DisplayText -Blank
                                Write-Warning "Could not upload or get the Intermediate CA `"$($intermediateCACertName)`",`r`n         manual action may be required"
                                Write-ToLogFile -W -C ADC-CertUpload -M "Could not upload or get the Intermediate CA ($($intermediateCACertName)), manual action may be required."
                                Write-DisplayText -Blank
                                Write-DisplayText -Line "Status"
                            }
                        }
                    } else {
                        $intermediateCACertKeyName = $ADCIntermediateCA.sslcertkey.certkey
                        Write-ToLogFile -D -C ADC-CertUpload -M "IntermediateCA exists, saving existing name `"$intermediateCACertKeyName`" (Serial:$($ADCIntermediateCA.sslcertkey.serial)) for later use."
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
                    if (-not [String]::IsNullOrEmpty($($ExistingCertificateDetails.sslcertkey.certkey))) {
                        $CertificateCertKeyName = $($ExistingCertificateDetails.sslcertkey.certkey)
                        $CertificateCertKeyNameEscaped = $CertificateCertKeyName.Replace('\u0027', "'").Replace('\u003c', "<").Replace('\u003e', ">").Replace('\u0026', "&")
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
                                Write-ToLogFile -D -C ADC-CertUpload -M "Could not determine (before-unlink) linked details"
                            }
                            $payload = @{"certkey" = "$CertificateCertKeyNameEscaped"; }
                            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action unlink
                            try {
                                Write-ToLogFile -D -C ADC-CertUpload -M "Linked details (after-unlink)"
                                $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type "sslcertchain_binding" -Resource $CertificateCertKeyName
                                $response.sslcertchain_binding.sslcertchain_sslcertkey_binding | ForEach-Object {
                                    Write-ToLogFile -D -C ADC-CertUpload -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                                }
                            } catch {
                                Write-ToLogFile -D -C ADC-CertUpload -M "Could not determine (after-unlink) linked details"
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
                        if (-not [String]::IsNullOrEmpty($($CertRequest.CertKeyNameToUpdate))) {
                            $CertificateCertKeyName = $($CertRequest.CertKeyNameToUpdate)
                            $CertificateCertKeyNameEscaped = $CertificateCertKeyName.Replace('\u0027', "'").Replace('\u003c', "<").Replace('\u003e', ">").Replace('\u0026', "&")
                            Write-ToLogFile -I -C ADC-CertUpload -M "Adding new certificate as `"$($CertRequest.CertKeyNameToUpdate)`""
                        } else {
                            $CertificateCertKeyName = $CertificateName
                            $CertificateCertKeyNameEscaped = $CertificateCertKeyName.Replace('\u0027', "'").Replace('\u003c', "<").Replace('\u003e', ">").Replace('\u0026', "&")
                            $ExistingCertificateDetails = try { Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey -Resource $CertificateName -ErrorAction SilentlyContinue } catch { $null }
                            if (-not [String]::IsNullOrEmpty($($ExistingCertificateDetails.sslcertkey.certkey))) {
                                Write-Warning "Certificate `"$CertificateCertKeyName`" already exists, please update manually! Or if you need to update an existing Certificate, specify the `"-CertKeyNameToUpdate`" Parameter."
                                Write-ToLogFile -W -C ADC-CertUpload -M "Certificate `"$CertificateCertKeyName`" already exists, please update manually! Or if you need to update an existing Certificate, specify the `"-CertKeyNameToUpdate`" Parameter."
                                Invoke-RegisterError 1 "Certificate `"$CertificateCertKeyName`" already exists, please update manually! Or if you need to update an existing Certificate, specify the `"-CertKeyNameToUpdate`" Parameter."
                                continue
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
                        $payload = @{certkey = "$CertificateCertKeyNameEscaped"; cert = "$CertificatePemFileName"; key = $CertificatePemFileName; password = "true"; inform = "PEM"; passplain = "$(ConvertTo-PlainText -SecureString $PfxPassword)" }
                    } else {
                        Write-ToLogFile -D -C ADC-CertUpload -M "ADC verion is higher than 12, using Pfx certificates"
                        $payload = @{certkey = $CertificateCertKeyNameEscaped; cert = $CertificatePfxFileName; key = $CertificatePfxFileName; password = "true"; inform = "PFX"; passplain = "$(ConvertTo-PlainText -SecureString $PfxPassword)" }
                    }
                    try {
                        if ($ADCCertKeyUpdating) {
                            Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                            Write-ToLogFile -I -C ADC-CertUpload -M "Update the certificate and key to the ADC config."
                            try {
                                $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action update
                                Write-ToLogFile -I -C ADC-CertUpload -M "Certificate updated successfully."
                            } catch {
                                Write-ToLogFile -E -C ADC-RemovePrevious -M "Could not update certificate at first attempt, $($_.Exception.Message)"
                                try {
                                    Write-ToLogFile -I -C ADC-CertUpload -M "Certificate update second attempt (nodomaincheck=true)"
                                    $payload.nodomaincheck = $true
                                    $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action update
                                    Write-ToLogFile -I -C ADC-CertUpload -M "Certificate updated successfully!"
                                } catch {
                                    Write-ToLogFile -E -C ADC-RemovePrevious -M "Could not remove previous files, $($_.Exception.Message)"
                                    Invoke-RegisterError 1 "Certificate update failed!"
                                    continue
                                }
                            }
                            if ($CertRequest.RemovePrevious) {
                                try {
                                    Write-DisplayText -ForeGroundColor Yellow "*"
                                    Write-ToLogFile -I -C ADC-RemovePrevious -M "-RemovePrevious parameter was specified, retrieving files."
                                    Write-DisplayText -Line "Removing previous cert"
                                    if ([String]::IsNullOrEmpty($ExistingCertificateDetails.sslcertkey.cert)) {
                                        Write-DisplayText -ForeGroundColor Red "ERROR: Could not retrieve previous certificate details, cannot remove previous files."
                                    } else {
                                        $Arguments = @{ filename = "$($ExistingCertificateDetails.sslcertkey.cert)"; filelocation = "/nsconfig/ssl/" }
                                        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type systemfile -Arguments $Arguments
                                        $PreviousCertFileName = $response.systemfile.filename
                                        Write-DisplayText -ForeGroundColor Cyan -NoNewLine "$PreviousCertFileName"
                                        Write-ToLogFile -D -C ADC-RemovePrevious -M "PreviousCertFileName: `"$PreviousCertFileName`""
                                        $Arguments = @{ filename = "$($ExistingCertificateDetails.sslcertkey.key)"; filelocation = "/nsconfig/ssl/" }
                                        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type systemfile -Arguments $Arguments
                                        $PreviousKeyFileName = $response.systemfile.filename
                                        Write-ToLogFile -D -C ADC-RemovePrevious -M "PreviousKeyFileName: `"$PreviousKeyFileName`""
                                        $Arguments = @{ filelocation = "/nsconfig/ssl/" }
                                        if (-not [String]::IsNullOrEmpty($PreviousCertFileName)) {
                                            Write-ToLogFile -I -C ADC-RemovePrevious -M "Removing file: `"/nsconfig/ssl/$PreviousCertFileName`""
                                            try {
                                                Write-DisplayText -ForeGroundColor Yellow -NoNewLine " *"
                                                $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type systemfile -Resource $PreviousCertFileName -Arguments $Arguments
                                                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                                                Write-ToLogFile -I -C ADC-RemovePrevious -M "Success"
                                                Write-DisplayText -ForeGroundColor Green " Removed"
                                            } catch {
                                                Write-ToLogFile -E -C ADC-RemovePrevious -M "Could not remove previous certificate file, $($_.Exception.Message)"
                                                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                                Write-DisplayText -ForeGroundColor Red "Failed to remove"
                                            }
                                        }
                                        if ((-not [String]::IsNullOrEmpty($PreviousKeyFileName)) -and ($PreviousCertFileName -ne $PreviousKeyFileName)) {
                                            Write-ToLogFile -I -C ADC-RemovePrevious -M "Removing file: `"/nsconfig/ssl/$PreviousKeyFileName`""
                                            try {
                                                Write-DisplayText -ForeGroundColor Yellow -NoNewLine " *"
                                                $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type systemfile -Resource $PreviousKeyFileName -Arguments $Arguments
                                                Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
                                                Write-ToLogFile -I -C ADC-RemovePrevious -M "Success"
                                                Write-DisplayText -ForeGroundColor Green " Removed"
                                            } catch {
                                                Write-ToLogFile -E -C ADC-RemovePrevious -M "Could not remove previous certificate file, $($_.Exception.Message)"
                                                Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                                Write-DisplayText -ForeGroundColor Red "Failed to remove"
                                            }
                                        } else {
                                            Write-ToLogFile -I -C ADC-RemovePrevious -M "Same file, `"/nsconfig/ssl/$PreviousKeyFileName`" was already removed."
                                        }
                                        Write-DisplayText -Line "Status"
                                        Write-DisplayText -ForeGroundColor Yellow -NoNewLine "*"
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
                    Write-ToLogFile -I -C ADC-CertUpload -M "Link `"$CertificateCertKeyName`" to `"$intermediateCACertKeyName`""
                    try {
                        $payload = @{"certkey" = "$CertificateCertKeyNameEscaped"; "linkcertkeyname" = "$intermediateCACertKeyName"; }
                        $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type sslcertkey -Payload $payload -Action link -ErrorAction Stop
                        Write-ToLogFile -I -C ADC-CertUpload -M "Link successfull."
                        Write-ToLogFile -D -C ADC-CertUpload -M "Response: $($response | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
                    } catch {
                        Write-DisplayText -Blank
                        Write-Warning -Message "Could not link the certificate`"$CertificateCertKeyName`"`r`n         to Intermediate `"$intermediateCACertKeyName`""
                        Write-ToLogFile -E -C ADC-CertUpload -M "Could not link the certificate `"$CertificateCertKeyName`" to Intermediate `"$intermediateCACertKeyName`"."
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
                        Write-ToLogFile -D -C ADC-CertUpload -M "Could not determine (after-link) linked details"
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
                        if (-not ($CertRequest | Get-Member -Name "CertExpires" -ErrorAction SilentlyContinue -MemberType NoteProperty)) {
                            $CertRequest | Add-Member -MemberType NoteProperty -Name "CertExpires" -Value $PAOrder.CertExpires
                        } else {
                            $CertRequest.CertExpires = $PAOrder.CertExpires
                        }
                        if (-not ($CertRequest | Get-Member -Name "RenewAfter" -ErrorAction SilentlyContinue -MemberType NoteProperty)) {
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
                    try {
                        $FinalCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 "$($CertificateFullPath)"
                    } catch {
                        Write-ToLogFile -E -C ADC-CertUpload -M "Error while retrieving certificate details, $($_.Exception.Message)"
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                    }
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
                    Write-DisplayText -ForeGroundColor Cyan "$($intermediateCACertName)  [$($ChainFile.NotAfter.ToString('yyyy-MM-dd'))]"
                    Write-DisplayText -Line "Intermediate Certkey Name"
                    Write-DisplayText -ForeGroundColor Cyan $intermediateCACertKeyName
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
                    Write-ToLogFile -I -C ADC-CertUpload -M "Intermediate: $($intermediateCACertName)  [$($ChainFile.NotAfter.ToString('yyyy-MM-dd'))]"
                    Write-ToLogFile -I -C ADC-CertUpload -M "Intermediate Certkey Name: $intermediateCACertKeyName"
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
                        $mailDataItem.Text += "Issued by CA: $($intermediateCACertName)  [$($ChainFile.NotAfter.ToString('yyyy-MM-dd'))] - (ADC SSL Certkey Name: $intermediateCACertKeyName)"
                        $mailDataItem.Code = "OK"
                    } catch {
                        Write-ToLogFile -D -C ADC-CertUpload-Mail -M "Error while gathering data for mail, Error: $($_.Exception.Message)"
                        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                        $mailDataItem.Text += "`r`nError while gathering data for mail, Error: $($_.Exception.Message)"
                    }

                    #region UpdateGlobalVPNCertBinding

                    if ($CertRequest.UpdateGlobalVPNCertBinding) {
                        Write-DisplayText -Title "Global VPN Certificate Binding"
                        try {
                            Write-DisplayText -Line "Certificate Key Name"
                            if (-not $($CertRequest.CertKeyNameToUpdate)) {
                                Write-ToLogFile -E -C "UpdateGlobalVPNCertBinding" -M "No Certificate Key Name found"
                                Write-DisplayText -ForeGroundColor Red "No Certificate Key Name found"
                                Invoke-RegisterError 1 "No Certificate Key Name found"
                            } else {
                                Write-DisplayText -ForeGroundColor Cyan $($CertRequest.CertKeyNameToUpdate)
                            }
                            if ($updateGlobalVPNCertBindingActionRequired -eq $true) {
                                Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding" -M "Retrieving current SSL Certificate Binding for VPN Global"
                                Write-DisplayText -Line "Check Current Binding"
                                if ($response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type vpnglobal_sslcertkey_binding | Select-Object -ExpandProperty vpnglobal_sslcertkey_binding -ErrorAction SilentlyContinue) {
                                    Write-ToLogFile -D -C "UpdateGlobalVPNCertBinding" -M "Response: $($response | ConvertTo-Json -Compress)"
                                    if ($currentBinding = $response | Where-Object { $_.certkeyname -ieq $($CertRequest.CertKeyNameToUpdate) } ) {
                                        Write-DisplayText -ForeGroundColor Cyan "Current Bindings found"
                                        Write-ToLogFile -D -C "UpdateGlobalVPNCertBinding" -M "Current Binding: $($currentBinding | ConvertTo-Json -Compress)"
                                        Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding" -M "Unbinding current certificate"
                                        Write-DisplayText -Line "Unbinding Current Cert"
                                        $arguments = @{ certkeyname = $($CertRequest.CertKeyNameToUpdate) }
                                        try {
                                            $null = Invoke-ADCRestApi -Session $ADCSession -Method DELETE -Type vpnglobal_sslcertkey_binding -Arguments $arguments
                                            Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding" -M "Successfully unbound certificate"
                                            Write-DisplayText -ForeGroundColor Green "Successfully unbound certificate"
                                        } catch {
                                            Write-ToLogFile -E -C "UpdateGlobalVPNCertBinding" -M "Failed to unbind certificate"
                                            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                            Write-DisplayText -ForeGroundColor Red "Failed to unbind certificate"
                                        }
                                    } else {
                                        Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding" -M "Bindings found, but not the one we are looking for"
                                        Write-DisplayText -ForeGroundColor Cyan "Bindings found, but not the one we are looking for"
                                    }
                                } else {
                                    if ($updateGlobalVPNCertBindingActionRequired -eq $true) {
                                        Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding" -M "Binding was removed earlier, no current binding found"
                                        Write-DisplayText -ForeGroundColor Cyan "Binding was removed earlier, no current binding found"
                                    } else {
                                        Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding" -M "No current binding found"
                                        Write-DisplayText -ForeGroundColor Cyan "No current binding found"
                                    }
                                }
                                try {
                                    Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding" -M "Binding new certificate"
                                    $payload = @{
                                        certkeyname = $($CertRequest.CertKeyNameToUpdate)
                                    }
                                    Write-DisplayText -Line "Binding New Certificate"
                                    $result = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type vpnglobal_sslcertkey_binding -Payload $payload
                                    Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding" -M "Successfully bound certificate"
                                    Write-DisplayText -ForeGroundColor Green "Successfully bound certificate"
                                } catch {
                                    Write-ToLogFile -E -C "UpdateGlobalVPNCertBinding" -M "Failed to bind certificate"
                                    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                    Write-DisplayText -ForeGroundColor Red "Failed to bind certificate"
                                }
                                $MailData += "SSLVPN (Global) Certificate binding updated: $($CertRequest.CertKeyNameToUpdate)"

                                Write-DisplayText -Line "Include CA"
                                if ($CertRequest.GlobalVPNCertBindingIncludeCA) {
                                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type vpnglobal_sslcertkey_binding | Select-Object -ExpandProperty vpnglobal_sslcertkey_binding -ErrorAction SilentlyContinue
                                    $vpnglobalCACertBinding = $response | Where-Object { $_.cacert -ieq $intermediateCACertKeyName }
                                    if ($vpnglobalCACertBinding) {
                                        Write-DisplayText -ForeGroundColor Cyan "Already included CA: $($vpnglobalCACertBinding.cacert) ($($vpnglobalCACertBinding.crlcheck))"
                                        Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding" -M "Already included CA: $($vpnglobalCACertBinding.cacert) ($($vpnglobalCACertBinding.crlcheck))"
                                    } else {
                                        Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding" -M "No CA binding found, will try to bind CA now, adding CA: $($intermediateCACertKeyName)"
                                        $payload = @{
                                            cacert = $intermediateCACertKeyName
                                        }
                                        Write-DisplayText -ForeGroundColor Cyan "$($intermediateCACertKeyName)"
                                        Write-DisplayText -Line "Certificate validity check"
                                        if ($CertRequest.GlobalVPNCertBindingOcspCheck.ToLower() -in 'mandatory', 'optional') {
                                            $payload.ocspcheck = $CertRequest.GlobalVPNCertBindingOcspCheck.ToLower()
                                            Write-DisplayText -ForeGroundColor Cyan "OCSP Check: $($CertRequest.GlobalVPNCertBindingOcspCheck)"
                                        } elseif ($CertRequest.GlobalVPNCertBindingCrlCheck.ToLower() -in 'mandatory', 'optional') {
                                            $payload.crlcheck = $CertRequest.GlobalVPNCertBindingCrlCheck.ToLower()
                                            Write-DisplayText -ForeGroundColor Cyan "CRL Check: $($CertRequest.GlobalVPNCertBindingCrlCheck)"
                                        } else {
                                            Write-DisplayText -ForeGroundColor Cyan "No OCSP or CRL Check"
                                        }
                                        Write-DisplayText -Line "Binding CA"
                                        try {
                                            Write-ToLogFile -D -C "UpdateGlobalVPNCertBinding" -M "Binding CA with the following payload: $($payload | ConvertTo-Json -Compress)"
                                            $result = Invoke-ADCRestApi -Session $ADCSession -Method PUT -Type vpnglobal_sslcertkey_binding -Payload $payload
                                            Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding" -M "Successfully bound CA"
                                            Write-DisplayText -ForeGroundColor Green "Successfully bound CA"
                                        } catch {
                                            Write-ToLogFile -E -C "UpdateGlobalVPNCertBinding" -M "Failed to bind CA"
                                            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                                            Write-DisplayText -ForeGroundColor Red "Failed to bind CA"
                                        }
                                    }
                                } else {
                                    Write-DisplayText -ForeGroundColor Cyan "No CA included"
                                }
                            } else {
                                Write-DisplayText -Line "Action required"
                                Write-ToLogFile -I -C "UpdateGlobalVPNCertBinding" -M "No action required, certificate was not bound globally before. Will not be bound now."
                                Write-DisplayText -ForeGroundColor Green "No action required, certificate was not bound globally before. Will not be bound now."
                            }
                        } catch {
                            Write-ToLogFile -E -C "UpdateGlobalVPNCertBinding" -M "Caught an error, $($_.Exception.Message)"
                            Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
                            Invoke-RegisterError 1 "Caught an error, $($_.Exception.Message)"
                        }
                    }

                    #endregion UpdateGlobalVPNCertBinding

                    #region CleanupDNSRecords
                    if ($CertRequest.ValidationMethod -eq "dns") {
                        if ($UseNetScalerDNS -and (-not [String]::IsNullOrEmpty($AlternateDNSValidationDomain))) {
                            Write-ToLogFile -I -C ADC-CertUpload -M "Cleanup DNS Records using the NetScaler DNS Plugin"
                            Write-DisplayText -Title "Cleanup DNS Records"
                            foreach ($record in $TXTRecords) {
                                Invoke-NSRemoveTXTRecord -DomainName $record.AlternateTXTName -TXTValue $record.TXTValue -ErrorAction SilentlyContinue
                            }
                        } elseif ($PoshACMEPluginUsed -ne $true) {
                            Write-DisplayText -ForegroundColor Magenta "`r`n********************************************************************"
                            Write-DisplayText -ForegroundColor Magenta "* IMPORTANT: Don't forget to delete the created DNS records!!      *"
                            Write-DisplayText -ForegroundColor Magenta "********************************************************************"
                            Write-ToLogFile -I -C ADC-CertUpload -M "Don't forget to delete the created DNS records!!"
                            if (-not [String]::IsNullOrEmpty($AlternateDNSValidationDomain)) {
                                foreach ($Record in $TXTRecords) {
                                    Write-DisplayText -Blank
                                    Write-DisplayText -Line "DNS Hostname"
                                    Write-DisplayText -ForeGroundColor Cyan "$($record.AlternateCNAMEName)"
                                    Write-DisplayText -Line "TXT Record Name"
                                    Write-DisplayText -ForeGroundColor Yellow "$($Record.TXTName)"
                                    Write-ToLogFile -I -C ADC-CertUpload -M "TXT Record: `"$($record.AlternateCNAMEName)`" => `"$($Record.TXTName)`""
                                }
                            } else {
                                foreach ($Record in $TXTRecords) {
                                    Write-DisplayText -Blank
                                    Write-DisplayText -Line "DNS Hostname"
                                    Write-DisplayText -ForeGroundColor Cyan "$($Record.fqdn)"
                                    Write-DisplayText -Line "TXT Record Name"
                                    Write-DisplayText -ForeGroundColor Yellow "$($Record.TXTName)"
                                    Write-ToLogFile -I -C ADC-CertUpload -M "TXT Record: `"$($record.fqdn)`" => `"$($Record.TXTName)`""
                                }
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
                    #endregion CleanupDNSRecords

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
                    continue
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

            if (($CertRequest | Get-Member -Name PostPoSHScriptFilename -ErrorAction SilentlyContinue) -and (-not [String]::IsNullOrEmpty($($CertRequest.PostPoSHScriptFilename)))) {
                if (-not (Split-Path -Path $CertRequest.PostPoSHScriptFilename -Parent -ErrorAction SilentlyContinue)) {
                    Write-ToLogFile -I -C PostPoSHScript -M "PostPoSHScriptFilename is not a full path, trying to find it in the scripts folder."
                    $tempPath = Join-Path -Path (Join-Path -Path $ScriptRoot -ChildPath "scripts") -ChildPath $CertRequest.PostPoSHScriptFilename
                    Write-ToLogFile -I -C PostPoSHScript -M "Checking if `"$tempPath`" exists."
                    if (Test-Path -Path $tempPath) {
                        Write-ToLogFile -I -C PostPoSHScript -M "Found the script in the scripts folder."
                        $CertRequest.PostPoSHScriptFilename = $tempPath
                    } else {
                        Write-ToLogFile -W -C PostPoSHScript -M "Could not find the script in the scripts folder."
                    }
                } else {
                    Write-ToLogFile -I -C PostPoSHScript -M "PostPoSHScriptFilename is a full path."
                }
                $CertRequest.PostPoSHScriptFilename = try { (Resolve-Path -Path $CertRequest.PostPoSHScriptFilename).Path } catch { $null }
                if ((-not [String]::IsNullOrEmpty($($CertRequest.PostPoSHScriptFilename))) -and (Test-Path -Path $($CertRequest.PostPoSHScriptFilename))) {
                    Write-DisplayText -Title "Post PowerShell Script"
                    Write-ToLogFile -I -C PostPoSHScript -M "Post PowerShell Script defined, Filename: `"$($CertRequest.PostPoSHScriptFilename)`""
                    $pfxCertificateFilename = Join-Path -Path $CertificateDirectory -ChildPath $CertificatePfxWithChainFileName
                    if (-not [String]::IsNullOrEmpty($($FinalCertificate.Thumbprint)) -and (Test-Path $pfxCertificateFilename)) {
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
                            default {
                                Write-DisplayText -ForeGroundColor Yellow "Unknown Result! [$postPoSHScriptResult]"
                                Write-ToLogFile -W -C PostPoSHScript -M "Unknown Result while executing post PowerShell Script! [ $output.ExitCode / $postPoSHScriptResult ]"
                                $mailDataItem.Text += "Unknown Result while executing post PowerShell Script! [ $output.ExitCode / $postPoSHScriptResult ]"
                            }
                        }
                    } else {
                        Write-DisplayText -ForeGroundColor Yellow "SKIPPED! Not a valid certificate found!"
                        Write-ToLogFile -W -C PostPoSHScript -M "Not a valid certificate found! Skipped the execution."
                    }
                } elseif ((-not [String]::IsNullOrEmpty($($CertRequest.PostPoSHScriptFilename))) -and (-not (Test-Path -Path $($CertRequest.PostPoSHScriptFilename)))) {
                    Write-DisplayText -Title "Post PowerShell Script"
                    Write-DisplayText -Line "Script Path"
                    Write-DisplayText -NoNewLine -ForeGroundColor Cyan $CertRequest.PostPoSHScriptFilename
                    Write-DisplayText -ForeGroundColor Red " NOT FOUND!"
                    Write-ToLogFile -E -C PostPoSHScript -M "PoSH Script `"$($CertRequest.PostPoSHScriptFilename)`" NOT found!"
                } else {
                    Write-ToLogFile -I -C PostPoSHScript -M "No Post PowerShell Script defined"
                }
            } else {
                Write-ToLogFile -I -C PostPoSHScript -M "No Post PowerShell Script defined"
            }
            #endregion PostPoSHScriptFilename

        }
        if ($CertRequest.CleanExpiredCertsOnDisk -eq $true) {
            Write-ToLogFile -i -C RemoveExpiredCerts -M "Removing expired certificates on disk (`"*-$($CertRequest.CN.Replace('*.',''))`")"
            Write-DisplayText -Title "Removing expired certificates on disk (`"$($CertRequest.CertDir)\*-$($CertRequest.CN.Replace('*.',''))`")"
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

if ($CertRequest.DisableVipAfter -eq $true) {
    Write-DisplayText -Title "Post CSVip Action"
    Write-DisplayText -Line "Action"
    Write-DisplayText -ForeGroundColor Cyan "Required, DisableVipAfter was set"
    Write-ToLogFile -I -C PostCSActtion -M "DisableVipAfter was set for $($CertRequest.CsVipName)"
    try {
        Write-ToLogFile -I -C PostCSActtion -M "Get the Vip status for $($CertRequest.CsVipName)"
        $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csvserver -Resource "$($CertRequest.CsVipName)"
        Write-DisplayText -Line "State"
        if ($response.csvserver.curstate -like "UP") {
            Write-DisplayText "$($response.csvserver.curstate), needs to be disabled"
            Write-ToLogFile -E -C PostCSActtion -M "The CS Vip is enabled ($($response.csvserver.curstate)), disabling it now."
            $payload = @{"name" = "$($CertRequest.CsVipName)"; }
            $response = Invoke-ADCRestApi -Session $ADCSession -Method POST -Type csvserver -Payload $payload -Action disable
            Write-ToLogFile -I -C PostCSActtion -M "Verifying Content Switch to get latest data after enabling."
            $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type csvserver -Resource "$($CertRequest.CsVipName)"
            Write-DisplayText -Line "New State"
            Write-DisplayText "$($response.csvserver.curstate)"
            Write-ToLogFile -I -C PostCSActtion -M "Final state: $($response.csvserver.curstate)"
        } else {
            Write-DisplayText "$($response.csvserver.curstate), no action required."
            Write-ToLogFile -I -C PostCSActtion -M "$($response.csvserver.curstate), no action required."
        }
    } catch {
        $ExceptMessage = $_.Exception.Message
        Write-ToLogFile -E -C PostCSActtion -M "Error Verifying Content Switch. Details: $ExceptMessage"
        Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
    }
} else {
    Write-ToLogFile -I -C PostCSActtion -M "DisableVipAfter was not set for $($CertRequest.CsVipName)"
}


#endregion CleanupADC

#region RemoveTestCerts

if ($RemoveTestCertificates) {
    Write-DisplayText -Title "ADC - (Test) Certificate Cleanup"
    Write-ToLogFile -I -C RemoveTestCerts -M "Start removing the test certificates."
    Write-ToLogFile -I -C RemoveTestCerts -M "Trying to login into the Citrix ADC."
    $ADCSession = Connect-ADC -ManagementURL $Parameters.settings.ManagementURL -Credential $Credential -PassThru
    $intermediateCACertKeyName = "Fake LE Intermediate X1"
    $intermediateCASerial = "8be12a0e5944ed3c546431f097614fe5"
    Write-ToLogFile -I -C RemoveTestCerts -M "Retrieving existing certificates."
    $CertDetails = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type sslcertkey
    Write-ToLogFile -D -C RemoveTestCerts -M "Checking if IntermediateCA `"$intermediateCACertKeyName`" already exists."
    $intermediateCADetails = $CertDetails.sslcertkey | Where-Object { $_.serial -eq $intermediateCASerial }
    $LinkedCertificates = $CertDetails.sslcertkey | Where-Object { $_.linkcertkeyname -eq $intermediateCADetails.certkey }
    Write-ToLogFile -D -C RemoveTestCerts -M "The following certificates were found:"
    $LinkedCertificates | Select-Object certkey, linkcertkeyname, serial | ForEach-Object {
        Write-ToLogFile -D -C RemoveTestCerts -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
    }
    Write-DisplayText -Line "Linked Certkeys found"
    Write-DisplayText -ForeGroundColor Cyan "$(($LinkedCertificates | Measure-Object).Count)"
    foreach ($LinkedCertificate in $LinkedCertificates) {
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
    $FakeCerts = $CertDetails.sslcertkey | Where-Object { $_.issuer -match $intermediateCACertKeyName }
    Write-ToLogFile -D -C RemoveTestCerts -M "Test Cert data:"
    $FakeCerts | ForEach-Object {
        Write-ToLogFile -D -C RemoveTestCerts -M "$($_ | ConvertTo-Json -WarningAction SilentlyContinue -Depth 5 -Compress)"
    }
    Write-DisplayText -Line "Certificates found"
    Write-DisplayText -ForeGroundColor Cyan "$(($FakeCerts | Measure-Object).Count)"
    foreach ($FakeCert in $FakeCerts) {
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
        if (-not ($(Join-Path -Path $CertFilePath -ChildPath $CertFileName) -eq $(Join-Path -Path $KeyFilePath -ChildPath $KeyFileName))) {
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
    foreach ($CertFileToRemove in $CertFilesToRemove) {
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

if ($SaveConfig -and (-not [String]::IsNullOrEmpty($ConfigFile))) {
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
if (-not [String]::IsNullOrEmpty($RequestsWithErrors)) {
    $ExitCode = 0
    foreach ($FailedItem in $RequestsWithErrors) {
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
# MIImdwYJKoZIhvcNAQcCoIImaDCCJmQCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCN2SdS0dN/cH/s
# qosgzuR+PW1+0dXqSzui59M1W9FJ9aCCIAowggYUMIID/KADAgECAhB6I67aU2mW
# D5HIPlz0x+M/MA0GCSqGSIb3DQEBDAUAMFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLjAsBgNVBAMTJVNlY3RpZ28gUHVibGljIFRpbWUg
# U3RhbXBpbmcgUm9vdCBSNDYwHhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5
# WjBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSwwKgYD
# VQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIENBIFIzNjCCAaIwDQYJ
# KoZIhvcNAQEBBQADggGPADCCAYoCggGBAM2Y2ENBq26CK+z2M34mNOSJjNPvIhKA
# VD7vJq+MDoGD46IiM+b83+3ecLvBhStSVjeYXIjfa3ajoW3cS3ElcJzkyZlBnwDE
# JuHlzpbN4kMH2qRBVrjrGJgSlzzUqcGQBaCxpectRGhhnOSwcjPMI3G0hedv2eNm
# GiUbD12OeORN0ADzdpsQ4dDi6M4YhoGE9cbY11XxM2AVZn0GiOUC9+XE0wI7CQKf
# OUfigLDn7i/WeyxZ43XLj5GVo7LDBExSLnh+va8WxTlA+uBvq1KO8RSHUQLgzb1g
# bL9Ihgzxmkdp2ZWNuLc+XyEmJNbD2OIIq/fWlwBp6KNL19zpHsODLIsgZ+WZ1AzC
# s1HEK6VWrxmnKyJJg2Lv23DlEdZlQSGdF+z+Gyn9/CRezKe7WNyxRf4e4bwUtrYE
# 2F5Q+05yDD68clwnweckKtxRaF0VzN/w76kOLIaFVhf5sMM/caEZLtOYqYadtn03
# 4ykSFaZuIBU9uCSrKRKTPJhWvXk4CllgrwIDAQABo4IBXDCCAVgwHwYDVR0jBBgw
# FoAU9ndq3T/9ARP/FqFsggIv0Ao9FCUwHQYDVR0OBBYEFF9Y7UwxeqJhQo1SgLqz
# YZcZojKbMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0gADBMBgNVHR8ERTBDMEGg
# P6A9hjtodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3Rh
# bXBpbmdSb290UjQ2LmNybDB8BggrBgEFBQcBAQRwMG4wRwYIKwYBBQUHMAKGO2h0
# dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY1RpbWVTdGFtcGluZ1Jv
# b3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAN
# BgkqhkiG9w0BAQwFAAOCAgEAEtd7IK0ONVgMnoEdJVj9TC1ndK/HYiYh9lVUacah
# RoZ2W2hfiEOyQExnHk1jkvpIJzAMxmEc6ZvIyHI5UkPCbXKspioYMdbOnBWQUn73
# 3qMooBfIghpR/klUqNxx6/fDXqY0hSU1OSkkSivt51UlmJElUICZYBodzD3M/SFj
# eCP59anwxs6hwj1mfvzG+b1coYGnqsSz2wSKr+nDO+Db8qNcTbJZRAiSazr7KyUJ
# Go1c+MScGfG5QHV+bps8BX5Oyv9Ct36Y4Il6ajTqV2ifikkVtB3RNBUgwu/mSiSU
# ice/Jp/q8BMk/gN8+0rNIE+QqU63JoVMCMPY2752LmESsRVVoypJVt8/N3qQ1c6F
# ibbcRabo3azZkcIdWGVSAdoLgAIxEKBeNh9AQO1gQrnh1TA8ldXuJzPSuALOz1Uj
# b0PCyNVkWk7hkhVHfcvBfI8NtgWQupiaAeNHe0pWSGH2opXZYKYG4Lbukg7HpNi/
# KqJhue2Keak6qH9A8CeEOB7Eob0Zf+fU+CCQaL0cJqlmnx9HCDxF+3BLbUufrV64
# EbTI40zqegPZdA+sXCmbcZy6okx/SjwsusWRItFA3DE8MORZeFb6BmzBtqKJ7l93
# 9bbKBy2jvxcJI98Va95Q5JnlKor3m0E7xpMeYRriWklUPsetMSf2NvUQa/E5vVye
# fQIwggZFMIIELaADAgECAhAIMk+dt9qRb2Pk8qM8Xl1RMA0GCSqGSIb3DQEBCwUA
# MFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBTeXN0ZW1zIFMu
# QS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBDQTAeFw0yNDA0
# MDQxNDA0MjRaFw0yNzA0MDQxNDA0MjNaMGsxCzAJBgNVBAYTAk5MMRIwEAYDVQQH
# DAlTY2hpam5kZWwxIzAhBgNVBAoMGkpvaG4gQmlsbGVrZW5zIENvbnN1bHRhbmN5
# MSMwIQYDVQQDDBpKb2huIEJpbGxla2VucyBDb25zdWx0YW5jeTCCAaIwDQYJKoZI
# hvcNAQEBBQADggGPADCCAYoCggGBAMslntDbSQwHZXwFhmibivbnd0Qfn6sqe/6f
# os3pKzKxEsR907RkDMet2x6RRg3eJkiIr3TFPwqBooyXXgK3zxxpyhGOcuIqyM9J
# 28DVf4kUyZHsjGO/8HFjrr3K1hABNUszP0o7H3o6J31eqV1UmCXYhQlNoW9FOmRC
# 1amlquBmh7w4EKYEytqdmdOBavAD5Xq4vLPxNP6kyA+B2YTtk/xM27TghtbwFGKn
# u9Vwnm7dFcpLxans4ONt2OxDQOMA5NwgcUv/YTpjhq9qoz6ivG55NRJGNvUXsM3w
# 2o7dR6Xh4MuEGrTSrOWGg2A5EcLH1XqQtkF5cZnAPM8W/9HUp8ggornWnFVQ9/6M
# ga+ermy5wy5XrmQpN+x3u6tit7xlHk1Hc+4XY4a4ie3BPXG2PhJhmZAn4ebNSBwN
# Hh8z7WTT9X9OFERepGSytZVeEP7hgyptSLcuhpwWeR4QdBb7dV++4p3PsAUQVHFp
# wkSbrRTv4EiJ0Lcz9P1HPGFoHiFAQQIDAQABo4IBeDCCAXQwDAYDVR0TAQH/BAIw
# ADA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vY2NzY2EyMDIxLmNybC5jZXJ0dW0u
# cGwvY2NzY2EyMDIxLmNybDBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0
# dHA6Ly9jY3NjYTIwMjEub2NzcC1jZXJ0dW0uY29tMDUGCCsGAQUFBzAChilodHRw
# Oi8vcmVwb3NpdG9yeS5jZXJ0dW0ucGwvY2NzY2EyMDIxLmNlcjAfBgNVHSMEGDAW
# gBTddF1MANt7n6B0yrFu9zzAMsBwzTAdBgNVHQ4EFgQUO6KtBpOBgmrlANVAnyiQ
# C6W6lJwwSwYDVR0gBEQwQjAIBgZngQwBBAEwNgYLKoRoAYb2dwIFAQQwJzAlBggr
# BgEFBQcCARYZaHR0cHM6Ly93d3cuY2VydHVtLnBsL0NQUzATBgNVHSUEDDAKBggr
# BgEFBQcDAzAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBAEQsN8wg
# PMdWVkwHPPTN+jKpdns5AKVFjcn00psf2NGVVgWWNQBIQc9lEuTBWb54IK6Ga3hx
# QRZfnPNo5HGl73YLmFgdFQrFzZ1lnaMdIcyh8LTWv6+XNWfoyCM9wCp4zMIDPOs8
# LKSMQqA/wRgqiACWnOS4a6fyd5GUIAm4CuaptpFYr90l4Dn/wAdXOdY32UhgzmSu
# xpUbhD8gVJUaBNVmQaRqeU8y49MxiVrUKJXde1BCrtR9awXbqembc7Nqvmi60tYK
# lD27hlpKtj6eGPjkht0hHEsgzU0Fxw7ZJghYG2wXfpF2ziN893ak9Mi/1dmCNmor
# GOnybKYfT6ff6YTCDDNkod4egcMZdOSv+/Qv+HAeIgEvrxE9QsGlzTwbRtbm6gwY
# YcVBs/SsVUdBn/TSB35MMxRhHE5iC3aUTkDbceo/XP3uFhVL4g2JZHpFfCSu2TQr
# rzRn2sn07jfMvzeHArCOJgBW1gPqR3WrJ4hUxL06Rbg1gs9tU5HGGz9KNQMfQFQ7
# 0Wz7UIhezGcFcRfkIfSkMmQYYpsc7rfzj+z0ThfDVzzJr2dMOFsMlfj1T6l22GBq
# 9XQx0A4lcc5Fl9pRxbOuHHWFqIBD/BCEhwniOCySzqENd2N+oz8znKooSISStnkN
# aYXt6xblJF2dx9Dn89FK7d1IquNxOwt0tI5dMIIGYjCCBMqgAwIBAgIRAKQpO24e
# 3denNAiHrXpOtyQwDQYJKoZIhvcNAQEMBQAwVTELMAkGA1UEBhMCR0IxGDAWBgNV
# BAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGlt
# ZSBTdGFtcGluZyBDQSBSMzYwHhcNMjUwMzI3MDAwMDAwWhcNMzYwMzIxMjM1OTU5
# WjByMQswCQYDVQQGEwJHQjEXMBUGA1UECBMOV2VzdCBZb3Jrc2hpcmUxGDAWBgNV
# BAoTD1NlY3RpZ28gTGltaXRlZDEwMC4GA1UEAxMnU2VjdGlnbyBQdWJsaWMgVGlt
# ZSBTdGFtcGluZyBTaWduZXIgUjM2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEA04SV9G6kU3jyPRBLeBIHPNyUgVNnYayfsGOyYEXrn3+SkDYTLs1crcw/
# ol2swE1TzB2aR/5JIjKNf75QBha2Ddj+4NEPKDxHEd4dEn7RTWMcTIfm492TW22I
# 8LfH+A7Ehz0/safc6BbsNBzjHTt7FngNfhfJoYOrkugSaT8F0IzUh6VUwoHdYDpi
# ln9dh0n0m545d5A5tJD92iFAIbKHQWGbCQNYplqpAFasHBn77OqW37P9BhOASdmj
# p3IijYiFdcA0WQIe60vzvrk0HG+iVcwVZjz+t5OcXGTcxqOAzk1frDNZ1aw8nFhG
# EvG0ktJQknnJZE3D40GofV7O8WzgaAnZmoUn4PCpvH36vD4XaAF2CjiPsJWiY/j2
# xLsJuqx3JtuI4akH0MmGzlBUylhXvdNVXcjAuIEcEQKtOBR9lU4wXQpISrbOT8ux
# +96GzBq8TdbhoFcmYaOBZKlwPP7pOp5Mzx/UMhyBA93PQhiCdPfIVOCINsUY4U23
# p4KJ3F1HqP3H6Slw3lHACnLilGETXRg5X/Fp8G8qlG5Y+M49ZEGUp2bneRLZoyHT
# yynHvFISpefhBCV0KdRZHPcuSL5OAGWnBjAlRtHvsMBrI3AAA0Tu1oGvPa/4yeei
# Ayu+9y3SLC98gDVbySnXnkujjhIh+oaatsk/oyf5R2vcxHahajMCAwEAAaOCAY4w
# ggGKMB8GA1UdIwQYMBaAFF9Y7UwxeqJhQo1SgLqzYZcZojKbMB0GA1UdDgQWBBSI
# YYyhKjdkgShgoZsx0Iz9LALOTzAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIw
# ADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDBKBgNVHSAEQzBBMDUGDCsGAQQBsjEB
# AgEDCDAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAIBgZn
# gQwBBAIwSgYDVR0fBEMwQTA/oD2gO4Y5aHR0cDovL2NybC5zZWN0aWdvLmNvbS9T
# ZWN0aWdvUHVibGljVGltZVN0YW1waW5nQ0FSMzYuY3JsMHoGCCsGAQUFBwEBBG4w
# bDBFBggrBgEFBQcwAoY5aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVi
# bGljVGltZVN0YW1waW5nQ0FSMzYuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2Nz
# cC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAYEAAoE+pIZyUSH5ZakuPVKK
# 4eWbzEsTRJOEjbIu6r7vmzXXLpJx4FyGmcqnFZoa1dzx3JrUCrdG5b//LfAxOGy9
# Ph9JtrYChJaVHrusDh9NgYwiGDOhyyJ2zRy3+kdqhwtUlLCdNjFjakTSE+hkC9F5
# ty1uxOoQ2ZkfI5WM4WXA3ZHcNHB4V42zi7Jk3ktEnkSdViVxM6rduXW0jmmiu71Z
# pBFZDh7Kdens+PQXPgMqvzodgQJEkxaION5XRCoBxAwWwiMm2thPDuZTzWp/gUFz
# i7izCmEt4pE3Kf0MOt3ccgwn4Kl2FIcQaV55nkjv1gODcHcD9+ZVjYZoyKTVWb4V
# qMQy/j8Q3aaYd/jOQ66Fhk3NWbg2tYl5jhQCuIsE55Vg4N0DUbEWvXJxtxQQaVR5
# xzhEI+BjJKzh3TQ026JxHhr2fuJ0mV68AluFr9qshgwS5SpN5FFtaSEnAwqZv3IS
# +mlG50rK7W3qXbWwi4hmpylUfygtYLEdLQukNEX1jiOKMIIGgjCCBGqgAwIBAgIQ
# NsKwvXwbOuejs902y8l1aDANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYD
# VQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBS
# U0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjEwMzIyMDAwMDAwWhcNMzgw
# MTE4MjM1OTU5WjBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1p
# dGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3Qg
# UjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAiJ3YuUVnnR3d6Lkm
# gZpUVMB8SQWbzFoVD9mUEES0QUCBdxSZqdTkdizICFNeINCSJS+lV1ipnW5ihkQy
# C0cRLWXUJzodqpnMRs46npiJPHrfLBOifjfhpdXJ2aHHsPHggGsCi7uE0awqKggE
# /LkYw3sqaBia67h/3awoqNvGqiFRJ+OTWYmUCO2GAXsePHi+/JUNAax3kpqstbl3
# vcTdOGhtKShvZIvjwulRH87rbukNyHGWX5tNK/WABKf+Gnoi4cmisS7oSimgHUI0
# Wn/4elNd40BFdSZ1EwpuddZ+Wr7+Dfo0lcHflm/FDDrOJ3rWqauUP8hsokDoI7D/
# yUVI9DAE/WK3Jl3C4LKwIpn1mNzMyptRwsXKrop06m7NUNHdlTDEMovXAIDGAvYy
# nPt5lutv8lZeI5w3MOlCybAZDpK3Dy1MKo+6aEtE9vtiTMzz/o2dYfdP0KWZwZIX
# bYsTIlg1YIetCpi5s14qiXOpRsKqFKqav9R1R5vj3NgevsAsvxsAnI8Oa5s2oy25
# qhsoBIGo/zi6GpxFj+mOdh35Xn91y72J4RGOJEoqzEIbW3q0b2iPuWLA911cRxgY
# 5SJYubvjay3nSMbBPPFsyl6mY4/WYucmyS9lo3l7jk27MAe145GWxK4O3m3gEFEI
# kv7kRmefDR7Oe2T1HxAnICQvr9sCAwEAAaOCARYwggESMB8GA1UdIwQYMBaAFFN5
# v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBT2d2rdP/0BE/8WoWyCAi/QCj0U
# JTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAKBggr
# BgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAwUAYDVR0fBEkwRzBFoEOgQYY/aHR0
# cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRpZmljYXRpb25B
# dXRob3JpdHkuY3JsMDUGCCsGAQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0cDov
# L29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEADr5lQe1oRLjl
# ocXUEYfktzsljOt+2sgXke3Y8UPEooU5y39rAARaAdAxUeiX1ktLJ3+lgxtoLQhn
# 5cFb3GF2SSZRX8ptQ6IvuD3wz/LNHKpQ5nX8hjsDLRhsyeIiJsms9yAWnvdYOdEM
# q1W61KE9JlBkB20XBee6JaXx4UBErc+YuoSb1SxVf7nkNtUjPfcxuFtrQdRMRi/f
# InV/AobE8Gw/8yBMQKKaHt5eia8ybT8Y/Ffa6HAJyz9gvEOcF1VWXG8OMeM7Vy7B
# s6mSIkYeYtddU1ux1dQLbEGur18ut97wgGwDiGinCwKPyFO7ApcmVJOtlw9FVJxw
# /mL1TbyBns4zOgkaXFnnfzg4qbSvnrwyj1NiurMp4pmAWjR+Pb/SIduPnmFzbSN/
# G8reZCL4fvGlvPFk4Uab/JVCSmj59+/mB2Gn6G/UYOy8k60mKcmaAZsEVkhOFuoj
# 4we8CYyaR9vd9PGZKSinaZIkvVjbH/3nlLb0a7SBIkiRzfPfS9T+JesylbHa1LtR
# V9U/7m0q7Ma2CQ/t392ioOssXW7oKLdOmMBl14suVFBmbzrt5V5cQPnwtd3UOTpS
# 9oCG+ZZheiIvPgkDmA8FzPsnfXW5qHELB43ET7HHFHeRPRYrMBKjkb8/IN7Po0d0
# hQoF4TeMM+zYAJzoKQnVKOLg8pZVPT8wgga5MIIEoaADAgECAhEAmaOACiZVO2Wr
# 3G6EprPqOTANBgkqhkiG9w0BAQwFADCBgDELMAkGA1UEBhMCUEwxIjAgBgNVBAoT
# GVVuaXpldG8gVGVjaG5vbG9naWVzIFMuQS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0
# aWZpY2F0aW9uIEF1dGhvcml0eTEkMCIGA1UEAxMbQ2VydHVtIFRydXN0ZWQgTmV0
# d29yayBDQSAyMB4XDTIxMDUxOTA1MzIxOFoXDTM2MDUxODA1MzIxOFowVjELMAkG
# A1UEBhMCUEwxITAfBgNVBAoTGEFzc2VjbyBEYXRhIFN5c3RlbXMgUy5BLjEkMCIG
# A1UEAxMbQ2VydHVtIENvZGUgU2lnbmluZyAyMDIxIENBMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAnSPPBDAjO8FGLOczcz5jXXp1ur5cTbq96y34vuTm
# flN4mSAfgLKTvggv24/rWiVGzGxT9YEASVMw1Aj8ewTS4IndU8s7VS5+djSoMcbv
# IKck6+hI1shsylP4JyLvmxwLHtSworV9wmjhNd627h27a8RdrT1PH9ud0IF+njvM
# k2xqbNTIPsnWtw3E7DmDoUmDQiYi/ucJ42fcHqBkbbxYDB7SYOouu9Tj1yHIohzu
# C8KNqfcYf7Z4/iZgkBJ+UFNDcc6zokZ2uJIxWgPWXMEmhu1gMXgv8aGUsRdaCtVD
# 2bSlbfsq7BiqljjaCun+RJgTgFRCtsuAEw0pG9+FA+yQN9n/kZtMLK+Wo837Q4QO
# ZgYqVWQ4x6cM7/G0yswg1ElLlJj6NYKLw9EcBXE7TF3HybZtYvj9lDV2nT8mFSkc
# SkAExzd4prHwYjUXTeZIlVXqj+eaYqoMTpMrfh5MCAOIG5knN4Q/JHuurfTI5XDY
# O962WZayx7ACFf5ydJpoEowSP07YaBiQ8nXpDkNrUA9g7qf/rCkKbWpQ5boufUnq
# 1UiYPIAHlezf4muJqxqIns/kqld6JVX8cixbd6PzkDpwZo4SlADaCi2JSplKShBS
# ND36E/ENVv8urPS0yOnpG4tIoBGxVCARPCg1BnyMJ4rBJAcOSnAWd18Jx5n858JS
# qPECAwEAAaOCAVUwggFRMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFN10XUwA
# 23ufoHTKsW73PMAywHDNMB8GA1UdIwQYMBaAFLahVDkCw6A/joq8+tT4HKbROg79
# MA4GA1UdDwEB/wQEAwIBBjATBgNVHSUEDDAKBggrBgEFBQcDAzAwBgNVHR8EKTAn
# MCWgI6Ahhh9odHRwOi8vY3JsLmNlcnR1bS5wbC9jdG5jYTIuY3JsMGwGCCsGAQUF
# BwEBBGAwXjAoBggrBgEFBQcwAYYcaHR0cDovL3N1YmNhLm9jc3AtY2VydHVtLmNv
# bTAyBggrBgEFBQcwAoYmaHR0cDovL3JlcG9zaXRvcnkuY2VydHVtLnBsL2N0bmNh
# Mi5jZXIwOQYDVR0gBDIwMDAuBgRVHSAAMCYwJAYIKwYBBQUHAgEWGGh0dHA6Ly93
# d3cuY2VydHVtLnBsL0NQUzANBgkqhkiG9w0BAQwFAAOCAgEAdYhYD+WPUCiaU58Q
# 7EP89DttyZqGYn2XRDhJkL6P+/T0IPZyxfxiXumYlARMgwRzLRUStJl490L94C9L
# GF3vjzzH8Jq3iR74BRlkO18J3zIdmCKQa5LyZ48IfICJTZVJeChDUyuQy6rGDxLU
# UAsO0eqeLNhLVsgw6/zOfImNlARKn1FP7o0fTbj8ipNGxHBIutiRsWrhWM2f8pXd
# d3x2mbJCKKtl2s42g9KUJHEIiLni9ByoqIUul4GblLQigO0ugh7bWRLDm0CdY9rN
# LqyA3ahe8WlxVWkxyrQLjH8ItI17RdySaYayX3PhRSC4Am1/7mATwZWwSD+B7eMc
# ZNhpn8zJ+6MTyE6YoEBSRVrs0zFFIHUR08Wk0ikSf+lIe5Iv6RY3/bFAEloMU+vU
# BfSouCReZwSLo8WdrDlPXtR0gicDnytO7eZ5827NS2x7gCBibESYkOh1/w1tVxTp
# V2Na3PR7nxYVlPu1JPoRZCbH86gc96UTvuWiOruWmyOEMLOGGniR+x+zPF/2DaGg
# K2W1eEJfo2qyrBNPvF7wuAyQfiFXLwvWHamoYtPZo0LHuH8X3n9C+xN4YaNjt2yw
# zOr+tKyEVAotnyU9vyEVOaIYMk3IeBrmFnn0gbKeTTyYeEEUz/Qwt4HOUBCrW602
# NCmvO1nm+/80nLy5r0AZvCQxaQ4xggXDMIIFvwIBATBqMFYxCzAJBgNVBAYTAlBM
# MSEwHwYDVQQKExhBc3NlY28gRGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0Nl
# cnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBDQQIQCDJPnbfakW9j5PKjPF5dUTANBglg
# hkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3
# DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEV
# MC8GCSqGSIb3DQEJBDEiBCDSt/VZvFYV8yPDeg1JVcz6Hjf2rPNwT37q+4olTowW
# 9DANBgkqhkiG9w0BAQEFAASCAYB8Gvv5L9T+h2znHVxieHgf6askxuBW2AmaanBv
# XMIwB6WFFzKTVtS5ahunZ6by5JrkvXz+todL/KrSwjA6UARlcnF9OBZvlUxtwLSc
# J4OchCHzMI1Mofkgn8yhTYXlg0RN6vY7ktOUxMjtYJIULxxRxTqMUZdwYw9fFa6G
# P0xD1+KGeuUJV/OxzKJzZQsZz6XnF1qCwXRqDDA5Is2t9DFU1wO52sa8QoSTDgps
# fSF1Q5YU98+T9kt3Dz0aKO3hAF6R3slXMRlLL2qErwcvKW11E37MlazMSkxxZN+i
# eVBiSSWGfK1rU7CizbmfhG8STyHLZtF7iO4ua6t0FiiCp9Gf+Xs52mdq0rgIFKdM
# uVB81obDXIwWjiUFnscuYYgw2BHQrw7JoG/zepGBlSzBrxAoBFPYo413Sao7/nMZ
# 6ctDWsSwQvnwqjI62Zxp3vvw5rWfKhuUJDl+vvpjCSvZkO2tGOr3W4+cZxKVPJre
# yC3qShR/hFHcPd4chxK9W+N308ihggMjMIIDHwYJKoZIhvcNAQkGMYIDEDCCAwwC
# AQEwajBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSww
# KgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIENBIFIzNgIRAKQp
# O24e3denNAiHrXpOtyQwDQYJYIZIAWUDBAICBQCgeTAYBgkqhkiG9w0BCQMxCwYJ
# KoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNTA4MDQxMDE2MjFaMD8GCSqGSIb3
# DQEJBDEyBDCVCHo68v3WmICSeytL0jKNTax50CRqoovTPInDQmaj+2liSa3+Wpel
# TFQ/oC3gKG4wDQYJKoZIhvcNAQEBBQAEggIASG074Xe594xrKdzHdnDiJhxNpKyB
# Pl2o1//tApZKfx2iT6G4To9N8PuuLZYi15UZIhh8Oq2wwI4+xDxjI+cKvVTHATM8
# qYzSHgHdWiBtqFSqKx4weunfr7n3aSYeG2Qaps22dm2foxO65Y5l5clzJD64JDdp
# aZFk9/K0R/ql9wGnqzJKYZOx8GnjoL+LgijKQMx4xssJQiE2MkJzAazz+7wElhNM
# JMy8U8+aFRCDn0uJ55kM1hu2iNIeTr45B1X+UN8yc9wv1YWSvotdSfJru1oCiYb/
# 6LltUTDKMBBTUc7jDmaSz4o0OoOQWvvSq7ZKkvbAkL7wHDsLgQ1C8uNqW3kbfrmA
# WyapPtBa1XCEyIs+6cNmgRkA1mJRPWl+5M87h/6mb0d2QAfh8wSeBSyB+wlbxo/v
# Z2MzKVX5Cl0g8ftEOxD8Cr/qxKbgkMcBUjyBk3qpaM1XaeFq+8aY+JmU4zi1jAvP
# N3X79x66HBky1IsPc1r/GTgWbqQSgNRqDt7fpsASH5Ztw7pqQ6YRDURXb4ApnVJd
# g8VGX419XEcOzC0quAFFAC/nK6LZBdFeIyvgMtISyitAqPxmz0M0HtFRk+mqueit
# 7apcaLrmqQsCou0jyM0QG7I7dY9V2C4St9is4hOecnKs02Fm3SpfnCngF3Tl7bVD
# 6f8oZsV0zC4QSvI=
# SIG # End signature block
