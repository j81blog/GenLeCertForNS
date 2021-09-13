
# GenLeCertForNS.ps1

## SYNOPSIS
Create a new or update an existing Let's Encrypt certificate for one or more domains and add it to a store then update the SSL bindings for a ADC

## SYNTAX

### LECertificates (Default)
```
GenLeCertForNS.ps1 [-CleanPoshACMEStorage] -ManagementURL <String> [-Username <String>] [-Password <Object>]
 [-Credential <PSCredential>] -CN <String> [-SAN <String[]>] [-FriendlyName <String>]
 [-ValidationMethod <String>] [-CertKeyNameToUpdate <String>] [-RemovePrevious] -CertDir <String>
 [-PfxPassword <Object>] -EmailAddress <String> [-KeyLength <Int32>] [-Production] [-DisableLogging]
 [-LogFile <String>] [-LogLevel <String>] [-SaveADCConfig] [-SendMail] [-SMTPTo <String[]>]
 [-SMTPFrom <String>] [-SMTPCredential <PSCredential>] [-SMTPServer <String>] [-LogAsAttachment]
 [-DisableIPCheck] [-IPv6] [-UpdateIIS] [-IISSiteToUpdate <String>] -CsVipName <String[]> [-CspName <String>]
 [-CsVipBinding <String>] [-SvcName <String>] [-SvcDestination <String>] [-LbName <String>] [-RspName <String>]
 [-RsaName <String>] [-ConfigFile <String>] [-ForceCertRenew] [-NoConsoleOutput] [<CommonParameters>]
```

### Help
```
GenLeCertForNS.ps1 [-Help] [-NoConsoleOutput] [<CommonParameters>]
```

### CleanADC
```
GenLeCertForNS.ps1 [-CleanADC] -ManagementURL <String> [-Username <String>] [-Password <Object>]
 [-Credential <PSCredential>] [-DisableLogging] [-LogFile <String>] [-LogLevel <String>] [-SaveADCConfig]
 [-CsVipName <String[]>] [-CspName <String>] [-CsVipBinding <String>] [-SvcName <String>]
 [-SvcDestination <String>] [-LbName <String>] [-RspName <String>] [-RsaName <String>] [-NoConsoleOutput]
 [<CommonParameters>]
```

### CleanTestCertificate
```
GenLeCertForNS.ps1 [-RemoveTestCertificates] [-CleanPoshACMEStorage] -ManagementURL <String>
 [-Username <String>] [-Password <Object>] [-Credential <PSCredential>] [-DisableLogging] [-LogFile <String>]
 [-LogLevel <String>] [-NoConsoleOutput] [<CommonParameters>]
```

### CommandPolicyUser
```
GenLeCertForNS.ps1 -ManagementURL <String> [-Username <String>] [-Password <Object>]
 [-Credential <PSCredential>] [-LogFile <String>] [-LogLevel <String>] [-SaveADCConfig] [-CsVipName <String[]>]
 [-CspName <String>] [-SvcName <String>] [-LbName <String>] [-RspName <String>] [-RsaName <String>]
 [-CreateUserPermissions] [-NSCPName <String>] [-CreateApiUser] -ApiUsername <String> -ApiPassword <Object>
 [-NoConsoleOutput] [<CommonParameters>]
```

### CommandPolicy
```
GenLeCertForNS.ps1 -ManagementURL <String> [-Username <String>] [-Password <Object>]
 [-Credential <PSCredential>] [-LogFile <String>] [-LogLevel <String>] [-SaveADCConfig] -CsVipName <String[]>
 [-CspName <String>] [-SvcName <String>] [-LbName <String>] [-RspName <String>] [-RsaName <String>]
 [-CreateUserPermissions] [-NSCPName <String>] [-NoConsoleOutput] [<CommonParameters>]
```

### AutoRun
```
GenLeCertForNS.ps1 [-Production] -ConfigFile <String> [-AutoRun] [-ForceCertRenew] [-NoConsoleOutput]
 [<CommonParameters>]
```

## DESCRIPTION
The script will utilize Posh-ACME to create a new or update an existing certificate for one or more domains.
If generated successfully the script will add the certificate to the ADC and update the SSL binding for a web site.
This script is for use with a Citrix ADC (v11.x and up).
The script will validate the dns records provided.
For example, the domain(s) listed must be configured with the same IP Address that is configured (via NAT) to a Content Switch.
Or Use DNS verification if a WildCard domain was specified.

## EXAMPLES

### EXAMPLE 1
```
.\GenLeCertForNS.ps1 -CreateUserPermissions -CreateApiUser -CsVipName "CSVIPNAME" -ApiUsername "le-user" -ApiPassword "LEP@ssw0rd" -CPName "MinLePermissionGroup" -Username nsroot -Password "nsroot" -ManagementURL https://citrixadc.domain.local
```

This command will create a Command Policy with the minimum set of permissions, you need to run this once to create (or when you want to change something).
Be sure to run the script next with the same parameters as specified when running this command, the same for -SvcName (Default "svc_letsencrypt_cert_dummy"), -LbName (Default: "lb_letsencrypt_cert"), -RspName (Default: "rsp_letsencrypt"), -RsaName (Default: "rsa_letsencrypt"), -CspName (Default: "csp_NSCertCsp")
Next time you want to generate certificates you can specify the new user  -Username le-user -Password "LEP@ssw0rd"

### EXAMPLE 2
```
.\GenLeCertForNS.ps1 -CN "domain.com" -EmailAddress "hostmaster@domain.com" -SAN "sts.domain.com","www.domain.com","vpn.domain.com" -PfxPassword "P@ssw0rd" -CertDir "C:\Certificates" -ManagementURL "http://192.168.100.1" -CsVipName "cs_domain.com_http" -Password "P@ssw0rd" -Username "nsroot" -CertKeyNameToUpdate "san_domain_com" -LogLevel Debug -Production
```

Generate a (Production) certificate for hostname "domain.com" with alternate names : "sts.domain.com, www.domain.com, vpn.domain.com".
Using the email address "hostmaster@domain.com".
At the end storing the certificates  in "C:\Certificates" and uploading them to the ADC.
The Content Switch "cs_domain.com_http" will be used to validate the certificates.

### EXAMPLE 3
```
.\GenLeCertForNS.ps1 -CN "domain.com" -EmailAddress "hostmaster@domain.com" -SAN "*.domain.com","*.test.domain.com" -PfxPassword "P@ssw0rd" -CertDir "C:\Certificates" -ManagementURL "http://192.168.100.1" -Password "P@ssw0rd" -Username "nsroot" -CertKeyNameToUpdate "san_domain_com" -LogLevel Debug -Production
```

Generate a (Production) Wildcard (*) certificate for hostname "domain.com" with alternate names : "*.domain.com, *.test.domain.com.
Using the email address "hostmaster@domain.com".
At the end storing the certificates  in "C:\Certificates" and uploading them to the ADC.
NOTE: Only a DNS verification is possible when using WildCards!

### EXAMPLE 4
```
.\GenLeCertForNS.ps1 -CleanADC -ManagementURL "http://192.168.100.1" -CsVipName "cs_domain.com_http" -Password "P@ssw0rd" -Username "nsroot"
```

Cleaning left over configuration from this script when something went wrong during a previous attempt to generate new certificates.

### EXAMPLE 5
```
.\GenLeCertForNS.ps1 -RemoveTestCertificates -ManagementURL "http://192.168.100.1" -Password "P@ssw0rd" -Username "nsroot"
```

Removing ALL the test certificates from your ADC.

### EXAMPLE 6
```
.\GenLeCertForNS.ps1 -AutoRun -ConfigFile ".\GenLe-Config.json"
```

Running the script with previously saved parameters.
To create a test certificate.
NOTE: you can create the json file by specifying the -ConfigFile ".\GenLe-Config.json" parameter with your previous parameters

### EXAMPLE 7
```
.\GenLeCertForNS.ps1 -AutoRun -ConfigFile ".\GenLe-Config.json" -Production
```

Running the script with previously saved parameters.
To create a Production (trusted) certificate
NOTE: you can create the json file by specifying the -ConfigFile ".\GenLe-Config.json" parameter with your previous parameters

### EXAMPLE 8
```
.\GenLeCertForNS.ps1 -CreateUserPermissions -NSCPName script-GenLeCertForNS -CreateApiUser -ApiUsername GenLEUser -ApiPassword P@ssw0rd! -ManagementURL https://citrixadc.domain.local -Username nsroot -Password nsr00t! -CsVipName cs_domain2.com_http,cs_domain2.com_http,cs_domain3.com_http
```

Create a Group (Command Policy) with limited user permissions required to run the script and a user that will be member of that group.
With all VIPs that can be used by the script.

## PARAMETERS

### -Help
Display the detailed information about this script

```yaml
Type: SwitchParameter
Parameter Sets: Help
Aliases: h

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -CleanADC
Clean-up the ADC configuration made within this script, for when somewhere it gone wrong

```yaml
Type: SwitchParameter
Parameter Sets: CleanADC
Aliases: CleanNS

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -RemoveTestCertificates
Remove all the Test/Staging certificates signed by the "Fake LE Intermediate X1" staging intermediate

```yaml
Type: SwitchParameter
Parameter Sets: CleanTestCertificate
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -CleanPoshACMEStorage
Force cleanup of the Posh-Acme certificates located in "%LOCALAPPDATA%\Posh-ACME"

```yaml
Type: SwitchParameter
Parameter Sets: LECertificates, CleanTestCertificate
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ManagementURL
Management URL, used to connect to the ADC

```yaml
Type: String
Parameter Sets: LECertificates, CleanADC, CleanTestCertificate, CommandPolicyUser, CommandPolicy
Aliases: URL, NSManagementURL

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Username
ADC Username with enough access to configure it

```yaml
Type: String
Parameter Sets: LECertificates, CleanADC, CleanTestCertificate, CommandPolicyUser, CommandPolicy
Aliases: User, NSUsername, ADCUsername

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Password
ADC Username password

```yaml
Type: Object
Parameter Sets: LECertificates, CleanADC, CleanTestCertificate, CommandPolicyUser, CommandPolicy
Aliases: NSPassword, ADCPassword

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
Use a PSCredential object instead of a Username or password.
Use "Get-Credential" to generate a credential object
C:\PS\> $Credential = Get-Credential

```yaml
Type: PSCredential
Parameter Sets: LECertificates, CleanADC, CleanTestCertificate, CommandPolicyUser, CommandPolicy
Aliases: NSCredential, ADCCredential

Required: False
Position: Named
Default value: [System.Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

### -CN
(Common Name) The Primary (first) dns record for the certificate
Example: "domain.com"

```yaml
Type: String
Parameter Sets: LECertificates
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SAN
(Subject Alternate Name) every following domain listed in this certificate.
separated via an comma , and between quotes "".
Example: "sts.domain.com","www.domain.com","vpn.domain.com"
Example Wildcard: "*.domain.com","*.pub.domain.com"
NOTE: Only a DNS verification is possible when using WildCards!

```yaml
Type: String[]
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: @()
Accept pipeline input: False
Accept wildcard characters: False
```

### -FriendlyName
The display name of the certificate, if not specified the CN will used.
You can specify an empty value if required.
Example (Empty display name) : ""
Example (Set your own name) : "Custom Name"

```yaml
Type: String
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ValidationMethod
{{ Fill ValidationMethod Description }}

```yaml
Type: String
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: Http
Accept pipeline input: False
Accept wildcard characters: False
```

### -CertKeyNameToUpdate
ADC SSL Certkey name currently in use, that needs to be renewed

```yaml
Type: String
Parameter Sets: LECertificates
Aliases: NSCertNameToUpdate

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RemovePrevious
If the new certificate was updated successfully, remove the previous files.
This parameter works only if -CertKeyNameToUpdate was specified and previous files are found.
Else this setting will be ignored!

```yaml
Type: SwitchParameter
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -CertDir
Directory where to store the certificates

```yaml
Type: String
Parameter Sets: LECertificates
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PfxPassword
Specify a password for the PFX certificate, if not specified a new password is generated at the end

```yaml
Type: Object
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EmailAddress
The email address used to request the certificates and receive a notification when the certificates (almost) expires

```yaml
Type: String
Parameter Sets: LECertificates
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -KeyLength
Specify the KeyLength of the new to be generated certificate
Default: 2048

```yaml
Type: Int32
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: 2048
Accept pipeline input: False
Accept wildcard characters: False
```

### -Production
Use the production Let's encrypt server, without this parameter the staging (test) server will be used

```yaml
Type: SwitchParameter
Parameter Sets: LECertificates, AutoRun
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisableLogging
Turn off logging to logfile.
Default ON

```yaml
Type: SwitchParameter
Parameter Sets: LECertificates, CleanADC, CleanTestCertificate
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogFile
{{ Fill LogFile Description }}

```yaml
Type: String
Parameter Sets: LECertificates, CleanADC, CleanTestCertificate, CommandPolicyUser, CommandPolicy
Aliases: LogLocation

Required: False
Position: Named
Default value: <DEFAULT>
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogLevel
The Log level you want to have specified.
With LogLevel: Error; Only Error (E) data will be written or shown.
With LogLevel: Warning; Only Error (E) and Warning (W) data will be written or shown.
With LogLevel: Info; Only Error (E), Warning (W) and Info (I) data will be written or shown.
With LogLevel: Debug; All, Error (E), Warning (W), Info (I) and Debug (D) data will be written or shown.
You can also define a (Global) variable in your script $LogLevel, the function will use this level instead (if not specified with the command)
Default value: Info

```yaml
Type: String
Parameter Sets: LECertificates, CleanADC, CleanTestCertificate, CommandPolicyUser, CommandPolicy
Aliases:

Required: False
Position: Named
Default value: Info
Accept pipeline input: False
Accept wildcard characters: False
```

### -SaveADCConfig
{{ Fill SaveADCConfig Description }}

```yaml
Type: SwitchParameter
Parameter Sets: LECertificates, CleanADC, CommandPolicyUser, CommandPolicy
Aliases: SaveNSConfig

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -SendMail
Specify this parameter if you want to send a mail at the end, don't forget to specify SMTPTo, SMTPFrom, SMTPServer and if required SMTPCredential

```yaml
Type: SwitchParameter
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -SMTPTo
Specify one or more email addresses.
Email addresses can be specified as "user.name@domain.com" or "User Name \<user.name@domain.com\>"
If specifying multiple email addresses, separate them wit a comma.

```yaml
Type: String[]
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SMTPFrom
Specify the Email address where mails are send from
The email address can be specified as "user.name@domain.com" or "User Name \<user.name@domain.com\>"

```yaml
Type: String
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SMTPCredential
Specify the Mail server credentials, only if credentials are required to send mails

```yaml
Type: PSCredential
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: [System.Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

### -SMTPServer
Specify the SMTP Mail server fqdn or IP-address

```yaml
Type: String
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LogAsAttachment
If you specify this parameter, the log will be attached as attachment when sending the mail.

```yaml
Type: SwitchParameter
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -DisableIPCheck
If you want to skip the IP Address verification, specify this parameter

```yaml
Type: SwitchParameter
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -IPv6
If specified, the script will try run with IPv6 checks (EXPERIMENTAL)

```yaml
Type: SwitchParameter
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -UpdateIIS
If specified, the script will try to add the generated certificate to the personal computer store and bind it to the site

```yaml
Type: SwitchParameter
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -IISSiteToUpdate
Select a IIS Site you want to add the certificate to.
Default value when not specifying this parameter is "Default Web Site".

```yaml
Type: String
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: Default Web Site
Accept pipeline input: False
Accept wildcard characters: False
```

### -CsVipName
Name of the HTTP ADC Content Switch used for the domain validation.
Specify only one when requesting a certificate
Specify all possible VIPs when creating a Command Policy (User group, -NSCPName), so they all can be used by the members

```yaml
Type: String[]
Parameter Sets: LECertificates, CommandPolicy
Aliases: NSCsVipName

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

```yaml
Type: String[]
Parameter Sets: CleanADC, CommandPolicyUser
Aliases: NSCsVipName

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CspName
ADC Content Switch Policy name
Default: "csp_NSCertCsp"

```yaml
Type: String
Parameter Sets: LECertificates, CleanADC, CommandPolicyUser, CommandPolicy
Aliases: NSCspName

Required: False
Position: Named
Default value: Csp_letsencrypt
Accept pipeline input: False
Accept wildcard characters: False
```

### -CsVipBinding
ADC Content Switch binding used for the validation
Default: 11

```yaml
Type: String
Parameter Sets: LECertificates, CleanADC
Aliases: NSCsVipBinding

Required: False
Position: Named
Default value: 11
Accept pipeline input: False
Accept wildcard characters: False
```

### -SvcName
ADC Load Balance service name
Default "svc_letsencrypt_cert_dummy"

```yaml
Type: String
Parameter Sets: LECertificates, CleanADC, CommandPolicyUser, CommandPolicy
Aliases: NSSvcName

Required: False
Position: Named
Default value: Svc_letsencrypt_cert_dummy
Accept pipeline input: False
Accept wildcard characters: False
```

### -SvcDestination
IP Address used for the ADC Service (leave default 1.2.3.4, only change when already used

```yaml
Type: String
Parameter Sets: LECertificates, CleanADC
Aliases: NSSvcDestination

Required: False
Position: Named
Default value: 1.2.3.4
Accept pipeline input: False
Accept wildcard characters: False
```

### -LbName
ADC Load Balance VIP name
Default: "lb_letsencrypt_cert"

```yaml
Type: String
Parameter Sets: LECertificates, CleanADC, CommandPolicyUser, CommandPolicy
Aliases: NSLbName

Required: False
Position: Named
Default value: Lb_letsencrypt_cert
Accept pipeline input: False
Accept wildcard characters: False
```

### -RspName
ADC Responder Policy name
Default: "rsp_letsencrypt"

```yaml
Type: String
Parameter Sets: LECertificates, CleanADC, CommandPolicyUser, CommandPolicy
Aliases: NSRspName

Required: False
Position: Named
Default value: Rsp_letsencrypt
Accept pipeline input: False
Accept wildcard characters: False
```

### -RsaName
ADC Responder Action name
Default: "rsa_letsencrypt"

```yaml
Type: String
Parameter Sets: LECertificates, CleanADC, CommandPolicyUser, CommandPolicy
Aliases: NSRsaName

Required: False
Position: Named
Default value: Rsa_letsencrypt
Accept pipeline input: False
Accept wildcard characters: False
```

### -CreateUserPermissions
When this parameter is configured, a User Group (Command Policy) will be created with a limited set of permissions required to run this script.
Also specify all VIP, LB svc names if you want other than default values.
Mandatory parameter is the CsVipName.

```yaml
Type: SwitchParameter
Parameter Sets: CommandPolicyUser, CommandPolicy
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -NSCPName
You can change the name of the Command Policy that will be created when you configure the -CreateUserPermissions parameter
Default: \`"script-GenLeCertForNS\`"

```yaml
Type: String
Parameter Sets: CommandPolicyUser, CommandPolicy
Aliases:

Required: False
Position: Named
Default value: Script-GenLeCertForNS
Accept pipeline input: False
Accept wildcard characters: False
```

### -CreateApiUser
When this parameter is configured, a (System) User will be created.
This will me a member of the Command policy configured with -NSCPName

```yaml
Type: SwitchParameter
Parameter Sets: CommandPolicyUser
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ApiUsername
The Username for the (System) User

```yaml
Type: String
Parameter Sets: CommandPolicyUser
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ApiPassword
The Password for the (System) User

```yaml
Type: Object
Parameter Sets: CommandPolicyUser
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ConfigFile
Use an existing or save all the "current" parameters to a json file of your choosing for later reuse of the same parameters.

```yaml
Type: String
Parameter Sets: LECertificates
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

```yaml
Type: String
Parameter Sets: AutoRun
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AutoRun
This parameter is used to make sure you are deliberately using the parameters from the config file and run the script automatically.

```yaml
Type: SwitchParameter
Parameter Sets: AutoRun
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -ForceCertRenew
Specify this parameter if you want to renew certificate even though it's still valid.

```yaml
Type: SwitchParameter
Parameter Sets: LECertificates, AutoRun
Aliases: Force

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -NoConsoleOutput
When Specified, no output will be written to the console.
Exception: Warning, Verbose and Error messages.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
File Name : GenLeCertForNS.ps1
Version   : v2.10.2
Author    : John Billekens
Requires  : PowerShell v5.1 and up
            ADC 11.x and up
            Run As Administrator
            Posh-ACME 4.2.0 (Will be installed via this script) Thank you @rmbolger for providing the HTTP validation method!
            Microsoft .NET Framework 4.7.1 or later (when using Posh-ACME/WildCard certificates)

## RELATED LINKS

[https://blog.j81.nl](https://blog.j81.nl)
