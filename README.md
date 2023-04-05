# GenLeCertForNS

This article describes how to use the *'GenLeCertForNS.ps1'* script and helps you to create a Let's Encrypt certificates for your NetScaler

## Content

- [General](#General)
- [Requirements](#Requirements)
- [Logging](#Logging)
- [Create specific user permissions (optional)](#Create-specific-user-permissions-(optional))
- [Create a SAN certificate (no manual actions)](#Create-a-SAN-certificate-(no-manual-actions))
- [Generate a wildcard certificate (manual)](#Generate-a-wildcard-certificate-(manual))
- [Generate a wildcard certificate (automagically)](#Generate-a-wildcard-certificate-(automagically))
- [Using a config file (used for Scheduled runs)](#Using-a-config-file-(used-for-Scheduled-runs))
  * [Basics](#Basics)
  * [Passwords](#Passwords)
  * [Multiple Certificate requests](#Multiple-Certificate-requests)
- [Manual ADC Cleanup](#Manual-ADC-Cleanup)
- [Remove test certificates](#Remove-test-certificates)
- [Using a batch file](#Using-a-batch-file)

## General

This script (currently) only supports Let's Encrypt certificates. It has only the ability to generate certificates and add them to the ADC configuration or update excising certificates.
If you add a new certificate, you will have to assign it by yourself to a vip.
If you update an existing certificate (by specifying a name for the *-CertKeyNameToUpdate \<CertKeyName\>* parameter) the script update this certificate. And if it is already bound to a vip, this will automatically be updates with it.

The basic command line options (help output): [GenLeCertForNS.ps1](docs/GenLeCertForNS.ps1.md)

## Requirements

The script requires the following

- PowerShell v5.1 and up (limited/untested with v6 and higher)
- ADC (NetScaler) 12.1 and higher (older versions might work as expected, I follow [Citrix Product matrix](https://www.citrix.com/support/product-lifecycle/product-matrix.html) supported versions)
- Microsoft .NET Framework 4.7.2 or higher
- Posh-ACME PowerShell module (installed and/or updated automatically)

## Logging

With version 2.10.x and higher it's possible to log everything with a definable level of output.
By default (if not specifying this parameter) the value of *'Info'* will be set. This can be configured by specifying the *'-LogLevel \<LogLevel\>'* parameter.
Possible values:

- *Error*
- *Warning*
- *Info*
- *Debug*
- *None*

If not changed, a logfile with the name *'GenLeCertForNS.txt'* will be generated in the same directory as the script. By specifying the *'-LogFile \<LogFilePathAndName\>'* parameter, you can change the file.

```powershell
GenLeCertForNS.ps1 [...] -LogLevel 'Debug' -LogFile 'C:\Log\LetsEncryptScriptLog.txt'
```

## Create specific user permissions (optional)

This command will create a Command Policy (*-CPName 'LetsEncrypt'*) with the minimum set of permissions, you need to run this once to create (or when you want to change something).

Be sure to run the script with the same parameters as you would when generating a certificate. Use for example the same values for the following parameters *-SvcName* (***Default: 'svc_letsencrypt_cert_dummy'***), *-LbName* (***Default: 'lb_letsencrypt_cert'***), *-RspName* (***Default: 'rsp_letsencrypt'***), *-RsaName* (***Default: 'rsa_letsencrypt'***), *-CspName* (***Default: 'csp_NSCertCsp'***)
Next time you want to generate certificates you can specify the new user *-Username 'le-user' -Password 'LEP@ssw0rd'*
> ***NOTE:*** When u want to use a different content switch or multiple new content switches, you have to run this command again with specifying multiple content switches.
CsVipName = 'cs_domain.com_http','cs_domain2.com_http','cs_domain3.com_http'

```PowerShell
$params = @{
    CreateUserPermissions = $true
    CreateApiUser = $true
    CsVipName = 'cs_domain.com_http'
    ApiUsername = 'le-user'
    ApiPassword = 'LEP@ssw0rd'
    CPName = 'LetsEncrypt'
    Username = 'nsroot'
    Password = 'LEP@ssw0rd'
    ManagementURL = 'https://citrixadc.domain.local'
}
GenLeCertForNS.ps1 @params
```

or as one line

```PowerShell
GenLeCertForNS.ps1 -CreateUserPermissions -CreateApiUser -CsVipName 'cs_domain.com_http' -ApiUsername 'le-user' -ApiPassword 'LEP@ssw0rd' -CPName 'LetsEncrypt' -Username 'nsroot' -Password 'LEP@ssw0rd' -ManagementURL 'https://citrixadc.domain.local'
```

## Create a SAN certificate (no manual actions)

Generate a (Production) certificate for hostname 'domain.com' with alternate names : 'sts.domain.com, www.domain.com, vpn.domain.com'. Using the email address 'hostmaster@domain.com'. At the end storing the certificates in 'C:\Certificates' and uploading them to the ADC. The Content Switch 'cs_domain.com_http' will be used to validate the certificates.

> ***NOTE:*** Always test without the ***-Production*** parameter, as you have limited reties. Make sure after every change that you test it first without the ***-Production*** parameter!

```PowerShell
$params = @{
    CN = 'domain.com'
    EmailAddress = 'hostmaster@domain.com'
    SAN = 'sts.domain.com','www.domain.com','vpn.domain.com'
    PfxPassword = 'PfxP@ssw0rd'
    CertDir = 'C:\Certificates'
    ManagementURL = 'https://192.168.100.1'
    CsVipName = 'cs_domain.com_http'
    Username = 'le-user'
    Password = 'LEP@ssw0rd'
    CertKeyNameToUpdate = 'san_domain_com'
    LogLevel = 'Debug'
}
GenLeCertForNS.ps1 @params [-Production]
```

or as one line

```PowerShell
GenLeCertForNS.ps1 -CN 'domain.com' -EmailAddress 'hostmaster@domain.com' -SAN 'sts.domain.com','www.domain.com','vpn.domain.com' -PfxPassword 'PfxP@ssw0rd' -CertDir 'C:\Certificates' -ManagementURL 'https://192.168.100.1' -CsVipName 'cs_domain.com_http' -Username 'le-user' -Password 'LEP@ssw0rd' -CertKeyNameToUpdate 'san_domain_com' -LogLevel 'Debug' [-Production]
```

## Generate a wildcard certificate (manual)

Generate a (Production) Wildcard (*) certificate for hostname 'domain.com' with alternate names : '*.domain.com, *.test.domain.com. Using the email address 'hostmaster@domain.com'. At the end storing the certificates  in 'C:\Certificates' and uploading them to the ADC.
> ***NOTE:*** When using WildCards only a DNS verification is possible! It's not possible to use a HTTP validation (per Let's Encrypt ACME design).

If you don't configure any further parameters (see next example) you must complete the actions manually. During the process a number of TXT records will be shown. These must me configured in DNS before you can continue.

> ***NOTE:*** Always test without the ***-Production*** parameter, as you have limited reties. Make sure after every change that you test it first without the ***-Production*** parameter!

```PowerShell
$params = @{
    CN = 'domain.com'
    SAN = '*.domain.com','*.test.domain.com'
    EmailAddress = 'hostmaster@domain.com'
    PfxPassword = 'PfxP@ssw0rd'
    CertDir = 'C:\Certificates'
    ManagementURL = 'https://192.168.100.1'
    Username = 'le-user'
    Password = 'LEP@ssw0rd'
    CertKeyNameToUpdate = 'wildcard.domain.com'
    LogLevel = 'Debug'
}
GenLeCertForNS.ps1 @params [-Production]
```

## Generate a wildcard certificate (automagically)

Starting with version 2.10.0 and higher, this scripts supports the DNS plugins offered by Posh-ACME. You need to specify the DNS parameters, needed to connect to the DNS provider.
Generate a (Production) Wildcard (&ast;.domain.tld) certificate for hostname 'domain.com' with alternate names : '&ast;.domain.com, &ast;.test.domain.com. Using the email address 'hostmaster@domain.com'. At the end storing the certificates  in 'C:\Certificates' and uploading them to the ADC.
> ***NOTE:*** Only a DNS verification is possible when using WildCards!

> ***NOTE:*** Always test without the ***-Production*** parameter, as you have limited reties. Make sure after every change that you test it first without the ***-Production*** parameter!

```PowerShell
$params = @{
    CN = 'domain.com'
    EmailAddress = 'hostmaster@domain.com'
    SAN = '*.domain.com'
    PfxPassword = 'PfxP@ssw0rd'
    CertDir = 'C:\Certificates'
    ManagementURL = 'http://192.168.100.1'
    Password = 'LEP@ssw0rd'
    Username = 'le-user'
    CertKeyNameToUpdate = 'wildcard_domain_com'
    DNSPlugin = 'Aurora'
    DNSParams = @{AuroraCredential = $((New-Object PSCredential 'KEYKEYKEY', $(ConvertTo-SecureString -String 'SECRETSECRETSECRET' -AsPlainText -Force))); AuroraApi = 'api.auroradns.eu' }
}
GenLeCertForNS.ps1 @params [-Production]
```

## Using a config file (used for Scheduled runs)

Starting with version 2.9.3 and higher, an option was added to generate a config file. This file is in a json format and can contain almost all parameters.
You can use this file to request multiple certificates.
The named parameters in the JSON config file are the same as specified on the command line.

### Basics

To generate a JSON config file you just run your command you would use to create your certificate and only add the 'ConfigFile' parameter. Take for example the command we used in the second example:

> ***NOTE:*** Always test without the ***-Production*** parameter, as you have limited reties. Make sure after every change that you test it first without the ***-Production*** parameter!

```PowerShell
$params = @{
    CN = 'domain.com'
    EmailAddress = 'hostmaster@domain.com'
    SAN = 'sts.domain.com','www.domain.com','vpn.domain.com'
    PfxPassword = 'PfxP@ssw0rd'
    CertDir = 'C:\Certificates'
    ManagementURL = 'https://192.168.100.1'
    CsVipName = 'cs_domain.com_http'
    Username = 'le-user'
    Password = 'LEP@ssw0rd'
    CertKeyNameToUpdate = 'san_domain_com'
    LogLevel = 'Debug'

    ConfigFile = '.\GenLe-Config.json'
}
GenLeCertForNS.ps1 @params [-Production]
```

When you execute it this time, all the normal tasks run and a certificate will be generated. And afterwards the file you specified in the 'ConfigFile' parameter will be created ('GenLe-Config.json') in the same location as you script.
This file will contain all the parameters you specified (and the ones you didn't specified with their default values)

```json
{
    "settings": {
        "ManagementURL": "https://192.168.100.1",
        "ADCCredentialUsername": "le-user",
        "ADCCredentialPassword": {
            "Password": "76492d1116743f0423...YwB3ACsANgBOAGgATABYAFoAZQB4AH==",
            "IsEncrypted": true
        },
        "DisableLogging": false,
        "LogFile": "C:\\Scripts\\GenLeCertForNS.txt",
        "LogLevel": "Debug",
        "SaveADCConfig": false,
        "SendMail": false,
        "SMTPTo": null,
        "SMTPFrom": "",
        "SMTPCredentialUsername": null,
        "SMTPCredentialPassword": null,
        "SMTPServer": "",
        "SvcName": "svc_letsencrypt_cert_dummy",
        "SvcDestination": "1.2.3.4",
        "LbName": "lb_letsencrypt_cert",
        "RspName": "rsp_letsencrypt",
        "RsaName": "rsa_letsencrypt",
        "CspName": "csp_letsencrypt",
        "CsVipBinding": "11",
        "ScriptVersion": "2.9.3"
    },
    "certrequests": [
        {
            "CN": "domain.com",
            "SANs": "sts.domain.com','www.domain.com','vpn.domain.com",
            "FriendlyName": "domain.com",
            "CsVipName": "cs_domain.com_http",
            "CertKeyNameToUpdate": "san_domain_com",
            "RemovePrevious": false,
            "CertDir": "C:\\Certificates",
            "EmailAddress": "hostmaster@domain.com",
            "KeyLength": 2048,
            "ValidationMethod": "http",
            "CertExpires": "",
            "RenewAfter": "",
            "ForceCertRenew": false,
            "DisableIPCheck": false,
            "PfxPassword": {
                "Password": "76492d1116743f0...AZAA5AGQANwA3AA==",
                "IsEncrypted": true
            },
            "UpdateIIS": false,
            "IISSiteToUpdate": "Default Web Site"
        }
    ]
}
```

> ***NOTE:*** Always test without the ***-Production*** parameter, as you have limited reties. Make sure after every change that you test it first without the ***-Production*** parameter!

```PowerShell
$params = @{
    AutoRun = $true
    ConfigFile = '.\GenLe-Config.json'
}

GenLeCertForNS.ps1 @params [-Production]
```

or as one line

```PowerShell
GenLeCertForNS.ps1 -AutoRun -ConfigFile '.\GenLe-Config.json' [-Production]
```

If you run one of these commands, you'll end up again with the same result as before. But then by just specifying the config file.

### Passwords

You might have noticed that the passwords are scrambled. These are being 'encrypted'. If you want to change the password in the config file you can just enter your new password and save it (don't forget to set 'IsEncrypted' to ***true***)
The next time you run the script and use the updated config file. The password will be encrypted and saved again in en unreadable format.

```json
"PfxPassword": {
    "Password": "NewClearTextP@ssw0rd",
    "IsEncrypted": false
}
```

### Multiple Certificate requests

With a config file you can specify multiple certificate requests. This way you don't need to create multiple command lines for different certificates.
All you need is to copy the last part, between ***"certrequests": [*** { CERT REQUEST PARAMS } ***]*** (don't forget to include the curly brackets *{}* and separate each certificate request with a comma)

```json
"certrequests": [
    { CERT REQUEST PARAMS },
    { CERT REQUEST PARAMS },
    { CERT REQUEST PARAMS }
]
```

For the sake of this example I left out some critical parameters, you will need to copy all parameters when doing this!

```json
"certrequests": [
    {
        "CN": "domain.com",
        "SANs": "sts.domain.com','www.domain.com','vpn.domain.com",
        "CsVipName": "cs_domain.com_http",
        "CertKeyNameToUpdate": "san_domain_com",
        "...": "...",
        "IISSiteToUpdate": "Default Web Site"
    }
]

```

Just copy the part and separate each instance with a comma.

```json
"certrequests": [
    {
        "CN": "domain.com",
        "SANs": "sts.domain.com','www.domain.com','vpn.domain.com",
        "CsVipName": "cs_domain.com_http",
        "CertKeyNameToUpdate": "san_domain_com",
        "...": "..."
    },
    {
        "CN": "portal.domain.nl",
        "SANs": "",
        "CsVipName": "cs_domain.nl_http",
        "CertKeyNameToUpdate": "portal.domain.nl",
        "...": "..."
    },
    {
        "CN": "domain3.com",
        "SANs": "sts.domain3.com','www.domain3.com','vpn.domain3.com",
        "CsVipName": "cs_domain3.com_http",
        "CertKeyNameToUpdate": "san_domain3_com",
        "...": "..."
    }
]

```

If you run the script with these three certificate request the script will run once and generate all three certificates requested.

> ***IMPORTANT:*** If your json config file is not in the right format, the script will FAIL!
I suggest you use Notepad++ and install the *"JSON Viewer"* plugin, and after each change of the config file just run the *"Format JSON"* command.
If this plugin runs it will format/restructure and check the JSON file for errors.

## Manual ADC Cleanup

In some circumstances it may happen that the script stops. This may leave leftover config in the ADC. You can remote it manually or running the script with the following parameters.
> ***NOTE:*** Specify the same names as during the run that failed like the *'CsVipName'*.

```PowerShell
GenLeCertForNS.ps1 -CleanADC -ManagementURL 'http://192.168.100.1' -CsVipName 'cs_domain.com_http' -Password 'LEP@ssw0rd' -Username 'le-user'
```

## Remove test certificates

Removing ALL the test certificates from your ADC.

```PowerShell
GenLeCertForNS.ps1 -RemoveTestCertificates -ManagementURL 'http://192.168.100.1' -Password 'LEP@ssw0rd' -Username 'le-user'
```

## Using a batch file

Is some situations you might need to use a batch file to start this script. You can use the following template and specify your own values.

> ***NOTE:*** The first part of the script is a safeguard to always check and run *'GenLeCertForNS.ps1'* elevated.

```dos
@ECHO OFF
setlocal EnableDelayedExpansion
REM  --> Check for permissions to find out if script has elevated privileges.
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have elevated privileges.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

goto StartScript

You can place your own comments here

:StartScript

SET OPTIONS=-CN "domain.com"
SET OPTIONS=%OPTIONS% -EmailAddress "hostmaster@domain.com"
SET OPTIONS=%OPTIONS% -SAN "sts.domain.com","www.domain.com","vpn.domain.com"
SET OPTIONS=%OPTIONS% -PfxPassword "P@ssw0rd"
SET OPTIONS=%OPTIONS% -CertDir "C:\Certificates"
SET OPTIONS=%OPTIONS% -ManagementURL "http://192.168.100.1"
SET OPTIONS=%OPTIONS% -CsVipName "cs_domain.com_http"
SET OPTIONS=%OPTIONS% -Username "nsroot"
SET OPTIONS=%OPTIONS% -Password "P@ssw0rd"
SET OPTIONS=%OPTIONS% -CertKeyNameToUpdate "san_domain_com"
rem SET OPTIONS=%OPTIONS% -LogLevel Debug
SET OPTIONS=%OPTIONS% -LogFile "le-certificates.txt"
rem SET OPTIONS=%OPTIONS%  -ConfigFile ".\GenLe-Config.json"
rem SET OPTIONS=%OPTIONS% -DisableIPCheck
rem SET OPTIONS=%OPTIONS% -Production

%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -Command "& {.\GenLeCertForNS.ps1 %OPTIONS%}"
```
