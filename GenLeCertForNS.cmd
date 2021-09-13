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

rem ===== Help Example - HTTP =====

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
rem SET OPTIONS=%OPTIONS% -Production

NOTE: Use the "-Production" only if you're sure everything works, you can only use the Let's Encrypt production server 5 times per week.

rem ===== Help Example - DNS =====

SET OPTIONS=-CN "domain.com"
SET OPTIONS=%OPTIONS% -EmailAddress "hostmaster@domain.com"
SET OPTIONS=%OPTIONS% -SAN "*.domain.com"
rem SET OPTIONS=%OPTIONS% -DNSPlugin "Aurora"
rem SET OPTIONS=%OPTIONS% -DNSParams @{AuroraCredential=$((New-Object PSCredential 'KEYKEYKEY',$(ConvertTo-SecureString -String 'SECRETSECRETSECRET' -AsPlainText -Force))); AuroraApi='api.auroradns.eu'}
SET OPTIONS=%OPTIONS% -PfxPassword "P@ssw0rd"
SET OPTIONS=%OPTIONS% -CertDir "C:\Certificates"
SET OPTIONS=%OPTIONS% -ManagementURL "http://192.168.100.1"
SET OPTIONS=%OPTIONS% -CsVipName "cs_domain.com_http"
SET OPTIONS=%OPTIONS% -Username "nsroot"
SET OPTIONS=%OPTIONS% -Password "P@ssw0rd"
SET OPTIONS=%OPTIONS% -CertKeyNameToUpdate "san_domain_com"
rem SET OPTIONS=%OPTIONS% -LogLevel Debug
rem SET OPTIONS=%OPTIONS% -Production

NOTE: Use the "-Production" only if you're sure everything works, you can only use the Let's Encrypt production server 5 times per week.

rem ===== Auto Run Example ====

SET OPTIONS=%OPTIONS% -AutoRun
SET OPTIONS=%OPTIONS% -ConfigFile ".\LetsEncryptCerificates.json"
SET OPTIONS=%OPTIONS% -Production

NOTE: Use the "-Production" only if you're sure everything works, you can only use the Let's Encrypt production server 5 times per week.
NOTE: Use the "-Verbose" parameter to get diagnostic output

rem ===== End Help Example =====

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
SET OPTIONS=%OPTIONS% -LogFile "le-certificates.txt"
rem SET OPTIONS=%OPTIONS% -LogLevel Debug
rem SET OPTIONS=%OPTIONS% -ConfigFile ".\GenLe-Config.json"
rem SET OPTIONS=%OPTIONS% -DisableIPCheck
rem SET OPTIONS=%OPTIONS% -Production

%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -Command "& {.\GenLeCertForNS.ps1 %OPTIONS%}"
