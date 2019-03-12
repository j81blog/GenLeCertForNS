@ECHO OFF
setlocal EnableDelayedExpansion
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
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

rem ===== Help Example =====

SET OPTIONS=-CN "domain.com"
SET OPTIONS=%OPTIONS% -EmailAddress "hostmaster@domain.com"
SET OPTIONS=%OPTIONS% -SAN "sts.domain.com","www.domain.com","vpn.domain.com"
SET OPTIONS=%OPTIONS% -PfxPassword "P@ssw0rd"
SET OPTIONS=%OPTIONS% -CertDir "C:\Certificates"
SET OPTIONS=%OPTIONS% -NSManagementURL "http://192.168.100.1"
SET OPTIONS=%OPTIONS% -NSCsVipName "cs_domain.com_http"
SET OPTIONS=%OPTIONS% -NSPassword "P@ssw0rd"
SET OPTIONS=%OPTIONS% -NSUsername "nsroot"
SET OPTIONS=%OPTIONS% -NSCertNameToUpdate "san_domain_com"
rem SET OPTIONS=%OPTIONS% -Production
SET OPTIONS=%OPTIONS% -Verbose

NOTE: Use the "-Production" only if you're sure everything works, you can only use the Let's Encrypt production server 5 times per week.
NOTE: Use the "-Verbose" parameter to get diagnostic output

rem ===== End Help Example =====

:StartScript

SET OPTIONS=-CN "domain.com"
SET OPTIONS=%OPTIONS% -EmailAddress "hostmaster@domain.com"
SET OPTIONS=%OPTIONS% -SAN "sts.domain.com","www.domain.com","vpn.domain.com"
SET OPTIONS=%OPTIONS% -PfxPassword "P@ssw0rd"
SET OPTIONS=%OPTIONS% -CertDir "C:\Certificates"
SET OPTIONS=%OPTIONS% -NSManagementURL "http://192.168.100.1"
SET OPTIONS=%OPTIONS% -NSCsVipName "cs_domain.com_http"
SET OPTIONS=%OPTIONS% -NSPassword "P@ssw0rd"
SET OPTIONS=%OPTIONS% -NSUsername "nsroot"
SET OPTIONS=%OPTIONS% -NSCertNameToUpdate "san_domain_com"
rem SET OPTIONS=%OPTIONS% -Production
SET OPTIONS=%OPTIONS% -Verbose

%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%~dp0GenLeCertForNS.ps1" %OPTIONS%
