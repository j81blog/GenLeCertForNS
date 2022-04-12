[CmdletBinding()]
<#
.SYNOPSIS
    Update the .... certificate
.DESCRIPTION
    Update the .... certificate
.PARAMETER Thumbprint
    Certificate thumbprint
.PARAMETER PFXfilename
    Contains the (full) path to the PFX certificate file
.PARAMETER PFXPassword
    Password for the PFX file
.NOTES
    File Name : _template.ps1
    Version   : v1.0.0
    Author    : John Billekens
    Requires  : PowerShell v5.1 and up
                Written to be used with GenLeCertForNS
                Run As Administrator
.LINK
    https://blog.j81.nl
#>
[CmdletBinding()]
param(
    [String]$Thumbprint,

    [String]$PFXfilename,
    
    [SecureString]$PFXPassword,

    [parameter(ValueFromRemainingArguments, DontShow)]
    [Object]$RemainingArguments
)

#requires -version 5.1
#Requires -RunAsAdministrator

$exitCode = 0
$LogComponentName = "CustomExample"

try {
    #placeholder if Command Write-ToLogFile is not available
    if (-not (Get-Command -Name Write-ToLogFile)) { function Write-ToLogFile { } }
    <#
    
    # You can use the following code to import the certificate to the local machine
    
    $importedCertificate = Import-PfxCertificate -FilePath $PFXfilename -CertStoreLocation Cert:\LocalMachine\My -Password $PFXPassword
    if ($importedCertificate.Thumbprint -notlike $Thumbprint) {
        Write-ToLogFile -D -C $LogComponentName -M "`"$($importedCertificate.Thumbprint)`" is not equal to `"$Thumbprint`""
    }
    $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $Thumbprint }
    
    #>

    <#
    #Your own script here

    #if you specified your own custom (extra) Arguments (-PostPoSHScriptExtraParameters @{ examplename="value" })
    #You can use the argument in this script by specifying the $RemainingArguments.examplename variable ('examplename' can be any name, an more than one )

    #>

    
} catch {
    Write-ToLogFile -E -C $LogComponentName -M "Caught an error, $($_.Exception.Message)"
    Write-ToLogFile -D -B "Full Error Details    :`r`n$( Get-ExceptionDetails $_ )"
    $exitCode = 1
}
Write-ToLogFile -D -C $LogComponentName -M "Exiting with EXITCODE: $exitCode"
exit $exitCode
