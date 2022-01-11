Extra scripts.

To use these scripts add the following parameter to your commandline:
c:\PathTo\GenLeCertForNS.ps1 ... -PostPoSHScriptFilename "c:\PathTo\script.ps1"

Additionally you can add your own extra parameters (input) to your script.

c:\PathTo\GenLeCertForNS.ps1 ... -PostPoSHScriptFilename "c:\PathTo\script.ps1" -PostPoSHScriptExtraParameters @{ Param1="Param1Value"; Param2="Param2Value" }

If you are using a json file add the lines to your json config (make sure each entry in the same section ends with a comma except the last entry).

"PostPoSHScriptExtraParameters":  {
        "IISSiteName": "Default Web Site",
        "Param2": "Param2Value"
    },
"PostPoSHScriptFilename":  "C:\\PathTo\\script.ps1"

NOTE: Validate the json-file using a formatter tool for example.

scripts:

001. UpdateRemoteAccessCertificate.ps1 - Update a Certificate for Remote Access
     - Script Parameter => -PostPoSHScriptFilename "c:\PathTo\UpdateRemoteAccessCertificate.ps1"
     - JSON file, "certrequests" section (add comma ',' to current line to add entry):
"PostPoSHScriptFilename":  "C:\\PathTo\\UpdateRemoteAccessCertificate.ps1"

002. UpdateIIS.ps1 - Update IIS certificate (and binding)
     - Script Parameter =>  -PostPoSHScriptFilename "c:\PathTo\UpdateIIS.ps1" -PostPoSHScriptExtraParameters @{ IISSiteName="Default Web Site" }
     - JSON file, "certrequests" section (add comma ',' to current line to add entry):
"PostPoSHScriptFilename":  "C:\\PathTo\\UpdateIIS.ps1",
"PostPoSHScriptExtraParameters":  {
        "IISSiteName":  "Default Web Site"
    }
