# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "11" -and $_.message -match "Image.*System" -and $_.message -match "TargetFilename.*.*\Internet Explorer\iertutil.dll") -or ($_.ID -eq "7" -and $_.message -match "Image.*.*\Internet Explorer\iexplore.exe" -and $_.message -match "ImageLoaded.*.*\Internet Explorer\iertutil.dll"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_dcom_iertutil_dll_hijack";
    $detectedMessage = "Detects a threat actor creating a file named `iertutil.dll` in the `C:Program FilesInternet Explorer` directory over the network and loading it for a DCOM InternetExplorer DLL Hijack scenario.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ((($_.ID -eq "11" -and $_.message -match "Image.*System" -and $_.message -match "TargetFilename.*.*\Internet Explorer\iertutil.dll") -or ($_.ID -eq "7" -and $_.message -match "Image.*.*\Internet Explorer\iexplore.exe" -and $_.message -match "ImageLoaded.*.*\Internet Explorer\iertutil.dll"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
