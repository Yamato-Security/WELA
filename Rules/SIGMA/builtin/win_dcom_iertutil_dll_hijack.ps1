# Get-WinEvent -LogName Security | where {(($_.ID -eq "5145" -and $_.message -match "RelativeTargetName.*.*\Internet Explorer\iertutil.dll") -and  -not ($_.message -match "SubjectUserName.*.*$")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_dcom_iertutil_dll_hijack";
    $detectedMessage = "Detects a threat actor creating a file named `iertutil.dll` in the `C:Program FilesInternet Explorer` directory over the network for a DCOM InternetExplorer DLL Hijack scenario.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "5145" -and $_.message -match "RelativeTargetName.*.*\Internet Explorer\iertutil.dll") -and -not ($_.message -match "SubjectUserName.*.*$")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
