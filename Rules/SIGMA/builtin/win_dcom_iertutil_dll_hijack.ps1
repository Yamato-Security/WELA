# Get-WinEvent -LogName Security | where {(($_.ID -eq "5145" -and $_.message -match "RelativeTargetName.*.*\Internet Explorer\iertutil.dll") -and  -not ($_.message -match "SubjectUserName.*.*$")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_dcom_iertutil_dll_hijack";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_dcom_iertutil_dll_hijack";
            $detectedMessage = "Detects a threat actor creating a file named `iertutil.dll` in the `C:Program FilesInternet Explorer` directory over the network for a DCOM InternetExplorer DLL Hijack scenario.";
            $result = $event |  where { (($_.ID -eq "5145" -and $_.message -match "RelativeTargetName.*.*\\Internet Explorer\\iertutil.dll") -and -not ($_.message -match "SubjectUserName.*.*$")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result -and $result.Count -ne 0) {
                Write-Output ""; 
                Write-Output "Detected! RuleName:$ruleName";
                Write-Output $detectedMessage;
                Write-Output $result;
                Write-Output ""; 
            }
        };
        . Search-DetectableEvents $args;
    };
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
