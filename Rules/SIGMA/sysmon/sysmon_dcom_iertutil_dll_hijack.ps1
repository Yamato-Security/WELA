# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "11" -and $_.message -match "Image.*System" -and $_.message -match "TargetFilename.*.*\\Internet Explorer\\iertutil.dll") -or ($_.ID -eq "7" -and $_.message -match "Image.*.*\\Internet Explorer\\iexplore.exe" -and $_.message -match "ImageLoaded.*.*\\Internet Explorer\\iertutil.dll"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_dcom_iertutil_dll_hijack";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_dcom_iertutil_dll_hijack";
            $detectedMessage = "Detects a threat actor creating a file named `iertutil.dll` in the `C:Program FilesInternet Explorer` directory over the network and loading it for a DCOM InternetExplorer DLL Hijack scenario.";
            $result = $event |  where { ((($_.ID -eq "11" -and $_.message -match "Image.*System" -and $_.message -match "TargetFilename.*.*\\Internet Explorer\\iertutil.dll") -or ($_.ID -eq "7" -and $_.message -match "Image.*.*\\Internet Explorer\\iexplore.exe" -and $_.message -match "ImageLoaded.*.*\\Internet Explorer\\iertutil.dll"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
