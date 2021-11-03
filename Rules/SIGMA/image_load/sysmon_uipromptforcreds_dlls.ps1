# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7") -and (($_.message -match "ImageLoaded.*.*\credui.dll" -or $_.message -match "ImageLoaded.*.*\wincredui.dll") -or ($_.message -match "credui.dll" -or $_.message -match "wincredui.dll"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_uipromptforcreds_dlls";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_uipromptforcreds_dlls";
            $detectedMessage = "Detects potential use of UIPromptForCredentials functions by looking for some of the DLLs needed for it.";
            $result = $event |  where { (($_.ID -eq "7") -and (($_.message -match "ImageLoaded.*.*\\credui.dll" -or $_.message -match "ImageLoaded.*.*\\wincredui.dll") -or ($_.message -match "credui.dll" -or $_.message -match "wincredui.dll"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
