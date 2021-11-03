# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "3" -and $_.message -match "ParentImage.*.*\msbuild.exe" -and ($_.message -match "80" -or $_.message -match "443") -and $_.message -match "Initiated.*true") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "silenttrinity_stager_msbuild_activity";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "silenttrinity_stager_msbuild_activity";
            $detectedMessage = "Detects a possible remote connections to Silenttrinity c2";
            $result = $event |  where { ($_.ID -eq "3" -and $_.message -match "ParentImage.*.*\\msbuild.exe" -and ($_.message -match "80" -or $_.message -match "443") -and $_.message -match "Initiated.*true") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
