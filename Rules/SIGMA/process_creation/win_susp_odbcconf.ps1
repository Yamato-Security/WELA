# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\odbcconf.exe" -and ($_.message -match "CommandLine.*.*-f" -or $_.message -match "CommandLine.*.*regsvr")) -or ($_.message -match "ParentImage.*.*\\odbcconf.exe" -and $_.message -match "Image.*.*\\rundll32.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_odbcconf";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_susp_odbcconf";
                    $detectedMessage = "Detects defence evasion attempt via odbcconf.exe execution to load DLL";
                $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\odbcconf.exe" -and ($_.message -match "CommandLine.*.*-f" -or $_.message -match "CommandLine.*.*regsvr")) -or ($_.message -match "ParentImage.*.*\\odbcconf.exe" -and $_.message -match "Image.*.*\\rundll32.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
