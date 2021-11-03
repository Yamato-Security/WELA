# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*objectcategory" -or $_.message -match "CommandLine.*.*trustdmp" -or $_.message -match "CommandLine.*.*dcmodes" -or $_.message -match "CommandLine.*.*dclist" -or $_.message -match "CommandLine.*.*computers_pwdnotreqd") -and $_.message -match "Image.*.*\\adfind.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_adfind";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_susp_adfind";
                    $detectedMessage = "Detects the execution of a AdFind for Active Directory enumeration ";
                $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*objectcategory" -or $_.message -match "CommandLine.*.*trustdmp" -or $_.message -match "CommandLine.*.*dcmodes" -or $_.message -match "CommandLine.*.*dclist" -or $_.message -match "CommandLine.*.*computers_pwdnotreqd") -and $_.message -match "Image.*.*\\adfind.exe") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
