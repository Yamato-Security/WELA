# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\sc.exe") -and $_.message -match "CommandLine.*.*sdset" -and $_.message -match "CommandLine.*.*D;;" -and ($_.message -match "CommandLine.*.*;;;IU" -or $_.message -match "CommandLine.*.*;;;SU" -or $_.message -match "CommandLine.*.*;;;BA" -or $_.message -match "CommandLine.*.*;;;SY" -or $_.message -match "CommandLine.*.*;;;WD")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_service_dacl_modification";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_service_dacl_modification";
            $detectedMessage = "Detects suspicious DACL modifications that can  be used to hide services or make them unstopable";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\sc.exe") -and $_.message -match "CommandLine.*.*sdset" -and $_.message -match "CommandLine.*.*D;;" -and ($_.message -match "CommandLine.*.*;;;IU" -or $_.message -match "CommandLine.*.*;;;SU" -or $_.message -match "CommandLine.*.*;;;BA" -or $_.message -match "CommandLine.*.*;;;SY" -or $_.message -match "CommandLine.*.*;;;WD")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
