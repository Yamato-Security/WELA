# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*-Sta" -and $_.message -match "CommandLine.*.*-Nop" -and $_.message -match "CommandLine.*.*-Window" -and $_.message -match "CommandLine.*.*Hidden" -and ($_.message -match "CommandLine.*.*-Command" -or $_.message -match "CommandLine.*.*-EncodedCommand")) -or ($_.message -match "CommandLine.*.*sv o (New-Object IO.MemorySteam);sv d " -or $_.message -match "CommandLine.*.*mshta file.hta" -or $_.message -match "CommandLine.*.*GruntHTTP" -or $_.message -match "CommandLine.*.*-EncodedCommand cwB2ACAAbwAgA"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_covenant";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_covenant";
            $detectedMessage = "Detects suspicious command lines used in Covenant luanchers";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*-Sta" -and $_.message -match "CommandLine.*.*-Nop" -and $_.message -match "CommandLine.*.*-Window" -and $_.message -match "CommandLine.*.*Hidden" -and ($_.message -match "CommandLine.*.*-Command" -or $_.message -match "CommandLine.*.*-EncodedCommand")) -or ($_.message -match "CommandLine.*.*sv o (New-Object IO.MemorySteam);sv d " -or $_.message -match "CommandLine.*.*mshta file.hta" -or $_.message -match "CommandLine.*.*GruntHTTP" -or $_.message -match "CommandLine.*.*-EncodedCommand cwB2ACAAbwAgA"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
