# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*delete.*" -and ((($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\wmic.exe" -or $_.message -match "Image.*.*\\vssadmin.exe" -or $_.message -match "Image.*.*\\diskshadow.exe") -and $_.message -match "CommandLine.*.*shadow.*") -or (($_.message -match "Image.*.*\\wbadmin.exe") -and $_.message -match "CommandLine.*.*catalog.*" -and $_.message -match "CommandLine.*.*quiet.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_shadow_copies_deletion";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_shadow_copies_deletion";
            $detectedMessage = "Shadow Copies deletion using operating systems utilities";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*delete.*" -and ((($_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\wmic.exe" -or $_.message -match "Image.*.*\\vssadmin.exe" -or $_.message -match "Image.*.*\\diskshadow.exe") -and $_.message -match "CommandLine.*.*shadow.*") -or (($_.message -match "Image.*.*\\wbadmin.exe") -and $_.message -match "CommandLine.*.*catalog.*" -and $_.message -match "CommandLine.*.*quiet.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
