# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update).*" -or $_.message -match "CommandLine.*.* -NoP -NonI -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update);.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_powershell_empire_uac_bypass";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_powershell_empire_uac_bypass";
            $detectedMessage = "Detects some Empire PowerShell UAC bypass methods";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update).*" -or $_.message -match "CommandLine.*.* -NoP -NonI -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update);.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
