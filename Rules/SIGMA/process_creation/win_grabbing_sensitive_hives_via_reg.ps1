# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\reg.exe" -and ($_.message -match "CommandLine.*.*save.*" -or $_.message -match "CommandLine.*.*export.*" -or $_.message -match "CommandLine.*.*ˢave.*" -or $_.message -match "CommandLine.*.*eˣport.*") -and ($_.message -match "CommandLine.*.*hklm.*" -or $_.message -match "CommandLine.*.*hk˪m.*" -or $_.message -match "CommandLine.*.*hkey_local_machine.*" -or $_.message -match "CommandLine.*.*hkey_˪ocal_machine.*" -or $_.message -match "CommandLine.*.*hkey_loca˪_machine.*" -or $_.message -match "CommandLine.*.*hkey_˪oca˪_machine.*") -and ($_.message -match "CommandLine.*.*\system" -or $_.message -match "CommandLine.*.*\sam" -or $_.message -match "CommandLine.*.*\security" -or $_.message -match "CommandLine.*.*\ˢystem" -or $_.message -match "CommandLine.*.*\syˢtem" -or $_.message -match "CommandLine.*.*\ˢyˢtem" -or $_.message -match "CommandLine.*.*\ˢam" -or $_.message -match "CommandLine.*.*\ˢecurity")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_grabbing_sensitive_hives_via_reg";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_grabbing_sensitive_hives_via_reg";
            $detectedMessage = "Dump sam, system or security hives using REG.exe utility";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\reg.exe" -and ($_.message -match "CommandLine.*.*save.*" -or $_.message -match "CommandLine.*.*export.*" -or $_.message -match "CommandLine.*.*ˢave.*" -or $_.message -match "CommandLine.*.*eˣport.*") -and ($_.message -match "CommandLine.*.*hklm.*" -or $_.message -match "CommandLine.*.*hk˪m.*" -or $_.message -match "CommandLine.*.*hkey_local_machine.*" -or $_.message -match "CommandLine.*.*hkey_˪ocal_machine.*" -or $_.message -match "CommandLine.*.*hkey_loca˪_machine.*" -or $_.message -match "CommandLine.*.*hkey_˪oca˪_machine.*") -and ($_.message -match "CommandLine.*.*\\system" -or $_.message -match "CommandLine.*.*\\sam" -or $_.message -match "CommandLine.*.*\\security" -or $_.message -match "CommandLine.*.*\\ˢystem" -or $_.message -match "CommandLine.*.*\\syˢtem" -or $_.message -match "CommandLine.*.*\\ˢyˢtem" -or $_.message -match "CommandLine.*.*\\ˢam" -or $_.message -match "CommandLine.*.*\\ˢecurity")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
