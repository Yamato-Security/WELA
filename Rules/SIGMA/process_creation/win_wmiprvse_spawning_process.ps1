# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\WmiPrvSe.exe" -and  -not (($_.message -match "0x3e7" -or $_.message -match "null") -or ($_.message -match "0x3e7" -or $_.message -match "null") -or $_.message -match "User.*NT AUTHORITY\\SYSTEM" -or ($_.message -match "Image.*.*\\WmiPrvSE.exe" -or $_.message -match "Image.*.*\\WerFault.exe"))) -and  -not (-not LogonId="*")) -and  -not (-not SubjectLogonId="*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_wmiprvse_spawning_process";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_wmiprvse_spawning_process";
            $detectedMessage = "Detects wmiprvse spawning processes";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\WmiPrvSe.exe" -and -not (($_.message -match "0x3e7" -or $_.message -match "null") -or ($_.message -match "0x3e7" -or $_.message -match "null") -or $_.message -match "User.*NT AUTHORITY\\SYSTEM" -or ($_.message -match "Image.*.*\\WmiPrvSE.exe" -or $_.message -match "Image.*.*\\WerFault.exe"))) -and -not (-not $_.message -match "LogonId")) -and -not (-not $_.message -match "SubjectLogonId")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
