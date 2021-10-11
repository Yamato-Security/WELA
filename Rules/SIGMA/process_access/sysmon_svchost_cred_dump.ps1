# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "10") -and ($_.message -match "TargetImage.*.*\svchost.exe" -and $_.message -match "GrantedAccess.*0x143a") -and  -not (($_.message -match "SourceImage.*.*\services.exe" -or $_.message -match "SourceImage.*.*\msiexec.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_svchost_cred_dump";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_svchost_cred_dump";
            $detectedMessage = "Detects when a process, such as mimikatz, accesses the memory of svchost to dump credentials";
            $result = $event |  where { (($_.ID -eq "10") -and ($_.message -match "TargetImage.*.*\\svchost.exe" -and $_.message -match "GrantedAccess.*0x143a") -and -not (($_.message -match "SourceImage.*.*\\services.exe" -or $_.message -match "SourceImage.*.*\\msiexec.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
