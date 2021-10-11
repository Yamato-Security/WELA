# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\AppData\Local\Temp\SAM-.*" -and $_.message -match "TargetFilename.*.*.dmp.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_quarkspw_filedump";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_quarkspw_filedump";
            $detectedMessage = "Detects a dump file written by QuarksPwDump password dumper";
            $result = $event |  where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\AppData\\Local\\Temp\\SAM-.*" -and $_.message -match "TargetFilename.*.*.dmp.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
