# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Imphash.*09D278F9DE118EF09163C6140255C690") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*C:\\Windows\\Temp\\dumpert.dmp") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_hack_dumpert";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "sysmon_hack_dumpert";
            $detectedMessage = "Detects the use of Dumpert process dumper, which dumps the lsass.exe process memory";
            $results = @();
            $results += $event | where { ($_.ID -eq "1" -and $_.message -match "Imphash.*09D278F9DE118EF09163C6140255C690") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*C:\\Windows\\Temp\\dumpert.dmp") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $detectedMessage;    
                    Write-Host $result;
                    Write-Host
                }
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
