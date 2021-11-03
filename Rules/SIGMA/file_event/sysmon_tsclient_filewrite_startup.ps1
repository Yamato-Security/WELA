# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "Image.*.*\mstsc.exe" -and $_.message -match "TargetFilename.*.*\Microsoft\Windows\Start Menu\Programs\Startup\") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_tsclient_filewrite_startup";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_tsclient_filewrite_startup";
            $detectedMessage = "Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder";
            $result = $event |  where { ($_.ID -eq "11" -and $_.message -match "Image.*.*\\mstsc.exe" -and $_.message -match "TargetFilename.*.*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
