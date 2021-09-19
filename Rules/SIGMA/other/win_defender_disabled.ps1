# Get-WinEvent -LogName Microsoft-Windows-Windows Defender/Operational | where { ((($_.ID -eq "5001" -or $_.ID -eq "5010" -or $_.ID -eq "5012" -or $_.ID -eq "5101") -or (($_.message -match "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" -or $_.message -match "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender" -or $_.message -match "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender") -and $_.message -match "Details.*DWORD (0x00000001)"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "EventType.*SetValue" -and $_.message -match "TargetObject.*HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware" -and $_.message -match "Details.*DWORD (0x00000001)") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "7036" -and $_.message -match "Message.*The Windows Defender Antivirus Service service entered the stopped state") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_defender_disabled";
    $detectedMessage = "Detects disabling Windows Defender threat protection";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $results = @();
            $results += $event | where { ((($_.ID -eq "5001" -or $_.ID -eq "5010" -or $_.ID -eq "5012" -or $_.ID -eq "5101") -or (($_.message -match "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" -or $_.message -match "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender" -or $_.message -match "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender") -and $_.message -match "Details.*DWORD (0x00000001)"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "EventType.*SetValue" -and $_.message -match "TargetObject.*HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware" -and $_.message -match "Details.*DWORD (0x00000001)") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "7036" -and $_.message -match "Message.*The Windows Defender Antivirus Service service entered the stopped state") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
