# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\CreateMiniDump.exe.*" -or $_.message -match "Imphash.*4a07f944a83e8a7c2525efa35dd30e2f")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\lsass.dmp") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_hktl_createminidump";
    $detectedMessage = "Detects the use of CreateMiniDump hack tool used to dump the LSASS process memory for credential extraction on the attacker's machine";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $results = @();
            $results += $event | where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\CreateMiniDump.exe.*" -or $_.message -match "Imphash.*4a07f944a83e8a7c2525efa35dd30e2f")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\lsass.dmp") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }
        }
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}