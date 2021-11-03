# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\CreateMiniDump.exe" -or $_.message -match "Imphash.*4a07f944a83e8a7c2525efa35dd30e2f")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\lsass.dmp") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message

function Add-Rule {

    $ruleName = "win_hktl_createminidump";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_hktl_createminidump";
            $detectedMessage = "Detects the use of CreateMiniDump hack tool used to dump the LSASS process memory for credential extraction on the attacker's machine";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\CreateMiniDump.exe" -or $_.message -match "Imphash.*4a07f944a83e8a7c2525efa35dd30e2f")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*\\lsass.dmp") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            
            foreach ($result in $results) {
                if ($result -and $result.Count -ne 0) {
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;    
                    Write-Output $result;
                    Write-Output ""; 
                }
            }
        }
        . Search-DetectableEvents $args;
    };
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
