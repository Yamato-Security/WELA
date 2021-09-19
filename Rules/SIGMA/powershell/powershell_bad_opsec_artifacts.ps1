# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {((($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*$DoIt.*" -or $_.message -match "ScriptBlockText.*.*harmj0y.*" -or $_.message -match "ScriptBlockText.*.*mattifestation.*" -or $_.message -match "ScriptBlockText.*.*_RastaMouse.*" -or $_.message -match "ScriptBlockText.*.*tifkin_.*" -or $_.message -match "ScriptBlockText.*.*0xdeadbeef.*")) -or ($_.ID -eq "4103" -and ($_.message -match "Payload.*.*$DoIt.*" -or $_.message -match "Payload.*.*harmj0y.*" -or $_.message -match "Payload.*.*mattifestation.*" -or $_.message -match "Payload.*.*_RastaMouse.*" -or $_.message -match "Payload.*.*tifkin_.*" -or $_.message -match "Payload.*.*0xdeadbeef.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_bad_opsec_artifacts";
    $detectedMessage = "Focuses on trivial artifacts observed in variants of prevalent offensive ps1 payloads, including Cobalt Strike Beacon, PoshC2, Powerview, Letmein, Empire, Powersploit, and other attack payloads that often undergo minimal changes by attackers due to bad opsec.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {((($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*$DoIt.*" -or $_.message -match "ScriptBlockText.*.*harmj0y.*" -or $_.message -match "ScriptBlockText.*.*mattifestation.*" -or $_.message -match "ScriptBlockText.*.*_RastaMouse.*" -or $_.message -match "ScriptBlockText.*.*tifkin_.*" -or $_.message -match "ScriptBlockText.*.*0xdeadbeef.*")) -or ($_.ID -eq "4103" -and ($_.message -match "Payload.*.*$DoIt.*" -or $_.message -match "Payload.*.*harmj0y.*" -or $_.message -match "Payload.*.*mattifestation.*" -or $_.message -match "Payload.*.*_RastaMouse.*" -or $_.message -match "Payload.*.*tifkin_.*" -or $_.message -match "Payload.*.*0xdeadbeef.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
