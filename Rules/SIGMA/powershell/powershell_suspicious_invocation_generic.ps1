# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match " -enc " -or $_.message -match " -EncodedCommand ") -and ($_.message -match " -w hidden " -or $_.message -match " -window hidden " -or $_.message -match " -windowstyle hidden ") -and ($_.message -match " -noni " -or $_.message -match " -noninteractive ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_suspicious_invocation_generic";
    $detectedMessage = "Detects suspicious PowerShell invocation command parameters";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.message -match " -enc " -or $_.message -match " -EncodedCommand ") -and ($_.message -match " -w hidden " -or $_.message -match " -window hidden " -or $_.message -match " -windowstyle hidden ") -and ($_.message -match " -noni " -or $_.message -match " -noninteractive ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
