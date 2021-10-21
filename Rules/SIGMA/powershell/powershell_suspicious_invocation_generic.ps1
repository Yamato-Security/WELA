# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match " -enc " -or $_.message -match " -EncodedCommand ") -and ($_.message -match " -w hidden " -or $_.message -match " -window hidden " -or $_.message -match " -windowstyle hidden ") -and ($_.message -match " -noni " -or $_.message -match " -noninteractive ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_suspicious_invocation_generic";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_suspicious_invocation_generic";
            $detectedMessage = "Detects suspicious PowerShell invocation command parameters";
            $result = $event |  where { (($_.message -match " -enc " -or $_.message -match " -EncodedCommand ") -and ($_.message -match " -w hidden " -or $_.message -match " -window hidden " -or $_.message -match " -windowstyle hidden ") -and ($_.message -match " -noni " -or $_.message -match " -noninteractive ")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
