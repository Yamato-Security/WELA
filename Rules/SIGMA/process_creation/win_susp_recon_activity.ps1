# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "net group "domain admins" /domain" -or $_.message -match "net localgroup administrators" -or $_.message -match "net group "enterprise admins" /domain")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_recon_activity";
    $detectedMessage = "Detects suspicious command line activity on Windows systems";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "net group ""domain admins"" /domain" -or $_.message -match "net localgroup administrators" -or $_.message -match "net group ""enterprise admins"" /domain")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
