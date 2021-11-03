# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "net group "domain admins" /domain" -or $_.message -match "net localgroup administrators" -or $_.message -match "net group "enterprise admins" /domain")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_recon_activity";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_recon_activity";
            $detectedMessage = "Detects suspicious command line activity on Windows systems";
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "net group ""domain admins"" /domain" -or $_.message -match "net localgroup administrators" -or $_.message -match "net group ""enterprise admins"" /domain")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
