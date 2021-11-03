# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Get-Inbox.ps1" -or $_.message -match "ScriptBlockText.*.*Microsoft.Office.Interop.Outlook" -or $_.message -match "ScriptBlockText.*.*Microsoft.Office.Interop.Outlook.olDefaultFolders" -or $_.message -match "ScriptBlockText.*.*-comobject outlook.application")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_suspicious_mail_acces";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_suspicious_mail_acces";
            $detectedMessage = "Adversaries may target user email on local systems to collect sensitive information. Files containing email data can be acquired from a user’s local system, such as Outlook storage or cache files. ";
            $result = $event |  where { ($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Get-Inbox.ps1" -or $_.message -match "ScriptBlockText.*.*Microsoft.Office.Interop.Outlook" -or $_.message -match "ScriptBlockText.*.*Microsoft.Office.Interop.Outlook.olDefaultFolders" -or $_.message -match "ScriptBlockText.*.*-comobject outlook.application")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
