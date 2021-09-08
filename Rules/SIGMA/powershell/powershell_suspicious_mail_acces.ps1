# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Get-Inbox.ps1.*" -or $_.message -match "ScriptBlockText.*.*Microsoft.Office.Interop.Outlook.*" -or $_.message -match "ScriptBlockText.*.*Microsoft.Office.Interop.Outlook.olDefaultFolders.*" -or $_.message -match "ScriptBlockText.*.*-comobject outlook.application.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "powershell_suspicious_mail_acces";
    $detectedMessage = "Adversaries may target user email on local systems to collect sensitive information. Files containing email data can be acquired from a user’s local system, such as Outlook storage or cache files. ";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Get-Inbox.ps1.*" -or $_.message -match "ScriptBlockText.*.*Microsoft.Office.Interop.Outlook.*" -or $_.message -match "ScriptBlockText.*.*Microsoft.Office.Interop.Outlook.olDefaultFolders.*" -or $_.message -match "ScriptBlockText.*.*-comobject outlook.application.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
