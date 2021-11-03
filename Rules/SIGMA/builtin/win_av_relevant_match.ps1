# Get-WinEvent -LogName Application | where {(($_.message -match "HTool-" -or $_.message -match "Hacktool" -or $_.message -match "ASP/Backdoor" -or $_.message -match "JSP/Backdoor" -or $_.message -match "PHP/Backdoor" -or $_.message -match "Backdoor.ASP" -or $_.message -match "Backdoor.JSP" -or $_.message -match "Backdoor.PHP" -or $_.message -match "Webshell" -or $_.message -match "Portscan" -or $_.message -match "Mimikatz" -or $_.message -match "WinCred" -or $_.message -match "PlugX" -or $_.message -match "Korplug" -or $_.message -match "Pwdump" -or $_.message -match "Chopper" -or $_.message -match "WmiExec" -or $_.message -match "Xscan" -or $_.message -match "Clearlog" -or $_.message -match "ASPXSpy") -and  -not (($_.message -match "Keygen" -or $_.message -match "Crack"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_av_relevant_match";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_av_relevant_match";
            $detectedMessage = "This detection method points out highly relevant Antivirus events";
            $result = $event | where { (($_.message -match "HTool-" -or $_.message -match "Hacktool" -or $_.message -match "ASP/Backdoor" -or $_.message -match "JSP/Backdoor" -or $_.message -match "PHP/Backdoor" -or $_.message -match "Backdoor.ASP" -or $_.message -match "Backdoor.JSP" -or $_.message -match "Backdoor.PHP" -or $_.message -match "Webshell" -or $_.message -match "Portscan" -or $_.message -match "Mimikatz" -or $_.message -match "WinCred" -or $_.message -match "PlugX" -or $_.message -match "Korplug" -or $_.message -match "Pwdump" -or $_.message -match "Chopper" -or $_.message -match "WmiExec" -or $_.message -match "Xscan" -or $_.message -match "Clearlog" -or $_.message -match "ASPXSpy") -and -not (($_.message -match "Keygen" -or $_.message -match "Crack"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
