# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.ID -eq "1") -and ($_.message -match "ParentImage.*.*\userinit.exe" -and  -not ($_.message -match "Image.*.*\explorer.exe")) -and  -not (($_.message -match "CommandLine.*.*netlogon.bat" -or $_.message -match "CommandLine.*.*UsrLogon.cmd"))) -or $_.message -match "CommandLine.*.*UserInitMprLogonScript")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_logon_scripts_userinitmprlogonscript_proc";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_logon_scripts_userinitmprlogonscript_proc";
            $detectedMessage = "Detects creation or execution of UserInitMprLogonScript persistence method";
            $result = $event |  where { (($_.ID -eq "1") -and ((($_.ID -eq "1") -and ($_.message -match "ParentImage.*.*\\userinit.exe" -and -not ($_.message -match "Image.*.*\\explorer.exe")) -and -not (($_.message -match "CommandLine.*.*netlogon.bat" -or $_.message -match "CommandLine.*.*UsrLogon.cmd"))) -or $_.message -match "CommandLine.*.*UserInitMprLogonScript")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
