# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.ID -eq "1") -and ($_.message -match "ParentImage.*.*\userinit.exe" -and  -not ($_.message -match "Image.*.*\explorer.exe")) -and  -not (($_.message -match "CommandLine.*.*netlogon.bat.*" -or $_.message -match "CommandLine.*.*UsrLogon.cmd.*"))) -or $_.message -match "CommandLine.*.*UserInitMprLogonScript.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_logon_scripts_userinitmprlogonscript_proc";
    $detectedMessage = "Detects creation or execution of UserInitMprLogonScript persistence method"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ((($_.ID -eq "1") -and ($_.message -match "ParentImage.*.*\userinit.exe" -and -not ($_.message -match "Image.*.*\explorer.exe")) -and -not (($_.message -match "CommandLine.*.*netlogon.bat.*" -or $_.message -match "CommandLine.*.*UsrLogon.cmd.*"))) -or $_.message -match "CommandLine.*.*UserInitMprLogonScript.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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