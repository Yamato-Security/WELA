# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*Invoke-WMIMethod win32_process -name create -argumentlist" -and $_.message -match "CommandLine.*.*rundll32 c:\windows") -or ($_.message -match "CommandLine.*.*wmic /node:" -and $_.message -match "CommandLine.*.*process call create "rundll32 c:\windows"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_unc2452_ps";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_unc2452_ps";
            $detectedMessage = "Detects a specific PowerShell command line pattern used by the UNC2452 actors as mentioned in Microsoft and Symantec reports";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*Invoke-WMIMethod win32_process -name create -argumentlist" -and $_.message -match "CommandLine.*.*rundll32 c:\\windows") -or ($_.message -match "CommandLine.*.*wmic /node:" -and $_.message -match "CommandLine.*.*process call create ""rundll32 c:\\windows"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
