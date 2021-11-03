# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Description.*System.Management.Automation" -and $_.message -match "ImageLoaded.*.*System.Management.Automation") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_powershell_execution_moduleload";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_powershell_execution_moduleload";
            $detectedMessage = "Detects execution of PowerShell";
            $result = $event |  where { ($_.ID -eq "7" -and $_.message -match "Description.*System.Management.Automation" -and $_.message -match "ImageLoaded.*.*System.Management.Automation") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
