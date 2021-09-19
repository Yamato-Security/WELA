# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7") -and ($_.message -match "Description.*System.Management.Automation" -and $_.message -match "ImageLoaded.*.*System.Management.Automation.*") -and  -not ($_.message -match "Image.*.*\powershell.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_alternate_powershell_hosts_moduleload";
    $detectedMessage = "Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "7") -and ($_.message -match "Description.*System.Management.Automation" -and $_.message -match "ImageLoaded.*.*System.Management.Automation.*") -and -not ($_.message -match "Image.*.*\powershell.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
