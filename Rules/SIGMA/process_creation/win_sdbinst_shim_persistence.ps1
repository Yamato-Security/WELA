# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\sdbinst.exe") -and ($_.message -match "CommandLine.*.*.sdb.*")) -and  -not (($_.message -match "CommandLine.*.*iisexpressshim.sdb.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_sdbinst_shim_persistence";
    $detectedMessage = "Detects installation of a new shim using sdbinst.exe. A shim can be used to load malicious DLLs into applications.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\sdbinst.exe") -and ($_.message -match "CommandLine.*.*.sdb.*")) -and -not (($_.message -match "CommandLine.*.*iisexpressshim.sdb.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
