# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\sdbinst.exe") -and ($_.message -match "CommandLine.*.*.sdb")) -and  -not (($_.message -match "CommandLine.*.*iisexpressshim.sdb"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_sdbinst_shim_persistence";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_sdbinst_shim_persistence";
                    $detectedMessage = "Detects installation of a new shim using sdbinst.exe. A shim can be used to load malicious DLLs into applications.";
                $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\sdbinst.exe") -and ($_.message -match "CommandLine.*.*.sdb")) -and -not (($_.message -match "CommandLine.*.*iisexpressshim.sdb"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
