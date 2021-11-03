# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\print.exe") -and ($_.message -match "CommandLine.*print") -and ($_.message -match "CommandLine.*.*/D") -and ($_.message -match "CommandLine.*.*.exe")) -and  -not (($_.message -match "CommandLine.*.*print.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_print";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_print";
            $detectedMessage = "Attackers can use print.exe for remote file copy";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\print.exe") -and ($_.message -match "CommandLine.*print") -and ($_.message -match "CommandLine.*.*/D") -and ($_.message -match "CommandLine.*.*.exe")) -and -not (($_.message -match "CommandLine.*.*print.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
