# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "ParentImage.*.*\\regsvr32.exe" -and  -not (($_.message -match "CommandLine.*.*.dll" -or $_.message -match "CommandLine.*.*.ocx" -or $_.message -match "CommandLine.*.*.cpl" -or $_.message -match "CommandLine.*.*.ax" -or $_.message -match "CommandLine.*.*.bav" -or $_.message -match "CommandLine.*.*.ppl"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_regsvr32_no_dll";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_regsvr32_no_dll";
            $detectedMessage = "Detects a regsvr.exe execution that doesn't contain a DLL in the command line";
            $result = $event |  where { (($_.ID -eq "1") -and $_.message -match "ParentImage.*.*\\regsvr32.exe" -and -not (($_.message -match "CommandLine.*.*.dll" -or $_.message -match "CommandLine.*.*.ocx" -or $_.message -match "CommandLine.*.*.cpl" -or $_.message -match "CommandLine.*.*.ax" -or $_.message -match "CommandLine.*.*.bav" -or $_.message -match "CommandLine.*.*.ppl"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
