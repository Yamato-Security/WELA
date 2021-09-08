# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "ParentImage.*.*\regsvr32.exe" -and  -not (($_.message -match "CommandLine.*.*.dll.*" -or $_.message -match "CommandLine.*.*.ocx.*" -or $_.message -match "CommandLine.*.*.cpl.*" -or $_.message -match "CommandLine.*.*.ax.*" -or $_.message -match "CommandLine.*.*.bav.*" -or $_.message -match "CommandLine.*.*.ppl.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_regsvr32_no_dll";
    $detectedMessage = "Detects a regsvr.exe execution that doesn't contain a DLL in the command line";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and $_.message -match "ParentImage.*.*\regsvr32.exe" -and -not (($_.message -match "CommandLine.*.*.dll.*" -or $_.message -match "CommandLine.*.*.ocx.*" -or $_.message -match "CommandLine.*.*.cpl.*" -or $_.message -match "CommandLine.*.*.ax.*" -or $_.message -match "CommandLine.*.*.bav.*" -or $_.message -match "CommandLine.*.*.ppl.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
