# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.* -name IEHarden .*" -and $_.message -match "CommandLine.*.* -value 0 .*") -or ($_.message -match "CommandLine.*.* -name DEPOff .*" -and $_.message -match "CommandLine.*.* -value 1 .*") -or ($_.message -match "CommandLine.*.* -name DisableFirstRunCustomize .*" -and $_.message -match "CommandLine.*.* -value 2 .*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_susp_disable_ie_features";
    $detectedMessage = "Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.* -name IEHarden .*" -and $_.message -match "CommandLine.*.* -value 0 .*") -or ($_.message -match "CommandLine.*.* -name DEPOff .*" -and $_.message -match "CommandLine.*.* -value 1 .*") -or ($_.message -match "CommandLine.*.* -name DisableFirstRunCustomize .*" -and $_.message -match "CommandLine.*.* -value 2 .*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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