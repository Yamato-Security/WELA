# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.* -name IEHarden " -and $_.message -match "CommandLine.*.* -value 0 ") -or ($_.message -match "CommandLine.*.* -name DEPOff " -and $_.message -match "CommandLine.*.* -value 1 ") -or ($_.message -match "CommandLine.*.* -name DisableFirstRunCustomize " -and $_.message -match "CommandLine.*.* -value 2 "))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_disable_ie_features";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_disable_ie_features";
            $detectedMessage = "Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.* -name IEHarden " -and $_.message -match "CommandLine.*.* -value 0 ") -or ($_.message -match "CommandLine.*.* -name DEPOff " -and $_.message -match "CommandLine.*.* -value 1 ") -or ($_.message -match "CommandLine.*.* -name DisableFirstRunCustomize " -and $_.message -match "CommandLine.*.* -value 2 "))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
