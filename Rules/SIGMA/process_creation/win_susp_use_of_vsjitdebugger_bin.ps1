# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "ParentImage.*.*\\vsjitdebugger.exe" -and  -not ((($_.ID -eq "1") -and ($_.message -match "Image.*.*\\vsimmersiveactivatehelper.*.exe" -or $_.message -match "Image.*.*\\devenv.exe")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_use_of_vsjitdebugger_bin";
    $detectedMessage = "There is an option for a MS VS Just-In-Time Debugger ""vsjitdebugger.exe"" to launch specified executable and attach a debugger. This option may be used adversaries to execute malicious code by signed verified binary. The debugger is installed alongside with Microsoft Visual Studio package.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and $_.message -match "ParentImage.*.*\\vsjitdebugger.exe" -and -not ((($_.ID -eq "1") -and ($_.message -match "Image.*.*\\vsimmersiveactivatehelper.*.exe" -or $_.message -match "Image.*.*\\devenv.exe")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
