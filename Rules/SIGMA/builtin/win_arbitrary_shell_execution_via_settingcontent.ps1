# Get-WinEvent -LogName Security | where {($_.message -match "CommandLine.*.*.SettingContent-ms.*" -and  -not (($_.message -match "FilePath.*.*immersivecontrolpanel.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_arbitrary_shell_execution_via_settingcontent";
    $detectedMessage = "The .SettingContent-ms file type was introduced in Windows 10 and allows a user to create ""shortcuts"" to various Windows 10 setting pages. These files are simply XML and contain paths to various Windows 10 settings binaries.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.message -match "CommandLine.*.*.SettingContent-ms.*" -and -not (($_.message -match "FilePath.*.*immersivecontrolpanel.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
