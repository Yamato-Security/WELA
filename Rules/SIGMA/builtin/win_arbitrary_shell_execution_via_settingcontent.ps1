# Get-WinEvent -LogName Security | where {($_.message -match "CommandLine.*.*.SettingContent-ms" -and  -not (($_.message -match "FilePath.*.*immersivecontrolpanel"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_arbitrary_shell_execution_via_settingcontent";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_arbitrary_shell_execution_via_settingcontent";
            $detectedMessage = "The .SettingContent-ms file type was introduced in Windows 10 and allows a user to create ""shortcuts"" to various Windows 10 setting pages. These files are simply XML and contain paths to various Windows 10 settings binaries.";
            $result = $event |  where { ($_.message -match "CommandLine.*.*.SettingContent-ms" -and -not (($_.message -match "FilePath.*.*immersivecontrolpanel"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
