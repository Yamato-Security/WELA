# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*reg.exe save hklm\sam %temp%\~reg_sam.save.*" -or $_.message -match "CommandLine.*.*1q2w3e4r@#$@#$@#$.*" -or $_.message -match "CommandLine.*.* -hp1q2w3e4 .*" -or $_.message -match "CommandLine.*.*.dat data03 10000 -p .*") -or ($_.message -match "CommandLine.*.*process call create.*" -and $_.message -match "CommandLine.*.* > %temp%\~.*") -or ($_.message -match "CommandLine.*.*netstat -aon | find .*" -and $_.message -match "CommandLine.*.* > %temp%\~.*") -or ($_.message -match "CommandLine.*.*.255 10 C:\ProgramData\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_lazarus_activity_dec20";
    $detectedMessage = "Detects different process creation events as described in various threat reports on Lazarus group activity";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*reg.exe save hklm\\sam %temp%\\~reg_sam.save.*" -or $_.message -match "CommandLine.*.*1q2w3e4r@#$@#$@#$.*" -or $_.message -match "CommandLine.*.* -hp1q2w3e4 .*" -or $_.message -match "CommandLine.*.*.dat data03 10000 -p .*") -or ($_.message -match "CommandLine.*.*process call create.*" -and $_.message -match "CommandLine.*.* > %temp%\\~.*") -or ($_.message -match "CommandLine.*.*netstat -aon | find .*" -and $_.message -match "CommandLine.*.* > %temp%\\~.*") -or ($_.message -match "CommandLine.*.*.255 10 C:\\ProgramData\\.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
