# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "OriginalFileName.*7z.*.exe" -or $_.message -match "OriginalFileName.*.*rar.exe" -or $_.message -match "OriginalFileName.*.*Command.*Line.*RAR") -and ($_.message -match "CommandLine.*.* -p" -or $_.message -match "CommandLine.*.* -ta" -or $_.message -match "CommandLine.*.* -tb" -or $_.message -match "CommandLine.*.* -sdel" -or $_.message -match "CommandLine.*.* -dw" -or $_.message -match "CommandLine.*.* -hp")) -and  -not ($_.message -match "ParentImage.*C:\\Program")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_compression_params";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_compression_params";
            $detectedMessage = "Detects suspicious command line arguments of common data compression tools";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "OriginalFileName.*7z.*.exe" -or $_.message -match "OriginalFileName.*.*rar.exe" -or $_.message -match "OriginalFileName.*.*Command.*Line.*RAR") -and ($_.message -match "CommandLine.*.* -p" -or $_.message -match "CommandLine.*.* -ta" -or $_.message -match "CommandLine.*.* -tb" -or $_.message -match "CommandLine.*.* -sdel" -or $_.message -match "CommandLine.*.* -dw" -or $_.message -match "CommandLine.*.* -hp")) -and -not ($_.message -match "ParentImage.*C:\\Program")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
