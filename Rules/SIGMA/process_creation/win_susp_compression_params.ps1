# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "OriginalFileName.*7z.*.exe" -or $_.message -match "OriginalFileName.*.*rar.exe" -or $_.message -match "OriginalFileName.*.*Command.*Line.*RAR.*") -and ($_.message -match "CommandLine.*.* -p.*" -or $_.message -match "CommandLine.*.* -ta.*" -or $_.message -match "CommandLine.*.* -tb.*" -or $_.message -match "CommandLine.*.* -sdel.*" -or $_.message -match "CommandLine.*.* -dw.*" -or $_.message -match "CommandLine.*.* -hp.*")) -and  -not ($_.message -match "ParentImage.*C:\Program.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_compression_params";
    $detectedMessage = "Detects suspicious command line arguments of common data compression tools";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "OriginalFileName.*7z.*.exe" -or $_.message -match "OriginalFileName.*.*rar.exe" -or $_.message -match "OriginalFileName.*.*Command.*Line.*RAR.*") -and ($_.message -match "CommandLine.*.* -p.*" -or $_.message -match "CommandLine.*.* -ta.*" -or $_.message -match "CommandLine.*.* -tb.*" -or $_.message -match "CommandLine.*.* -sdel.*" -or $_.message -match "CommandLine.*.* -dw.*" -or $_.message -match "CommandLine.*.* -hp.*")) -and -not ($_.message -match "ParentImage.*C:\Program.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
