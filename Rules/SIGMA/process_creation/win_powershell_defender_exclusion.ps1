# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.ID -eq "1" -and $_.message -match "CommandLine.*.*Add-MpPreference .*" -and ($_.message -match "CommandLine.*.* -ExclusionPath .*" -or $_.message -match "CommandLine.*.* -ExclusionExtension .*" -or $_.message -match "CommandLine.*.* -ExclusionProcess .*")) -or ($_.message -match "CommandLine.*.*QWRkLU1wUHJlZmVyZW5jZ.*" -or $_.message -match "CommandLine.*.*FkZC1NcFByZWZlcmVuY2.*" -or $_.message -match "CommandLine.*.*BZGQtTXBQcmVmZXJlbmNl.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_powershell_defender_exclusion";
    $detectedMessage = "Detects requests to exclude files, folders or processes from Antivirus scanning using PowerShell cmdlets";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.ID -eq "1" -and $_.message -match "CommandLine.*.*Add-MpPreference .*" -and ($_.message -match "CommandLine.*.* -ExclusionPath .*" -or $_.message -match "CommandLine.*.* -ExclusionExtension .*" -or $_.message -match "CommandLine.*.* -ExclusionProcess .*")) -or ($_.message -match "CommandLine.*.*QWRkLU1wUHJlZmVyZW5jZ.*" -or $_.message -match "CommandLine.*.*FkZC1NcFByZWZlcmVuY2.*" -or $_.message -match "CommandLine.*.*BZGQtTXBQcmVmZXJlbmNl.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
