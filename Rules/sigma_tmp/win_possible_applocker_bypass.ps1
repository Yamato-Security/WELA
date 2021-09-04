# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*\msdt.exe.*" -or $_.message -match "CommandLine.*.*\installutil.exe.*" -or $_.message -match "CommandLine.*.*\regsvcs.exe.*" -or $_.message -match "CommandLine.*.*\regasm.exe.*" -or $_.message -match "CommandLine.*.*\msbuild.exe.*" -or $_.message -match "CommandLine.*.*\ieexec.exe.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_possible_applocker_bypass";
    $detectedMessage = "Detects execution of executables that can be used to bypass Applocker whitelisting"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*\msdt.exe.*" -or $_.message -match "CommandLine.*.*\installutil.exe.*" -or $_.message -match "CommandLine.*.*\regsvcs.exe.*" -or $_.message -match "CommandLine.*.*\regasm.exe.*" -or $_.message -match "CommandLine.*.*\msbuild.exe.*" -or $_.message -match "CommandLine.*.*\ieexec.exe.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
