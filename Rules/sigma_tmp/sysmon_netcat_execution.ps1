# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\ncat.exe") -or ($_.message -match "CommandLine.*.* -lvp .*" -or $_.message -match "CommandLine.*.* -l --proxy-type http .*" -or $_.message -match "CommandLine.*.* --exec cmd.exe .*" -or $_.message -match "CommandLine.*.* -vnl --exec .*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_netcat_execution";
    $detectedMessage = "Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\ncat.exe") -or ($_.message -match "CommandLine.*.* -lvp .*" -or $_.message -match "CommandLine.*.* -l --proxy-type http .*" -or $_.message -match "CommandLine.*.* --exec cmd.exe .*" -or $_.message -match "CommandLine.*.* -vnl --exec .*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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