# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" -or $_.message -match "HKEY_LOCAL_MACHINE\Software\Microsoft\Office test\Special\Perf")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_office_test_regadd";
    $detectedMessage = "Detects the addition of office test registry that allows a user to specify an arbitrary DLL that will be executed everytime an Office application is started"

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and ($_.message -match "HKEY_CURRENT_USER\Software\Microsoft\Office test\Special\Perf" -or $_.message -match "HKEY_LOCAL_MACHINE\Software\Microsoft\Office test\Special\Perf")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
