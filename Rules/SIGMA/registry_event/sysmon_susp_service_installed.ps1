# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and (($_.message -match "HKLM\\System\\CurrentControlSet\\Services\\NalDrv\\ImagePath" -or $_.message -match "HKLM\\System\\CurrentControlSet\\Services\\PROCEXP152\\ImagePath") -and  -not (($_.message -match "Image.*.*\\procexp64.exe" -or $_.message -match "Image.*.*\\procexp.exe" -or $_.message -match "Image.*.*\\procmon64.exe" -or $_.message -match "Image.*.*\\procmon.exe"))) -and  -not (($_.message -match "Details.*.*\\WINDOWS\\system32\\Drivers\\PROCEXP152.SYS.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_service_installed";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "sysmon_susp_service_installed";
                $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and (($_.message -match "HKLM\\System\\CurrentControlSet\\Services\\NalDrv\\ImagePath" -or $_.message -match "HKLM\\System\\CurrentControlSet\\Services\\PROCEXP152\\ImagePath") -and -not (($_.message -match "Image.*.*\\procexp64.exe" -or $_.message -match "Image.*.*\\procexp.exe" -or $_.message -match "Image.*.*\\procmon64.exe" -or $_.message -match "Image.*.*\\procmon.exe"))) -and -not (($_.message -match "Details.*.*\\WINDOWS\\system32\\Drivers\\PROCEXP152.SYS.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
