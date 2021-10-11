# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\regsvr32.exe" -and $_.message -match "CommandLine.*.*\\Temp\\.*") -or ($_.message -match "Image.*.*\\regsvr32.exe" -and $_.message -match "ParentImage.*.*\\powershell.exe") -or ($_.message -match "Image.*.*\\regsvr32.exe" -and $_.message -match "ParentImage.*.*\\cmd.exe") -or ($_.message -match "Image.*.*\\regsvr32.exe" -and $_.message -match "CommandLine.*.*/i:.*" -and ($_.message -match "CommandLine.*.*http.*" -or $_.message -match "CommandLine.*.*ftp.*") -and $_.message -match "CommandLine.*.*scrobj.dll") -or ($_.message -match "Image.*.*\\wscript.exe" -and $_.message -match "ParentImage.*.*\\regsvr32.exe") -or ($_.message -match "Image.*.*\\EXCEL.EXE" -and $_.message -match "CommandLine.*.*..\\..\\..\\Windows\\System32\\regsvr32.exe .*") -or ($_.message -match "ParentImage.*.*\\mshta.exe" -and $_.message -match "Image.*.*\\regsvr32.exe") -or ($_.message -match "Image.*.*\\regsvr32.exe" -and ($_.message -match "CommandLine.*.*\\AppData\\Local.*" -or $_.message -match "CommandLine.*.*C:\\Users\\Public.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_regsvr32_anomalies";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_regsvr32_anomalies";
            $detectedMessage = "Detects various anomalies in relation to regsvr32.exe";
            $result = $event | where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\regsvr32.exe" -and $_.message -match "CommandLine.*.*\\Temp\\.*") -or ($_.message -match "Image.*.*\\regsvr32.exe" -and $_.message -match "ParentImage.*.*\\powershell.exe") -or ($_.message -match "Image.*.*\\regsvr32.exe" -and $_.message -match "ParentImage.*.*\\cmd.exe") -or ($_.message -match "Image.*.*\\regsvr32.exe" -and $_.message -match "CommandLine.*.*/i:.*" -and ($_.message -match "CommandLine.*.*http.*" -or $_.message -match "CommandLine.*.*ftp.*") -and $_.message -match "CommandLine.*.*scrobj.dll") -or ($_.message -match "Image.*.*\\wscript.exe" -and $_.message -match "ParentImage.*.*\\regsvr32.exe") -or ($_.message -match "Image.*.*\\EXCEL.EXE" -and $_.message -match "CommandLine.*.*..\\..\\..\\Windows\\System32\\regsvr32.exe .*") -or ($_.message -match "ParentImage.*.*\\mshta.exe" -and $_.message -match "Image.*.*\\regsvr32.exe") -or ($_.message -match "Image.*.*\\regsvr32.exe" -and ($_.message -match "CommandLine.*.*\\AppData\\Local.*" -or $_.message -match "CommandLine.*.*C:\\Users\\Public.*")))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
