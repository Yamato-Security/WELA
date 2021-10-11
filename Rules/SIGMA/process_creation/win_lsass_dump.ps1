# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.message -match "CommandLine.*.*lsass.*" -and $_.message -match "CommandLine.*.*.dmp.*") -and  -not ($_.message -match "Image.*.*\werfault.exe")) -or ($_.message -match "Image.*.*\procdump.*" -and $_.message -match "Image.*.*.exe" -and $_.message -match "CommandLine.*.*lsass.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_lsass_dump";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_lsass_dump";
            $detectedMessage = "Detect creation of dump files containing the memory space of lsass.exe, which contains sensitive credentials. Identifies usage of Sysinternals procdump.exe to export the memory space of lsass.exe which contains sensitive credentials.";
            $result = $event |  where { (($_.ID -eq "1") -and ((($_.message -match "CommandLine.*.*lsass.*" -and $_.message -match "CommandLine.*.*.dmp.*") -and -not ($_.message -match "Image.*.*\\werfault.exe")) -or ($_.message -match "Image.*.*\\procdump.*" -and $_.message -match "Image.*.*.exe" -and $_.message -match "CommandLine.*.*lsass.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
