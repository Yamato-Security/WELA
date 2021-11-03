# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((($_.ID -eq "1") -and $_.message -match "OriginalFileName.*procdump" -and  -not (($_.message -match "Image.*.*\\procdump.exe" -or $_.message -match "Image.*.*\\procdump64.exe"))) -or (($_.ID -eq "1") -and ($_.message -match "CommandLine.*.* -ma " -and $_.message -match "CommandLine.*.* -accepteula ") -and  -not (($_.message -match "CommandLine.*.*\\procdump.exe" -or $_.message -match "CommandLine.*.*\\procdump64.exe"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_renamed_procdump";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_renamed_procdump";
            $detectedMessage = "Detects the execution of a renamed ProcDump executable often used by attackers or malware";
            $result = $event |  where { (($_.ID -eq "1") -and ((($_.ID -eq "1") -and $_.message -match "OriginalFileName.*procdump" -and -not (($_.message -match "Image.*.*\\procdump.exe" -or $_.message -match "Image.*.*\\procdump64.exe"))) -or (($_.ID -eq "1") -and ($_.message -match "CommandLine.*.* -ma " -and $_.message -match "CommandLine.*.* -accepteula ") -and -not (($_.message -match "CommandLine.*.*\\procdump.exe" -or $_.message -match "CommandLine.*.*\\procdump64.exe"))))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
