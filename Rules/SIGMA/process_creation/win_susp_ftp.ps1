# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.ID -eq "1" -and $_.message -match "CommandLine.*.*-s:" -and ($_.message -match "Image.*.*ftp.exe" -or $_.message -match "OriginalFileName.*.*ftp.exe")) -or (($_.ID -eq "1") -and $_.message -match "OriginalFileName.*.*ftp.exe" -and  -not ($_.message -match "Image.*.*ftp.exe")) -or $_.message -match "ParentImage.*.*ftp.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_ftp";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_ftp";
            $detectedMessage = "Detects renamed ftp.exe, ftp.exe script execution and child processes ran by ftp.exe";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.ID -eq "1" -and $_.message -match "CommandLine.*.*-s:" -and ($_.message -match "Image.*.*ftp.exe" -or $_.message -match "OriginalFileName.*.*ftp.exe")) -or (($_.ID -eq "1") -and $_.message -match "OriginalFileName.*.*ftp.exe" -and -not ($_.message -match "Image.*.*ftp.exe")) -or $_.message -match "ParentImage.*.*ftp.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
