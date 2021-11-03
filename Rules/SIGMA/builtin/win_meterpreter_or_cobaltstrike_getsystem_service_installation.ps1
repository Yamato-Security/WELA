# Get-WinEvent -LogName System | where {((($_.Service File Name -eq "*cmd*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*%COMSPEC%*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*cmd.exe*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*rundll32*" -and $_.Service File Name -eq "*.dll,a*" -and $_.Service File Name -eq "*/p:*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "6") -and (($_.Service File Name -eq "*cmd*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*%COMSPEC%*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*cmd.exe*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*rundll32*" -and $_.Service File Name -eq "*.dll,a*" -and $_.Service File Name -eq "*/p:*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Security | where {((($_.Service File Name -eq "*cmd*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*%COMSPEC%*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*cmd.exe*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*rundll32*" -and $_.Service File Name -eq "*.dll,a*" -and $_.Service File Name -eq "*/p:*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message


function Add-Rule {

    $ruleName = "win_meterpreter_or_cobaltstrike_getsystem_service_installation";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ((($_.Message -Like "*cmd*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*%COMSPEC%*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*cmd.exe*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*rundll32*" -and $_.Message -Like "*.dll,a*" -and $_.Message -Like "*/p:*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { (($_.ID -eq "6") -and (($_.Message -Like "*cmd*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*%COMSPEC%*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*cmd.exe*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*rundll32*" -and $_.Message -Like "*.dll,a*" -and $_.Message -Like "*/p:*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ((($_.Message -Like "*cmd*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*%COMSPEC%*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*cmd.exe*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*rundll32*" -and $_.Message -Like "*.dll,a*" -and $_.Message -Like "*/p:*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            
            foreach ($result in $results) {
                if ($result -and $result.Count -ne 0) {
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;    
                    Write-Output $result;
                    Write-Output ""; 
                }
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
