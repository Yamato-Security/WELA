# Get-WinEvent -LogName System | where {((($_.Service File Name -eq "*cmd*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*%COMSPEC%*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*cmd.exe*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*rundll32*" -and $_.Service File Name -eq "*.dll,a*" -and $_.Service File Name -eq "*/p:*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "6") -and (($_.Service File Name -eq "*cmd*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*%COMSPEC%*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*cmd.exe*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*rundll32*" -and $_.Service File Name -eq "*.dll,a*" -and $_.Service File Name -eq "*/p:*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Security | where {((($_.Service File Name -eq "*cmd*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*%COMSPEC%*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*cmd.exe*" -and $_.Service File Name -eq "*/c*" -and $_.Service File Name -eq "*echo*" -and $_.Service File Name -eq "*\\pipe\\*") -or ($_.Service File Name -eq "*rundll32*" -and $_.Service File Name -eq "*.dll,a*" -and $_.Service File Name -eq "*/p:*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message


function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_meterpreter_or_cobaltstrike_getsystem_service_installation";
    $detectedMessage = "Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = @();
            $results += $event | where { ((($_.Message -Like "*cmd*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*%COMSPEC%*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*cmd.exe*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*rundll32*" -and $_.Message -Like "*.dll,a*" -and $_.Message -Like "*/p:*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { (($_.ID -eq "6") -and (($_.Message -Like "*cmd*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*%COMSPEC%*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*cmd.exe*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*rundll32*" -and $_.Message -Like "*.dll,a*" -and $_.Message -Like "*/p:*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ((($_.Message -Like "*cmd*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*%COMSPEC%*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*cmd.exe*" -and $_.Message -Like "*/c*" -and $_.Message -Like "*echo*" -and $_.Message -Like "*\\pipe\\*") -or ($_.Message -Like "*rundll32*" -and $_.Message -Like "*.dll,a*" -and $_.Message -Like "*/p:*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
