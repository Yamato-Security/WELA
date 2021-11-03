# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* /c copy" -or $_.message -match "CommandLine.*.*xcopy") -and $_.message -match "CommandLine.*.*\\System32\\") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_copy_system32";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_copy_system32";
            $detectedMessage = "Detects a suspicious copy command that copies a system program from System32 to another directory on disk - sometimes used to use LOLBINs like certutil or desktopimgdownldr to a different location with a different name";
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* /c copy" -or $_.message -match "CommandLine.*.*xcopy") -and $_.message -match "CommandLine.*.*\\System32\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            ;
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
