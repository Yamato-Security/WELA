# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\sc.exe" -and $_.message -match "IntegrityLevel.*Medium" -and ($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*config" -and $_.message -match "CommandLine.*.*binPath") -or ($_.message -match "CommandLine.*.*failure" -and $_.message -match "CommandLine.*.*command"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_using_sc_to_change_sevice_image_path_by_non_admin";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_using_sc_to_change_sevice_image_path_by_non_admin";
            $detectedMessage = "Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\sc.exe" -and $_.message -match "IntegrityLevel.*Medium" -and ($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*config" -and $_.message -match "CommandLine.*.*binPath") -or ($_.message -match "CommandLine.*.*failure" -and $_.message -match "CommandLine.*.*command"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
