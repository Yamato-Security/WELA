# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\sc.exe" -and $_.message -match "IntegrityLevel.*Medium" -and ($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*config.*" -and $_.message -match "CommandLine.*.*binPath.*") -or ($_.message -match "CommandLine.*.*failure.*" -and $_.message -match "CommandLine.*.*command.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_using_sc_to_change_sevice_image_path_by_non_admin";
    $detectedMessage = "Detection of sc.exe utility spawning by user with Medium integrity level to change service ImagePath or FailureCommand";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Image.*.*\sc.exe" -and $_.message -match "IntegrityLevel.*Medium" -and ($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*config.*" -and $_.message -match "CommandLine.*.*binPath.*") -or ($_.message -match "CommandLine.*.*failure.*" -and $_.message -match "CommandLine.*.*command.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
