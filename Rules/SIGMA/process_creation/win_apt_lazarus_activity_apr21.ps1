# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*mshta.*" -and $_.message -match "CommandLine.*.*.zip.*") -or (($_.message -match "C:\Windows\System32\wbem\wmiprvse.exe") -and ($_.message -match "C:\Windows\System32\mshta.exe")) -or (($_.message -match "ParentImage.*.*:\Users\Public\.*") -and ($_.message -match "C:\Windows\System32\rundll32.exe")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_lazarus_activity_apr21";
    $detectedMessage = "Detects different process creation events as described in Malwarebytes's threat report on Lazarus group activity";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*mshta.*" -and $_.message -match "CommandLine.*.*.zip.*") -or (($_.message -match "C:\Windows\System32\wbem\wmiprvse.exe") -and ($_.message -match "C:\Windows\System32\mshta.exe")) -or (($_.message -match "ParentImage.*.*:\Users\Public\.*") -and ($_.message -match "C:\Windows\System32\rundll32.exe")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
