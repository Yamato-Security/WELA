# Get-WinEvent -LogName Windows PowerShell | where {($_.message -match "CommandLine.*.*Get-WmiObject.*" -and $_.message -match "CommandLine.*.* Win32_Shadowcopy.*" -and ($_.message -match "CommandLine.*.*Delete().*" -or $_.message -match "CommandLine.*.*Remove-WmiObject.*") -and $_.ID -eq "400") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_delete_volume_shadow_copies";
    $detectedMessage = "Shadow Copies deletion using operating systems utilities via PowerShell";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.message -match "CommandLine.*.*Get-WmiObject.*" -and $_.message -match "CommandLine.*.* Win32_Shadowcopy.*" -and ($_.message -match "CommandLine.*.*Delete().*" -or $_.message -match "CommandLine.*.*Remove-WmiObject.*") -and $_.ID -eq "400") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
