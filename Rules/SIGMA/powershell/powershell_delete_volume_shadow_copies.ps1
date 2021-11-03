# Get-WinEvent -LogName Windows PowerShell | where {($_.message -match "CommandLine.*.*Get-WmiObject" -and $_.message -match "CommandLine.*.* Win32_Shadowcopy" -and ($_.message -match "CommandLine.*.*Delete()" -or $_.message -match "CommandLine.*.*Remove-WmiObject") -and $_.ID -eq "400") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_delete_volume_shadow_copies";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_delete_volume_shadow_copies";
            $detectedMessage = "Shadow Copies deletion using operating systems utilities via PowerShell";
            $result = $event |  where { ($_.message -match "CommandLine.*.*Get-WmiObject" -and $_.message -match "CommandLine.*.* Win32_Shadowcopy" -and ($_.message -match "CommandLine.*.*Delete()" -or $_.message -match "CommandLine.*.*Remove-WmiObject") -and $_.ID -eq "400") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
