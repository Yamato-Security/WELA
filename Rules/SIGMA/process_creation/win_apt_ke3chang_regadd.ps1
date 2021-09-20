# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*-Property DWORD -name DisableFirstRunCustomize -value 2 -Force.*" -or $_.message -match "CommandLine.*.*-Property String -name Check_Associations -value.*" -or $_.message -match "CommandLine.*.*-Property DWORD -name IEHarden -value 0 -Force.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_ke3chang_regadd";
    $detectedMessage = "Detects Registry modifications performed by Ke3chang malware in campaigns running in 2019 and 2020";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*-Property DWORD -name DisableFirstRunCustomize -value 2 -Force.*" -or $_.message -match "CommandLine.*.*-Property String -name Check_Associations -value.*" -or $_.message -match "CommandLine.*.*-Property DWORD -name IEHarden -value 0 -Force.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
