# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\rasautou.exe" -or $_.message -match "OriginalFileName.*rasdlui.exe") -and ($_.message -match "CommandLine.*.*-d.*" -and $_.message -match "CommandLine.*.*-p.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_rasautou_dll_execution";
    $detectedMessage = "Detects using Rasautou.exe for loading arbitrary .DLL specified in -d option and executes the export specified in -p. ";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\rasautou.exe" -or $_.message -match "OriginalFileName.*rasdlui.exe") -and ($_.message -match "CommandLine.*.*-d.*" -and $_.message -match "CommandLine.*.*-p.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
