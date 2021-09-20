# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\tree.com" -or $_.message -match "Image.*.*\WMIC.exe" -or $_.message -match "Image.*.*\doskey.exe" -or $_.message -match "Image.*.*\sc.exe") -and $_.message -match "ParentCommandLine.*.* > %TEMP%\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_susp_recon";
    $detectedMessage = "Once established within a system or network, an adversary may use automated techniques for collecting internal data.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\tree.com" -or $_.message -match "Image.*.*\\WMIC.exe" -or $_.message -match "Image.*.*\\doskey.exe" -or $_.message -match "Image.*.*\\sc.exe") -and $_.message -match "ParentCommandLine.*.* > %TEMP%\\.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
