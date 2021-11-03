# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\tree.com" -or $_.message -match "Image.*.*\WMIC.exe" -or $_.message -match "Image.*.*\doskey.exe" -or $_.message -match "Image.*.*\sc.exe") -and $_.message -match "ParentCommandLine.*.* > %TEMP%\") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "process_creation_susp_recon";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "process_creation_susp_recon";
            $detectedMessage = "Once established within a system or network, an adversary may use automated techniques for collecting internal data.";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\tree.com" -or $_.message -match "Image.*.*\\WMIC.exe" -or $_.message -match "Image.*.*\\doskey.exe" -or $_.message -match "Image.*.*\\sc.exe") -and $_.message -match "ParentCommandLine.*.* > %TEMP%\\") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
