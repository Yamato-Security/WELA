# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.ID -eq "1") -and (($_.ID -eq "1" -and $_.message -match "CommandLine.*.* -e" -and $_.message -match "CommandLine.*.* JAB" -and $_.message -match "CommandLine.*.* -w" -and $_.message -match "CommandLine.*.* hidden ") -or ($_.ID -eq "1" -and $_.message -match "CommandLine.*.* -e" -and ($_.message -match "CommandLine.*.* BA^J" -or $_.message -match "CommandLine.*.* SUVYI" -or $_.message -match "CommandLine.*.* SQBFAFgA" -or $_.message -match "CommandLine.*.* aQBlAHgA" -or $_.message -match "CommandLine.*.* aWV4I" -or $_.message -match "CommandLine.*.* IAA" -or $_.message -match "CommandLine.*.* IAB" -or $_.message -match "CommandLine.*.* UwB" -or $_.message -match "CommandLine.*.* cwB")) -or ($_.message -match "CommandLine.*.*.exe -ENCOD "))) -and  -not ($_.message -match "CommandLine.*.* -ExecutionPolicy" -and $_.message -match "CommandLine.*.*remotesigned ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_powershell_enc_cmd";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_powershell_enc_cmd";
            $detectedMessage = "Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet)";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.ID -eq "1") -and (($_.ID -eq "1" -and $_.message -match "CommandLine.*.* -e" -and $_.message -match "CommandLine.*.* JAB" -and $_.message -match "CommandLine.*.* -w" -and $_.message -match "CommandLine.*.* hidden ") -or ($_.ID -eq "1" -and $_.message -match "CommandLine.*.* -e" -and ($_.message -match "CommandLine.*.* BA^J" -or $_.message -match "CommandLine.*.* SUVYI" -or $_.message -match "CommandLine.*.* SQBFAFgA" -or $_.message -match "CommandLine.*.* aQBlAHgA" -or $_.message -match "CommandLine.*.* aWV4I" -or $_.message -match "CommandLine.*.* IAA" -or $_.message -match "CommandLine.*.* IAB" -or $_.message -match "CommandLine.*.* UwB" -or $_.message -match "CommandLine.*.* cwB")) -or ($_.message -match "CommandLine.*.*.exe -ENCOD "))) -and -not ($_.message -match "CommandLine.*.* -ExecutionPolicy" -and $_.message -match "CommandLine.*.*remotesigned ")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
