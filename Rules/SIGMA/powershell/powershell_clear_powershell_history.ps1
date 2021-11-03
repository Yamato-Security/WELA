# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {((($_.ID -eq "4104" -and ((($_.message -match "ScriptBlockText.*.*del" -or $_.message -match "ScriptBlockText.*.*Remove-Item" -or $_.message -match "ScriptBlockText.*.*rm") -and $_.message -match "ScriptBlockText.*.*(Get-PSReadlineOption).HistorySavePath") -or ($_.message -match "ScriptBlockText.*.*Set-PSReadlineOption" -and $_.message -match "ScriptBlockText.*.*–HistorySaveStyle" -and $_.message -match "ScriptBlockText.*.*SaveNothing"))) -or ($_.ID -eq "4103" -and ((($_.message -match "Payload.*.*del" -or $_.message -match "Payload.*.*Remove-Item" -or $_.message -match "Payload.*.*rm") -and $_.message -match "Payload.*.*(Get-PSReadlineOption).HistorySavePath") -or ($_.message -match "Payload.*.*Set-PSReadlineOption" -and $_.message -match "Payload.*.*–HistorySaveStyle" -and $_.message -match "Payload.*.*SaveNothing"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_clear_powershell_history";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_clear_powershell_history";
            $detectedMessage = "Detects keywords that could indicate clearing PowerShell history";
            $result = $event |  where { ((($_.ID -eq "4104" -and ((($_.message -match "ScriptBlockText.*.*del" -or $_.message -match "ScriptBlockText.*.*Remove-Item" -or $_.message -match "ScriptBlockText.*.*rm") -and $_.message -match "ScriptBlockText.*.*(Get-PSReadlineOption).HistorySavePath") -or ($_.message -match "ScriptBlockText.*.*Set-PSReadlineOption" -and $_.message -match "ScriptBlockText.*.*–HistorySaveStyle" -and $_.message -match "ScriptBlockText.*.*SaveNothing"))) -or ($_.ID -eq "4103" -and ((($_.message -match "Payload.*.*del" -or $_.message -match "Payload.*.*Remove-Item" -or $_.message -match "Payload.*.*rm") -and $_.message -match "Payload.*.*(Get-PSReadlineOption).HistorySavePath") -or ($_.message -match "Payload.*.*Set-PSReadlineOption" -and $_.message -match "Payload.*.*–HistorySaveStyle" -and $_.message -match "Payload.*.*SaveNothing"))))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
