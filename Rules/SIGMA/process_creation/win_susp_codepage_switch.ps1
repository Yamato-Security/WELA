# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\chcp.com" -and ($_.message -match "CommandLine.*.* 936" -or $_.message -match "CommandLine.*.* 1258")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_codepage_switch";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_codepage_switch";
            $detectedMessage = "Detects a code page switch in command line or batch scripts to a rare language";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\chcp.com" -and ($_.message -match "CommandLine.*.* 936" -or $_.message -match "CommandLine.*.* 1258")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
