# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\\rundll32.exe" -and $_.message -match "CommandLine.*.*,#") -and  -not ($_.message -match "CommandLine.*.*EDGEHTML.dll" -and $_.message -match "CommandLine.*.*#141")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_rundll32_by_ordinal";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_rundll32_by_ordinal";
            $detectedMessage = "Detects suspicious calls of DLLs in rundll32.dll exports by ordinal";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*\\rundll32.exe" -and $_.message -match "CommandLine.*.*,#") -and -not ($_.message -match "CommandLine.*.*EDGEHTML.dll" -and $_.message -match "CommandLine.*.*#141")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
