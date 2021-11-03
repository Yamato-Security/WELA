# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\rundll32.exe" -and $_.message -match "CommandLine.*.*pcwutl" -and $_.message -match "CommandLine.*.*LaunchApplication") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_pcwutl";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_pcwutl";
            $detectedMessage = "Detects launch of executable by calling the LaunchApplication function from pcwutl.dll library.";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\rundll32.exe" -and $_.message -match "CommandLine.*.*pcwutl" -and $_.message -match "CommandLine.*.*LaunchApplication") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
