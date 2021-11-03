# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\rundll32.exe" -and $_.message -match "CommandLine.*.*,dll_u") -or $_.message -match "CommandLine.*.* -export dll_u ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_equationgroup_dll_u_load";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_equationgroup_dll_u_load";
            $detectedMessage = "Detects a specific tool and export used by EquationGroup";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "Image.*.*\\rundll32.exe" -and $_.message -match "CommandLine.*.*,dll_u") -or $_.message -match "CommandLine.*.* -export dll_u ")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
