# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*Execute.*" -and $_.message -match "CommandLine.*.*CreateObject.*" -and $_.message -match "CommandLine.*.*RegRead.*" -and $_.message -match "CommandLine.*.*window.close.*" -and $_.message -match "CommandLine.*.*\Microsoft\Windows\CurrentVersion.*") -and  -not (($_.message -match "CommandLine.*.*\Software\Microsoft\Windows\CurrentVersion\Run.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_vbscript_unc2452";
    $detectedMessage = "Detects suspicious inline VBScript keywords as used by UNC2452";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*Execute.*" -and $_.message -match "CommandLine.*.*CreateObject.*" -and $_.message -match "CommandLine.*.*RegRead.*" -and $_.message -match "CommandLine.*.*window.close.*" -and $_.message -match "CommandLine.*.*\Microsoft\Windows\CurrentVersion.*") -and -not (($_.message -match "CommandLine.*.*\Software\Microsoft\Windows\CurrentVersion\Run.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
