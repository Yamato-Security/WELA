# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\cscript.exe" -and $_.message -match "CommandLine.*.*winrm.*" -and $_.message -match "CommandLine.*.*invoke Create wmicimv2/Win32_.*" -and $_.message -match "CommandLine.*.*-r:http.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_winrm_execution";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_winrm_execution";
            $detectedMessage = "Detects an attempt to execude code or create service on remote host via winrm.vbs.";
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\cscript.exe" -and $_.message -match "CommandLine.*.*winrm.*" -and $_.message -match "CommandLine.*.*invoke Create wmicimv2/Win32_.*" -and $_.message -match "CommandLine.*.*-r:http.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $detectedMessage;
                Write-Host $result;
                Write-Host
            }
        };
        . Search-DetectableEvents $args;
    };
    if(! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    } else {
       Write-Host "Rule Import Error" -Foreground Yellow;
    }
}
