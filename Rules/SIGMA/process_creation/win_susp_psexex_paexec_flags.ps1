# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*\\127.0.0.1" -and $_.message -match "CommandLine.*.* -s " -and $_.message -match "CommandLine.*.*cmd.exe") -or ($_.message -match "CommandLine.*.* /accepteula " -and $_.message -match "CommandLine.*.*cmd /c " -and $_.message -match "CommandLine.*.* -u " -and $_.message -match "CommandLine.*.* -p "))) -and  -not (($_.message -match "CommandLine.*.*paexec" -or $_.message -match "CommandLine.*.*PsExec"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_psexex_paexec_flags";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_psexex_paexec_flags";
            $detectedMessage = "Detects suspicious flags used by PsExec and PAExec but no usual program name in command line";
            $result = $event | where { (($_.ID -eq "1") -and (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*\\127.0.0.1" -and $_.message -match "CommandLine.*.* -s " -and $_.message -match "CommandLine.*.*cmd.exe") -or ($_.message -match "CommandLine.*.* /accepteula " -and $_.message -match "CommandLine.*.*cmd /c " -and $_.message -match "CommandLine.*.* -u " -and $_.message -match "CommandLine.*.* -p "))) -and -not (($_.message -match "CommandLine.*.*paexec" -or $_.message -match "CommandLine.*.*PsExec"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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
