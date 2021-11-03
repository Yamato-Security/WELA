# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*VBoxRT.dll,RTR3Init" -or $_.message -match "CommandLine.*.*VBoxC.dll" -or $_.message -match "CommandLine.*.*VBoxDrv.sys") -or ($_.message -match "CommandLine.*.*startvm" -or $_.message -match "CommandLine.*.*controlvm"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_run_virtualbox";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_run_virtualbox";
            $detectedMessage = "Adversaries can carry out malicious operations using a virtual instance to avoid detection. This rule is built to detect the registration of the Virtualbox driver or start of a Virtualbox VM.";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*VBoxRT.dll,RTR3Init" -or $_.message -match "CommandLine.*.*VBoxC.dll" -or $_.message -match "CommandLine.*.*VBoxDrv.sys") -or ($_.message -match "CommandLine.*.*startvm" -or $_.message -match "CommandLine.*.*controlvm"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
