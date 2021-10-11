# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\\dctask64.exe") -and  -not (($_.message -match "CommandLine.*.*DesktopCentral_Agent\\agent.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_dctask64_proc_inject";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_dctask64_proc_inject";
            $detectedMessage = "Detects suspicious process injection using ZOHO's dctask64.exe";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\dctask64.exe") -and -not (($_.message -match "CommandLine.*.*DesktopCentral_Agent\\agent.*"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
