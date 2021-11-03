# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "PipeName.*\mojo.5688.8052.183894939787088877" -or $_.message -match "PipeName.*\mojo.5688.8052.35780273329370473" -or $_.message -match "PipeName.*\mypipe-f" -or $_.message -match "PipeName.*\mypipe-h" -or $_.message -match "PipeName.*\ntsvcs_" -or $_.message -match "PipeName.*\scerpc_")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_cobaltstrike_pipe_patterns";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_cobaltstrike_pipe_patterns";
            $detectedMessage = "Detects the creation of a named pipe with a pattern found in CobaltStrike malleable C2 profiles";
            $result = $event |  where { (($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "PipeName.*\\mojo.5688.8052.183894939787088877" -or $_.message -match "PipeName.*\\mojo.5688.8052.35780273329370473" -or $_.message -match "PipeName.*\\mypipe-f" -or $_.message -match "PipeName.*\\mypipe-h" -or $_.message -match "PipeName.*\\ntsvcs_" -or $_.message -match "PipeName.*\\scerpc_")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
