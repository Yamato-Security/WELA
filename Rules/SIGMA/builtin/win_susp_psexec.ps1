# Get-WinEvent -LogName Security | where {(($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\IPC$" -and ($_.message -match "RelativeTargetName.*.*-stdin" -or $_.message -match "RelativeTargetName.*.*-stdout" -or $_.message -match "RelativeTargetName.*.*-stderr")) -and  -not ($_.ID -eq "5145" -and $_.message -match "ShareName.*\.*\IPC$" -and $_.message -match "RelativeTargetName.*PSEXESVC")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_psexec";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_psexec";
            $detectedMessage = "detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one";
            $result = $event |  where { (($_.ID -eq "5145" -and $_.message -match "ShareName.*\\.*\\IPC$" -and ($_.message -match "RelativeTargetName.*.*-stdin" -or $_.message -match "RelativeTargetName.*.*-stdout" -or $_.message -match "RelativeTargetName.*.*-stderr")) -and -not ($_.ID -eq "5145" -and $_.message -match "ShareName.*\\.*\\IPC$" -and $_.message -match "RelativeTargetName.*PSEXESVC")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
