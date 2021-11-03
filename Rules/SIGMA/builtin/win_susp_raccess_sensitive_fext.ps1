# Get-WinEvent -LogName Security | where {(($_.ID -eq "5145") -and ($_.message -match "RelativeTargetName.*.*.pst" -or $_.message -match "RelativeTargetName.*.*.ost" -or $_.message -match "RelativeTargetName.*.*.msg" -or $_.message -match "RelativeTargetName.*.*.nst" -or $_.message -match "RelativeTargetName.*.*.oab" -or $_.message -match "RelativeTargetName.*.*.edb" -or $_.message -match "RelativeTargetName.*.*.nsf" -or $_.message -match "RelativeTargetName.*.*.bak" -or $_.message -match "RelativeTargetName.*.*.dmp" -or $_.message -match "RelativeTargetName.*.*.kirbi" -or $_.message -match "RelativeTargetName.*.*\groups.xml" -or $_.message -match "RelativeTargetName.*.*.rdp")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_raccess_sensitive_fext";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_raccess_sensitive_fext";
            $detectedMessage = "Detects known sensitive file extensions accessed on a network share";
            $result = $event |  where { (($_.ID -eq "5145") -and ($_.message -match "RelativeTargetName.*.*.pst" -or $_.message -match "RelativeTargetName.*.*.ost" -or $_.message -match "RelativeTargetName.*.*.msg" -or $_.message -match "RelativeTargetName.*.*.nst" -or $_.message -match "RelativeTargetName.*.*.oab" -or $_.message -match "RelativeTargetName.*.*.edb" -or $_.message -match "RelativeTargetName.*.*.nsf" -or $_.message -match "RelativeTargetName.*.*.bak" -or $_.message -match "RelativeTargetName.*.*.dmp" -or $_.message -match "RelativeTargetName.*.*.kirbi" -or $_.message -match "RelativeTargetName.*.*\\groups.xml" -or $_.message -match "RelativeTargetName.*.*.rdp")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
