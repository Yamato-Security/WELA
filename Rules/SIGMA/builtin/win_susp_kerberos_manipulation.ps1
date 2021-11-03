# Get-WinEvent -LogName Security | where {(($_.ID -eq "675" -or $_.ID -eq "4768" -or $_.ID -eq "4769" -or $_.ID -eq "4771") -and ($_.message -match "0x9" -or $_.message -match "0xA" -or $_.message -match "0xB" -or $_.message -match "0xF" -or $_.message -match "0x10" -or $_.message -match "0x11" -or $_.message -match "0x13" -or $_.message -match "0x14" -or $_.message -match "0x1A" -or $_.message -match "0x1F" -or $_.message -match "0x21" -or $_.message -match "0x22" -or $_.message -match "0x23" -or $_.message -match "0x24" -or $_.message -match "0x26" -or $_.message -match "0x27" -or $_.message -match "0x28" -or $_.message -match "0x29" -or $_.message -match "0x2C" -or $_.message -match "0x2D" -or $_.message -match "0x2E" -or $_.message -match "0x2F" -or $_.message -match "0x31" -or $_.message -match "0x32" -or $_.message -match "0x3E" -or $_.message -match "0x3F" -or $_.message -match "0x40" -or $_.message -match "0x41" -or $_.message -match "0x43" -or $_.message -match "0x44")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_kerberos_manipulation";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_kerberos_manipulation";
            $detectedMessage = "This method triggers on rare Kerberos Failure Codes caused by manipulations of Kerberos messages";
            $result = $event |  where { (($_.ID -eq "675" -or $_.ID -eq "4768" -or $_.ID -eq "4769" -or $_.ID -eq "4771") -and ($_.message -match "0x9" -or $_.message -match "0xA" -or $_.message -match "0xB" -or $_.message -match "0xF" -or $_.message -match "0x10" -or $_.message -match "0x11" -or $_.message -match "0x13" -or $_.message -match "0x14" -or $_.message -match "0x1A" -or $_.message -match "0x1F" -or $_.message -match "0x21" -or $_.message -match "0x22" -or $_.message -match "0x23" -or $_.message -match "0x24" -or $_.message -match "0x26" -or $_.message -match "0x27" -or $_.message -match "0x28" -or $_.message -match "0x29" -or $_.message -match "0x2C" -or $_.message -match "0x2D" -or $_.message -match "0x2E" -or $_.message -match "0x2F" -or $_.message -match "0x31" -or $_.message -match "0x32" -or $_.message -match "0x3E" -or $_.message -match "0x3F" -or $_.message -match "0x40" -or $_.message -match "0x41" -or $_.message -match "0x43" -or $_.message -match "0x44")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
