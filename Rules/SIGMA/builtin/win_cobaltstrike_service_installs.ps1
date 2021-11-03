# Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and (($_.Service File Name -eq "*ADMIN$*" -and $_.Service File Name -eq "*.exe*") -or ($_.Service File Name -eq "*%COMSPEC%*" -and $_.Service File Name -eq "*start*" -and $_.Service File Name -eq "*powershell*") -or ($_.Service File Name -eq "*powershell -nop -w hidden -encodedcommand*") -or ($_.Service File Name -eq "*SUVYIChOZXctT2JqZWN0IE5ldC5XZWJjbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTI3LjAuMC4xO*" -or $_.message -match "Service File Name.*.*lFWCAoTmV3LU9iamVjdCBOZXQuV2ViY2xpZW50KS5Eb3dubG9hZFN0cmluZygnaHR0cDovLzEyNy4wLjAuMT" -or $_.message -match "Service File Name.*.*JRVggKE5ldy1PYmplY3QgTmV0LldlYmNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly8xMjcuMC4wLjE6"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_cobaltstrike_service_installs";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_cobaltstrike_service_installs";
            $detectedMessage = "Detects known malicious service installs that appear in cases in which a Cobalt Strike beacon elevates privileges or lateral movement";
            $result = $event |  where { ($_.ID -eq "7045" -and (($_.message -like "*ADMIN$*" -and $_.message -like "*.exe*") -or ($_.message -like "*%COMSPEC%*" -and $_.message -like "*start*" -and $_.message -like "*powershell*") -or ($_.message -like "*powershell -nop -w hidden -encodedcommand*") -or ($_.message -Like "*SUVYIChOZXctT2JqZWN0IE5ldC5XZWJjbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTI3LjAuMC4xO*" -or $_.message -match "Service File Name.*.*lFWCAoTmV3LU9iamVjdCBOZXQuV2ViY2xpZW50KS5Eb3dubG9hZFN0cmluZygnaHR0cDovLzEyNy4wLjAuMT" -or $_.message -match "Service File Name.*.*JRVggKE5ldy1PYmplY3QgTmV0LldlYmNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly8xMjcuMC4wLjE6"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
