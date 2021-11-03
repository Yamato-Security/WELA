# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* asreproast " -or $_.message -match "CommandLine.*.* dump /service:krbtgt " -or $_.message -match "CommandLine.*.* kerberoast " -or $_.message -match "CommandLine.*.* createnetonly /program:" -or $_.message -match "CommandLine.*.* ptt /ticket:" -or $_.message -match "CommandLine.*.* /impersonateuser:" -or $_.message -match "CommandLine.*.* renew /ticket:" -or $_.message -match "CommandLine.*.* asktgt /user:" -or $_.message -match "CommandLine.*.* harvest /interval:" -or $_.message -match "CommandLine.*.* s4u /user:" -or $_.message -match "CommandLine.*.* s4u /ticket:" -or $_.message -match "CommandLine.*.* hash /password:")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_hack_rubeus";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_hack_rubeus";
            $detectedMessage = "Detects command line parameters used by Rubeus hack tool";
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* asreproast " -or $_.message -match "CommandLine.*.* dump /service:krbtgt " -or $_.message -match "CommandLine.*.* kerberoast " -or $_.message -match "CommandLine.*.* createnetonly /program:" -or $_.message -match "CommandLine.*.* ptt /ticket:" -or $_.message -match "CommandLine.*.* /impersonateuser:" -or $_.message -match "CommandLine.*.* renew /ticket:" -or $_.message -match "CommandLine.*.* asktgt /user:" -or $_.message -match "CommandLine.*.* harvest /interval:" -or $_.message -match "CommandLine.*.* s4u /user:" -or $_.message -match "CommandLine.*.* s4u /ticket:" -or $_.message -match "CommandLine.*.* hash /password:")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
