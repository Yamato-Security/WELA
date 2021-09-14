# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* asreproast .*" -or $_.message -match "CommandLine.*.* dump /service:krbtgt .*" -or $_.message -match "CommandLine.*.* kerberoast .*" -or $_.message -match "CommandLine.*.* createnetonly /program:.*" -or $_.message -match "CommandLine.*.* ptt /ticket:.*" -or $_.message -match "CommandLine.*.* /impersonateuser:.*" -or $_.message -match "CommandLine.*.* renew /ticket:.*" -or $_.message -match "CommandLine.*.* asktgt /user:.*" -or $_.message -match "CommandLine.*.* harvest /interval:.*" -or $_.message -match "CommandLine.*.* s4u /user:.*" -or $_.message -match "CommandLine.*.* s4u /ticket:.*" -or $_.message -match "CommandLine.*.* hash /password:.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_hack_rubeus";
    $detectedMessage = "Detects command line parameters used by Rubeus hack tool";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* asreproast .*" -or $_.message -match "CommandLine.*.* dump /service:krbtgt .*" -or $_.message -match "CommandLine.*.* kerberoast .*" -or $_.message -match "CommandLine.*.* createnetonly /program:.*" -or $_.message -match "CommandLine.*.* ptt /ticket:.*" -or $_.message -match "CommandLine.*.* /impersonateuser:.*" -or $_.message -match "CommandLine.*.* renew /ticket:.*" -or $_.message -match "CommandLine.*.* asktgt /user:.*" -or $_.message -match "CommandLine.*.* harvest /interval:.*" -or $_.message -match "CommandLine.*.* s4u /user:.*" -or $_.message -match "CommandLine.*.* s4u /ticket:.*" -or $_.message -match "CommandLine.*.* hash /password:.*")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
