# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.* /vss .*" -and $_.message -match "CommandLine.*.* /y .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_esentutl_activity";
    $detectedMessage = "Detects flags often used with the LOLBAS Esentutl for malicious activity. It could be used in rare cases by administrators to access locked files or during maintenance. ";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.* /vss .*" -and $_.message -match "CommandLine.*.* /y .*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;

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