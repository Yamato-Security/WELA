# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -and $_.message -match "CommandLine.*.*scecli\0" -and $_.message -match "CommandLine.*.*reg add") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_credential_access_via_password_filter";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_credential_access_via_password_filter";
            $detectedMessage = "Detects dropping of dll files in system32 that may be used to retrieve user credentials from LSASS";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*HKLM\\\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -and $_.message -match "CommandLine.*.*scecli\\0" -and $_.message -match "CommandLine.*.*reg add") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
