# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.ID -eq "1" -and $_.message -match "CommandLine.*.*cmd.exe" -and $_.message -match "CommandLine.*.*&1" -and ((($_.message -match "ParentImage.*.*\wmiprvse.exe" -or $_.message -match "ParentImage.*.*\mmc.exe" -or $_.message -match "ParentImage.*.*\explorer.exe" -or $_.message -match "ParentImage.*.*\services.exe") -and $_.message -match "CommandLine.*.*/Q" -and $_.message -match "CommandLine.*.*/c" -and $_.message -match "CommandLine.*.*\\127.0.0.1\") -or (($_.message -match "ParentCommandLine.*.*svchost.exe -k netsvcs" -or $_.message -match "ParentCommandLine.*.*taskeng.exe") -and $_.message -match "CommandLine.*.*/C" -and $_.message -match "CommandLine.*.*Windows\Temp\"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_impacket_lateralization";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_impacket_lateralization";
            $result = $event | where { (($_.ID -eq "1") -and $_.ID -eq "1" -and $_.message -match "CommandLine.*.*cmd.exe" -and $_.message -match "CommandLine.*.*&1" -and ((($_.message -match "ParentImage.*.*\\wmiprvse.exe" -or $_.message -match "ParentImage.*.*\\mmc.exe" -or $_.message -match "ParentImage.*.*\\explorer.exe" -or $_.message -match "ParentImage.*.*\\services.exe") -and $_.message -match "CommandLine.*.*/Q" -and $_.message -match "CommandLine.*.*/c" -and $_.message -match "CommandLine.*.*\\\\127.0.0.1\\") -or (($_.message -match "ParentCommandLine.*.*svchost.exe -k netsvcs" -or $_.message -match "ParentCommandLine.*.*taskeng.exe") -and $_.message -match "CommandLine.*.*/C" -and $_.message -match "CommandLine.*.*Windows\\Temp\\"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
