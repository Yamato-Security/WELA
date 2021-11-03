# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*rundll32.exe" -and $_.message -match "CommandLine.*.*%APPDATA%\") -and ($_.message -match "CommandLine.*.*.dat"," -or $_.message -match "CommandLine.*.*.dll",#1")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_sofacy";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_sofacy";
            $detectedMessage = "Detects Trojan loader acitivty as used by APT28";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*rundll32.exe" -and $_.message -match "CommandLine.*.*%APPDATA%\\") -and ($_.message -match "CommandLine.*.*.dat" -or $_.message -match "CommandLine.*.*.dll#1")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
