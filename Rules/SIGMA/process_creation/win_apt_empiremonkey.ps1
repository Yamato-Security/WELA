# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*/i:%APPDATA%\logs.txt scrobj.dll") -and (($_.message -match "Image.*.*\cutil.exe") -or ($_.message -match "Microsoft(C) Registerserver"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_empiremonkey";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_apt_empiremonkey";
            $detectedMessage = "Detects EmpireMonkey APT reported Activity";
            $result = $event | where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*/i:%APPDATA%\\logs.txt scrobj.dll") -and (($_.message -match "Image.*.*\\cutil.exe") -or ($_.message -match "Microsoft(C) Registerserver"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
