# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*\\msdt.exe" -or $_.message -match "CommandLine.*.*\\installutil.exe" -or $_.message -match "CommandLine.*.*\\regsvcs.exe" -or $_.message -match "CommandLine.*.*\\regasm.exe" -or $_.message -match "CommandLine.*.*\\msbuild.exe" -or $_.message -match "CommandLine.*.*\\ieexec.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_possible_applocker_bypass";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_possible_applocker_bypass";
            $detectedMessage = "Detects execution of executables that can be used to bypass Applocker whitelisting";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*\\msdt.exe" -or $_.message -match "CommandLine.*.*\\installutil.exe" -or $_.message -match "CommandLine.*.*\\regsvcs.exe" -or $_.message -match "CommandLine.*.*\\regasm.exe" -or $_.message -match "CommandLine.*.*\\msbuild.exe" -or $_.message -match "CommandLine.*.*\\ieexec.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
