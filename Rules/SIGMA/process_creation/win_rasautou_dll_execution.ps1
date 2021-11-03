# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\rasautou.exe" -or $_.message -match "OriginalFileName.*rasdlui.exe") -and ($_.message -match "CommandLine.*.*-d" -and $_.message -match "CommandLine.*.*-p")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_rasautou_dll_execution";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_rasautou_dll_execution";
            $detectedMessage = "Detects using Rasautou.exe for loading arbitrary .DLL specified in -d option and executes the export specified in -p. ";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.ID -eq "1") -and ($_.message -match "Image.*.*\\rasautou.exe" -or $_.message -match "OriginalFileName.*rasdlui.exe") -and ($_.message -match "CommandLine.*.*-d" -and $_.message -match "CommandLine.*.*-p")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
