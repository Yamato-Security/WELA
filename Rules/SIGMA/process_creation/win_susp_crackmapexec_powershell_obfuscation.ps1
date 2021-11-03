# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*powershell.exe" -and ($_.message -match "CommandLine.*.*join.*split" -or $_.message -match "CommandLine.*.*( $ShellId[1]+$ShellId[13]+'x')" -or $_.message -match "CommandLine.*.*( $PSHome[.*]+$PSHOME[.*]+" -or $_.message -match "CommandLine.*.*( $env:Public[13]+$env:Public[5]+'x')" -or $_.message -match "CommandLine.*.*( $env:ComSpec[4,.*,25]-Join'')" -or $_.message -match "CommandLine.*.*[1,3]+'x'-Join'')")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_crackmapexec_powershell_obfuscation";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_crackmapexec_powershell_obfuscation";
            $detectedMessage = "The CrachMapExec pentesting framework implements a PowerShell obfuscation with some static strings detected by this rule.";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "CommandLine.*.*powershell.exe" -and ($_.message -match "CommandLine.*.*join.*split" -or $_.message -match "CommandLine.*.*( $ShellId[1]+$ShellId[13]+'x')" -or $_.message -match "CommandLine.*.*( $PSHome[.*]+$PSHOME[.*]+" -or $_.message -match "CommandLine.*.*( $env:Public[13]+$env:Public[5]+'x')" -or $_.message -match "CommandLine.*.*( $env:ComSpec[4,.*,25]-Join'')" -or $_.message -match "CommandLine.*.*[1,3]+'x'-Join'')")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
