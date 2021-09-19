# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*powershell.exe.*" -and ($_.message -match "CommandLine.*.*join.*split.*" -or $_.message -match "CommandLine.*.*( $ShellId[1]+$ShellId[13]+'x').*" -or $_.message -match "CommandLine.*.*( $PSHome[.*]+$PSHOME[.*]+.*" -or $_.message -match "CommandLine.*.*( $env:Public[13]+$env:Public[5]+'x').*" -or $_.message -match "CommandLine.*.*( $env:ComSpec[4,.*,25]-Join'').*" -or $_.message -match "CommandLine.*.*[1,3]+'x'-Join'').*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_crackmapexec_powershell_obfuscation";
    $detectedMessage = "The CrachMapExec pentesting framework implements a PowerShell obfuscation with some static strings detected by this rule.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "CommandLine.*.*powershell.exe.*" -and ($_.message -match "CommandLine.*.*join.*split.*" -or $_.message -match "CommandLine.*.*( $ShellId[1]+$ShellId[13]+'x').*" -or $_.message -match "CommandLine.*.*( $PSHome[.*]+$PSHOME[.*]+.*" -or $_.message -match "CommandLine.*.*( $env:Public[13]+$env:Public[5]+'x').*" -or $_.message -match "CommandLine.*.*( $env:ComSpec[4,.*,25]-Join'').*" -or $_.message -match "CommandLine.*.*[1,3]+'x'-Join'').*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
