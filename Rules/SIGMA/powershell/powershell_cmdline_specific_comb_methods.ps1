# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\powershell.exe" -and (((($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*ToInt.*" -or $_.message -match "CommandLine.*.*ToDecimal.*" -or $_.message -match "CommandLine.*.*ToByte.*" -or $_.message -match "CommandLine.*.*ToUint.*" -or $_.message -match "CommandLine.*.*ToSingle.*" -or $_.message -match "CommandLine.*.*ToSByte.*") -and ($_.message -match "CommandLine.*.*ToChar.*" -or $_.message -match "CommandLine.*.*ToString.*" -or $_.message -match "CommandLine.*.*String.*")) -or ($_.message -match "CommandLine.*.*char.*" -and $_.message -match "CommandLine.*.*join.*")) -or ($_.message -match "CommandLine.*.*split.*" -and $_.message -match "CommandLine.*.*join.*")) -or ($_.message -match "CommandLine.*.*ForEach.*" -and $_.message -match "CommandLine.*.*Xor.*") -or ($_.message -match "CommandLine.*.*cOnvErTTO-SECUreStRIng.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_cmdline_specific_comb_methods";
    $detectedMessage = "Detects specific combinations of encoding methods in the PowerShell command lines";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "1" -and $_.message -match "Image.*.*\powershell.exe" -and (((($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*ToInt.*" -or $_.message -match "CommandLine.*.*ToDecimal.*" -or $_.message -match "CommandLine.*.*ToByte.*" -or $_.message -match "CommandLine.*.*ToUint.*" -or $_.message -match "CommandLine.*.*ToSingle.*" -or $_.message -match "CommandLine.*.*ToSByte.*") -and ($_.message -match "CommandLine.*.*ToChar.*" -or $_.message -match "CommandLine.*.*ToString.*" -or $_.message -match "CommandLine.*.*String.*")) -or ($_.message -match "CommandLine.*.*char.*" -and $_.message -match "CommandLine.*.*join.*")) -or ($_.message -match "CommandLine.*.*split.*" -and $_.message -match "CommandLine.*.*join.*")) -or ($_.message -match "CommandLine.*.*ForEach.*" -and $_.message -match "CommandLine.*.*Xor.*") -or ($_.message -match "CommandLine.*.*cOnvErTTO-SECUreStRIng.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
