# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*New-Object.*" -and $_.message -match "ScriptBlockText.*.*System.Net.NetworkInformation.Ping.*" -and $_.message -match "ScriptBlockText.*.*.Send(.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_icmp_exfiltration";
    $detectedMessage = "Detects Exfiltration Over Alternative Protocol - ICMP. Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel.";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*New-Object.*" -and $_.message -match "ScriptBlockText.*.*System.Net.NetworkInformation.Ping.*" -and $_.message -match "ScriptBlockText.*.*.Send(.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
