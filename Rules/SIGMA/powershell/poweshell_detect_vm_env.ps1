# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Get-WmiObject.*" -and ($_.message -match "ScriptBlockText.*.*MSAcpi_ThermalZoneTemperature.*" -or $_.message -match "ScriptBlockText.*.*Win32_ComputerSystem.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "poweshell_detect_vm_env";
    $detectedMessage = "Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {($_.ID -eq "4104" -and $_.message -match "ScriptBlockText.*.*Get-WmiObject.*" -and ($_.message -match "ScriptBlockText.*.*MSAcpi_ThermalZoneTemperature.*" -or $_.message -match "ScriptBlockText.*.*Win32_ComputerSystem.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
