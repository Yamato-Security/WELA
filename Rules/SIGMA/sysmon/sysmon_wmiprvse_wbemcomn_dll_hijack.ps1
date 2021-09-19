# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "Image.*System" -and $_.message -match "TargetFilename.*.*\\wbem\\wbemcomn.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Image.*.*\\wmiprvse.exe" -and $_.message -match "ImageLoaded.*.*\\wbem\\wbemcomn.dll") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_wmiprvse_wbemcomn_dll_hijack";
    $detectedMessage = "Detects a threat actor creating a file named `wbemcomn.dll` in the `C:WindowsSystem32wbem` directory over the network and loading it for a WMI DLL Hijack scenario.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            $results = @();
            $results += $event | where { ($_.ID -eq "11" -and $_.message -match "Image.*System" -and $_.message -match "TargetFilename.*.*\\wbem\\wbemcomn.dll") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            $results += $event | where { ($_.ID -eq "7" -and $_.message -match "Image.*.*\\wmiprvse.exe" -and $_.message -match "ImageLoaded.*.*\\wbem\\wbemcomn.dll") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            
            foreach ($result in $results) {
                if ($result.Count -ne 0) {
                    Write-Host
                    Write-Host "Detected! RuleName:$ruleName";
                    Write-Host $result
                    Write-Host $detectedMessage;    
                }
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
