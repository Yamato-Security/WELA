# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and (($_.message -match "TargetObject.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_Dlls" -or $_.message -match "TargetObject.*.*\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_Dlls") -or ($_.message -match "NewName.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_Dlls" -or $_.message -match "NewName.*.*\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_Dlls"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_new_dll_added_to_appinit_dlls_registry_key";
    $detectedMessage = "DLLs that are specified in the AppInit_DLLs value in the Registry key HKLMSoftwareMicrosoftWindows NTCurrentVersionWindows are loaded by user32.dll";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and (($_.message -match "TargetObject.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_Dlls" -or $_.message -match "TargetObject.*.*\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_Dlls") -or ($_.message -match "NewName.*.*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_Dlls" -or $_.message -match "NewName.*.*\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_Dlls"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
