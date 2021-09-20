# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*HKU\\.*" -and $_.message -match "TargetObject.*.*_Classes\\CLSID\\.*" -and $_.message -match "TargetObject.*.*\\InProcServer32\\(Default).*") -and  -not (((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ((($_.message -match "Details.*.*%%systemroot%%\\system32\\.*" -or $_.message -match "Details.*.*%%systemroot%%\\SysWow64\\.*") -or (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "Details.*.*\\AppData\\Local\\Microsoft\\OneDrive\\.*" -and ($_.message -match "Details.*.*\\FileCoAuthLib64.dll.*" -or $_.message -match "Details.*.*\\FileSyncShell64.dll.*" -or $_.message -match "Details.*.*\\FileSyncApi64.dll.*"))) -or ($_.message -match "Details.*.*\\AppData\\Local\\Microsoft\\TeamsMeetingAddin\\.*" -and $_.message -match "Details.*.*\\Microsoft.Teams.AddinLoader.dll.*") -or ($_.message -match "Details.*.*\\AppData\\Roaming\\Dropbox\\.*" -and $_.message -match "Details.*.*\\DropboxExt64..*.dll.*"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_registry_persistence_search_order";
    $detectedMessage = "Detects potential COM object hijacking leveraging the COM Search Order";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ($_.message -match "TargetObject.*.*HKU\\.*" -and $_.message -match "TargetObject.*.*_Classes\\CLSID\\.*" -and $_.message -match "TargetObject.*.*\\InProcServer32\\(Default).*") -and -not (((($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14")) -and ((($_.message -match "Details.*.*%%systemroot%%\\system32\\.*" -or $_.message -match "Details.*.*%%systemroot%%\\SysWow64\\.*") -or (($_.ID -eq "12" -or $_.ID -eq "13" -or $_.ID -eq "14") -and $_.message -match "Details.*.*\\AppData\\Local\\Microsoft\\OneDrive\\.*" -and ($_.message -match "Details.*.*\\FileCoAuthLib64.dll.*" -or $_.message -match "Details.*.*\\FileSyncShell64.dll.*" -or $_.message -match "Details.*.*\\FileSyncApi64.dll.*"))) -or ($_.message -match "Details.*.*\\AppData\\Local\\Microsoft\\TeamsMeetingAddin\\.*" -and $_.message -match "Details.*.*\\Microsoft.Teams.AddinLoader.dll.*") -or ($_.message -match "Details.*.*\\AppData\\Roaming\\Dropbox\\.*" -and $_.message -match "Details.*.*\\DropboxExt64..*.dll.*"))))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $input;
    };
    $ruleStack.Add($ruleName, $detectRule);
}
