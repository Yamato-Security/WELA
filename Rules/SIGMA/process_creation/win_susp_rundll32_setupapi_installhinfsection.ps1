# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\runonce.exe" -and $_.message -match "ParentImage.*.*\\rundll32.exe" -and $_.message -match "ParentCommandLine.*.*setupapi.dll.*" -and $_.message -match "ParentCommandLine.*.*InstallHinfSection.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_rundll32_setupapi_installhinfsection";
    $detectedMessage = "setupapi.dll library provide InstallHinfSection function for processing INF files. INF file may contain instructions allowing to create values in the registry, modify files and install drivers.";

    $detectRule = {
        param($input)
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\runonce.exe" -and $_.message -match "ParentImage.*.*\\rundll32.exe" -and $_.message -match "ParentCommandLine.*.*setupapi.dll.*" -and $_.message -match "ParentCommandLine.*.*InstallHinfSection.*") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
