# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\runonce.exe" -and $_.message -match "ParentImage.*.*\\rundll32.exe" -and $_.message -match "ParentCommandLine.*.*setupapi.dll" -and $_.message -match "ParentCommandLine.*.*InstallHinfSection") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_rundll32_setupapi_installhinfsection";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_rundll32_setupapi_installhinfsection";
            $detectedMessage = "setupapi.dll library provide InstallHinfSection function for processing INF files. INF file may contain instructions allowing to create values in the registry, modify files and install drivers.";
            $result = $event |  where { ($_.ID -eq "1" -and $_.message -match "Image.*.*\\runonce.exe" -and $_.message -match "ParentImage.*.*\\rundll32.exe" -and $_.message -match "ParentCommandLine.*.*setupapi.dll" -and $_.message -match "ParentCommandLine.*.*InstallHinfSection") } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
