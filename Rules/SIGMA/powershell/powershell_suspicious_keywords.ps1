# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match ".*System.Reflection.Assembly.Load.*" -or $_.message -match ".*[System.Reflection.Assembly]::Load.*" -or $_.message -match ".*[Reflection.Assembly]::Load.*" -or $_.message -match ".*System.Reflection.AssemblyName.*" -or $_.message -match ".*Reflection.Emit.AssemblyBuilderAccess.*" -or $_.message -match ".*Runtime.InteropServices.DllImportAttribute.*" -or $_.message -match ".*SuspendThread.*" -or $_.message -match ".*rundll32.*" -or $_.message -match ".*FromBase64.*" -or $_.message -match ".*Invoke-WMIMethod.*" -or $_.message -match ".*http://127.0.0.1.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_suspicious_keywords";
    $detectedMessage = "Detects keywords that could indicate the use of some PowerShell exploitation framework";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | !firstpipe!
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
