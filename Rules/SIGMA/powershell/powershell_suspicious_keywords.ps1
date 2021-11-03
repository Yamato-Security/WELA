# Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match "System.Reflection.Assembly.Load" -or $_.message -match "[System.Reflection.Assembly]::Load" -or $_.message -match "[Reflection.Assembly]::Load" -or $_.message -match "System.Reflection.AssemblyName" -or $_.message -match "Reflection.Emit.AssemblyBuilderAccess" -or $_.message -match "Runtime.InteropServices.DllImportAttribute" -or $_.message -match "SuspendThread" -or $_.message -match "rundll32" -or $_.message -match "FromBase64" -or $_.message -match "Invoke-WMIMethod" -or $_.message -match "http://127.0.0.1")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "powershell_suspicious_keywords";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "powershell_suspicious_keywords";
            $detectedMessage = "Detects keywords that could indicate the use of some PowerShell exploitation framework";
            $result = $event | where { (($_.message -match "System.Reflection.Assembly.Load" -or $_.message -match "[System.Reflection.Assembly]::Load" -or $_.message -match "[Reflection.Assembly]::Load" -or $_.message -match "System.Reflection.AssemblyName" -or $_.message -match "Reflection.Emit.AssemblyBuilderAccess" -or $_.message -match "Runtime.InteropServices.DllImportAttribute" -or $_.message -match "SuspendThread" -or $_.message -match "rundll32" -or $_.message -match "FromBase64" -or $_.message -match "Invoke-WMIMethod" -or $_.message -match "http://127.0.0.1")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
