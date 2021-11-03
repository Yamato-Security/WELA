# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and $_.message -match "Image.*.*\\GUP.exe" -and  -not (($_.message -match "Image.*.*\\Users\\.*\\AppData\\Local\\Notepad++\\updater\\GUP.exe" -or $_.message -match "Image.*.*\\Users\\.*\\AppData\\Roaming\\Notepad++\\updater\\GUP.exe" -or $_.message -match "Image.*.*\\Program Files\\Notepad++\\updater\\GUP.exe" -or $_.message -match "Image.*.*\\Program Files (x86)\\Notepad++\\updater\\GUP.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_gup";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_gup";
            $detectedMessage = "Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks";
            $result = $event |  where { (($_.ID -eq "1") -and $_.message -match "Image.*.*\\GUP.exe" -and -not (($_.message -match "Image.*.*\\Users\\.*\\AppData\\Local\\Notepad++\\updater\\GUP.exe" -or $_.message -match "Image.*.*\\Users\\.*\\AppData\\Roaming\\Notepad++\\updater\\GUP.exe" -or $_.message -match "Image.*.*\\Program Files\\Notepad++\\updater\\GUP.exe" -or $_.message -match "Image.*.*\\Program Files (x86)\\Notepad++\\updater\\GUP.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
