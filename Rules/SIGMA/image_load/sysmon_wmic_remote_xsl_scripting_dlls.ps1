# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "7" -and $_.message -match "Image.*.*\wmic.exe" -and ($_.message -match "ImageLoaded.*.*\jscript.dll" -or $_.message -match "ImageLoaded.*.*\vbscript.dll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_wmic_remote_xsl_scripting_dlls";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_wmic_remote_xsl_scripting_dlls";
            $detectedMessage = "Detects threat actors proxy executing code and bypassing application controls by leveraging wmic and the `/FORMAT` argument switch to download and execute an XSL file (i.e js, vbs, etc).";
            $result = $event |  where { ($_.ID -eq "7" -and $_.message -match "Image.*.*\\wmic.exe" -and ($_.message -match "ImageLoaded.*.*\\jscript.dll" -or $_.message -match "ImageLoaded.*.*\\vbscript.dll")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
