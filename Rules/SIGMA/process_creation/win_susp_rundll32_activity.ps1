# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*javascript:" -or $_.message -match "CommandLine.*.*.RegisterXLL") -or ($_.message -match "CommandLine.*.*url.dll" -and $_.message -match "CommandLine.*.*OpenURL") -or ($_.message -match "CommandLine.*.*url.dll" -and $_.message -match "CommandLine.*.*OpenURLA") -or ($_.message -match "CommandLine.*.*url.dll" -and $_.message -match "CommandLine.*.*FileProtocolHandler") -or ($_.message -match "CommandLine.*.*zipfldr.dll" -and $_.message -match "CommandLine.*.*RouteTheCall") -or ($_.message -match "CommandLine.*.*shell32.dll" -and $_.message -match "CommandLine.*.*Control_RunDLL") -or ($_.message -match "CommandLine.*.*shell32.dll" -and $_.message -match "CommandLine.*.*ShellExec_RunDLL") -or ($_.message -match "CommandLine.*.*mshtml.dll" -and $_.message -match "CommandLine.*.*PrintHTML") -or ($_.message -match "CommandLine.*.*advpack.dll" -and $_.message -match "CommandLine.*.*LaunchINFSection") -or ($_.message -match "CommandLine.*.*advpack.dll" -and $_.message -match "CommandLine.*.*RegisterOCX") -or ($_.message -match "CommandLine.*.*ieadvpack.dll" -and $_.message -match "CommandLine.*.*LaunchINFSection") -or ($_.message -match "CommandLine.*.*ieadvpack.dll" -and $_.message -match "CommandLine.*.*RegisterOCX") -or ($_.message -match "CommandLine.*.*ieframe.dll" -and $_.message -match "CommandLine.*.*OpenURL") -or ($_.message -match "CommandLine.*.*shdocvw.dll" -and $_.message -match "CommandLine.*.*OpenURL") -or ($_.message -match "CommandLine.*.*syssetup.dll" -and $_.message -match "CommandLine.*.*SetupInfObjectInstallAction'") -or ($_.message -match "CommandLine.*.*setupapi.dll" -and $_.message -match "CommandLine.*.*InstallHinfSection") -or ($_.message -match "CommandLine.*.*pcwutl.dll" -and $_.message -match "CommandLine.*.*LaunchApplication") -or ($_.message -match "CommandLine.*.*dfshim.dll" -and $_.message -match "CommandLine.*.*ShOpenVerbApplication"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_rundll32_activity";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_rundll32_activity";
            $detectedMessage = "Detects suspicious process related to rundll32 based on arguments";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*javascript:" -or $_.message -match "CommandLine.*.*.RegisterXLL") -or ($_.message -match "CommandLine.*.*url.dll" -and $_.message -match "CommandLine.*.*OpenURL") -or ($_.message -match "CommandLine.*.*url.dll" -and $_.message -match "CommandLine.*.*OpenURLA") -or ($_.message -match "CommandLine.*.*url.dll" -and $_.message -match "CommandLine.*.*FileProtocolHandler") -or ($_.message -match "CommandLine.*.*zipfldr.dll" -and $_.message -match "CommandLine.*.*RouteTheCall") -or ($_.message -match "CommandLine.*.*shell32.dll" -and $_.message -match "CommandLine.*.*Control_RunDLL") -or ($_.message -match "CommandLine.*.*shell32.dll" -and $_.message -match "CommandLine.*.*ShellExec_RunDLL") -or ($_.message -match "CommandLine.*.*mshtml.dll" -and $_.message -match "CommandLine.*.*PrintHTML") -or ($_.message -match "CommandLine.*.*advpack.dll" -and $_.message -match "CommandLine.*.*LaunchINFSection") -or ($_.message -match "CommandLine.*.*advpack.dll" -and $_.message -match "CommandLine.*.*RegisterOCX") -or ($_.message -match "CommandLine.*.*ieadvpack.dll" -and $_.message -match "CommandLine.*.*LaunchINFSection") -or ($_.message -match "CommandLine.*.*ieadvpack.dll" -and $_.message -match "CommandLine.*.*RegisterOCX") -or ($_.message -match "CommandLine.*.*ieframe.dll" -and $_.message -match "CommandLine.*.*OpenURL") -or ($_.message -match "CommandLine.*.*shdocvw.dll" -and $_.message -match "CommandLine.*.*OpenURL") -or ($_.message -match "CommandLine.*.*syssetup.dll" -and $_.message -match "CommandLine.*.*SetupInfObjectInstallAction'") -or ($_.message -match "CommandLine.*.*setupapi.dll" -and $_.message -match "CommandLine.*.*InstallHinfSection") -or ($_.message -match "CommandLine.*.*pcwutl.dll" -and $_.message -match "CommandLine.*.*LaunchApplication") -or ($_.message -match "CommandLine.*.*dfshim.dll" -and $_.message -match "CommandLine.*.*ShOpenVerbApplication"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
