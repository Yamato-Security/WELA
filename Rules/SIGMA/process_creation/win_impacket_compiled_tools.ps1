# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\goldenPac.*" -or $_.message -match "Image.*.*\karmaSMB.*" -or $_.message -match "Image.*.*\kintercept.*" -or $_.message -match "Image.*.*\ntlmrelayx.*" -or $_.message -match "Image.*.*\rpcdump.*" -or $_.message -match "Image.*.*\samrdump.*" -or $_.message -match "Image.*.*\secretsdump.*" -or $_.message -match "Image.*.*\smbexec.*" -or $_.message -match "Image.*.*\smbrelayx.*" -or $_.message -match "Image.*.*\wmiexec.*" -or $_.message -match "Image.*.*\wmipersist.*") -or ($_.message -match "Image.*.*\atexec_windows.exe" -or $_.message -match "Image.*.*\dcomexec_windows.exe" -or $_.message -match "Image.*.*\dpapi_windows.exe" -or $_.message -match "Image.*.*\findDelegation_windows.exe" -or $_.message -match "Image.*.*\GetADUsers_windows.exe" -or $_.message -match "Image.*.*\GetNPUsers_windows.exe" -or $_.message -match "Image.*.*\getPac_windows.exe" -or $_.message -match "Image.*.*\getST_windows.exe" -or $_.message -match "Image.*.*\getTGT_windows.exe" -or $_.message -match "Image.*.*\GetUserSPNs_windows.exe" -or $_.message -match "Image.*.*\ifmap_windows.exe" -or $_.message -match "Image.*.*\mimikatz_windows.exe" -or $_.message -match "Image.*.*\netview_windows.exe" -or $_.message -match "Image.*.*\nmapAnswerMachine_windows.exe" -or $_.message -match "Image.*.*\opdump_windows.exe" -or $_.message -match "Image.*.*\psexec_windows.exe" -or $_.message -match "Image.*.*\rdp_check_windows.exe" -or $_.message -match "Image.*.*\sambaPipe_windows.exe" -or $_.message -match "Image.*.*\smbclient_windows.exe" -or $_.message -match "Image.*.*\smbserver_windows.exe" -or $_.message -match "Image.*.*\sniffer_windows.exe" -or $_.message -match "Image.*.*\sniff_windows.exe" -or $_.message -match "Image.*.*\split_windows.exe" -or $_.message -match "Image.*.*\ticketer_windows.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "win_impacket_compiled_tools";
    $detectedMessage = "Detects the execution of different compiled Windows binaries of the impacket toolset (based on names or part of their names - could lead to false positives)";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\goldenPac.*" -or $_.message -match "Image.*.*\karmaSMB.*" -or $_.message -match "Image.*.*\kintercept.*" -or $_.message -match "Image.*.*\ntlmrelayx.*" -or $_.message -match "Image.*.*\rpcdump.*" -or $_.message -match "Image.*.*\samrdump.*" -or $_.message -match "Image.*.*\secretsdump.*" -or $_.message -match "Image.*.*\smbexec.*" -or $_.message -match "Image.*.*\smbrelayx.*" -or $_.message -match "Image.*.*\wmiexec.*" -or $_.message -match "Image.*.*\wmipersist.*") -or ($_.message -match "Image.*.*\atexec_windows.exe" -or $_.message -match "Image.*.*\dcomexec_windows.exe" -or $_.message -match "Image.*.*\dpapi_windows.exe" -or $_.message -match "Image.*.*\findDelegation_windows.exe" -or $_.message -match "Image.*.*\GetADUsers_windows.exe" -or $_.message -match "Image.*.*\GetNPUsers_windows.exe" -or $_.message -match "Image.*.*\getPac_windows.exe" -or $_.message -match "Image.*.*\getST_windows.exe" -or $_.message -match "Image.*.*\getTGT_windows.exe" -or $_.message -match "Image.*.*\GetUserSPNs_windows.exe" -or $_.message -match "Image.*.*\ifmap_windows.exe" -or $_.message -match "Image.*.*\mimikatz_windows.exe" -or $_.message -match "Image.*.*\netview_windows.exe" -or $_.message -match "Image.*.*\nmapAnswerMachine_windows.exe" -or $_.message -match "Image.*.*\opdump_windows.exe" -or $_.message -match "Image.*.*\psexec_windows.exe" -or $_.message -match "Image.*.*\rdp_check_windows.exe" -or $_.message -match "Image.*.*\sambaPipe_windows.exe" -or $_.message -match "Image.*.*\smbclient_windows.exe" -or $_.message -match "Image.*.*\smbserver_windows.exe" -or $_.message -match "Image.*.*\sniffer_windows.exe" -or $_.message -match "Image.*.*\sniff_windows.exe" -or $_.message -match "Image.*.*\split_windows.exe" -or $_.message -match "Image.*.*\ticketer_windows.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
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
