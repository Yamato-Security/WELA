# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "\isapi_http" -or $_.message -match "\isapi_dg" -or $_.message -match "\isapi_dg2" -or $_.message -match "\sdlrpc" -or $_.message -match "\ahexec" -or $_.message -match "\winsession" -or $_.message -match "\lsassw" -or $_.message -match "\46a676ab7f179e511e30dd2dc41bd388" -or $_.message -match "\9f81f59bc58452127884ce513865ed20" -or $_.message -match "\e710f28d59aa529d6792ca6ff0ca1b34" -or $_.message -match "\rpchlp_3" -or $_.message -match "\NamePipe_MoreWindows" -or $_.message -match "\pcheap_reuse" -or $_.message -match "\gruntsvc" -or $_.message -match "\583da945-62af-10e8-4902-a8f205c72b2e" -or $_.message -match "\bizkaz" -or $_.message -match "\svcctl" -or $_.message -match "PipeName.*\Posh" -or $_.message -match "\jaccdpqnvbrrxlaf" -or $_.message -match "\csexecsvc")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_mal_namedpipes";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_mal_namedpipes";
            $detectedMessage = "Detects the creation of a named pipe used by known APT malware";
            $result = $event |  where { (($_.ID -eq "17" -or $_.ID -eq "18") -and ($_.message -match "\\isapi_http" -or $_.message -match "\\isapi_dg" -or $_.message -match "\\isapi_dg2" -or $_.message -match "\\sdlrpc" -or $_.message -match "\\ahexec" -or $_.message -match "\\winsession" -or $_.message -match "\\lsassw" -or $_.message -match "\\46a676ab7f179e511e30dd2dc41bd388" -or $_.message -match "\\9f81f59bc58452127884ce513865ed20" -or $_.message -match "\\e710f28d59aa529d6792ca6ff0ca1b34" -or $_.message -match "\\rpchlp_3" -or $_.message -match "\\NamePipe_MoreWindows" -or $_.message -match "\\pcheap_reuse" -or $_.message -match "\\gruntsvc" -or $_.message -match "\\583da945-62af-10e8-4902-a8f205c72b2e" -or $_.message -match "\\bizkaz" -or $_.message -match "\\svcctl" -or $_.message -match "PipeName.*\\Posh" -or $_.message -match "\\jaccdpqnvbrrxlaf" -or $_.message -match "\\csexecsvc")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
