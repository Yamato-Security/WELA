# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "3") -and ($_.message -match "DestinationPort.*3389" -and $_.message -match "Initiated.*true") -and  -not (($_.message -match "Image.*.*\\mstsc.exe" -or $_.message -match "Image.*.*\\RTSApp.exe" -or $_.message -match "Image.*.*\\RTS2App.exe" -or $_.message -match "Image.*.*\\RDCMan.exe" -or $_.message -match "Image.*.*\\ws_TunnelService.exe" -or $_.message -match "Image.*.*\\RSSensor.exe" -or $_.message -match "Image.*.*\\RemoteDesktopManagerFree.exe" -or $_.message -match "Image.*.*\\RemoteDesktopManager.exe" -or $_.message -match "Image.*.*\\RemoteDesktopManager64.exe" -or $_.message -match "Image.*.*\\mRemoteNG.exe" -or $_.message -match "Image.*.*\\mRemote.exe" -or $_.message -match "Image.*.*\\Terminals.exe" -or $_.message -match "Image.*.*\\spiceworks-finder.exe" -or $_.message -match "Image.*.*\\FSDiscovery.exe" -or $_.message -match "Image.*.*\\FSAssessment.exe" -or $_.message -match "Image.*.*\\MobaRTE.exe" -or $_.message -match "Image.*.*\\chrome.exe" -or $_.message -match "Image.*.*\\thor.exe" -or $_.message -match "Image.*.*\\thor64.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_susp_rdp";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_susp_rdp";
            $detectedMessage = "Detects Non-Standard Tools Connecting to TCP port 3389 indicating possible lateral movement";
            $result = $event |  where { (($_.ID -eq "3") -and ($_.message -match "DestinationPort.*3389" -and $_.message -match "Initiated.*true") -and -not (($_.message -match "Image.*.*\\mstsc.exe" -or $_.message -match "Image.*.*\\RTSApp.exe" -or $_.message -match "Image.*.*\\RTS2App.exe" -or $_.message -match "Image.*.*\\RDCMan.exe" -or $_.message -match "Image.*.*\\ws_TunnelService.exe" -or $_.message -match "Image.*.*\\RSSensor.exe" -or $_.message -match "Image.*.*\\RemoteDesktopManagerFree.exe" -or $_.message -match "Image.*.*\\RemoteDesktopManager.exe" -or $_.message -match "Image.*.*\\RemoteDesktopManager64.exe" -or $_.message -match "Image.*.*\\mRemoteNG.exe" -or $_.message -match "Image.*.*\\mRemote.exe" -or $_.message -match "Image.*.*\\Terminals.exe" -or $_.message -match "Image.*.*\\spiceworks-finder.exe" -or $_.message -match "Image.*.*\\FSDiscovery.exe" -or $_.message -match "Image.*.*\\FSAssessment.exe" -or $_.message -match "Image.*.*\\MobaRTE.exe" -or $_.message -match "Image.*.*\\chrome.exe" -or $_.message -match "Image.*.*\\thor.exe" -or $_.message -match "Image.*.*\\thor64.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
