# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "Image.*.*\\GfxDownloadWrapper.exe" -and  -not ($_.message -match "CommandLine.*.*gameplayapi.intel.com")) -and  -not ($_.message -match "ParentImage.*.*\\GfxDownloadWrapper.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_file_download_via_gfxdownloadwrapper";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_file_download_via_gfxdownloadwrapper";
            $detectedMessage = "Detects when GfxDownloadWrapper.exe downloads file from non standard URL";
            $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "Image.*.*\\GfxDownloadWrapper.exe" -and -not ($_.message -match "CommandLine.*.*gameplayapi.intel.com")) -and -not ($_.message -match "ParentImage.*.*\\GfxDownloadWrapper.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
