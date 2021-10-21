# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7") -and $_.message -match "ImageLoaded.*.*MicrosoftAccountTokenProvider.dll" -and  -not (($_.message -match "Image.*.*BackgroundTaskHost.exe" -or $_.message -match "Image.*.*devenv.exe" -or $_.message -match "Image.*.*iexplore.exe" -or $_.message -match "Image.*.*MicrosoftEdge.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_abusing_azure_browser_sso";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "sysmon_abusing_azure_browser_sso";
            $detectedMessage = "Detects abusing Azure Browser SSO by requesting OAuth 2.0 refresh tokens for an Azure-AD-authenticated Windows user (i.e. the machine is joined to Azure AD and a user logs in with their Azure AD account) wanting to perform SSO authentication in the browser. An attacker can use this to authenticate to Azure AD in a browser as that user.";
            $result = $event |  where { (($_.ID -eq "7") -and $_.message -match "ImageLoaded.*.*MicrosoftAccountTokenProvider.dll" -and -not (($_.message -match "Image.*.*BackgroundTaskHost.exe" -or $_.message -match "Image.*.*devenv.exe" -or $_.message -match "Image.*.*iexplore.exe" -or $_.message -match "Image.*.*MicrosoftEdge.exe"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
