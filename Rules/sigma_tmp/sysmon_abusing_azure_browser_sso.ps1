# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "7") -and $_.message -match "ImageLoaded.*.*MicrosoftAccountTokenProvider.dll" -and  -not (($_.message -match "Image.*.*BackgroundTaskHost.exe" -or $_.message -match "Image.*.*devenv.exe" -or $_.message -match "Image.*.*iexplore.exe" -or $_.message -match "Image.*.*MicrosoftEdge.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_abusing_azure_browser_sso";
    $detectedMessage = "Detects abusing Azure Browser SSO by requesting OAuth 2.0 refresh tokens for an Azure-AD-authenticated Windows user (i.e. the machine is joined to Azure AD and a user logs in with their Azure AD account) wanting to perform SSO authentication in the browser. An attacker can use this to authenticate to Azure AD in a browser as that user."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "7") -and $_.message -match "ImageLoaded.*.*MicrosoftAccountTokenProvider.dll" -and -not (($_.message -match "Image.*.*BackgroundTaskHost.exe" -or $_.message -match "Image.*.*devenv.exe" -or $_.message -match "Image.*.*iexplore.exe" -or $_.message -match "Image.*.*MicrosoftEdge.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:$ruleName"  
                Write-Host
                Write-Host $detectedMessage;
            }
            
        };
        Search-DetectableEvents $args[0];
    };
    $Global:ruleStack.Add($ruleName, $detectRule);
}
