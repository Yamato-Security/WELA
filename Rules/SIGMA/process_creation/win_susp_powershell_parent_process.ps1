# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\mshta.exe" -or $_.message -match "ParentImage.*.*\\rundll32.exe" -or $_.message -match "ParentImage.*.*\\regsvr32.exe" -or $_.message -match "ParentImage.*.*\\services.exe" -or $_.message -match "ParentImage.*.*\\winword.exe" -or $_.message -match "ParentImage.*.*\\wmiprvse.exe" -or $_.message -match "ParentImage.*.*\\powerpnt.exe" -or $_.message -match "ParentImage.*.*\\excel.exe" -or $_.message -match "ParentImage.*.*\\msaccess.exe" -or $_.message -match "ParentImage.*.*\\mspub.exe" -or $_.message -match "ParentImage.*.*\\visio.exe" -or $_.message -match "ParentImage.*.*\\outlook.exe" -or $_.message -match "ParentImage.*.*\\amigo.exe" -or $_.message -match "ParentImage.*.*\\chrome.exe" -or $_.message -match "ParentImage.*.*\\firefox.exe" -or $_.message -match "ParentImage.*.*\\iexplore.exe" -or $_.message -match "ParentImage.*.*\\microsoftedgecp.exe" -or $_.message -match "ParentImage.*.*\\microsoftedge.exe" -or $_.message -match "ParentImage.*.*\\browser.exe" -or $_.message -match "ParentImage.*.*\\vivaldi.exe" -or $_.message -match "ParentImage.*.*\\safari.exe" -or $_.message -match "ParentImage.*.*\\sqlagent.exe" -or $_.message -match "ParentImage.*.*\\sqlserver.exe" -or $_.message -match "ParentImage.*.*\\sqlservr.exe" -or $_.message -match "ParentImage.*.*\\w3wp.exe" -or $_.message -match "ParentImage.*.*\\httpd.exe" -or $_.message -match "ParentImage.*.*\\nginx.exe" -or $_.message -match "ParentImage.*.*\\php-cgi.exe" -or $_.message -match "ParentImage.*.*\\jbosssvc.exe" -or $_.message -match "ParentImage.*.*MicrosoftEdgeSH.exe") -or $_.message -match "ParentImage.*.*tomcat") -and (($_.message -match "CommandLine.*.*powershell" -or $_.message -match "CommandLine.*.*pwsh") -or $_.message -match "Description.*Windows PowerShell" -or $_.message -match "Product.*PowerShell Core 6")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_susp_powershell_parent_process";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_susp_powershell_parent_process";
            $detectedMessage = "Detects a suspicious parents of powershell.exe";
            $result = $event |  where { (($_.ID -eq "1") -and (($_.message -match "ParentImage.*.*\\mshta.exe" -or $_.message -match "ParentImage.*.*\\rundll32.exe" -or $_.message -match "ParentImage.*.*\\regsvr32.exe" -or $_.message -match "ParentImage.*.*\\services.exe" -or $_.message -match "ParentImage.*.*\\winword.exe" -or $_.message -match "ParentImage.*.*\\wmiprvse.exe" -or $_.message -match "ParentImage.*.*\\powerpnt.exe" -or $_.message -match "ParentImage.*.*\\excel.exe" -or $_.message -match "ParentImage.*.*\\msaccess.exe" -or $_.message -match "ParentImage.*.*\\mspub.exe" -or $_.message -match "ParentImage.*.*\\visio.exe" -or $_.message -match "ParentImage.*.*\\outlook.exe" -or $_.message -match "ParentImage.*.*\\amigo.exe" -or $_.message -match "ParentImage.*.*\\chrome.exe" -or $_.message -match "ParentImage.*.*\\firefox.exe" -or $_.message -match "ParentImage.*.*\\iexplore.exe" -or $_.message -match "ParentImage.*.*\\microsoftedgecp.exe" -or $_.message -match "ParentImage.*.*\\microsoftedge.exe" -or $_.message -match "ParentImage.*.*\\browser.exe" -or $_.message -match "ParentImage.*.*\\vivaldi.exe" -or $_.message -match "ParentImage.*.*\\safari.exe" -or $_.message -match "ParentImage.*.*\\sqlagent.exe" -or $_.message -match "ParentImage.*.*\\sqlserver.exe" -or $_.message -match "ParentImage.*.*\\sqlservr.exe" -or $_.message -match "ParentImage.*.*\\w3wp.exe" -or $_.message -match "ParentImage.*.*\\httpd.exe" -or $_.message -match "ParentImage.*.*\\nginx.exe" -or $_.message -match "ParentImage.*.*\\php-cgi.exe" -or $_.message -match "ParentImage.*.*\\jbosssvc.exe" -or $_.message -match "ParentImage.*.*MicrosoftEdgeSH.exe") -or $_.message -match "ParentImage.*.*tomcat") -and (($_.message -match "CommandLine.*.*powershell" -or $_.message -match "CommandLine.*.*pwsh") -or $_.message -match "Description.*Windows PowerShell" -or $_.message -match "Product.*PowerShell Core 6")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
