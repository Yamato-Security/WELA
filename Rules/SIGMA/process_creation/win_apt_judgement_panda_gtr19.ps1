# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*eprod.ldf" -or ($_.message -match "CommandLine.*.*\ldifde.exe -f -n " -or $_.message -match "CommandLine.*.*\7za.exe a 1.7z " -or $_.message -match "CommandLine.*.*\aaaa\procdump64.exe" -or $_.message -match "CommandLine.*.*\aaaa\netsess.exe" -or $_.message -match "CommandLine.*.*\aaaa\7za.exe" -or $_.message -match "CommandLine.*.*copy .\1.7z \" -or $_.message -match "CommandLine.*.*copy \client\c$\aaaa\") -or $_.message -match "Image.*C:\Users\Public\7za.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_judgement_panda_gtr19";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
                $ruleName = "win_apt_judgement_panda_gtr19";
                    $detectedMessage = "Detects Judgement Panda activity as described in Global Threat Report 2019 by Crowdstrike";
                $result = $event |  where { (($_.ID -eq "1") -and ($_.message -match "CommandLine.*.*eprod.ldf" -or ($_.message -match "CommandLine.*.*\\ldifde.exe -f -n " -or $_.message -match "CommandLine.*.*\\7za.exe a 1.7z " -or $_.message -match "CommandLine.*.*\\aaaa\\procdump64.exe" -or $_.message -match "CommandLine.*.*\\aaaa\\netsess.exe" -or $_.message -match "CommandLine.*.*\\aaaa\\7za.exe" -or $_.message -match "CommandLine.*.*copy .\\1.7z \\" -or $_.message -match "CommandLine.*.*copy \\client\\c$\\aaaa\\") -or $_.message -match "Image.*C:\\Users\\Public\\7za.exe")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
