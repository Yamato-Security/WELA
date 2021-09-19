# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*windows\system32\Physmem.sys.*" -or ($_.message -match "Image.*.*Windows\system32\ime\SHARED\WimBootConfigurations.ini.*" -or $_.message -match "Image.*.*Windows\system32\ime\IMEJP\WimBootConfigurations.ini.*" -or $_.message -match "Image.*.*Windows\system32\ime\IMETC\WimBootConfigurations.ini.*")) -or ($_.ID -eq "1" -and ($_.message -match "Image.*.*windows\system32\filepath2.*" -or $_.message -match "Image.*.*windows\system32\ime.*") -and ($_.message -match "CommandLine.*.*reg add.*") -and ($_.message -match "CommandLine.*.*HKEY_LOCAL_MACHINE\software\classes\clsid\{7c857801-7381-11cf-884d-00aa004b2e24}\inprocserver32.*" -or $_.message -match "CommandLine.*.*HKEY_LOCAL_MACHINE\software\classes\clsid\{cf4cc405-e2c5-4ddd-b3ce-5e7582d8c9fa}\inprocserver32.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "sysmon_apt_sourgrum";
    $detectedMessage = "Suspicious behaviours related to an actor tracked by Microsoft as SOURGUM";

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event |  where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*windows\system32\Physmem.sys.*" -or ($_.message -match "Image.*.*Windows\system32\ime\SHARED\WimBootConfigurations.ini.*" -or $_.message -match "Image.*.*Windows\system32\ime\IMEJP\WimBootConfigurations.ini.*" -or $_.message -match "Image.*.*Windows\system32\ime\IMETC\WimBootConfigurations.ini.*")) -or ($_.ID -eq "1" -and ($_.message -match "Image.*.*windows\system32\filepath2.*" -or $_.message -match "Image.*.*windows\system32\ime.*") -and ($_.message -match "CommandLine.*.*reg add.*") -and ($_.message -match "CommandLine.*.*HKEY_LOCAL_MACHINE\software\classes\clsid\{7c857801-7381-11cf-884d-00aa004b2e24}\inprocserver32.*" -or $_.message -match "CommandLine.*.*HKEY_LOCAL_MACHINE\software\classes\clsid\{cf4cc405-e2c5-4ddd-b3ce-5e7582d8c9fa}\inprocserver32.*")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message;
            if ($result.Count -ne 0) {
                Write-Host
                Write-Host "Detected! RuleName:\$ruleName";
                Write-Host $result;
                Write-Host $detectedMessage;
            }
            
        };
        . Search-DetectableEvents $args[0];
    };
    $ruleStack.Add($ruleName, $detectRule);
}
