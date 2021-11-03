# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "Image.*.*\\Powershell.exe") -and ($_.message -match "CommandLine.*.* -windowstyle h " -or $_.message -match "CommandLine.*.* -windowstyl h" -or $_.message -match "CommandLine.*.* -windowsty h" -or $_.message -match "CommandLine.*.* -windowst h" -or $_.message -match "CommandLine.*.* -windows h" -or $_.message -match "CommandLine.*.* -windo h" -or $_.message -match "CommandLine.*.* -wind h" -or $_.message -match "CommandLine.*.* -win h" -or $_.message -match "CommandLine.*.* -wi h" -or $_.message -match "CommandLine.*.* -win h " -or $_.message -match "CommandLine.*.* -win hi " -or $_.message -match "CommandLine.*.* -win hid " -or $_.message -match "CommandLine.*.* -win hidd " -or $_.message -match "CommandLine.*.* -win hidde " -or $_.message -match "CommandLine.*.* -NoPr " -or $_.message -match "CommandLine.*.* -NoPro " -or $_.message -match "CommandLine.*.* -NoProf " -or $_.message -match "CommandLine.*.* -NoProfi " -or $_.message -match "CommandLine.*.* -NoProfil " -or $_.message -match "CommandLine.*.* -nonin " -or $_.message -match "CommandLine.*.* -nonint " -or $_.message -match "CommandLine.*.* -noninte " -or $_.message -match "CommandLine.*.* -noninter " -or $_.message -match "CommandLine.*.* -nonintera " -or $_.message -match "CommandLine.*.* -noninterac " -or $_.message -match "CommandLine.*.* -noninteract " -or $_.message -match "CommandLine.*.* -noninteracti " -or $_.message -match "CommandLine.*.* -noninteractiv " -or $_.message -match "CommandLine.*.* -ec " -or $_.message -match "CommandLine.*.* -encodedComman " -or $_.message -match "CommandLine.*.* -encodedComma " -or $_.message -match "CommandLine.*.* -encodedComm " -or $_.message -match "CommandLine.*.* -encodedCom " -or $_.message -match "CommandLine.*.* -encodedCo " -or $_.message -match "CommandLine.*.* -encodedC " -or $_.message -match "CommandLine.*.* -encoded " -or $_.message -match "CommandLine.*.* -encode " -or $_.message -match "CommandLine.*.* -encod " -or $_.message -match "CommandLine.*.* -enco " -or $_.message -match "CommandLine.*.* -en ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_powershell_suspicious_parameter_variation";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_powershell_suspicious_parameter_variation";
            $detectedMessage = "Detects suspicious PowerShell invocation with a parameter substring";
            $result = $event |  where { ($_.ID -eq "1" -and ($_.message -match "Image.*.*\\Powershell.exe") -and ($_.message -match "CommandLine.*.* -windowstyle h " -or $_.message -match "CommandLine.*.* -windowstyl h" -or $_.message -match "CommandLine.*.* -windowsty h" -or $_.message -match "CommandLine.*.* -windowst h" -or $_.message -match "CommandLine.*.* -windows h" -or $_.message -match "CommandLine.*.* -windo h" -or $_.message -match "CommandLine.*.* -wind h" -or $_.message -match "CommandLine.*.* -win h" -or $_.message -match "CommandLine.*.* -wi h" -or $_.message -match "CommandLine.*.* -win h " -or $_.message -match "CommandLine.*.* -win hi " -or $_.message -match "CommandLine.*.* -win hid " -or $_.message -match "CommandLine.*.* -win hidd " -or $_.message -match "CommandLine.*.* -win hidde " -or $_.message -match "CommandLine.*.* -NoPr " -or $_.message -match "CommandLine.*.* -NoPro " -or $_.message -match "CommandLine.*.* -NoProf " -or $_.message -match "CommandLine.*.* -NoProfi " -or $_.message -match "CommandLine.*.* -NoProfil " -or $_.message -match "CommandLine.*.* -nonin " -or $_.message -match "CommandLine.*.* -nonint " -or $_.message -match "CommandLine.*.* -noninte " -or $_.message -match "CommandLine.*.* -noninter " -or $_.message -match "CommandLine.*.* -nonintera " -or $_.message -match "CommandLine.*.* -noninterac " -or $_.message -match "CommandLine.*.* -noninteract " -or $_.message -match "CommandLine.*.* -noninteracti " -or $_.message -match "CommandLine.*.* -noninteractiv " -or $_.message -match "CommandLine.*.* -ec " -or $_.message -match "CommandLine.*.* -encodedComman " -or $_.message -match "CommandLine.*.* -encodedComma " -or $_.message -match "CommandLine.*.* -encodedComm " -or $_.message -match "CommandLine.*.* -encodedCom " -or $_.message -match "CommandLine.*.* -encodedCo " -or $_.message -match "CommandLine.*.* -encodedC " -or $_.message -match "CommandLine.*.* -encoded " -or $_.message -match "CommandLine.*.* -encode " -or $_.message -match "CommandLine.*.* -encod " -or $_.message -match "CommandLine.*.* -enco " -or $_.message -match "CommandLine.*.* -en ")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
    if (! $ruleStack[$ruleName]) {
        $ruleStack.Add($ruleName, $detectRule);
    }
    else {
        Write-Host "Rule Import Error"  -Foreground Yellow;
    }
}
