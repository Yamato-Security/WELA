# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ((((((((((((($_.ID -eq "1") -and $_.message -match "Image.*.*\\CamMute.exe" -and  -not (($_.message -match "Image.*.*\\Lenovo\\Communication Utility\\" -or $_.message -match "Image.*.*\\Lenovo\\Communications Utility\\"))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\chrome_frame_helper.exe" -and  -not ($_.message -match "Image.*.*\\Google\\Chrome\\application\\"))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\dvcemumanager.exe" -and  -not ($_.message -match "Image.*.*\\Microsoft Device Emulator\\"))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\Gadget.exe" -and  -not ($_.message -match "Image.*.*\\Windows Media Player\\"))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\hcc.exe" -and  -not ($_.message -match "Image.*.*\\HTML Help Workshop\\"))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\hkcmd.exe" -and  -not (($_.message -match "Image.*.*\\System32\\" -or $_.message -match "Image.*.*\\SysNative\\" -or $_.message -match "Image.*.*\\SysWowo64\\")))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\Mc.exe" -and  -not (($_.message -match "Image.*.*\\Microsoft Visual Studio" -or $_.message -match "Image.*.*\\Microsoft SDK" -or $_.message -match "Image.*.*\\Windows Kit")))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\MsMpEng.exe" -and  -not (($_.message -match "Image.*.*\\Microsoft Security Client\\" -or $_.message -match "Image.*.*\\Windows Defender\\" -or $_.message -match "Image.*.*\\AntiMalware\\")))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\msseces.exe" -and  -not (($_.message -match "Image.*.*\\Microsoft Security Center\\" -or $_.message -match "Image.*.*\\Microsoft Security Client\\" -or $_.message -match "Image.*.*\\Microsoft Security Essentials\\")))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\OInfoP11.exe" -and  -not ($_.message -match "Image.*.*\\Common Files\\Microsoft Shared\\"))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\OleView.exe" -and  -not (($_.message -match "Image.*.*\\Microsoft Visual Studio" -or $_.message -match "Image.*.*\\Microsoft SDK" -or $_.message -match "Image.*.*\\Windows Kit" -or $_.message -match "Image.*.*\\Windows Resource Kit\\")))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\rc.exe" -and  -not (($_.message -match "Image.*.*\\Microsoft Visual Studio" -or $_.message -match "Image.*.*\\Microsoft SDK" -or $_.message -match "Image.*.*\\Windows Kit" -or $_.message -match "Image.*.*\\Windows Resource Kit\\" -or $_.message -match "Image.*.*\\Microsoft.NET\\"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_plugx_susp_exe_locations";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $ruleName = "win_plugx_susp_exe_locations";
            $detectedMessage = "Detects the execution of an executable that is typically used by PlugX for DLL side loading started from an uncommon location";
            $result = $event |  where { (($_.ID -eq "1") -and ((((((((((((($_.ID -eq "1") -and $_.message -match "Image.*.*\\CamMute.exe" -and -not (($_.message -match "Image.*.*\\Lenovo\\Communication Utility\\" -or $_.message -match "Image.*.*\\Lenovo\\Communications Utility\\"))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\chrome_frame_helper.exe" -and -not ($_.message -match "Image.*.*\\Google\\Chrome\\application\\"))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\dvcemumanager.exe" -and -not ($_.message -match "Image.*.*\\Microsoft Device Emulator\\"))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\Gadget.exe" -and -not ($_.message -match "Image.*.*\\Windows Media Player\\"))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\hcc.exe" -and -not ($_.message -match "Image.*.*\\HTML Help Workshop\\"))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\hkcmd.exe" -and -not (($_.message -match "Image.*.*\\System32\\" -or $_.message -match "Image.*.*\\SysNative\\" -or $_.message -match "Image.*.*\\SysWowo64\\")))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\Mc.exe" -and -not (($_.message -match "Image.*.*\\Microsoft Visual Studio" -or $_.message -match "Image.*.*\\Microsoft SDK" -or $_.message -match "Image.*.*\\Windows Kit")))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\MsMpEng.exe" -and -not (($_.message -match "Image.*.*\\Microsoft Security Client\\" -or $_.message -match "Image.*.*\\Windows Defender\\" -or $_.message -match "Image.*.*\\AntiMalware\\")))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\msseces.exe" -and -not (($_.message -match "Image.*.*\\Microsoft Security Center\\" -or $_.message -match "Image.*.*\\Microsoft Security Client\\" -or $_.message -match "Image.*.*\\Microsoft Security Essentials\\")))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\OInfoP11.exe" -and -not ($_.message -match "Image.*.*\\Common Files\\Microsoft Shared\\"))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\OleView.exe" -and -not (($_.message -match "Image.*.*\\Microsoft Visual Studio" -or $_.message -match "Image.*.*\\Microsoft SDK" -or $_.message -match "Image.*.*\\Windows Kit" -or $_.message -match "Image.*.*\\Windows Resource Kit\\")))) -or (($_.ID -eq "1") -and $_.message -match "Image.*.*\\rc.exe" -and -not (($_.message -match "Image.*.*\\Microsoft Visual Studio" -or $_.message -match "Image.*.*\\Microsoft SDK" -or $_.message -match "Image.*.*\\Windows Kit" -or $_.message -match "Image.*.*\\Windows Resource Kit\\" -or $_.message -match "Image.*.*\\Microsoft.NET\\"))))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
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
