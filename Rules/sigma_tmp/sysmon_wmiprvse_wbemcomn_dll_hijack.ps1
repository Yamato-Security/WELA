
function Add-Rule {
    param (
        [bool] $isLiveAnalysis
    )
    $ruleName = "sysmon_wmiprvse_wbemcomn_dll_hijack";
    $detectedMessage = "Detects a threat actor creating a file named `wbemcomn.dll` in the `C:WindowsSystem32wbem` directory over the network and loading it for a WMI DLL Hijack scenario."

    $detectRule = {
        function Search-DetectableEvents {
            param (
                $event
            )
            
            $result = $event | !firstpipe!
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
