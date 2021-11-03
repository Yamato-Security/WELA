# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "53a44c2396d15c3a03723fa5e5db54cafd527635" -or $_.message -match "9c5e496921e3bc882dc40694f1dcc3746a75db19" -or $_.message -match "aeb573accfd95758550cf30bf04f389a92922844" -or $_.message -match "79ef78a797403a4ed1a616c68e07fff868a8650a" -or $_.message -match "4f6f38b4cec35e895d91c052b1f5a83d665c2196" -or $_.message -match "1e8c2cac2e4ce7cbd33c3858eb2e24531cb8a84d" -or $_.message -match "e841a63e47361a572db9a7334af459ddca11347a" -or $_.message -match "c28f606df28a9bc8df75a4d5e5837fc5522dd34d" -or $_.message -match "2e94b305d6812a9f96e6781c888e48c7fb157b6b" -or $_.message -match "dd44133716b8a241957b912fa6a02efde3ce3025" -or $_.message -match "8793bf166cb89eb55f0593404e4e933ab605e803" -or $_.message -match "a39b57032dbb2335499a51e13470a7cd5d86b138" -or $_.message -match "41cc2b15c662bc001c0eb92f6cc222934f0beeea" -or $_.message -match "d209430d6af54792371174e70e27dd11d3def7a7" -or $_.message -match "1c6452026c56efd2c94cea7e0f671eb55515edb0" -or $_.message -match "c6b41d3afdcdcaf9f442bbe772f5da871801fd5a" -or $_.message -match "4923d460e22fbbf165bbbaba168e5a46b8157d9f" -or $_.message -match "f201504bd96e81d0d350c3a8332593ee1c9e09de" -or $_.message -match "ddd2db1127632a2a52943a2fe516a2e7d05d70d2")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "257" -and ($_.message -match "asyspy256.ddns.net" -or $_.message -match "hotkillmail9sddcc.ddns.net" -or $_.message -match "rosaf112.ddns.net" -or $_.message -match "cvdfhjh1231.myftp.biz" -or $_.message -match "sz2016rose.ddns.net" -or $_.message -match "dffwescwer4325.myftp.biz" -or $_.message -match "cvdfhjh1231.ddns.net")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
# Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and ($_.message -match "e570585edc69f9074cb5e8a790708336bd45ca0f") -and  -not (($_.message -match "Image.*.*:\\Program Files(x86)\\" -or $_.message -match "Image.*.*:\\Program Files\\"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message

function Add-Rule {

    $ruleName = "win_apt_gallium";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "win_apt_gallium";
            $detectedMessage = "Detects artefacts associated with activity group GALLIUM - Microsoft Threat Intelligence Center indicators released in December 2019.";
            $results = [System.Collections.ArrayList] @();
            $tmp = $event | where { ($_.ID -eq "1" -and ($_.message -match "53a44c2396d15c3a03723fa5e5db54cafd527635" -or $_.message -match "9c5e496921e3bc882dc40694f1dcc3746a75db19" -or $_.message -match "aeb573accfd95758550cf30bf04f389a92922844" -or $_.message -match "79ef78a797403a4ed1a616c68e07fff868a8650a" -or $_.message -match "4f6f38b4cec35e895d91c052b1f5a83d665c2196" -or $_.message -match "1e8c2cac2e4ce7cbd33c3858eb2e24531cb8a84d" -or $_.message -match "e841a63e47361a572db9a7334af459ddca11347a" -or $_.message -match "c28f606df28a9bc8df75a4d5e5837fc5522dd34d" -or $_.message -match "2e94b305d6812a9f96e6781c888e48c7fb157b6b" -or $_.message -match "dd44133716b8a241957b912fa6a02efde3ce3025" -or $_.message -match "8793bf166cb89eb55f0593404e4e933ab605e803" -or $_.message -match "a39b57032dbb2335499a51e13470a7cd5d86b138" -or $_.message -match "41cc2b15c662bc001c0eb92f6cc222934f0beeea" -or $_.message -match "d209430d6af54792371174e70e27dd11d3def7a7" -or $_.message -match "1c6452026c56efd2c94cea7e0f671eb55515edb0" -or $_.message -match "c6b41d3afdcdcaf9f442bbe772f5da871801fd5a" -or $_.message -match "4923d460e22fbbf165bbbaba168e5a46b8157d9f" -or $_.message -match "f201504bd96e81d0d350c3a8332593ee1c9e09de" -or $_.message -match "ddd2db1127632a2a52943a2fe516a2e7d05d70d2")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message;
            [void]$results.Add($tmp);
            $tmp = $event | where { ($_.ID -eq "257" -and ($_.message -match "asyspy256.ddns.net" -or $_.message -match "hotkillmail9sddcc.ddns.net" -or $_.message -match "rosaf112.ddns.net" -or $_.message -match "cvdfhjh1231.myftp.biz" -or $_.message -match "sz2016rose.ddns.net" -or $_.message -match "dffwescwer4325.myftp.biz" -or $_.message -match "cvdfhjh1231.ddns.net")) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            [void]$results.Add($tmp);
            $tmp = $event | where { (($_.ID -eq "1") -and ($_.message -match "e570585edc69f9074cb5e8a790708336bd45ca0f") -and -not (($_.message -match "Image.*.*:\\Program Files(x86)\\" -or $_.message -match "Image.*.*:\\Program Files\\"))) } | select TimeCreated, Id, RecordId, ProcessId, MachineName, Message
            [void]$results.Add($tmp);
            
            foreach ($result in $results) {
                if ($result -and $result.Count -ne 0) {
                    Write-Output ""; 
                    Write-Output "Detected! RuleName:$ruleName";
                    Write-Output $detectedMessage;    
                    Write-Output $result;
                    Write-Output ""; 
                }
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
