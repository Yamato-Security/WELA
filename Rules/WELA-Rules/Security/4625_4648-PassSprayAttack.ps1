
function Add-Rule {
    $ruleName = "4625_4648-PassSprayAttack";
    $detectRule = {
        
        function Search-DetectableEvents {
            param (
                $event
            )

            $ruleName = "4625_4648-PassSprayAttack";
            $detectedMessage = "Distributed Account Explicit Credential Use (Password Spray Attack) in timeframe on WELA";        
            $target = $event | where { $_.LogName -eq "Security" -and ($event.id -eq 4648 -or $event.id -eq 4625) }

            $PasswordGuessDetection = @{ FirstDetect = $null ; Count = 0 }
            $PasswordGuessTimeframeMinutes = 1
            $PasswordGuessCount = 3

            foreach ($record in $target) {
                $eventXML = [xml]$record.ToXml()
                $username = $eventXML.Event.EventData.Data[1]."#text"
                $hostname = $eventXML.Event.EventData.Data[2]."#text"
                $targetusername = $eventXML.Event.EventData.Data[5]."#text"
                $sourceip = ""
                if ($record.id -eq 4648) {
                    $sourceip = $eventXML.Event.EventData.Data[12]."#text"
                }
                else {
                    $sourceip = $eventXML.Event.EventData.Data[19]."#text"
                }
                $EventTimestampString = $record.TimeCreated.ToString($DateFormat)
                $EventTimestampDateTime = [datetime]::ParseExact($EventTimestampString, $DateFormat, $null)
                if (!$PasswordGuessDetection.FirstDetect) {
                    $PasswordGuessDetection.FirstDetect = $EventTimestampString
                    $PasswordGuessDetection.Count++;
                }
                else {
                    $TimeBetweenEvents = ( $EventTimestampDateTime - $PasswordGuessDetection.FirstDetect ).TotalMinutes
                    if ( $TimeBetweenEvents -gt $PasswordGuessTimeframeMinutes -and $PasswordGuessDetection.Count -lt $PasswordGuessCount ) {
                        $PasswordGuessDetection.FirstDetect = $null 
                        $PasswordGuessDetection.Count = 0
                    }
                    if ( $ElapsedTime -le $PasswordGuessTimeframeMinutes -and $PasswordGuessDetection.Count -ge $PasswordGuessCount -and $TimeBetweenEvents -gt 0 ) {    
                        Write-Host "$EventTimestampString Alert! Password guess attack detected! Target User: $msgTargetUserName IP Address: $msgIpAddress (Threshold: $PasswordGuessCount times in $PasswordGuessTimeframeMinutes minutes.)"
                        $PasswordGuessDetection.FirstDetect = $PasswordGuessDetection.FirstDetect.Addminutes($PasswordGuessTimeframeMinutes)
                        $PasswordGuessDetection.Count = 0
                    } 
                }
            }
        };
        . Search-DetectableEvents $args;
    };
    $ruleStack.Add($ruleName, $detectRule);
}