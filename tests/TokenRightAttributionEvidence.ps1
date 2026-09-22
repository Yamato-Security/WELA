# Test-only strict correlation. This helper never changes WELA scoring or policy.
function Get-WelaTokenAttributionMatch {
 param([string]$Text,$Context)
 if($Text.Length -gt 65536){throw 'Event XML exceeds the fixture bound.'}
 $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=65536
 $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Text),$settings);$xml=[Xml.XmlDocument]::new();$xml.XmlResolver=$null
 try{$xml.Load($reader)}finally{$reader.Dispose()}
 $ns=[Xml.XmlNamespaceManager]::new($xml.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
 if($xml.DocumentElement.LocalName -cne 'Event' -or $xml.DocumentElement.NamespaceURI -cne $ns.LookupNamespace('e') -or $xml.SelectNodes('/e:Event/e:System',$ns).Count -ne 1 -or $xml.SelectNodes('/e:Event/e:EventData',$ns).Count -ne 1){return $null}
 $system=$xml.SelectSingleNode('/e:Event/e:System',$ns)
 foreach($field in @('Provider','EventID','Version','Level','Task','Opcode','Keywords','TimeCreated','EventRecordID','Channel','Computer')){if($system.SelectNodes('e:'+$field,$ns).Count -ne 1){return $null}}
 $p=$system.SelectSingleNode('e:Provider',$ns)
 if($p.GetAttribute('Name') -cne 'Microsoft-Windows-Security-Auditing' -or $p.GetAttribute('Guid') -ine '{54849625-5478-4994-a5ba-3e3b0328c30d}'){return $null}
 foreach($pair in @(@('EventID','4703'),@('Version','0'),@('Level','0'),@('Opcode','0'),@('Task',[string]$Context.Task),@('Keywords','0x8020000000000000'),@('Channel','Security'))){if($system.SelectSingleNode('e:'+$pair[0],$ns).InnerText -cne $pair[1]){return $null}}
 if(@($Context.Computers|Where-Object{$_ -ieq $system.SelectSingleNode('e:Computer',$ns).InnerText}).Count -ne 1){return $null}
 $record=0L;if(-not[long]::TryParse($system.SelectSingleNode('e:EventRecordID',$ns).InnerText,[ref]$record) -or $record -le $Context.Watermark){return $null}
 $data=@{};$fields=$xml.SelectNodes('/e:Event/e:EventData/e:Data',$ns)
 foreach($node in $fields){$name=$node.GetAttribute('Name');if(-not $name -or $data.ContainsKey($name)){return $null};$data[$name]=$node.InnerText}
 foreach($field in @('SubjectUserSid','SubjectLogonId','TargetUserSid','TargetLogonId','ProcessName','ProcessId','EnabledPrivilegeList','DisabledPrivilegeList')){if(-not $data.ContainsKey($field)){return $null}}
 if($data.SubjectUserSid -cne $Context.Sid -or $data.TargetUserSid -cne $Context.Sid -or $data.SubjectLogonId -ine $Context.AuthenticationId -or $data.TargetLogonId -ine $Context.AuthenticationId -or $data.ProcessName -ine $Context.ProcessName){return $null}
 if($data.ProcessId -cnotmatch '^0x[0-9a-fA-F]+$' -or [Convert]::ToUInt64($data.ProcessId.Substring(2),16) -ne [uint64]$Context.ProcessId){return $null}
 $direction=$null
 if($data.DisabledPrivilegeList -ceq 'SeDebugPrivilege' -and $data.EnabledPrivilegeList -ceq '-'){$direction='Disable'}
 if($data.EnabledPrivilegeList -ceq 'SeDebugPrivilege' -and $data.DisabledPrivilegeList -ceq '-'){$direction='Restore'}
 if(-not $direction){return $null}
 $textTime=$system.SelectSingleNode('e:TimeCreated',$ns).GetAttribute('SystemTime');if($textTime -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,7})?Z$'){return $null}
 $time=[DateTime]::Parse($textTime,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToFileTimeUtc()
 if($time -lt $Context.DisableStartedFileTime -or $time -gt $Context.OperationCompletedFileTime){return $null}
 [pscustomobject]@{RecordId=$record;Direction=$direction;Utc=$textTime;Data=$data}
}
function Assert-WelaTokenAttributionTimes {
 param($Operation,[long]$Launched,[long]$Observed)
 $previous=$Launched
 foreach($name in @('DisableStartedFileTime','DisableReturnedFileTime','RestoreStartedFileTime','RestoreReturnedFileTime','OperationCompletedFileTime')){
  $value=$Operation.$name
  if(($value -isnot [long] -and $value -isnot [int]) -or $value -le 0 -or $value -lt $previous -or $value -gt $Observed){throw 'Native operation timestamps must be typed, monotonic and within parent observations.'}
  $previous=$value
 }
 if($Launched -gt $Observed -or ($Observed-$Launched) -gt 950000000){throw 'Parent operation envelope exceeds its bounded worker lifetime.'}
}
