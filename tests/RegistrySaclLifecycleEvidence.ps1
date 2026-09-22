# Test-only attribution for the single fixture-owned REG_SZ creation.
function Test-WelaRegistrySaclFixtureEvent {
    param([string]$Xml,$Operation)
    $reader=$null
    try {
        if($Xml.Length -gt 131072){return $false}
        $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=131072
        $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Xml),$settings);$doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.Load($reader)
        $ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
        if($doc.DocumentElement.LocalName -cne 'Event' -or $doc.DocumentElement.NamespaceURI -cne $ns.LookupNamespace('e') -or $doc.SelectNodes('/e:Event/e:System',$ns).Count -ne 1 -or $doc.SelectNodes('/e:Event/e:EventData',$ns).Count -ne 1){return $false}
        $system=@{};foreach($name in @('Provider','EventID','Version','Task','Keywords','Channel','Computer','EventRecordID','TimeCreated')){$nodes=$doc.SelectNodes("/e:Event/e:System/e:$name",$ns);if($nodes.Count -ne 1){return $false};$system[$name]=$nodes[0]}
        if($system.Provider.GetAttribute('Name') -cne 'Microsoft-Windows-Security-Auditing' -or $system.Provider.GetAttribute('Guid').Trim('{}') -ine '54849625-5478-4994-a5ba-3e3b0328c30d' -or $system.EventID.InnerText -cne '4657' -or $system.Version.InnerText -cne '0' -or $system.Task.InnerText -cne '12801' -or $system.Keywords.InnerText -ine '0x8020000000000000' -or $system.Channel.InnerText -cne 'Security' -or $system.Computer.InnerText -ine $Operation.Computer -or [long]$system.EventRecordID.InnerText -le $Operation.RecordIdBefore){return $false}
        $time=ConvertTo-WelaArrivalUtc $system.TimeCreated.GetAttribute('SystemTime');if($time -lt (ConvertTo-WelaArrivalUtc $Operation.Write.StartedUtc) -or $time -gt (ConvertTo-WelaArrivalUtc $Operation.Write.CompletedUtc)){return $false}
        $fields=@{};foreach($node in $doc.SelectSingleNode('/e:Event/e:EventData',$ns).ChildNodes){if($node.NodeType -eq 'Whitespace'){continue};if($node.NodeType -ne 'Element' -or $node.LocalName -cne 'Data' -or $node.NamespaceURI -cne $ns.LookupNamespace('e') -or @($node.ChildNodes|Where-Object NodeType -eq Element).Count){return $false};$name=$node.GetAttribute('Name');if(-not $name -or $fields.ContainsKey($name)){return $false};$fields[$name]=$node.InnerText}
        if($fields.Count -ne 14){return $false};foreach($name in @('SubjectUserSid','SubjectUserName','SubjectDomainName','SubjectLogonId','ObjectName','ObjectValueName','HandleId','OperationType','OldValueType','OldValue','NewValueType','NewValue','ProcessId','ProcessName')){if(-not $fields.ContainsKey($name)){return $false}}
        if($fields.SubjectUserSid -cne $Operation.Token.Sid -or $fields.ObjectName -ine $Operation.NativePath -or $fields.ObjectValueName -cne $Operation.Write.ValueName -or $fields.OperationType -cne '%%1904' -or $fields.NewValueType -cne '%%1873' -or $fields.NewValue -cne $Operation.Write.Value -or $fields.ProcessName -ine $Operation.Engine){return $false}
        foreach($name in @('SubjectLogonId','ProcessId','HandleId')){if($fields[$name] -cnotmatch '^0x[0-9a-fA-F]+$'){return $false}}
        if([Convert]::ToUInt64($fields.SubjectLogonId.Substring(2),16) -ne [Convert]::ToUInt64($Operation.Token.AuthenticationId.Substring(2),16) -or [Convert]::ToUInt64($fields.ProcessId.Substring(2),16) -ne $Operation.ProcessId -or [Convert]::ToUInt64($fields.HandleId.Substring(2),16) -ne [Convert]::ToUInt64($Operation.Write.HandleId.Substring(2),16)){return $false}
        $true
    }catch{$false}finally{if($reader){$reader.Dispose()}}
}
