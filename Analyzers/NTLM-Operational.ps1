# Analyze the following logs
# 8001 : Outgoing NTLM authentication traffic that would be blocked.
# 8002 : Incoming NTLM Traffic that would be blocked
# 8004 : NTLM authentication to Domain Controller that would be blocked.

# In order to produce these logs you need to turn on the following settings via Group Policy
# Under "Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options"
# Network security: Restrict NTLM: Audit Incoming NTLM Traffic -> Enable auditing for all accounts
# Network security: Restrict NTLM: Audit NTLM authentication in this domain	-> Enable all
# Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers -> Audit all
# It is also recommended to increase the log size as the default is very small and logs will become overwritten quickly.

function SecureChannelTypeLookup ($secureChannelType) {
   
    #Reference: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/4d1235e3-2c96-4e9f-a147-3cb338a0d09f

    switch ( $secureChannelType ) {
        "0" { $return = "Null (Unauthenticated channel type. Shouldn't be used.)" }
        "1" { $return = "MsvAp (Secure channel between local NT LAN Manager security provider and Netlogon server.)" }
        "2" { $return = "Workstation (Secure channel between domain member to DC.)" }
        "3" { $return = "Trusted DNS Domain (Secure channel between two  DCs through trust relationship via Trusted Domain Object between two AD domains.)" }
        "4" { $return = "Trust Domain Secure (Secure channel between two DCs via trust relationship between domains.)" }
        "5" { $return = "Uas Server (Secure channel between a LAN Manager server to DC. Shouldn't be used.)" }
        "6" { $return = "Server (Secure channel from backup DC to primary DC.)" }
        "7" { $return = "Cdc (Secure channel from Read-Only DC (RODC) to DC.)" }
        else { $return = "Unknown."}
    }
    return  $return
}

function Analyze-NTLMOperationalBasic {

    $WineventFilter = @{}
    $EventIDsToAnalyze = 8001, 8002, 8004
    $WineventFilter.Add("ID", $EventIDsToAnalyze)

    if ( $StartTimeline -ne "" ) { 
        $StartTimeline = [DateTime]::ParseExact($StartTimeline, $DateFormat, $null) 
        $WineventFilter.Add( "StartTime" , $StartTimeline )   
    }

    if ( $EndTimeline -ne "" ) { 
        $EndTimeline = [DateTime]::ParseExact($EndTimeline, $DateFormat, $null) 
        $WineventFilter.Add( "EndTime" , $EndTimeline )
    }

    $WineventFilter.Add( "Path", $LogFile )
    $filesize = Format-FileSize( (get-item $LogFile).length )
    $filesizeMB = (Get-Item $LogFile).length / 1MB 

    $filesizeMB = $filesizeMB * 0.1
    $ApproxTimeInSeconds = $filesizeMB * 60
    $TempTimeSpan = New-TimeSpan -Seconds $ApproxTimeInSeconds
    $RuntimeHours = $TempTimeSpan.Hours.ToString()
    $RuntimeMinutes = $TempTimeSpan.Minutes.ToString()
    $RuntimeSeconds = $TempTimeSpan.Seconds.ToString()

    Write-Host ( $Create_LogonTimeline_Filename -f $LogFile )           # "File Name: {0}"
    Write-Host ( $Create_LogonTimeline_Filesize -f $filesize )          # "File Size: {0}"
    Write-Host ( $Create_LogonTimeline_Estimated_Processing_Time -f $RuntimeHours, $RuntimeMinutes, $RuntimeSeconds )   # "Estimated processing time: {0} hours {1} minutes {2} seconds"
    Write-Host

    $newestEvent = Get-WinEvent -FilterHashtable $WineventFilter -MaxEvents 1
    $eventXML = [xml]$newestEvent.ToXml()
    if ( $UTC -eq $true ) {
        $FirstEventTime = $newestEvent.TimeCreated.ToUniversalTime().ToString($DateFormat)
    }
    else {
        $FirstEventTime = $newestEvent.TimeCreated.ToString($DateFormat) 
    }
    Write-Host "First Log: " $FirstEventTime

    $oldestEvent = Get-WinEvent -FilterHashtable $WineventFilter -MaxEvents 1 -Oldest 
    $eventXML = [xml]$oldestEvent.ToXml()
    if ( $UTC -eq $true ) {
        $LastEventTime = $oldestEvent.TimeCreated.ToUniversalTime().ToString($DateFormat)
    }
    else {
        $LastEventTime = $oldestEvent.TimeCreated.ToString($DateFormat) 
    }
    Write-Host "Last Log:  " $LastEventTime

    $logs = Get-WinEvent -FilterHashtable $WineventFilter -Oldest
    $eventlist = @{}
    $8001_NumberOfLogs = 0
    $8002_NumberOfLogs = 0
    $8004_NumberOfLogs = 0
    
    $8001_TargetNameList = New-Object System.Collections.Generic.List[string]
    $8001_ClientUserNameList = New-Object System.Collections.Generic.List[string]
    #8001_$UserNameList = New-Object System.Collections.Generic.List[string]
    #8001_$DomainNameList = New-Object System.Collections.Generic.List[string]
    #8001_$ProcessNameList = New-Object System.Collections.Generic.List[string]
    #8001_$ClientUserNameList = New-Object System.Collections.Generic.List[string]
    #8001_$ClientDomainNameList = New-Object System.Collections.Generic.List[string]
    $8002_ClientUserNameList = New-Object System.Collections.Generic.List[string]
    $8004_SChannelNameList = New-Object System.Collections.Generic.List[string]
    $8004_UserNameList = New-Object System.Collections.Generic.List[string]
    $8004_WorkstationNameList = New-Object System.Collections.Generic.List[string]
    $8004_SChannelTypeList = New-Object System.Collections.Generic.List[string]

    foreach ( $event in $logs ) {

        #8001: Outgoing NTLM
        #UserName, DomainName, ProcessName, ClientUserName, ClientDomainName seems to always be null so they are omitted.
        #Only TargetName and ClientUserName give useful info.
        if ($event.Id -eq "8001") { 
            $8001_NumberOfLogs++
            
            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
            
                switch ( $data.name ) {
                        
                    "TargetName" { $8001_msgTargetName = $data.'#text' }  
                    "UserName" { $8001_msgUserName = $data.'#text' }  
                    "DomainName" { $8001_msgDomainName = $data.'#text' }  
                    "ProcessName" { $8001_msgProcessName = $data.'#text' }  
                    "ClientUserName" { $8001_msgClientUserName = $data.'#text' }  
                    "ClientDomainName" { $8001_msgClientDomainName = $data.'#text' }  
                }
            }
            
            if ( $8001_TargetNameList -notcontains $8001_msgTargetName ) { $8001_TargetNameList.Add($8001_msgTargetName) }
            if ( $8001_ClientUserNameList -notcontains $8001_msgClientUserName ) { $8001_ClientUserNameList.Add($8001_msgClientUserName) }
            #if ( $8001_UserNameList -notcontains $8001_msgUserName ) { $8001_UserNameList.Add($8001_msgUserName) }
            #if ( $8001_DomainNameList -notcontains $8001_msgDomainName ) { $8001_DomainNameList.Add($8001_msgDomainName) }
            #if ( $8001_ProcessNameList -notcontains $8001_msgProcessName ) { $8001_ProcessNameList.Add($8001_msgProcessName) }
            #if ( $8001_ClientDomainNameList -notcontains $8001_msgClientDomainName ) { $8001_ClientDomainNameList.Add($8001_msgClientDomainName) }
            
        }

        #8002: Incoming NTLM
        #Only ClientUserName seems to be useful for analysis.
        if ($event.Id -eq "8002") { 
            $8002_NumberOfLogs++
           
            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
            
                switch ( $data.name ) {
                         
                    "ClientUserName" { $8002_msgClientUserName = $data.'#text' }  
 
                }
            }
            
            if ( $8002_ClientUserNameList -notcontains $8002_msgClientUserName ) { $8002_ClientUserNameList.Add($8002_msgClientUserName) }
 
        }

        #8004: NTLM Authentication on the DC
        #Ignoring the DomainName
        #Analyzing SChannelName, UserName, WorkstationName, SChannelType
        if ($event.Id -eq "8004") { 
            $8004_NumberOfLogs++
           
            $eventXML = [xml]$event.ToXml()

            foreach ($data in $eventXML.Event.EventData.data) {
            
                switch ( $data.name ) {
                         
                    "SChannelName" { $8004_msgSChannelName = $data.'#text' }  
                    "UserName" { $8004_msgUserName = $data.'#text' }  
                    "WorkstationName" { $8004_msgWorkstationName = $data.'#text' }  
                    "SChannelType" { $8004_msgSChannelType = $data.'#text' }  
 
                }
            }
            
            if ( $8004_SChannelNameList -notcontains $8004_msgSChannelName ) { $8004_SChannelNameList.Add($8004_msgSChannelName) }
            if ( $8004_UserNameList -notcontains $8004_msgUserName ) { $8004_UserNameList.Add($8004_msgUserName) }
            if ( $8004_WorkstationNameList -notcontains $8004_msgWorkstationName ) { $8004_WorkstationNameList.Add($8004_msgWorkstationName) }
            if ( $8004_SChannelTypeList -notcontains $8004_msgSChannelType ) { $8004_SChannelTypeList.Add($8004_msgSChannelType) }
 
        }
    }        

    if ( $HostLanguage.Name -eq "ja-JP" -or $Japanese -eq $true ) {
        Write-Host
        Write-Host "8001（外向けのNTLM認証）のログ解析:"
        Write-Host  "以下のサーバにNTLM認証を行っている："
        $8001_TargetNameArray = $8001_TargetNameList.ToArray()
        $8001_TargetNameArray -join "`n" #Print with newlines. Would nice to be able to do without the array conversion but don't know how.
        Write-Host
        Write-Host "以下のユーザ名でNTLM認証を行っている："
        [System.Collections.ArrayList]$8001_ClientUserNameArray = $8001_ClientUserNameList.ToArray()
        $8001_ClientUserNameArray.Remove("(NULL)")
        $8001_ClientUserNameArray -join "`n" 

        Write-Host
        Write-Host "8002（内向けのNTLM認証）のログ解析:"
        Write-Host "以下のユーザ名でNTLM認証を行っている："
        $8002_ClientUserNameArray = $8002_ClientUserNameList.ToArray()
        $8002_ClientUserNameArray -join "`n" 
        Write-Host

        Write-Host "8004 (DCに対するNTLM認証)のログ解析:"
        Write-Host "セキュアチャンネル名："
        $8004_SChannelNameArray = $8004_SChannelNameList.ToArray()
        $8004_SChannelNameArray -join "`n" 
        Write-Host
        Write-Host "ユーザ名："
        $8004_UserNameArray = $8004_UserNameList.ToArray()
        $8004_UserNameArray -join "`n"
        Write-Host
        Write-Host "端末名："
        [System.Collections.ArrayList]$8004_WorkstationNameArray = $8004_WorkstationNameList.ToArray()
        $8004_WorkstationNameArray.Remove("NULL")
        $8004_WorkstationNameArray -join "`n"
        Write-Host
        Write-Host "セキュアチャンネルタイプ："
        $8004_SChannelTypeArray = $8004_SChannelTypeList.ToArray()

        foreach ( $i in $8004_SChannelTypeArray ) {
            
            $SecureChannelName = SecureChannelTypeLookup( $i )
            Write-Host ”$i : $SecureChannelName”
        
        }
    }
    else  {

        Write-Host
        Write-Host "8001 (Outbound NTLM Authentication) Log Analysis:"
        Write-Host  "Outgoing NTLM authentication to servers:"
        $8001_TargetNameArray = $8001_TargetNameList.ToArray()
        $8001_TargetNameArray -join "`n" 
        Write-Host
        Write-Host "Outgoing NTLM authentication with usernames:"
        [System.Collections.ArrayList]$8001_ClientUserNameArray = $8001_ClientUserNameList.ToArray()
        $8001_ClientUserNameArray.Remove("(NULL)")
        $8001_ClientUserNameArray -join "`n" 

        Write-Host
        Write-Host "8002 (Inbound NTLM  Authentication) Log Analysis:"
        Write-Host "Inbound NTLM authentication with usernames："
        $8002_ClientUserNameArray = $8002_ClientUserNameList.ToArray()
        $8002_ClientUserNameArray -join "`n" 
        Write-Host

        Write-Host
        Write-Host "8004 (NTLM  Authentication to DC) Log Analysis:"
        Write-Host "Secure Channel Names："
        $8004_SChannelNameArray = $8004_SChannelNameList.ToArray()
        $8004_SChannelNameArray -join "`n" 
        Write-Host
        Write-Host "Usernames："
        $8004_UserNameArray = $8004_UserNameList.ToArray()
        $8004_UserNameArray -join "`n"
        Write-Host
        Write-Host "Workstation Names："
        [System.Collections.ArrayList]$8004_WorkstationNameArray = $8004_WorkstationNameList.ToArray()
        $8004_WorkstationNameArray.Remove("NULL")
        $8004_WorkstationNameArray -join "`n"
        Write-Host
        Write-Host "Secure Channel Types："
        $8004_SChannelTypeArray = $8004_SChannelTypeList.ToArray()

        foreach ( $i in $8004_SChannelTypeArray ) {
            
            $SecureChannelName = SecureChannelTypeLookup( $i )
            Write-Host ”$i : $SecureChannelName”
        
        }

    }
    Write-Host
    Write-Host "------------"
    Write-Host "8001 Events: " $8001_NumberOfLogs
    Write-Host "8002 Events: " $8002_NumberOfLogs
    Write-Host "8004 Events: " $8004_NumberOfLogs
    Write-Host
}

