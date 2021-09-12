<#
language config:English version
#>

# function Create-EventIDStatistics
$Create_EventIDStatistics_CreatingStatisticsMessage = "Creating Event ID Statistics.`nPlease be patient."
$Create_EventIDStatistics_TotalEventLogs = "Total event logs:"
$Create_EventIDStatistics_FileSize = "File size:"
$Create_EventIDStatistics_FirstEvent = "First event:"
$Create_EventIDStatistics_LastEvent = "Last event:"
$Create_EventIDStatistics_ProcessingTime = "Processing time: {0} hours {1} minutes {2} seconds."
$Create_EventIDStatistics_Count = "Count"
$Create_EventIDStatistics_ID = "ID"
$Create_EventIDStatistics_Event = "Event"
$Create_EventIDStatistics_TimelineOutput = "Timeline Output"
$Create_EventIDStatistics_Comment = "Comment"


$1100 = @{
    EventTitle = 'Event logging service was shut down';
    Comment    = 'Good for finding signs of anti-forensics but most likely false positives when the system shuts down.';
}
$1101 = @{
    EventTitle = 'Audit Events Have Been Dropped By The Transport';
}
$1102 = @{
    EventTitle     = 'Event log was cleared';
    TimelineDetect = "Yes";
    Comment        = 'Should not happen normally so this is a good event to look out for.';
}
$1107 = @{
    EventTitle = 'Event processing error';
}
$4608 = @{
    EventTitle = 'Windows started up';
}
$4610 = @{
    EventTitle = 'An authentication package has been loaded by the Local Security Authority';
}
$4611 = @{
    EventTitle = 'A trusted logon process has been registered with the Local Security Authority';
}
$4614 = @{
    EventTitle = 'A notification package has been loaded by the Security Account Manager';
}
$4616 = @{
    EventTitle = 'System time was changed';
}
$4622 = @{
    
    EventTitle = 'A security package has been loaded by the Local Security Authority';
}
$4624 = @{
    
    EventTitle     = 'Account logon';
    TimelineDetect = "Yes";
}
$4625 = @{
    EventTitle     = 'Failed logon';
    TimelineDetect = "Yes"; 
}
$4634 = @{
    EventTitle     = 'Logoff';
    TimelineDetect = "Yes"
}
$4647 = @{
    EventTitle     = 'Logoff';
    TimelineDetect = "Yes" 
}
$4648 = @{
    EventTitle     = 'Explicit logon';
    TimelineDetect = "Yes"
}
$4672 = @{
    EventTitle     = 'Admin logon';
    TimelineDetect = "Yes";
}
$4688 = @{
    EventTitle = 'New process started';
}
$4696 = @{
    EventTitle = 'Primary token assigned to process';
}
$4692 = @{
    EventTitle = 'Backup of data protection master key was attempted';
}
$4697 = @{
    EventTitle = 'Service installed';
}
$4717 = @{
    EventTitle = 'System security access was granted to an account';
}
$4719 = @{
    EventTitle = 'System audit policy was changed';
}
$4720 = @{
    EventTitle     = 'User account created';
    TimelineDetect = "Yes"
}
$4722 = @{
    EventTitle = 'User account enabled';
}
$4724 = @{
    EventTitle = 'Password reset';
}
$4725 = @{
    EventTitle = 'User account disabled';
}
$4726 = @{
    EventTitle = 'User account deleted';
} 
$4728 = @{
    EventTitle = 'User added to security global group';
}
    
$4729 = @{
    EventTitle = 'User removed from security global group';
}
    
$4732 = @{
    EventTitle = 'User added to security local group';
}
    
$4733 = @{
    EventTitle = 'User removed from security local group';
}
    
$4735 = @{
    EventTitle = 'Security local group was changed';
}
    
$4727 = @{
    EventTitle = 'Security global group was changed';
}
    
$4738 = @{
    EventTitle = 'User account''s properties changed';
}
    
$4739 = @{
    EventTitle = 'Domain policy changed';
}
    
$4776 = @{
    EventTitle = 'NTLM logon to local user';
}
    
$4778 = @{
    EventTitle = 'RDP session reconnected or user switched back through Fast User Switching';
}
    
$4779 = @{
    EventTitle = 'RDP session disconnected or user switched away through Fast User Switching';
}
    
$4797 = @{
    EventTitle = 'Attempt to query the account for a blank password';
}
      
$4798 = @{
    EventTitle = 'User''s local group membership was enumerated';
}
    
$4799 = @{
    EventTitle = 'Local group membership was enumerated';
}
     
$4781 = @{
    EventTitle = 'User name was changed';
}
    
$4800 = @{
    EventTitle = 'Workstation was locked';
}
    
$4801 = @{
    EventTitle = 'Workstation was unlocked';
}
    
$4826 = @{
    EventTitle = 'Boot configuration data loaded';
}
    
$4902 = @{
    EventTitle = 'Per-user audit policy table was created';
}
     
$4904 = @{
    EventTitle = 'Attempt to register a security event source';
}
    
$4905 = @{
    EventTitle = 'Attempt to unregister a security event source';
}
     
$4907 = @{
    EventTitle = 'Auditing settings on object was changed';
}
     
$4944 = @{
    EventTitle = 'Policy active when firewall started';
}
    
$4945 = @{
    EventTitle = 'Rule listed when the firewall started' ; 
    Comment    = "Too much noise when firewall starts" ;
}
$4946 = @{
    EventTitle = 'Rule added to firewall exception list';
}
    
$4947 = @{
    EventTitle = 'Rule modified in firewall exception list';
}
    
$4948 = @{
    EventTitle = 'Rule deleted in firewall exception list';
}
    
$4954 = @{
    EventTitle = 'New setting applied to firewall group policy';
}
    
$4956 = @{
    EventTitle = 'Firewall active profile changed';
}
    
$5024 = @{
    EventTitle = 'Firewall started';
}
    
$5033 = @{
    EventTitle = 'Firewall driver started';
}
     
$5038 = @{
    EventTitle = 'Code integrity determined that the image hash of a file is not valid';
}
    
$5058 = @{
    EventTitle = 'Key file operation';
}
     
$5059 = @{
    EventTitle = 'Key migration operation';
}
    
$5061 = @{
    EventTitle = 'Cryptographic operation';
}
     
$5140 = @{
    EventTitle = 'Network share object was accessed';
}
    
$5142 = @{
    EventTitle = 'A network share object was added';
}
    
$5144 = @{
    EventTitle = 'A network share object was deleted';
}
    
$5379 = @{
    EventTitle = 'Credential Manager credentials were read';
}
    
$5381 = @{
    EventTitle = 'Vault credentials were read';
}
    
$5382 = @{
    EventTitle = 'Vault credentials were read';
}
    
$5478 = @{
    EventTitle = 'IPsec Services started';
}
    
$5889 = @{
    EventTitle = 'An object was deleted to the COM+ Catalog';
}
$5890 = @{
    EventTitle = 'An object was added to the COM+ Catalog';
}
$unregistered_event_id = @{
    EventTitle = "Unknown";
}

# function Create-LogonTimeline
$Create_LogonTimeline_Welcome_Message = "Creating a logon timeline excluding noisy events such as service, system and machine account local logons.`nPlease be patient."
$Create_LogonTimeline_Filesize = 'File Size: {0}'
$Create_LogonTimeline_Estimated_Processing_Time = "Estimated processing time: {0} hours {1} minutes {2} seconds"
$Create_LogonTimeline_ElapsedTimeOutput = "{0} Days {1} Hours {2} Min. {3} Sec."
$Create_LogonTimeline_Timezone = "Timezone"
$Create_LogonTimeline_LogonTime = "Logon Time"
$Create_LogonTimeline_LogoffTime = "Logoff Time"
$Create_LogonTimeline_ElapsedTime = "Elapsed Time"
$Create_LogonTimeline_Type = "Type"
$Create_LogonTimeline_TargetUser = "Target User"
$Create_LogonTimeline_Auth = "Auth"
$Create_LogonTimeline_isAdmin = "Admin"
$Create_LogonTimeline_SourceWorkstation = "Source Workstation"
$Create_LogonTimeline_SourceIpAddress = "Source IP Address"
$Create_LogonTimeline_SourceIpPort = "Source Port"
$Create_LogonTimeline_LogonID = "Logon ID"
$Create_LogonTimeline_Processing_Time = "Processing time: {0} hours {1} minutes {2} seconds."
$Create_LogonTimeline_NoLogoffEvent = "No logoff event"
$Create_LogonTimeline_Total_Logon_Event_Records = "Total logon event records: "
$Create_LogonTimeline_Data_Reduction = "Log event data reduction: "
$Create_LogonTimeline_Total_Filtered_Logons = "Total filtered logons: "
$Create_LogonTimeline_Type0 = "Type 0 System Logons (System runtime):"
$Create_LogonTimeline_Type2 = "Type 2 Interactive Logons (Ex: Console logon, VNC) (Dangerous: Credentials in memory):"
$Create_LogonTimeline_Type3 = "Type 3 Network Logons (Ex: SMB Share, net command, rpcclient, psexec, winrm):"
$Create_LogonTimeline_Type4 = "Type 4 Batch Logons (Ex: Scheduled Tasks):"
$Create_LogonTimeline_Type5 = "Type 5 Service Logons:"
$Create_LogonTimeline_Type7 = "Type 7 Screen Unlock (and RDP reconnect) Logons:"
$Create_LogonTimeline_Type8 = "Type 8 NetworkCleartext Logons (Ex: IIS Basic Auth)(Dangerous: plaintext password used for authentication):"
$Create_LogonTimeline_Type9 = "Type 9 NewCredentials Logons (Ex: runas /netonly command)(Dangerous: Credentials in memory):"
$Create_LogonTimeline_Type10 = "Type 10 RemoteInteractive Logons (Ex: RDP) (Dangerous: Credentials in memory):"
$Create_LogonTimeline_Type11 = "Type 11 CachedInteractive/Cached Credentials Logons (Ex: Cannot connect to DC for authentication):"
$Create_LogonTimeline_Type12 = "Type 12 CachedRemoteInteractive (Ex: RDP with cached credentials, Microsoft Live Accounts):"
$Create_LogonTimeline_Type13 = "Type 13 CachedUnlocked Logons (Ex: Unlock or RDP reconnect without authenticated to DC):"
$Create_LogonTimeline_TypeOther = "Other Type Logons:"



#function Show-Contributors
$Show_Contributors =
"Contributors:

oginoPmP - Developer
DustInDark - Localization, Japanese Translations
Tsubokku - Japanese Translations

Please contribute to this project for fame and glory!
"

function Show-Help {
    Write-Host 
    Write-Host "Windows Event Log Analyzer(WELA)" -ForegroundColor Green
    Write-Host "Version: $YEAVersion" -ForegroundColor Green
    Write-Host "Authors: Zach Mathis (@yamatosecurity), Yamato Security Members" -ForegroundColor Green
    Write-Host 

    Write-Host "Please specify some options:" 
    Write-Host

    Write-Host "Analysis Source (Specify one):"

    Write-Host "   -LiveAnalysis" -NoNewline -ForegroundColor Green
    Write-Host " : Creates a timeline based on the live host's log"

    Write-Host "   -LogFile <path-to-logfile>" -NoNewline -ForegroundColor Green
    Write-Host " : Creates a timelime from an offline .evtx file"

    Write-Host
    Write-Host "Analysis Type (Specify one):"

    Write-Host "   -EventIDStatistics" -NoNewline -ForegroundColor Green
    Write-Host " : Output event ID statistics" 
    
    Write-Host "   -LogonTimeline" -NoNewline -ForegroundColor Green
    Write-Host " : Output a simple timeline of user logons"

    Write-Host 
    Write-Host "Output Types (Default: Standard Output):"

    Write-Host "   -SaveOutput <outputfile-path>" -NoNewline -ForegroundColor Green
    Write-Host " : Output results to a text file"

    Write-Host "   -OutputCSV" -NoNewline -ForegroundColor Green
    Write-Host " : Outputs to CSV"

    Write-Host "   -OutputGUI" -NoNewline -ForegroundColor Green
    Write-Host " : Outputs to the Out-GridView GUI"

    Write-Host 
    Write-Host "Analysis Options:"

    Write-Host "   -StartTimeline ""<YYYY-MM-DD HH:MM:SS>""" -NoNewline -ForegroundColor Green
    Write-Host " : Specify the start of the timeline"

    Write-Host "   -EndTimeline ""<YYYY-MM-DD HH:MM:SS>""" -NoNewline -ForegroundColor Green
    Write-Host " : Specify the end of the timeline"

    Write-Host "   -IsDC" -NoNewline -ForegroundColor Green
    Write-Host " : Specify if the logs are from a DC"

    Write-Host 
    Write-Host "Output Options:"

    Write-Host "   -USDateFormat" -NoNewline -ForegroundColor Green
    Write-Host " : Output the dates in MM-DD-YYYY format (Default: YYYY-MM-DD)"

    Write-Host "   -EuropeDateFormat" -NoNewline -ForegroundColor Green
    Write-Host " : Output the dates in DD-MM-YYYY format (Default: YYYY-MM-DD)"

    Write-Host "   -UTC" -NoNewline -ForegroundColor Green
    Write-Host " : Output in UTC time (default is the local timezone)"
    
    Write-Host "   -HideTimezone" -NoNewline -ForegroundColor Green
    Write-Host " : Hides the timezone"

    Write-Host "   -ShowLogonID" -NoNewline -ForegroundColor Green
    Write-Host " : Specify if you want to see Logon IDs"

    Write-Host "   -Japanese" -NoNewline -ForegroundColor Green
    Write-Host " : Output in Japanese"

    Write-Host
    Write-Host "Other:"

    Write-Host "   -ShowContributors" -NoNewline -ForegroundColor Green
    Write-Host " : Show the contributors" 

    Write-Host "   -QuietLogo" -NoNewline -ForegroundColor Green
    Write-Host " : Hide Execute WELA Logo" 

    Write-Host
    
}