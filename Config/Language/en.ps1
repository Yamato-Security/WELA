<#
language config:English version
#>

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
    
    EventTitle      = 'Account logon';
    TimelineDetect = "Yes";
}
$4625 = @{
    EventTitle      = 'Failed logon';
    TimelineDetect = "Yes"; 
}
$4634 = @{
    EventTitle      = 'Logoff';
    TimelineDetect = "Yes"
}
$4647 = @{
    EventTitle      = 'Logoff';
    TimelineDetect = "Yes" 
}
$4648 = @{
    EventTitle      = 'Explicit logon';
    TimelineDetect = "Yes"
}
$4672 = @{
    EventTitle      = 'Admin logon';
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
    EventTitle = 'Domain policy channged';
}
    
$4776 = @{
    EventTitle = 'NTLM logon to local user';
}
    
$4778 = @{
    EventTitle = 'RDP session reconnected or user switched back through Fast Userr Switching';
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
    Comment = "Too much noise when firewall starts" ;
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
    EventTitle = 'An object was added to the COM+ Catalog';
}
$5890 = @{
    EventTitle = 'An object was added to the COM+ Catalog';
}
$unregistered_event_id = @{
    EventTitle = "Unknown";
}