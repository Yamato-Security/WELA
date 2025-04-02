function ShowVerboseSecurity {
    $m_credential_validation = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_kerberos_authentication_service = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_kerberos_sevice_ticket_operations = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_computer_account_management = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_other_account_management = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_security_group_management = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_user_account_management = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_plug_and_play_events = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_process_creation = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_process_termination = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_rpc_events = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_token_right_adjusted_events = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_directory_service_access = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_account_lockout = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_logoff = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_logon = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_other_logon_logoff_events = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_special_logon = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_certification_services = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_detailed_file_share = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_file_share = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_file_system = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_filtering_platform_connection = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_filtering_platform_packet_drop = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_kernel_object = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_handle_manipulation = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_other_object_access_events = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_registry = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_removable_storage = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_sam = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_audit_policy_change = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_authentication_policy_change = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_authorization_policy_change = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_filtering_platform_policy_change = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_mpssvc_rule_level_policy_change = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_other_policy_change_events = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_non_sensitive_use_events = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_sensitive_privilege_use = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_other_system_events = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_security_state_change = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_security_system_extension = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"
    $m_system_integrity = "disabled (critical: 10 | high: 100 | medium | low: 10, info: 1000)"

    $msg  = @"
Detailed Security category settings:
Account Logon
  - Credential Validation $m_credential_validation
    - Volume: Depends on NTLM usage. Could be high on DCs and low on clients and servers.
    - Default settings: Client OS: No Auditing | Server OS: Success
    - Recommended settings: Client and Server OSes: Success and Failure
  - Kerberos Authentication Service $m_kerberos_authentication_service
    - Volume: High
    - Default settings: Client OS: No Auditing | Server OS: Success
    - Recommended settings: Client OS: No Auditing | Server OS: Success and Failure
  - Kerberos Service Ticket Operations $m_kerberos_sevice_ticket_operations
    - Volume: High
    - Default settings: Client OS: No Auditing | Server OS: Success
    - Recommended settings: Domain Controllers: Success and Failure
Account Management
  - Computer Account Management $m_computer_account_management
    - Volume: Low
    - Default settings: Client OS: No Auditing | Server OS: Success Only
    - Recommended settings: Domain Controllers: Success and Failure
  - Other Account Management Events $m_other_account_management
    - Volume: Low
    - Default settings: No Auditing
    - Recommended settings: Success and Failure
  - Security Group Management $m_security_group_management
    - Volume: Low
    - Default settings: Success
    - Recommended settings: Success and Failure
  - User Account Management $m_user_account_management
    - Volume: Low
    - Default settings: Success
    - Recommended settings: Success and Failure
Detailed Tracking
  - Plug and Play Events $m_plug_and_play_events
    - Volume: Typcially low
    - Default settings: No Auditing
    - Recommended settings: Success and Failure
  - Process Creation $m_process_creation
    - Volume: High
    - Default settings: No Auditing
    - Recommended settings: Success and Failure if sysmon is not configured.
  - Process Termination $m_process_termination
    - Volume: High
    - Default settings: No Auditing
    - Recommended settings: No Auditing unless you want to track the lifespan of processes.
  - RPC (Remote Procedure Call) Events $m_rpc_events
    - Volume: High on RPC servers (According to Microsoft)
    - Default settings: No Auditing
    - Recommended settings: Unknown. Needs testing.
  - Token Right Adjusted Events $m_token_right_adjusted_events
    - Volume: Unknown
    - Default settings: No Auditing
    - Recommended settings: Unknown. Needs testing.
DS (Directory Service) Access
  - Directory Service Access $m_directory_service_access
    - Volume: High
    - Default settings: Client OS: No Auditing | Server OS: Success
    - Recommended settings: Client OS: No Auditing | ADDS Server: Success and Failure
  - Directory Service Changes
    - Volume: High
    - Default settings: No Auditing
    - Recommended settings: Client OS: No Auditing | ADDS Server: Success and Failure
Logon/Logoff
  - Account Lockout $m_account_lockout
    - Volume: Low
    - Default settings: Success
    - Recommended settings: Success and Failure
  - Group Membership
    - Volume: Adds an extra 4627 event to every logon.
    - Default settings: No Auditing
    - Recommended settings: No Auditing
  - Logoff $m_logoff
    - Volume: High
    - Default settings: Success
    - Recommended settings: Success
  - Logon $m_logon
    - Volume: Low on clients, medium on DCs or network servers
    - Default settings: Client OS: Success | Server OS: Success and Failure
    - Recommended settings: Success and Failure
  - Other Logon/Logoff Events $m_other_logon_logoff_events
    - Volume: Low
    - Default settings: No Auditing
    - Recommended settings: Success and Failure
  - Special Logon $m_special_logon
    - Volume: Low on clients. Medium on DC or network servers.
    - Default settings: Success
    - Recommended settings: Success and Failure
Object Access
  - Certification Services $m_certification_services
    - Volume: Low to medium
    - Default settings: No Auditing
    - Recommended settings: Success and Failure for AD CS role servers.
  - Detailed File Share $m_detailed_file_share
    - Volume: Very high for file servers and DCs, however, may be necessary if you want to track who is accessing what files as well as detect various lateral movement.
    - Default settings: No Auditing
    - Recommended settings: No Auditing due to the high noise level. Enable if you can though.
  - File Share $m_file_share
    - Volume: High for file servers and DCs.
    - Default settings: No Auditing
    - Recommended settings: Success and Failure
  - File System $m_file_system
    - Volume: Depends on SACL rules
    - Default settings: No Auditing
    - Recommended settings: Enable SACLs just for sensitive files
  - Filtering Platform Connection $m_filtering_platform_connection
    - Volume: High
    - Default settings: No Auditing
    - Recommended settings: Success and Failure if you have enough space and are not monitoring network connections with sysmon. This should cause a high amount of events though.
  - Filtering Platform Packet Drop $m_filtering_platform_packet_drop
    - Volume: High
    - Default settings: No Auditing
    - Recommended settings: Success and Failure if you have enough space and are not monitoring network connections with sysmon. This should cause a high amount of events though.
  - Kernel Object $m_kernel_object
    - Volume: High if auditing access of global object access is enabled
    - Default settings: No Auditing
    - Recommended settings: Success and Failure but do not enable Audit the access of global system objects as you will generate too many 4663: Object Access events.
  - Handle Manipulation $m_handle_manipulation
    - Volume: High
    - Default settings: No Auditing
    - Recommended settings: Success and Failure
  - Other Object Access Events $m_other_object_access_events
    - Volume: Low
    - Default settings: No Auditing
    - Recommended settings: Success and Failure
  - Registry $m_registry
    - Volume: Depends on SACLs
    - Default settings: No Auditing
    - Recommended settings: Set SACLs for only the registry keys that you want to monitor
  - Removable Storage $m_removable_storage
    - Volume: Depends on how much removable storage is used
    - Default settings: No Auditing
    - Recommended settings: Success and Failure if you want to monitor external device usage.
  - SAM $m_sam
    - Volume: High volume of events on Domain Controllers
    - Default settings: No Auditing
    - Recommended settings: Success and Failure if you can but may cause too high volume of noise so should be tested beforehand.
Policy Change
  - Audit Policy Change $m_audit_policy_change
    - Volume: Low
    - Default settings: Success
    - Recommended settings: Success and Failure
  - Authentication Policy Change $m_authentication_policy_change
    - Volume: Low
    - Default settings: Success
    - Recommended settings: Success and Failure
  - Authorization Policy Change $m_authorization_policy_change
    - Volume: Medium to High
    - Default settings: No Auditing
    - Recommended settings: Unknown. Needs testing.
  - Filtering Platform Policy Change $m_filtering_platform_policy_change
    - Volume: Low
    - Default settings: No Auditing
    - Recommended settings: Unknown, Needs testing.
  - MPSSVC Rule-Level Policy Change $m_mpssvc_rule_level_policy_change
    - Volume: Low
    - Default settings: No Auditing
    - Recommended settings: Unknown. Needs testing.
  - Other Policy Change Events $m_other_policy_change_events
    - Volume: Low
    - Default settings: No Auditing
    - Recommended settings: No Auditing (Note: ACSC recommends Success and Failure, however, this results in a lot of noise of 5447 (A Windows Filtering Platform filter has been changed) events being generated.)
Privilege Use
  - Non Sensitive Use Events $m_non_sensitive_use_events
    - Volume: Very high
    - Default settings: No Auditing
    - Recommended settings: No Auditing
  - Sensitive Privilege Use $m_sensitive_privilege_use
    - Volume: High
    - Default settings: No Auditing
    - Recommended settings: Success and Failure However, this may be too noisy.
System
  - Other System Events $m_other_system_events
    - Volume: Low
    - Default settings: Success and Failure
    - Recommended settings: Unknown. Needs testing.
  - Security State Change $m_security_state_change
    - Volume: Low
    - Default settings: Success
    - Recommended settings: Success and Failure
  - Security System Extension $m_security_system_extension
    - Volume: Low, but more on DCs
    - Default settings: No Auditing
    - Recommended settings: Success and Failure
  - System Integrity $m_system_integrity
    - Volume: Low
    - Default settings: Sucess, Failure
    - Recommended settings: Success and Failure
"@

    $msgLines = $msg -split "`n"
    foreach ($line in $msgLines) {
        if ($line -contains 'disabled') {
            Write-Host $line -ForegroundColor Red
        } else {
            Write-Host "****"
            Write-Host $line
        }
    }
    Write-Host ""
}