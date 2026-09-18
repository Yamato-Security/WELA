# Native audit controls and their prerequisites

The WELA native profile supports the following audit subcategories in addition to
its original configure policy list. Source-specific profiles keep their own
success/failure masks; selecting a profile does not combine all guides globally.

| Subcategory | WELA target | Other reviewed requirements |
| --- | --- | --- |
| Group Membership | Success | Microsoft SCT, CIS v4 and ASD native: Success; CIS specifies a minimum. |
| Application Group Management | Success and Failure | CIS v4 section 17.2.1: both outcomes. |
| Authorization Policy Change | Success | CIS v4 and Server 2025 SCT: Success; Microsoft WEF Appendix A: both outcomes. |
| MPSSVC Rule-Level Policy Change | Success and Failure | Microsoft SCT, CIS v4 and Microsoft WEF: both outcomes. |
| IPsec Driver | Success and Failure | CIS v4 and Microsoft generic audit guidance: both outcomes. |
| Kernel Object | Success and Failure | ASD native: both outcomes; matching object SACLs and access semantics are separate prerequisites. |

The mask describes policy configuration, not a promise that every operation emits
both kinds of event. Event generation depends on Windows version, role, object
access, and whether the activity occurs. Application Group Management events are
only relevant when application groups are used. Group Membership events provide
logon group context; they do not substitute for Security Group Management events.
IPsec Driver auditing does not enable IPsec or define connection security rules.

Enabling Kernel Object auditing does not create a matching audit ACE on every
object. The plan records this dependency; WELA must not count a rule as verified
solely because the auditpol setting is enabled. The existing `configure-sacl`
command handles selected file/registry targets, not arbitrary kernel objects or
AD directory objects.

Use `plan` to inspect the selected profile and its source provenance before
applying it. The plan distinguishes exact and minimum masks, settings the source
leaves unconfigured, and controls that do not apply to the selected role/build.
Minimum Success or Failure requirements preserve the other effective audit bit.
The advanced-audit profile does not install Sysmon or change firewall enforcement.

## Source versions

- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319): Windows 11 24H2/25H2 and Windows Server 2022/2025 v2602 packages.
- [Microsoft audit recommendations](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations).
- [Microsoft WEF Appendix A](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection).
- [ASD Windows event logging and forwarding](https://www.cyber.gov.au/business-government/detecting-responding-to-threats/event-logging/windows-event-logging-and-forwarding): 2021 publication, native fallback.
- CIS Windows 11 Enterprise and Windows Server 2022 **v4.0.0**: historical reviewed benchmarks, not a claim about current CIS requirements. The profile data records control numbers and source links.

Tests exercise policy masks, source-profile differences and the object-auditing
dependency. They do not establish live event production or detection coverage;
validate those on the applicable Windows roles with representative benign events.
