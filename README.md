# Active Directory Kill Chain Attack & Defense

<img width="650" src="https://camo.githubusercontent.com/9547d8152e3490a6e5e3da0279faab64340885be/68747470733a2f2f646f63732e6d6963726f736f66742e636f6d2f656e2d75732f616476616e6365642d7468726561742d616e616c79746963732f6d656469612f61747461636b2d6b696c6c2d636861696e2d736d616c6c2e6a7067">

## Summary
This document was designed to be a useful, informational asset for those looking to understand the specific tactics, techniques, and procedures (TTPs) attackers are leveraging to compromise active directory and guidance to mitigation, detection, and prevention. And understand Active Directory Kill Chain Attack and Modern Post Exploitation Adversary Tradecraft Activity.

## Table of Contents
* [Discovery](#discovery)
* [Privilege Escalation](#privilege-escalation)
* [Defense Evasion](#defense-evasion)
* [Credential Dumping](#credential-dumping)
* [Lateral Movement](#lateral-movement)
* [Persistence](#persistence)
* [Defense & Detection](#defense-&-detection)

------

## Discovery
### SPN Scanning
* [SPN Scanning – Service Discovery without Network Port Scanning](https://adsecurity.org/?p=1508)
* [Active Directory: PowerShell script to list all SPNs used](https://social.technet.microsoft.com/wiki/contents/articles/18996.active-directory-powershell-script-to-list-all-spns-used.aspx)
* [Discovering Service Accounts Without Using Privileges](https://blog.stealthbits.com/discovering-service-accounts-without-using-privileges/)

### Data Mining
* [A Data Hunting Overview](https://thevivi.net/2018/05/23/a-data-hunting-overview/)
* [Push it, Push it Real Good](https://www.harmj0y.net/blog/redteaming/push-it-push-it-real-good/)
* [Finding Sensitive Data on Domain SQL Servers using PowerUpSQL](https://blog.netspi.com/finding-sensitive-data-domain-sql-servers-using-powerupsql/)
* [Sensitive Data Discovery in Email with MailSniper](https://www.youtube.com/watch?v=ZIOw_xfqkKM)
* [Remotely Searching for Sensitive Files](https://www.fortynorthsecurity.com/remotely-search/)
* [I Hunt Sysadmins - harmj0y](http://www.harmj0y.net/blog/penetesting/i-hunt-sysadmins/)

### User Hunting
* [Hidden Administrative Accounts: BloodHound to the Rescue](https://www.crowdstrike.com/blog/hidden-administrative-accounts-bloodhound-to-the-rescue/)
* [Active Directory Recon Without Admin Rights](https://adsecurity.org/?p=2535)
* [Gathering AD Data with the Active Directory PowerShell Module](https://adsecurity.org/?p=3719)
* [Using ActiveDirectory module for Domain Enumeration from PowerShell Constrained Language Mode](http://www.labofapenetrationtester.com/2018/10/domain-enumeration-from-PowerShell-CLM.html)
* [PowerUpSQL Active Directory Recon Functions](https://github.com/NetSPI/PowerUpSQL/wiki/Active-Directory-Recon-Functions)
* [Derivative Local Admin](https://medium.com/@sixdub/derivative-local-admin-cdd09445aac8)
* [Automated Derivative Administrator Search](https://wald0.com/?p=14)
* [Dumping Active Directory Domain Info – with PowerUpSQL!](https://blog.netspi.com/dumping-active-directory-domain-info-with-powerupsql/)
* [Local Group Enumeration](https://www.harmj0y.net/blog/redteaming/local-group-enumeration/)
* [Attack Mapping With Bloodhound](https://blog.stealthbits.com/local-admin-mapping-bloodhound)
* [Situational Awareness](https://pentestlab.blog/2018/05/28/situational-awareness/)
* [Commands for Domain Network Compromise](https://www.javelin-networks.com/static/5fcc6e84.pdf)
* [A Pentester’s Guide to Group Scoping](https://www.harmj0y.net/blog/activedirectory/a-pentesters-guide-to-group-scoping/)

### LAPS
* [Microsoft LAPS Security & Active Directory LAPS Configuration Recon](https://adsecurity.org/?p=3164)
* [Running LAPS with PowerView](https://www.harmj0y.net/blog/powershell/running-laps-with-powerview/)
* [RastaMouse LAPS Part 1 & 2](https://rastamouse.me/tags/laps/)

### AppLocker
* [Enumerating AppLocker Config](https://rastamouse.me/blog/applocker/)

### Active Directory Federation Services
* [118 Attacking ADFS Endpoints with PowerShell Karl Fosaaen](https://www.youtube.com/watch?v=oTyLdAUjw30)
* [Using PowerShell to Identify Federated Domains](https://blog.netspi.com/using-powershell-identify-federated-domains/)
* [LyncSniper: A tool for penetration testing Skype for Business and Lync deployments](https://github.com/mdsecresearch/LyncSniper)
* [Troopers 19 - I am AD FS and So Can You](https://www.slideshare.net/DouglasBienstock/troopers-19-i-am-ad-fs-and-so-can-you)
------

## Privilege Escalation

### Abusing Active Directory Certificate Services
* [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)

### PetitPotam 
* [PetitPotam](https://github.com/topotam/PetitPotam)
* [From Stranger to DA // Using PetitPotam to NTLM relay to Domain Administrator](https://blog.truesec.com/2021/08/05/from-stranger-to-da-using-petitpotam-to-ntlm-relay-to-active-directory/)

### Zerologon
* [Cobalt Strike ZeroLogon-BOF](https://github.com/rsmudge/ZeroLogon-BOF)
* [CVE-2020-1472 POC](https://github.com/dirkjanm/CVE-2020-1472)
* [Zerologon: instantly become domain admin by subverting Netlogon cryptography (CVE-2020-1472)](https://www.secura.com/blog/zero-logon)

### Passwords in SYSVOL & Group Policy Preferences
* [Finding Passwords in SYSVOL & Exploiting Group Policy Preferences](https://adsecurity.org/?p=2288)
* [Pentesting in the Real World: Group Policy Pwnage](https://blog.rapid7.com/2016/07/27/pentesting-in-the-real-world-group-policy-pwnage/)

### MS14-068 Kerberos Vulnerability
* [MS14-068: Vulnerability in (Active Directory) Kerberos Could Allow Elevation of Privilege](https://adsecurity.org/?p=525)
* [Digging into MS14-068, Exploitation and Defence](https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/)
* [From MS14-068 to Full Compromise – Step by Step](https://www.trustedsec.com/2014/12/ms14-068-full-compromise-step-step/)

### DNSAdmins
* [Abusing DNSAdmins privilege for escalation in Active Directory](http://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
* [From DNSAdmins to Domain Admin, When DNSAdmins is More than Just DNS Administration](https://adsecurity.org/?p=4064)

### Kerberos Delegation
* [Constructing Kerberos Attacks with Delegation Primitives](https://shenaniganslabs.io/media/Constructing%20Kerberos%20Attacks%20with%20Delegation%20Primitives.pdf)
* [No Shells Required - a Walkthrough on Using Impacket and Kerberos to Delegate Your Way to DA](http://blog.redxorblue.com/2019/12/no-shells-required-using-impacket-to.html)
* [CVE-2020-17049: Kerberos Bronze Bit Attack – Overview](https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-overview/)

#### Unconstrained Delegation
* [Domain Controller Print Server + Unconstrained Kerberos Delegation = Pwned Active Directory Forest](https://adsecurity.org/?p=4056)
* [Active Directory Security Risk #101: Kerberos Unconstrained Delegation (or How Compromise of a Single Server Can Compromise the Domain)](https://adsecurity.org/?p=1667)
* [Unconstrained Delegation Permissions](https://blog.stealthbits.com/unconstrained-delegation-permissions/)
* [Trust? Years to earn, seconds to break](https://labs.mwrinfosecurity.com/blog/trust-years-to-earn-seconds-to-break/)
* [Hunting in Active Directory: Unconstrained Delegation & Forests Trusts](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
* [Exploiting Unconstrained Delegation](https://www.riccardoancarani.it/exploiting-unconstrained-delegation/)

#### Constrained Delegation
* [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
* [From Kekeo to Rubeus](https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/)
* [S4U2Pwnage](http://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)
* [Kerberos Delegation, Spns And More...](https://www.secureauth.com/blog/kerberos-delegation-spns-and-more)

#### Resource-Based Constrained Delegation
* [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [Kerberos Resource-based Constrained Delegation: Computer Object Take Over](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution)
* [Resource Based Constrained Delegation](https://blog.stealthbits.com/resource-based-constrained-delegation-abuse/)
* [A Case Study in Wagging the Dog: Computer Takeover](http://www.harmj0y.net/blog/activedirectory/a-case-study-in-wagging-the-dog-computer-takeover/)
* [BloodHound 2.1's New Computer Takeover Attack](https://www.youtube.com/watch?v=RUbADHcBLKg)

### Insecure Group Policy Object Permission Rights
* [Abusing GPO Permissions](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [A Red Teamer’s Guide to GPOs and OUs](https://wald0.com/?p=179)
* [File templates for GPO Abuse](https://github.com/rasta-mouse/GPO-Abuse)
* [GPO Abuse - Part 1](https://rastamouse.me/blog/gpo-abuse-pt1/)
* [GPO Abuse - Part 2](https://rastamouse.me/blog/gpo-abuse-pt2/)
* [SharpGPOAbuse](https://github.com/mwrlabs/SharpGPOAbuse)

### Insecure ACLs Permission Rights
* [Exploiting Weak Active Directory Permissions With Powersploit](https://blog.stealthbits.com/exploiting-weak-active-directory-permissions-with-powersploit/)
* [Escalating privileges with ACLs in Active Directory
](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [Abusing Active Directory Permissions with PowerView
](http://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/)
* [BloodHound 1.3 – The ACL Attack Path Update](https://wald0.com/?p=112)
* [Scanning for Active Directory Privileges & Privileged Accounts](https://adsecurity.org/?p=3658)
* [Active Directory Access Control List – Attacks and Defense](https://techcommunity.microsoft.com/t5/Enterprise-Mobility-Security/Active-Directory-Access-Control-List-8211-Attacks-and-Defense/ba-p/250315)
* [aclpwn - Active Directory ACL exploitation with BloodHound](https://www.slideshare.net/DirkjanMollema/aclpwn-active-directory-acl-exploitation-with-bloodhound)

### Domain Trusts
* [A Guide to Attacking Domain Trusts](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
* [It's All About Trust – Forging Kerberos Trust Tickets to Spoof Access across Active Directory Trusts](https://adsecurity.org/?p=1588)
* [Active Directory forest trusts part 1 - How does SID filtering work?](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work)
* [The Forest Is Under Control. Taking over the entire Active Directory forest](https://hackmag.com/security/ad-forest/)
* [Not A Security Boundary: Breaking Forest Trusts](https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d)
* [The Trustpocalypse](http://www.harmj0y.net/blog/redteaming/the-trustpocalypse/)
* [Pentesting Active Directory Forests](https://www.dropbox.com/s/ilzjtlo0vbyu1u0/Carlos%20Garcia%20-%20Rooted2019%20-%20Pentesting%20Active%20Directory%20Forests%20public.pdf?dl=0)
* [Security Considerations for Active Directory (AD) Trusts](https://adsecurity.org/?p=282)
* [Kerberos Golden Tickets are Now More Golden](https://adsecurity.org/?p=1640)

### DCShadow
* [Privilege Escalation With DCShadow](https://blog.stealthbits.com/privilege-escalation-with-dcshadow/)
* [DCShadow](https://pentestlab.blog/2018/04/16/dcshadow/)
* [DCShadow explained: A technical deep dive into the latest AD attack technique](https://blog.alsid.eu/dcshadow-explained-4510f52fc19d)
* [DCShadow - Silently turn off Active Directory Auditing](http://www.labofapenetrationtester.com/2018/05/dcshadow-sacl.html)
* [DCShadow - Minimal permissions, Active Directory Deception, Shadowception and more](http://www.labofapenetrationtester.com/2018/04/dcshadow.html)

### RID
* [Rid Hijacking: When Guests Become Admins](https://blog.stealthbits.com/rid-hijacking-when-guests-become-admins/)

### Microsoft SQL Server
* [How to get SQL Server Sysadmin Privileges as a Local Admin with PowerUpSQL](https://blog.netspi.com/get-sql-server-sysadmin-privileges-local-admin-powerupsql/)
* [Compromise With Powerupsql – Sql Attacks](https://blog.stealthbits.com/compromise-with-powerupsql-sql-attacks/)

### Red Forest
* [Attack and defend Microsoft Enhanced Security Administrative](https://download.ernw-insight.de/troopers/tr18/slides/TR18_AD_Attack-and-Defend-Microsoft-Enhanced-Security.pdf)

### Exchange
* [Exchange-AD-Privesc](https://github.com/gdedrouas/Exchange-AD-Privesc)
* [Abusing Exchange: One API call away from Domain Admin](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
* [NtlmRelayToEWS](https://github.com/Arno0x/NtlmRelayToEWS)

### NTLM Relay & LLMNR/NBNS
* [Pwning with Responder – A Pentester’s Guide](https://www.notsosecure.com/pwning-with-responder-a-pentesters-guide/)
* [Practical guide to NTLM Relaying in 2017 (A.K.A getting a foothold in under 5 minutes)](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)
* [Relaying credentials everywhere with ntlmrelayx](https://www.fox-it.com/en/insights/blogs/blog/inside-windows-network/)
* [Beyond LLMNR/NBNS Spoofing – Exploiting Active Directory-Integrated DNS](https://blog.netspi.com/exploiting-adidns/)
* [Combining NTLM Relaying and Kerberos delegation](https://chryzsh.github.io/relaying-delegation/)
* [mitm6 – compromising IPv4 networks via IPv6](https://www.fox-it.com/en/news/blog/mitm6-compromising-ipv4-networks-via-ipv6/)
* [The worst of both worlds: Combining NTLM Relaying and Kerberos delegation](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)
------

## Lateral Movement
### Microsoft SQL Server Database links
* [SQL Server – Link… Link… Link… and Shell: How to Hack Database Links in SQL Server!](https://blog.netspi.com/how-to-hack-database-links-in-sql-server/)
* [SQL Server Link Crawling with PowerUpSQL](https://blog.netspi.com/sql-server-link-crawling-powerupsql/)

### Pass The Hash
* [Performing Pass-the-hash Attacks With Mimikatz](https://blog.stealthbits.com/passing-the-hash-with-mimikatz)
* [How to Pass-the-Hash with Mimikatz](https://blog.cobaltstrike.com/2015/05/21/how-to-pass-the-hash-with-mimikatz/)
* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy](https://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)

### System Center Configuration Manager (SCCM)
* [Targeted Workstation Compromise With Sccm](https://enigma0x3.net/2015/10/27/targeted-workstation-compromise-with-sccm/)
* [PowerSCCM - PowerShell module to interact with SCCM deployments](https://github.com/PowerShellMafia/PowerSCCM)

### WSUS
* [Remote Weaponization of WSUS MITM](https://www.sixdub.net/?p=623)
* [WSUSpendu](https://www.blackhat.com/docs/us-17/wednesday/us-17-Coltel-WSUSpendu-Use-WSUS-To-Hang-Its-Clients-wp.pdf)
* [Leveraging WSUS – Part One](https://ijustwannared.team/2018/10/15/leveraging-wsus-part-one/)

### Password Spraying
* [Password Spraying Windows Active Directory Accounts - Tradecraft Security Weekly #5](https://www.youtube.com/watch?v=xB26QhnL64c)
* [Attacking Exchange with MailSniper](https://www.blackhillsinfosec.com/attacking-exchange-with-mailsniper/)
* [A Password Spraying tool for Active Directory Credentials by Jacob Wilkin](https://github.com/SpiderLabs/Spray)
* [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit)

### Automated Lateral Movement
* [GoFetch is a tool to automatically exercise an attack plan generated by the BloodHound application](https://github.com/GoFetchAD/GoFetch)
* [DeathStar - Automate getting Domain Admin using Empire](https://github.com/byt3bl33d3r/DeathStar)
* [ANGRYPUPPY - Bloodhound Attack Path Automation in CobaltStrike](https://github.com/vysec/ANGRYPUPPY)
------

## Defense Evasion

### In-Memory Evasion
* [Bypassing Memory Scanners with Cobalt Strike and Gargoyle](https://labs.mwrinfosecurity.com/blog/experimenting-bypassing-memory-scanners-with-cobalt-strike-and-gargoyle/)
* [In-Memory Evasions Course](https://www.youtube.com/playlist?list=PL9HO6M_MU2nc5Q31qd2CwpZ8J4KFMhgnK)
* [Bring Your Own Land (BYOL) – A Novel Red Teaming Technique](https://www.fireeye.com/blog/threat-research/2018/06/bring-your-own-land-novel-red-teaming-technique.html)

### Endpoint Detection and Response (EDR) Evasion
* [Red Teaming in the EDR age](https://youtu.be/l8nkXCOYQC4)
* [Sharp-Suite - Process Argument Spoofing](https://github.com/FuzzySecurity/Sharp-Suite)
* [Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)
* [Dechaining Macros and Evading EDR](https://www.countercept.com/blog/dechaining-macros-and-evading-edr/)
* [Bypass EDR’s memory protection, introduction to hooking](https://medium.com/@fsx30/bypass-edrs-memory-protection-introduction-to-hooking-2efb21acffd6)
* [Bypassing Cylance and other AVs/EDRs by Unhooking Windows APIs](https://ired.team/offensive-security/defense-evasion/bypassing-cylance-and-other-avs-edrs-by-unhooking-windows-apis)
* [Silencing Cylance: A Case Study in Modern EDRs](https://www.mdsec.co.uk/2019/03/silencing-cylance-a-case-study-in-modern-edrs/)

### OPSEC
* [Modern Defenses and YOU!](https://blog.cobaltstrike.com/2017/10/25/modern-defenses-and-you/)
* [OPSEC Considerations for Beacon Commands](https://blog.cobaltstrike.com/2017/06/23/opsec-considerations-for-beacon-commands/)
* [Red Team Tradecraft and TTP Guidance](https://sec564.com/#!docs/tradecraft.md)
* [Fighting the Toolset](https://www.youtube.com/watch?v=RoqVunX_sqA)

### Microsoft ATA & ATP Evasion
* [Red Team Techniques for Evading, Bypassing, and Disabling MS
Advanced Threat Protection and Advanced Threat Analytics](https://www.blackhat.com/docs/eu-17/materials/eu-17-Thompson-Red-Team-Techniques-For-Evading-Bypassing-And-Disabling-MS-Advanced-Threat-Protection-And-Advanced-Threat-Analytics.pdf)
* [Red Team Revenge - Attacking Microsoft ATA](https://www.slideshare.net/nikhil_mittal/red-team-revenge-attacking-microsoft-ata)
* [Evading Microsoft ATA for Active Directory Domination](https://www.slideshare.net/nikhil_mittal/evading-microsoft-ata-for-active-directory-domination)

### PowerShell ScriptBlock Logging Bypass
* [PowerShell ScriptBlock Logging Bypass](https://cobbr.io/ScriptBlock-Logging-Bypass.html)

### PowerShell Anti-Malware Scan Interface (AMSI) Bypass
* [How to bypass AMSI and execute ANY malicious Powershell code](https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html)
* [AMSI: How Windows 10 Plans to Stop Script-Based Attacks](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
* [AMSI Bypass: Patching Technique](https://www.cyberark.com/threat-research-blog/amsi-bypass-patching-technique/)
* [Invisi-Shell - Hide your Powershell script in plain sight. Bypass all Powershell security features](https://github.com/OmerYa/Invisi-Shell)
* [Dynamic Microsoft Office 365 AMSI In Memory Bypass Using VBA](https://secureyourit.co.uk/wp/2019/05/10/dynamic-microsoft-office-365-amsi-in-memory-bypass-using-vba/)
* [AmsiScanBuffer Bypass - Part 1](https://rastamouse.me/2018/10/amsiscanbuffer-bypass---part-1/)
* [AMSI Bypass](https://www.contextis.com/en/blog/amsi-bypass)

### Loading .NET Assemblies Anti-Malware Scan Interface (AMSI) Bypass
* [A PoC function to corrupt the g_amsiContext global variable in clr.dll in .NET Framework Early Access build 3694](https://gist.github.com/mattifestation/ef0132ba4ae3cc136914da32a88106b9)

### AppLocker & Device Guard Bypass
* [Living Off The Land Binaries And Scripts - (LOLBins and LOLScripts)](https://lolbas-project.github.io/)

### Sysmon Evasion
* [Subverting Sysmon: Application of a Formalized Security Product Evasion Methodology](https://github.com/mattifestation/BHUSA2018_Sysmon)
* [sysmon-config-bypass-finder](https://github.com/mkorman90/sysmon-config-bypass-finder)
* [Shhmon — Silencing Sysmon via Driver Unload](https://posts.specterops.io/shhmon-silencing-sysmon-via-driver-unload-682b5be57650)

### HoneyTokens Evasion
* [Forging Trusts for Deception in Active Directory](http://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
* [Honeypot Buster: A Unique Red-Team Tool](https://jblog.javelin-networks.com/blog/the-honeypot-buster/)

### Disabling Security Tools
* [Invoke-Phant0m - Windows Event Log Killer](https://github.com/hlldz/Invoke-Phant0m)

------

## Credential Dumping

### NTDS.DIT Password Extraction
* [How Attackers Pull the Active Directory Database (NTDS.dit) from a Domain Controller](https://adsecurity.org/?p=451)
* [Extracting Password Hashes From The Ntds.dit File](https://blog.stealthbits.com/extracting-password-hashes-from-the-ntds-dit-file/)

### SAM (Security Accounts Manager)
* [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)

### Kerberoasting
* [Kerberoasting Without Mimikatz](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
* [Cracking Kerberos TGS Tickets Using Kerberoast – Exploiting Kerberos to Compromise the Active Directory Domain](https://adsecurity.org/?p=2293)
* [Extracting Service Account Passwords With Kerberoasting](https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/)
* [Cracking Service Account Passwords with Kerberoasting](https://www.cyberark.com/blog/cracking-service-account-passwords-kerberoasting/)
* [Kerberoast PW list for cracking passwords with complexity requirements](https://gist.github.com/edermi/f8b143b11dc020b854178d3809cf91b5)
* [DerbyCon 2019 - Kerberoasting Revisited](https://www.slideshare.net/harmj0y/derbycon-2019-kerberoasting-revisited)

### Kerberos AP-REP Roasting
* [Roasting AS-REPs](http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/) 

### Windows Credential Manager/Vault
* [Operational Guidance for Offensive User DPAPI Abuse](https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/)
* [Jumping Network Segregation with RDP](https://rastamouse.me/blog/rdp-jump-boxes/)

### DCSync
* [Mimikatz and DCSync and ExtraSids, Oh My](https://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/)
* [Mimikatz DCSync Usage, Exploitation, and Detection](https://adsecurity.org/?p=1729)
* [Dump Clear-Text Passwords for All Admins in the Domain Using Mimikatz DCSync](https://adsecurity.org/?p=2053)

### LLMNR/NBT-NS Poisoning
* [LLMNR/NBT-NS Poisoning Using Responder](https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/)

### Others
* [Compromising Plain Text Passwords In Active Directory](https://blog.stealthbits.com/compromising-plain-text-passwords-in-active-directory)
* [Kerberos Tickets on Linux Red Teams](https://www.fireeye.com/blog/threat-research/2020/04/kerberos-tickets-on-linux-red-teams.html)
------

## Persistence
### Golden Ticket
* [Golden Ticket](https://pentestlab.blog/2018/04/09/golden-ticket/)
* [Kerberos Golden Tickets are Now More Golden](https://adsecurity.org/?p=1640)

### SID History
* [Sneaky Active Directory Persistence #14: SID History](https://adsecurity.org/?p=1772)

### Silver Ticket
* [How Attackers Use Kerberos Silver Tickets to Exploit Systems](https://adsecurity.org/?p=2011)
* [Sneaky Active Directory Persistence #16: Computer Accounts & Domain Controller Silver Tickets](https://adsecurity.org/?p=2753)

### DCShadow
* [Creating Persistence With Dcshadow](https://blog.stealthbits.com/creating-persistence-with-dcshadow/)

### AdminSDHolder
* [Sneaky Active Directory Persistence #15: Leverage AdminSDHolder & SDProp to (Re)Gain Domain Admin Rights](https://adsecurity.org/?p=1906)
* [Persistence Using Adminsdholder And Sdprop](https://blog.stealthbits.com/persistence-using-adminsdholder-and-sdprop/)

### Group Policy Object
* [Sneaky Active Directory Persistence #17: Group Policy](https://adsecurity.org/?p=2716)

### Skeleton Keys
* [Unlocking All The Doors To Active Directory With The Skeleton Key Attack](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)
* [Skeleton Key](https://pentestlab.blog/2018/04/10/skeleton-key/)
* [Attackers Can Now Use Mimikatz to Implant Skeleton Key on Domain Controllers & BackDoor Your Active Directory Forest](https://adsecurity.org/?p=1275)

### SeEnableDelegationPrivilege
* [The Most Dangerous User Right You (Probably) Have Never Heard Of](https://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/)
* [SeEnableDelegationPrivilege Active Directory Backdoor](https://www.youtube.com/watch?v=OiqaO9RHskU)

### Security Support Provider
* [Sneaky Active Directory Persistence #12: Malicious Security Support Provider (SSP)](https://adsecurity.org/?p=1760)

### Directory Services Restore Mode
* [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
* [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

### ACLs & Security Descriptors
* [An ACE Up the Sleeve: Designing Active Directory DACL Backdoors](https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf)
* [Shadow Admins – The Stealthy Accounts That You Should Fear The Most](https://www.cyberark.com/threat-research-blog/shadow-admins-stealthy-accounts-fear/)
* [The Unintended Risks of Trusting Active Directory](https://www.slideshare.net/harmj0y/the-unintended-risks-of-trusting-active-directory)

## Tools & Scripts
* [Certify](https://github.com/GhostPack/Certify) - Certify is a C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS).
* [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) - PowerShell toolkit for auditing Active Directory Certificate Services (AD CS).
* [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) - Situational Awareness PowerShell framework
* [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Six Degrees of Domain Admin
* [Impacket](https://github.com/SecureAuthCorp/impacket) - Impacket is a collection of Python classes for working with network protocols
* [aclpwn.py](https://github.com/fox-it/aclpwn.py) - Active Directory ACL exploitation with BloodHound
* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - A swiss army knife for pentesting networks
* [ADACLScanner](https://github.com/canix1/ADACLScanner) - A tool with GUI or command linte used to create reports of access control lists (DACLs) and system access control lists (SACLs) in Active Directory
* [zBang](https://github.com/cyberark/zBang) - zBang is a risk assessment tool that detects potential privileged account threats
* [SafetyKatz](https://github.com/GhostPack/SafetyKatz) - SafetyKatz is a combination of slightly modified version of @gentilkiwi's Mimikatz project and @subTee's .NET PE Loader.
* [SharpDump](https://github.com/GhostPack/SharpDump) - SharpDump is a C# port of PowerSploit's Out-Minidump.ps1 functionality.
* [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL) - A PowerShell Toolkit for Attacking SQL Server
* [Rubeus](https://github.com/GhostPack/Rubeus) -  Rubeus is a C# toolset for raw Kerberos interaction and abuses
* [ADRecon](https://github.com/sense-of-security/ADRecon) - A tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment
* [Mimikatz](https://github.com/gentilkiwi/mimikatz) - Utility to extract plaintexts passwords, hash, PIN code and kerberos tickets from memory but also perform pass-the-hash, pass-the-ticket or build Golden tickets
* [Grouper](https://github.com/l0ss/Grouper) - A PowerShell script for helping to find vulnerable settings in AD Group Policy.
* [Powermad](https://github.com/Kevin-Robertson/Powermad) - PowerShell MachineAccountQuota and DNS exploit tools
* [RACE](https://github.com/samratashok/RACE) - RACE is a PowerShell module for executing ACL attacks against Windows targets.
* [DomainPasswordSpray](https://github.com/mdavis332/DomainPasswordSpray) - DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. 
* [MailSniper](https://github.com/dafthack/MailSniper) - MailSniper is a penetration testing tool for searching through email in a Microsoft Exchange environment for specific terms (passwords, insider intel, network architecture information, etc.)
* [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) - Tool to audit and attack LAPS environments.
* [CredDefense](https://github.com/CredDefense/CredDefense) - Credential and Red Teaming Defense for Windows Environments
* [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) - Active Directory information dumper via LDAP
* [SpoolSample](https://github.com/leechristensen/SpoolSample/) - PoC tool to coerce Windows hosts authenticate to other machines via the MS-RPRN RPC interface
* [adconnectdump](https://github.com/fox-it/adconnectdump) - Azure AD Connect password extraction
* [o365recon](https://github.com/nyxgeek/o365recon) - Script to retrieve information via O365 with a valid cred
* [ROADtools](https://github.com/dirkjanm/ROADtools) - ROADtools is a framework to interact with Azure AD. I
* [Stormspotter](https://github.com/Azure/Stormspotter) - Stormspotter creates an “attack graph” of the resources in an Azure subscription.
* [AADInternals](https://github.com/Gerenios/AADInternals) - AADInternals is PowerShell module for administering Azure AD and Office 365
* [MicroBurst: A PowerShell Toolkit for Attacking Azure](https://github.com/NetSPI/MicroBurst) - MicroBurst includes functions and scripts that support Azure Services discovery, weak configuration auditing, and post exploitation actions such as credential dumping. 

## Ebooks
* [The Dog Whisperer’s Handbook – A Hacker’s Guide to the BloodHound Galaxy](https://www.ernw.de/download/BloodHoundWorkshop/ERNW_DogWhispererHandbook.pdf)
* [Varonis eBook: Pen Testing Active Directory Environments](https://www.varonis.com/blog/varonis-ebook-pen-testing-active-directory-environments/)

## Cheat Sheets
* [Tools Cheat Sheets](https://github.com/HarmJ0y/CheatSheets) - Tools (PowerView, PowerUp, Empire, and PowerSploit)
* [DogWhisperer - BloodHound Cypher Cheat Sheet (v2)](https://github.com/SadProcessor/Cheats/blob/master/DogWhispererV2.md)
* [PowerView-3.0 tips and tricks](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)
* [PowerView-2.0 tips and tricks](https://gist.github.com/HarmJ0y/3328d954607d71362e3c)
* [BloodhoundAD-Queries](https://github.com/Scoubi/BloodhoundAD-Queries)
* [Kerberos Attacks Cheat Sheet](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a)
* [Bloodhound Cypher Cheatsheet](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)
* [Kerberos cheatsheet](https://gist.github.com/knethteo/2fc8af6ea28199fd63a529a73a4176c7)
* [Active Directory Exploitation Cheat Sheet](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet)

## Other Resources
* [Tactics, Techniques and Procedures for Attacking Active Directory BlackHat Asia 2019](https://docs.google.com/presentation/d/1j2nW05H-iRz7-FVTRh-LBXQm6M6YIBQNWa4V7tp99YQ/)
* [Bloodhound walkthrough. A Tool for Many Tradecrafts](https://www.pentestpartners.com/security-blog/bloodhound-walkthrough-a-tool-for-many-tradecrafts/)
* [Attack Methods for Gaining Domain Admin Rights in Active Directory](https://adsecurity.org/?p=2362)
* [PowerShell Is Dead Epic Learnings](https://www.slideshare.net/nettitude_labs/powershellisdeadepiclearningslondon)
* [Finding Our Path: How We’re Trying to Improve Active Directory Security](https://docs.google.com/presentation/d/1lQHTqXZIDxwaIUnXdO-EdvGp79RzH1rbM4zE45Kki2I/edit#slide=id.g35f391192_00)
* [SteelCon 2019: Getting Splunky With Kerberos - Ross Bingham and Tom MacDonald](https://www.youtube.com/watch?v=JcFdNAleIk4&feature=youtu.be)
* [AD-security-workshop](https://github.com/wavestone-cdt/AD-security-workshop)

### Azure Active Directory
* [AZURE AD INTRODUCTION FOR RED TEAMERS](https://www.synacktiv.com/en/publications/azure-ad-introduction-for-red-teamers.html)
* [I'm in your cloud... reading everyone's email. Hacking Azure AD via Active Directory](https://www.slideshare.net/DirkjanMollema/im-in-your-cloud-reading-everyones-email-hacking-azure-ad-via-active-directory)
* [Utilizing Azure Services for Red Team Engagements](https://blog.netspi.com/utiilzing-azure-for-red-team-engagements/)
* [Blue Cloud of Death: Red Teaming Azure](https://speakerdeck.com/tweekfawkes/blue-cloud-of-death-red-teaming-azure-1)
* [Azure AD Connect for Red Teamers](https://blog.xpnsec.com/azuread-connect-for-redteam/)
* [Red Teaming Microsoft: Part 1 – Active Directory Leaks via Azure](https://www.blackhillsinfosec.com/red-teaming-microsoft-part-1-active-directory-leaks-via-azure/)
* [Attacking & Defending the Microsoft Cloud](https://adsecurity.org/wp-content/uploads/2019/08/2019-BlackHat-US-Metcalf-Morowczynski-AttackingAndDefendingTheMicrosoftCloud.pdf)
* [How to create a backdoor to Azure AD](https://o365blog.com/post/aadbackdoor/)
* [Azurehound Cypher Cheatsheet](https://hausec.com/2020/11/23/azurehound-cypher-cheatsheet/)
* [Keys of the kingdom: Playing God as Global Admin](https://o365blog.com/post/admin/)
------

## Defense & Detection
### Tools & Scripts
* [Invoke-TrimarcADChecks](https://gofile.io/d/IAKDLn) - The Invoke-TrimarcADChecks.ps1 PowerShell script is designed to gather data from a single domain AD forest to performed Active Directory Security Assessment (ADSA).
* [Create-Tiers in AD](https://github.com/davidprowe/AD_Sec_Tools) - Project Title Active Directory Auto Deployment of Tiers in any environment
* [SAMRi10](https://gallery.technet.microsoft.com/SAMRi10-Hardening-Remote-48d94b5b)  - Hardening SAM Remote Access in Windows 10/Server 2016
* [Net Cease](https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b)  - Hardening Net Session Enumeration
* [PingCastle](https://www.pingcastle.com/) - A tool designed to assess quickly the Active Directory security level with a methodology based on risk assessment and a maturity framework
* [Aorato Skeleton Key Malware Remote DC Scanner](https://gallery.technet.microsoft.com/Aorato-Skeleton-Key-24e46b73) - Remotely scans for the existence of the Skeleton Key Malware
* [Reset the krbtgt account password/keys](https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51) - This script will enable you to reset the krbtgt account password and related keys while minimizing the likelihood of Kerberos authentication issues being caused by the operation
* [Reset The KrbTgt Account Password/Keys For RWDCs/RODCs](https://gallery.technet.microsoft.com/Reset-The-KrbTgt-Account-5f45a414)
* [RiskySPN](https://github.com/cyberark/RiskySPN) - RiskySPNs is a collection of PowerShell scripts focused on detecting and abusing accounts associated with SPNs (Service Principal Name). 
* [Deploy-Deception](https://github.com/samratashok/Deploy-Deception) -  A PowerShell module to deploy active directory decoy objects
* [SpoolerScanner](https://github.com/vletoux/SpoolerScanner) - Check if MS-RPRN is remotely available with powershell/c#
* [dcept](https://github.com/secureworks/dcept) - A tool for deploying and detecting use of Active Directory honeytokens
* [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - Investigate malicious Windows logon by visualizing and analyzing Windows event log
* [DCSYNCMonitor](https://github.com/shellster/DCSYNCMonitor) - Monitors for DCSYNC and DCSHADOW attacks and create custom Windows Events for these events
* [Sigma](https://github.com/Neo23x0/sigma/) - Generic Signature Format for SIEM Systems
* [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) - System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log.
* [SysmonSearch](https://github.com/JPCERTCC/SysmonSearch) - Investigate suspicious activity by visualizing Sysmon's event log
* [ClrGuard](https://github.com/endgameinc/ClrGuard) - ClrGuard is a proof of concept project to explore instrumenting the Common Language Runtime (CLR) for security purposes.
* [Get-ClrReflection](https://gist.github.com/dezhub/2875fa6dc78083cedeab10abc551cb58) - Detects memory-only CLR (.NET) modules.
* [Get-InjectedThread](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2) - Get-InjectedThread looks at each running thread to determine if it is the result of memory injection.
* [SilkETW](https://github.com/fireeye/SilkETW) - SilkETW & SilkService are flexible C# wrappers for ETW, they are meant to abstract away the complexities of ETW and give people a simple interface to perform research and introspection. 
* [WatchAD](https://github.com/0Kee-Team/WatchAD) - AD Security Intrusion Detection System
* [Sparrow](https://github.com/cisagov/Sparrow) - Sparrow.ps1 was created by CISA's Cloud Forensics team to help detect possible compromised accounts and applications in the Azure/m365 environment.
* [DFIR-O365RC](https://github.com/ANSSI-FR/DFIR-O365RC) - The DFIR-O365RC PowerShell module is a set of functions that allow the DFIR analyst to collect logs relevant for Office 365 Business Email Compromise investigations.
* [AzureADIncidentResponse](https://www.powershellgallery.com/packages/AzureADIncidentResponse/4.0) - Tooling to assist in Azure AD incident response
* [ADTimeline](https://github.com/ANSSI-FR/ADTimeline) - The ADTimeline script generates a timeline based on Active Directory replication metadata for objects considered of interest.

### Sysmon Configuration
* [sysmon-modular](https://github.com/olafhartong/sysmon-modular) - A Sysmon configuration repository for everybody to customise
* [sysmon-dfir](https://github.com/MHaggis/sysmon-dfir) - Sources, configuration and how to detect evil things utilizing Microsoft Sysmon.
* [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) - Sysmon configuration file template with default high-quality event tracing

### Active Directory Security Checks (by Sean Metcalf - @Pyrotek3)

#### General Recommendations
* Manage local Administrator passwords (LAPS).
* Implement RDP Restricted Admin mode (as needed).
* Remove unsupported OSs from the network.
* Monitor scheduled tasks on sensitive systems (DCs, etc.).
* Ensure that OOB management passwords (DSRM) are changed regularly & securely stored.
* Use SMB v2/v3+
* Default domain Administrator & KRBTGT password should be changed every year & when an AD admin leaves.
* Remove trusts that are no longer necessary & enable SID filtering as appropriate.
* All domain authentications should be set (when possible) to: "Send NTLMv2 response onlyrefuse LM & NTLM."
* Block internet access for DCs, servers, & all administration systems.

#### Protect Admin Credentials
* No "user" or computer accounts in admin groups.
* Ensure all admin accounts are "sensitive & cannot be delegated".
* Add admin accounts to "Protected Users" group (requires Windows Server 2012 R2 Domain Controllers, 2012R2 DFL for domain protection).
* Disable all inactive admin accounts and remove from privileged groups.

#### Protect AD Admin Credentials
* Limit AD admin membership (DA, EA, Schema Admins, etc.) & only use custom delegation groups.
* ‘Tiered’ Administration mitigating credential theft impact.
* Ensure admins only logon to approved admin workstations & servers.
* Leverage time-based, temporary group membership for all admin accounts

#### Protect Service Account Credentials
* Limit to systems of the same security level.
* Leverage “(Group) Managed Service Accounts” (or PW >20 characters) to mitigate credential theft (kerberoast).
* Implement FGPP (DFL =>2008) to increase PW requirements for SAs and administrators.
* Logon restrictions – prevent interactive logon & limit logon capability to specific computers.
* Disable inactive SAs & remove from privileged groups.

#### Protect Resources
* Segment network to protect admin & critical systems.
* Deploy IDS to monitor the internal corporate network.
* Network device & OOB management on separate network.

#### Protect Domain Controllers
* Only run software & services to support AD.
* Minimal groups (& users) with DC admin/logon rights.
* Ensure patches are applied before running DCPromo (especially MS14-068 and other critical patches).
* Validate scheduled tasks & scripts.

#### Protect Workstations (& Servers)
* Patch quickly, especially privilege escalation vulnerabilities.
* Deploy security back-port patch (KB2871997).
* Set Wdigest reg key to 0 (KB2871997/Windows 8.1/2012R2+): HKEY_LOCAL_MACHINESYSTEMCurrentControlSetControlSecurityProvidersWdigest
* Deploy workstation whitelisting (Microsoft AppLocker) to block code exec in user folders – home dir & profile path.
* Deploy workstation app sandboxing technology (EMET) to mitigate application memory exploits (0-days).

#### Logging
* Enable enhanced auditing
* “Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings”
* Enable PowerShell module logging (“*”) & forward logs to central log server (WEF or other method).
* Enable CMD Process logging & enhancement (KB3004375) and forward logs to central log server.
* SIEM or equivalent to centralize as much log data as possible.
* User Behavioural Analysis system for enhanced knowledge of user activity (such as Microsoft ATA).

#### Security Pro’s Checks
* Identify who has AD admin rights (domain/forest).
* Identify who can logon to Domain Controllers (& admin rights to virtual environment hosting virtual DCs).
* Scan Active Directory Domains, OUs, AdminSDHolder, & GPOs for inappropriate custom permissions.
* Ensure AD admins (aka Domain Admins) protect their credentials by not logging into untrusted systems (workstations).
* Limit service account rights that are currently DA (or equivalent).

### Important Security Updates
|CVE|Title|Description|Link|
|---|-----|-----------|----|
|CVE-2020-1472|Netlogon Elevation of Privilege Vulnerability|An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC). An attacker who successfully exploited the vulnerability could run a specially crafted application on a device on the network.|https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1472|
|CVE-2019-1040|Windows NTLM Tampering Vulnerability|A tampering vulnerability exists in Microsoft Windows when a man-in-the-middle attacker is able to successfully bypass the NTLM MIC (Message Integrity Check) protection, aka 'Windows NTLM Tampering Vulnerability'.|https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1040|
|CVE-2019-0683|Active Directory Elevation of Privilege Vulnerability|An elevation of privilege vulnerability exists in Active Directory Forest trusts due to a default setting that lets an attacker in the trusting forest request delegation of a TGT for an identity from the trusted forest, aka 'Active Directory Elevation of Privilege Vulnerability'.|https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0683|
|CVE-2019-0708|Remote Desktop Services Remote Code Execution Vulnerability|A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'.|https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708|
|CVE-2018-8581|Microsoft Exchange Server Elevation of Privilege Vulnerability|An elevation of privilege vulnerability exists in Microsoft Exchange Server, aka "Microsoft Exchange Server Elevation of Privilege Vulnerability." This affects Microsoft Exchange Server.|https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8518|
|CVE-2017-0143|Windows SMB Remote Code Execution Vulnerability|The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability." This vulnerability is different from those described in CVE-2017-0144, CVE-2017-0145, CVE-2017-0146, and CVE-2017-0148.|https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0143|
|CVE-2016-0128|Windows SAM and LSAD Downgrade Vulnerability|The SAM and LSAD protocol implementations in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, Windows Server 2012 Gold and R2, Windows RT 8.1, and Windows 10 Gold and 1511 do not properly establish an RPC channel, which allows man-in-the-middle attackers to perform protocol-downgrade attacks and impersonate users by modifying the client-server data stream, aka "Windows SAM and LSAD Downgrade Vulnerability" or "BADLOCK."|https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2016-0128|
|CVE-2014-6324|Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780)|The Kerberos Key Distribution Center (KDC) in Microsoft Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote authenticated domain users to obtain domain administrator privileges via a forged signature in a ticket, as exploited in the wild in November 2014, aka "Kerberos Checksum Vulnerability."|https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-068|
|CVE-2014-1812|Vulnerability in Group Policy Preferences could allow elevation of privilege|The Group Policy implementation in Microsoft Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 does not properly handle distribution of passwords, which allows remote authenticated users to obtain sensitive credential information and consequently gain privileges by leveraging access to the SYSVOL share, as exploited in the wild in May 2014, aka "Group Policy Preferences Password Elevation of Privilege Vulnerability."|https://support.microsoft.com/en-us/help/2962486/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevati|

### Detection
|Attack|Event ID|
|------|--------|
|Account and Group Enumeration|4798: A user's local group membership was enumerated<br>4799: A security-enabled local group membership was enumerated|
|AdminSDHolder|4780: The ACL was set on accounts which are members of administrators groups|
|Kekeo|4624: Account Logon<br>4672: Admin Logon<br>4768: Kerberos TGS Request|
|Silver	Ticket|4624: Account Logon<br>4634: Account Logoff<br>4672: Admin Logon|
|Golden	Ticket|4624: Account Logon<br>4672: Admin Logon|
|PowerShell|4103: Script Block Logging<br>400: Engine Lifecycle<br>403: Engine Lifecycle<br>4103: Module Logging<br>600: Provider Lifecycle<br>|
|DCShadow|4742: A computer account was changed<br>5137: A directory service object was created<br>5141: A directory service object was deleted<br>4929: An Active Directory replica source naming context was removed|
|Skeleton Keys|4673: A privileged service was called<br>4611: A trusted logon process has been registered with the Local Security Authority<br>4688: A new process has been created<br>4689: A new process has exited|
|PYKEK MS14-068|4672: Admin Logon<br>4624: Account Logon<br>4768: Kerberos TGS Request|
|Kerberoasting|4769: A Kerberos ticket was requested|
|S4U2Proxy|4769: A Kerberos ticket was requested|
|Lateral Movement|4688: A new process has been created<br>4689: A process has exited<br>4624: An account was successfully logged on<br>4625: An account failed to log on|
|DNSAdmin|770: DNS Server plugin DLL has been loaded<br>541: The setting serverlevelplugindll on scope . has been set to `<dll path>`<br>150: DNS Server could not load or initialize the plug-in DLL|
|DCSync|4662: An operation was performed on an object|
|Password Spraying|4625: An account failed to log on<br>4771: Kerberos pre-authentication failed<br>4648: A logon was attempted using explicit credentials|

### Resources
* [How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/help/4557222/how-to-manage-the-changes-in-netlogon-secure-channel-connections-assoc)
* [Securing Active Directory: Performing an Active Directory Security Review](https://www.hub.trimarcsecurity.com/post/securing-active-directory-performing-an-active-directory-security-review)
* [ACTIVE DIRECTORY SECURITY ASSESSMENT CHECKLIST](https://www.cert.ssi.gouv.fr/uploads/guide-ad.html)
* [ASD Strategies to Mitigate Cyber Security Incidents](https://acsc.gov.au/publications/Mitigation_Strategies_2017.pdf)
* [Reducing the Active Directory Attack Surface](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface)
* [Changes to Ticket-Granting Ticket (TGT) Delegation Across Trusts in Windows Server (AskPFEPlat edition)](https://techcommunity.microsoft.com/t5/Premier-Field-Engineering/Changes-to-Ticket-Granting-Ticket-TGT-Delegation-Across-Trusts/ba-p/440283)
* [ADV190006 | Guidance to mitigate unconstrained delegation vulnerabilities](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV190006)
* [ADV190023 | Microsoft Guidance for Enabling LDAP Channel Binding and LDAP Signing](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV190023)
* [Active Directory: Ultimate Reading Collection](https://social.technet.microsoft.com/wiki/contents/articles/20964.active-directory-ultimate-reading-collection.aspx)
* [Security Hardening Tips and Recommendations](https://social.technet.microsoft.com/wiki/contents/articles/18931.security-hardening-tips-and-recommendations.aspx)
* [Securing Domain Controllers to Improve Active Directory Security](https://adsecurity.org/?p=3377)
* [Securing Windows Workstations: Developing a Secure Baseline](https://adsecurity.org/?p=3299)
* [Implementing Secure Administrative Hosts](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-secure-administrative-hosts)
* [Privileged Access Management for Active Directory Domain Services](https://docs.microsoft.com/en-us/microsoft-identity-manager/pam/privileged-identity-management-for-active-directory-domain-services)
* [Awesome Windows Domain Hardening](https://github.com/PaulSec/awesome-windows-domain-hardening)
* [Best Practices for Securing Active Directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [Introducing the Adversary Resilience Methodology — Part One](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-one-e38e06ffd604)
* [Introducing the Adversary Resilience Methodology — Part Two](https://posts.specterops.io/introducing-the-adversary-resilience-methodology-part-two-279a1ed7863d)
* [Mitigating Pass-the-Hash and Other Credential Theft, version 2](https://download.microsoft.com/download/7/7/A/77ABC5BD-8320-41AF-863C-6ECFB10CB4B9/Mitigating-Pass-the-Hash-Attacks-and-Other-Credential-Theft-Version-2.pdf)
* [Configuration guidance for implementing the Windows 10 and Windows Server 2016 DoD Secure Host Baseline settings](https://github.com/nsacyber/Windows-Secure-Host-Baseline)
* [Monitoring Active Directory for Signs of Compromise](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise)
* [Detecting Lateral Movement through Tracking Event Logs](https://www.jpcert.or.jp/english/pub/sr/Detecting%20Lateral%20Movement%20through%20Tracking%20Event%20Logs_version2.pdf)
* [Kerberos Golden Ticket Protection Mitigating Pass-the-Ticket on Active Directory](https://cert.europa.eu/static/WhitePapers/UPDATED%20-%20CERT-EU_Security_Whitepaper_2014-007_Kerberos_Golden_Ticket_Protection_v1_4.pdf)
* [Overview of Microsoft's "Best Practices for Securing Active Directory"](https://digital-forensics.sans.org/blog/2013/06/20/overview-of-microsofts-best-practices-for-securing-active-directory)
* [The Keys to the Kingdom: Limiting Active Directory Administrators](https://dsimg.ubm-us.net/envelope/155422/314202/1330537912_Keys_to_the_Kingdom_Limiting_AD_Admins.pdf)
* [Protect Privileged AD Accounts With Five Free Controls](https://blogs.sans.org/cyber-defense/2018/09/10/protect-privileged-ad-accounts-with-five-free-controls/)
* [The Most Common Active Directory Security Issues and What You Can Do to Fix Them](https://adsecurity.org/?p=1684)
* [Event Forwarding Guidance](https://github.com/nsacyber/Event-Forwarding-Guidance)
* [Planting the Red Forest: Improving AD on the Road to ESAE](https://www.mwrinfosecurity.com/our-thinking/planting-the-red-forest-improving-ad-on-the-road-to-esae/)
* [Detecting Kerberoasting Activity](https://adsecurity.org/?p=3458)
* [Security Considerations for Trusts](https://docs.microsoft.com/pt-pt/previous-versions/windows/server/cc755321(v=ws.10))
* [Advanced Threat Analytics suspicious activity guide](https://docs.microsoft.com/en-us/advanced-threat-analytics/suspicious-activity-guide)
* [Protection from Kerberos Golden Ticket](https://cert.europa.eu/static/WhitePapers/CERT-EU-SWP_14_07_PassTheGolden_Ticket_v1_1.pdf)
* [Windows 10 Credential Theft Mitigation Guide](https://download.microsoft.com/download/C/1/4/C14579CA-E564-4743-8B51-61C0882662AC/Windows%2010%20credential%20theft%20mitigation%20guide.docx)
* [Detecting Pass-The- Ticket and Pass-The- Hash Attack Using Simple WMI Commands](https://blog.javelin-networks.com/detecting-pass-the-ticket-and-pass-the-hash-attack-using-simple-wmi-commands-2c46102b76bc)
* [Step by Step Deploy Microsoft Local Administrator Password Solution](https://gallery.technet.microsoft.com/Step-by-Step-Deploy-Local-7c9ef772)
* [Active Directory Security Best Practices](https://www.troopers.de/downloads/troopers17/TR17_AD_signed.pdf)
* [Finally Deploy and Audit LAPS with Project VAST, Part 1 of 2](https://blogs.technet.microsoft.com/jonsh/2018/10/03/finally-deploy-and-audit-laps-with-project-vast-part-1-of-2/)
* [Windows Security Log Events](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)
* [Talk Transcript BSidesCharm Detecting the Elusive: Active Directory Threat Hunting](https://www.trimarcsecurity.com/single-post/Detecting-the-Elusive-Active-Directory-Threat-Hunting)
* [Preventing Mimikatz Attacks](https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5)
* [Understanding "Red Forest" - The 3-Tier ESAE and Alternative Ways to Protect Privileged Credentials](https://www.slideshare.net/QuestSoftware/understanding-red-forest-the-3tier-esae-and-alternative-ways-to-protect-privileged-credentials)
* [Securing Microsoft Active Directory Federation Server (ADFS)](https://adsecurity.org/?p=3782)
* [Azure AD and ADFS best practices: Defending against password spray attacks](https://www.microsoft.com/en-us/microsoft-365/blog/2018/03/05/azure-ad-and-adfs-best-practices-defending-against-password-spray-attacks/)
* [AD Reading: Active Directory Backup and Disaster Recovery](https://adsecurity.org/?p=22)
* [Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
* [Hunting For In-Memory .NET Attacks](https://www.endgame.com/blog/technical-blog/hunting-memory-net-attacks)
* [Mimikatz Overview, Defenses and Detection](https://www.sans.org/reading-room/whitepapers/detection/mimikatz-overview-defenses-detection-36780)
* [Trimarc Research: Detecting Password Spraying with Security Event Auditing](https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing)
* [Hunting for Gargoyle Memory Scanning Evasion](https://www.countercept.com/blog/hunting-for-gargoyle/)
* [Planning and getting started on the Windows Defender Application Control deployment process](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control-deployment-guide)
* [Preventing Lateral Movement Using Network Access Groups](https://medium.com/think-stack/preventing-lateral-movement-using-network-access-groups-7e8d539a9029)
* [How to Go from Responding to Hunting with Sysinternals Sysmon](https://onedrive.live.com/view.aspx?resid=D026B4699190F1E6!2843&ithint=file%2cpptx&app=PowerPoint&authkey=!AMvCRTKB_V1J5ow)
* [Windows Event Forwarding Guidance](https://github.com/palantir/windows-event-forwarding)
* [Threat Mitigation Strategies: Part 2 – Technical Recommendations and Information](http://threatexpress.com/2018/05/threat-mitigation-strategies-technical-recommendations-and-info-part-2/)
* [Modern Hardening: Lessons Learned on Hardening Applications and Services](https://channel9.msdn.com/Events/Ignite/2015/BRK3486)
* [ITSP.70.012 Guidance for Hardening Microsoft Windows 10 Enterprise](http://publications.gc.ca/collections/collection_2019/cstc-csec/D97-3-70-12-2019-eng.pdf)
* [Blue Team Tips](https://www.sneakymonkey.net/2018/06/25/blue-team-tips/)
* [Active Directory Domain Security Technical Implementation Guide (STIG)](https://www.stigviewer.com/stig/active_directory_domain/)
* [Active Directory Security Testing Guide - v2.0](https://www.slideshare.net/HuyKha2/adstg-v20-guidance)
* [Best practices for securing Active Directory Federation Services](https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/best-practices-securing-ad-fs)
* [The most common on premises vulnerabilities & misconfigurations](https://s3cur3th1ssh1t.github.io/The-most-common-on-premise-vulnerabilities-and-misconfigurations/)

## License
[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](http://creativecommons.org/publicdomain/zero/1.0)

To the extent possible under law, Rahmat Nurfauzi &#34;@infosecn1nja&#34; has waived all copyright and related or neighboring rights to this work.
