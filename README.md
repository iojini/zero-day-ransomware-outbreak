# Threat Hunt Report: Zero-Day Ransomware Outbreak Investigation

<img width="2052" height="1533" alt="ITDEv2_bordered" src="https://github.com/user-attachments/assets/235e4bd8-6402-44a4-9954-6560f4f47371" />

##  Scenario

An investigation was initiated following reports of a newly discovered ransomware strain called PwnCrypt affecting corporate networks. PwnCrypt is a newly reported ransomware strain leveraging PowerShell-based payloads to encrypt files on infected systems. The malware employs AES-256 encryption and targets specific directories including C:\Users\Public\Desktop. Encrypted files are identified by the .pwncrypt extension prepended to the original file extension (e.g., document.txt becomes document.pwncrypt.txt). Given the organization's immature security posture and lack of user security awareness training, it is plausible that the newly discovered PwnCrypt ransomware has infiltrated the corporate network through social engineering or phishing attacks

- [Scenario Creation](https://github.com/iojini/insider-threat-data-exfiltration/blob/main/insider-threat-data-exfiltration-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` table for archiving activity

Searched the DeviceFileEvents table and discovered archiving activity on the target device (i.e., employee-data-20251002004431.zip was created at 12:44:40.196 AM).

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "irene-test-vm-m"
| where FileName endswith ".zip"
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, ActionType, FileName
```
<img width="1938" height="739" alt="TH3_1" src="https://github.com/user-attachments/assets/75c0f7a9-3173-4ff0-b997-2722decc008a" />

---

### 2. Searched the `DeviceProcessEvents` table for suspicious activity before and after archive creation

Searched the DeviceProcessEvents table for activities occuring one minute before and one minute after the archive was created and discovered that a powershell script silently installed 7-zip on the device at 12:44:32.908 AM. Furthermore, 7-zip was used to compress employee data at 12:44:40.145 AM.

**Query used to locate events:**

```kql
// 2025-10-02T00:44:40.1965293Z
let VMName = "irene-test-vm-m";
let specificTime = datetime(2025-10-02T00:44:40.1965293Z);
DeviceProcessEvents
| where TimeGenerated between ((specificTime - 1m) .. (specificTime + 1m))
| where DeviceName == VMName
| order by TimeGenerated desc
| project TimeGenerated, FileName, ProcessCommandLine
```
<img width="1980" height="640" alt="TH3_2v3" src="https://github.com/user-attachments/assets/f5f8e619-eb3f-480c-b34c-d91f955f8cbe" />

---

### 3. Searched the `DeviceNetworkEvents` table for network activity indicative of exfiltration

Searched for any indication of successful exfiltration from the network and discovered outbound connections to Azure Blob Storage. PowerShell connected to sacyberrangedanger.blob.core.windows.net at 12:44:40.285 AM.

**Query used to locate events:**

```kql
let VMName = "irene-test-vm-m";
let specificTime = datetime(2025-10-02T00:44:40.1965293Z);
DeviceNetworkEvents
| where TimeGenerated between ((specificTime - 4m) .. (specificTime + 4m))
| where DeviceName == VMName
| order by TimeGenerated desc
| project TimeGenerated, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
```
<img width="1916" height="931" alt="TH3_3" src="https://github.com/user-attachments/assets/c6f7f817-4a4d-404f-98c8-e8136e31c31d" />

---

## Summary

The investigation revealed that a malicious PowerShell script (i.e., exfiltratedata.ps1) was executed on the target device with -ExecutionPolicy Bypass to evade security controls. The script performed three actions in sequence: it silently installed 7-Zip, used 7-Zip to compress employee data into an archive (i.e., employee-data-20251002004431.zip), and uploaded the archive to an external Azure Blob Storage account (i.e., sacyberrangedanger.blob.core.windows.net) over HTTPS. The entire operation was completed in approximately 10 seconds. The use of encrypted traffic over a standard port indicates an attempt to evade network-based detection by blending malicious activity with legitimate cloud service traffic, and confirms successful data exfiltration of employee information to an external storage account.

---

## Relevant MITRE ATT&CK TTPs

| Tactic | TTP Name | TTP ID | Description | Detection Relevance |
|--------|----------|:--------:|-------------|---------------------|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | A PowerShell script (exfiltratedata.ps1) was executed with -ExecutionPolicy Bypass to install 7-Zip, compress employee data, and upload the archive to Azure Blob Storage. | Identifies suspicious PowerShell execution through DeviceProcessEvents table, including command line arguments. |
| Defense Evasion | Obfuscated Files or Information | T1027 | The script was placed in C:\ProgramData, a common location used to blend in with legitimate software, and the archive was named with a timestamp to appear routine. | Identifies potentially malicious files stored in commonly abused directories. |
| Collection | Archive Collected Data | T1560 | 7-Zip was silently installed and used to compress employee data into a .zip archive (employee-data-20251002004431.zip) for exfiltration. | Identifies archiving activity through DeviceFileEvents and DeviceProcessEvents tables. |
| Exfiltration | Exfiltration Over Web Service: Exfiltration to Cloud Storage | T1567.002 | The compressed archive was uploaded to an external Azure Blob Storage account (sacyberrangedanger.blob.core.windows.net) over HTTPS (port 443). | Identifies outbound connections to cloud storage endpoints through DeviceNetworkEvents table. |

---

This table organizes the MITRE ATT&CK techniques (TTPs) observed during the investigation. The detection methods identified the full attack chain (i.e., script execution, data archiving, and exfiltration over encrypted cloud storage), thereby confirming successful data exfiltration of employee information to an external Azure Blob Storage account.

---

## Response Taken

| MITRE Mitigation ID | Name | Action Taken | Description | Relevance |
|---------------------|------|--------------|-------------|-----------|
| M1057 | Data Loss Prevention | DLP Policy Implementation | Implemented DLP policies to detect and block bulk transfers of sensitive files (e.g., employee data) to external cloud storage endpoints. | Prevents exfiltration of sensitive data by monitoring and restricting unauthorized transfers to external destinations. |
| M1037 | Filter Network Traffic | Egress Filtering Configuration | Configured firewall rules to restrict outbound connections to unapproved cloud storage services and require inspection of HTTPS traffic. | Limits exfiltration channels by blocking unauthorized cloud storage endpoints and enabling visibility into encrypted traffic. |
| M1038 | Execution Prevention | Application Whitelisting | Implemented application control policies to prevent unauthorized software installation (e.g., 7-Zip) and restrict PowerShell execution to approved scripts. | Mitigates unauthorized tool installation and script execution by enforcing a list of approved applications. |
| M1047 | Audit | Continuous Monitoring Configuration | Established ongoing monitoring of DeviceFileEvents, DeviceProcessEvents, and DeviceNetworkEvents tables for archive creation, suspicious script execution, and connections to cloud storage endpoints. | Enables early detection of future data staging and exfiltration attempts. |

---

The following response actions were taken: immediately isolated the affected device upon discovery of the exfiltration activity to prevent further data loss; implemented DLP policies to detect and block unauthorized transfers of sensitive data to external cloud storage; configured egress filtering to restrict outbound connections to unapproved cloud storage services; deployed application whitelisting to prevent unauthorized software installation and restrict PowerShell script execution; established ongoing monitoring for archive creation, suspicious process execution, and network connections to cloud storage endpoints.

---
