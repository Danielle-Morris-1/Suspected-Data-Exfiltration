# Suspected Data Exfiltration Incident Report

## 1. Executive Summary
- **Case ID / Title:** Suspected Data Exfiltration from PIPd Employee (`danielletargetm`) 
- **Date Range Investigated:** May 31, 2025 - June 2, 2025
- **Analyst:** Danielle Morris
- **Environment:** Environment: Cyber Range / Lab (Simulation Environment)
- **Goal:** Investigate potential data theft by John Doe.
- **Compromised Host:** `danielletargetm`
- **Targeted Account(s):** John Doe 
- **Summary:** An investigation into `danielletargetm` revealed strong indicators of automated data exfiltration. A malicious PowerShell script (`exfiltratedata.ps1`) was executed, which silently installed 7-Zip, generated and compressed fake employee data, and then uploaded it to an external Azure Blob Storage account using embedded credentials. The script also attempted to clean up its local footprint. This activity shows a consistent and highly suspicious pattern, indicating a sustained threat.

## 2. Scenario Overview

This investigation was initiated based on concerns from management regarding John Doe, an employee on a Performance Improvement Plan (PIP), and the potential for data theft from his assigned machine, `danielletargetm`. The scenario simulated a sophisticated data exfiltration attempt using scripting and legitimate tools for malicious purposes. The threat behavior involves the use of Living Off The Land Binaries (LOLBins) like PowerShell and `7z.exe` to achieve its objectives.

## 3. Mission & Hypothesis

- **Mission:** To determine if data exfiltration is occurring on `danielletargetm` and to identify the methods used.
- **Hypothesis:** John Doe is staging or compressing sensitive files before exfiltration.
- **Expected Techniques:** PowerShell execution, file compression, data transfer to external locations, and potential cleanup activities.

## 4. Methodology

- **Frameworks:** MITRE ATT&CK, PEAK (Prepare, Enrich, Analyze, Act, Confirm, Know)
- **Tools Used:** Microsoft Defender for Endpoint (MDE)
- **Query Language:** Kusto Query Language (KQL)
- **Steps Followed:** Initial queries were performed on `DeviceFileEvents` to look for suspicious `.zip` file activity. Timelines around suspicious file creations were investigated using `DeviceProcessEvents` to identify initiating processes. Script analysis was performed once `exfiltratedata.ps1` was identified.

## 5. Phase-by-Phase Breakdown

### Phase 1 - Execution & Ingress Tool Transfer

- **PEAK Step:** Prepare, Analyze
- **MITRE Tactics:** Execution, Defense Evasion
- **Techniques Expected / Validated:** T1059.001 (PowerShell), T1204.002 (User Execution), T1105 (Ingress Tool Transfer)

**What We Investigated:**
We investigated the initial instance of `.zip` file creation on `danielletargetm` to identify the processes involved.

**KQL Query Used:**
    ```kql
    let VMName = "danielletargetm";
    let specificTime = datetime(2025-05-31T16:50:02.0895454Z);
    DeviceProcessEvents
    | where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
    | where DeviceName == VMName
    | order by Timestamp desc

**What We Found:**
A PowerShell script (`exfiltratedata.ps1`) was executed, launched by `cmd.exe` with High integrity (elevated privileges). This script was responsible for silently installing `7-Zip` (`7z2408-x64.exe`) after downloading it from an external Azure Blob Storage URL. 

**Interpretation:**
This indicates automated and elevated execution of a script that downloads and installs unauthorized software. The use of PowerShell with `ExecutionPolicy Bypass` is a significant red flag for malicious activity. 

**Mapped MITRE Techniques:**
* **Execution** 
    * T1059.001: PowerShell  - PowerShell was used to execute the script and perform system actions. 
    * T1204.002: User Execution: Malicious File  - The script was initiated via `cmd.exe`, which could stem from a user action (e.g., clicking a malicious file or scheduled task). 
* **Defense Evasion** 
    * T1105: Ingress Tool Transfer  - The `7-Zip` installer was downloaded from an external URL. 

### Phase 2 - Collection & Compression

**PEAK Step:** Analyze 
**MITRE Tactics:** Collection 
**Techniques Expected / Validated:** T1005 (Data from Local System), T1560.001 (Archive Collected Data: Archive via Utility) 

**What We Investigated:**
We observed recurring patterns of `.csv` file compression and renaming. 

**KQL Query Used:**
```kql
DeviceFileEvents
| where DeviceName contains "danielletargetm"
| where FileName endswith ".zip"
| order by Timestamp desc
``` 

**What We Found:**
The `exfiltratedata.ps1` script generated fake employee data into a temporary CSV file (`employee-data-YYYYMMDDHHmmss.csv`). Subsequently, `7z.exe` was used to compress this CSV file into a `.zip` archive (`employee-data-YYYYMMDDHHmmss.zip`) within the `C:\ProgramData` directory. This behavior was observed on multiple dates (May 31 and June 2, 2025). 

**Interpretation:**
This is a clear preparation step for data exfiltration, where sensitive information is gathered and compressed to facilitate easier and more efficient transfer. The use of `7z.exe`, while legitimate, is often abused in such scenarios. 

**Mapped MITRE Techniques:**
* **Collection** 
    * T1005: Data from Local System  - The script generated and accessed "employee data" locally. 
    * T1560.001: Archive Collected Data: Archive via Utility  - `7z.exe` was used to compress the collected data into a `.zip` file. 

### Phase 3 - Exfiltration

**PEAK Step:** Analyze, Act 
**MITRE Tactics:** Exfiltration 
**Techniques Expected / Validated:** T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage) 

**What We Investigated:**
We analyzed the `exfiltratedata.ps1` script's functionality related to external communications. 

**KQL Query Used:**
(No specific KQL query for the exfiltration itself was provided in the findings, but the script analysis confirmed the action.)

**What We Found:**
The `exfiltratedata.ps1` script contained hardcoded Azure Blob Storage variables, including a target URL (`https://sacyberrangedanger.blob.core.windows.net/stolencompanydata/employee-data.zip`) and a critical hardcoded storage key. The script used `Invoke-WebRequest` to upload the compressed zip file directly to this external Azure Blob Storage URL. 

**Interpretation:**
This is the core exfiltration event, where the compressed data is transferred to an unauthorized external cloud storage. The presence of a hardcoded storage key is a severe security vulnerability, granting direct access to the storage account. 

**Mapped MITRE Techniques:**
* **Exfiltration** 
    * T1567.002: Exfiltration Over Web Service: Exfiltration to Cloud Storage  - The script specifically uploaded data to an Azure Blob Storage account. 

### Phase 4 - Persistence & Defense Evasion

**PEAK Step:** Enrich, Confirm 
**MITRE Tactics:** Persistence, Defense Evasion 
**Techniques Expected / Validated:** T1564.001 (Hide Artifacts: Hidden Files and Directories), T1070.004 (File Deletion) 

**What We Investigated:**
We reviewed the script for any cleanup or persistence mechanisms after data exfiltration. 

**KQL Query Used:**
(No specific KQL query for cleanup was provided in the findings, but the script analysis confirmed the actions.)

**What We Found:**
After the upload, the script moved both the generated temporary CSV file and the compressed zip file into a non-standard backup directory (`C:\ProgramData\backup\`). It also logs activity to an obscure log file (`C:\ProgramData\entropygorilla.log`). 

**Interpretation:**
These actions resemble an attempt by the attacker to manage their local footprint and avoid detection. Moving files to a "backup" directory and logging to an obscure file are common defense evasion techniques to reduce the chances of immediate discovery. 

**Mapped MITRE Techniques:**
* **Defense Evasion** 
    * T1564.001: Hide Artifacts: Hidden Files and Directories - Moving files to a non-standard "backup" directory could be an attempt to hide them. 
    * T1070.004: Indicator Removal: File Deletion - Although files are moved rather than deleted outright from the system, it's a form of cleaning up their initial creation points. 

## 6. Timeline of Attacker Activity

| Timestamp (UTC) | Event |
|---|---|
| 2025-05-31T16:50:02Z | Initial instance of `.zip` file creation and PowerShell script execution (`exfiltratedata.ps1`) detected.  |
| 2025-06-02 08:26:13 | `employee-data-20250602122605.zip` file created by `7z.exe`.  |
| 2025-06-02 08:26:14 | `employee-data-20250602122605.zip` renamed; `exfiltratedata.ps1` executed via PowerShell.  |
| Ongoing | Repeated creation of `zip` files containing `employee-data-*.csv` by `7z.exe` initiated by PowerShell via `cmd.exe` with elevation.  |
| Ongoing | Data uploaded to Azure Blob Storage (`https://sacyberrangedanger.blob.core.windows.net/stolencompanydata/employee-data.zip`).  |
| Ongoing | Generated files moved to `C:\ProgramData\backup\` and logs written to `C:\ProgramData\entropygorilla.log`.  |

## 7. MITRE ATT&CK Summary Table

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Execution | T1059.001 | PowerShell | `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\exfiltratedata.ps1` executed.  |
| Execution | T1204.002 | User Execution: Malicious File | `powershell.exe` launched via `cmd.exe` with elevation.  |
| Defense Evasion | T1105 | Ingress Tool Transfer | `7z2408-x64.exe` downloaded from `https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe`.  |
| Collection | T1005 | Data from Local System | `employee-data-YYYYMMDDHHmmss.csv` created with fake employee data.  |
| Collection | T1560.001 | Archive Collected Data: Archive via Utility | `7z.exe` used to compress `.csv` into `.zip` files.  |
| Exfiltration | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | `Invoke-WebRequest` uploaded `.zip` files to `https://sacyberrangedanger.blob.core.windows.net/stolencompanydata/employee-data.zip`.  |
| Defense Evasion | T1564.001 | Hide Artifacts: Hidden Files and Directories | Compressed and temporary CSV files moved to `C:\ProgramData\backup\`.  |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | Initial temporary files moved to backup directory, effectively cleaning up.  |

## 8. Indicators of Compromise (IoCs)

| Type | Value | Description |
|---|---|---|
| File Name | `exfiltratedata.ps1` | Malicious PowerShell script.  |
| File Path | `C:\programdata\exfiltratedata.ps1` | Location of the malicious script.  |
| File Name | `7z2408-x64.exe` | 7-Zip installer downloaded and used.  |
| URL | `https://sacyberrange00.blob.core.windows.net/vm-applications/7z2408-x64.exe` | Source URL for 7-Zip installer download.  |
| File Name Pattern | `employee-data-YYYYMMDDHHmmss.csv` | Temporary CSV file containing exfiltrated data.  |
| File Name Pattern | `employee-data-YYYYMMDDHHmmss.zip` | Compressed archive of exfiltrated data.  |
| Log File Path | `C:\ProgramData\entropygorilla.log` | Obscure log file used by the malicious script.  |
| Backup Folder Path | `C:\ProgramData\backup\` | Non-standard directory used for staging/cleanup.  |
| URL | `https://sacyberrangedanger.blob.core.windows.net/stolencompanydata/employee-data.zip` | Destination for exfiltrated data.  |


## 9. Defensive Recommendations

**Area** | **Recommendation**
---|---
**Endpoint Security** | **Immediate Isolation:** Isolate `danielletargetm` from the network to prevent further data exfiltration or lateral movement. 
**Forensics & Analysis** | **Deep Dive Forensic Analysis:** Conduct a full forensic analysis of `danielletargetm` to determine the initial compromise vector, identify any other malicious artifacts, and ascertain the full scope of data accessed or exfiltrated. 
**Credential Management** | **Credential Rotation:** Immediately investigate and rotate any credentials or keys related to the hardcoded Azure storage key found in the script. 
**Cloud Security** | **Azure Audit:** Audit the `sacyberrangedanger` Azure storage account for other uploaded files and activity. 
**Human Resources** | **User Interview/HR Coordination:** Coordinate with HR regarding John Doe and their access to `danielletargetm` and relevant data, providing a clear report of the technical findings. 
**Threat Hunting** | **Threat Hunting Expansion:** Expand threat hunting across the environment for similar scripts, `7-Zip` usage patterns, or outbound connections to known malicious Azure Blob Storage accounts. 
**Security Monitoring** | Implement robust monitoring for process creation events involving `powershell.exe` with `ExecutionPolicy Bypass` and its children processes, especially those involving compression utilities or outbound network connections to cloud storage.
**Software Management** | Implement software restriction policies to prevent unauthorized software (like `7-Zip` installers) from being downloaded and silently installed from untrusted sources.
**Network Security** | Enforce egress filtering to restrict outbound connections to known good destinations and block connections to suspicious cloud storage services.
**Application Control** | Restrict the execution of unsigned or untrusted PowerShell scripts.
**Data Loss Prevention (DLP)** | Implement DLP solutions to detect and prevent the exfiltration of sensitive data, regardless of the compression method used.

## 10. Conclusion

The investigation into `danielletargetm` successfully identified a **simulated, yet technically sound, data exfiltration attempt**. The `exfiltratedata.ps1` script demonstrated a **multi-stage attack lifecycle**, including:

- Tool transfer and execution  
- Data staging and compression  
- Exfiltration to external infrastructure  
- Defense evasion through persistence mechanisms

Although this activity was performed in a **controlled environment**, the **techniques and indicators of compromise (IOCs)** observed are directly applicable to real-world insider threat scenarios.

Notably, the activity occurred over multiple days, reinforcing the need for:

- **Continuous endpoint monitoring**
- **Behavior-based anomaly detection**
- **Proactive threat hunting practices**

Should such activity be detected in a production environment, **immediate escalation, containment, and comprehensive remediation** would be essential to protect corporate data and maintain operational integrity.


## Project Status

![Project Status](https://img.shields.io/badge/Status-Completed-brightgreen) 
![Focus](https://img.shields.io/badge/Focus-Threat%20Hunting-blue) 
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Defender-blueviolet) 
![Language](https://img.shields.io/badge/Scripting-KQL-yellow)



