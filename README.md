# Threat Hunt Report: Browser Hijack via PowerShell Startup Script

## Incident Summary

**Title:** Detection of Malicious PowerShell Script Execution on Workstations During Cybersecurity Conference  
**Date of Detection:** April 15, 2025  
**Affected Device:** `ash-threathunt`  
**User:** `ash`  

### Scenario

During an internal cybersecurity conference, several attendees experienced unexpected browser activity. Within 30–60 minutes of the event's start, multiple reports indicated that browsers were opening fullscreen white pages displaying the message:

> “We see your secrets, and your secrets are safe with us. For now.”

Some instances played background music.

#### Initial Findings
- The behavior was caused by a PowerShell script placed in the Windows **Startup folder**.
- The script opened a **local HTML file (creepy.html)** with a hidden PowerShell window.
- The source was a **shared Conference_Toolkit.zip** file distributed internally via **Slack** and **SharePoint**.
- The ZIP included `init.ps1` which:
  - Downloaded files (`creepy.html`, `spooky.mp3`)
  - Created `open-creepy.ps1` to auto-launch the page at login

> **Note:** This evaded endpoint protection due to trusted user context and inconspicuous script masking.

---

## High-Level IoC Discovery Plan

### Objectives
1. Identify systems with malicious files in the **Startup folder**  
2. Confirm execution of PowerShell scripts downloading payloads  
3. Trace spread via ZIP download and execution  
4. Assess whether sensitive data was accessed  
5. Notify stakeholders and enhance file-sharing vetting policies  

---

## Detection Tables Used

| Table Name               | Purpose                                                                 |
|--------------------------|-------------------------------------------------------------------------|
| `DeviceFileEvents`       | Detect dropped files in Startup folder (`creepy.html`, `open-creepy.ps1`, `spooky.mp3`) |
| `DeviceProcessEvents`    | Detect PowerShell/script execution and browser launches                 |
| `DeviceStartupProcessEvents` | Track scripts/browser launchers set to run at login             |

---

##  Steps Taken

###  Step 1: Detect File Creation — `creepy.html`
- **Date/Time:** April 15, 2025, 12:52 AM
- **Device:** `ash-threathunt`
- **File Path:** `C:\Users\Ash\Documents\LabPayload\creepy.html`
- **Created By:** `notepad.exe`
- **SHA256:** `78fc8676c9026c18f98edcb81e6e31a5cc8578e4714f943ddc70d4aa0d78ed6`

###  Step 2: Detect PowerShell Script Creation — `open-creepy.ps1`
- **Date/Time:** April 15, 2025, 1:12 AM
- **File Path:** `C:\Users\Ash\Documents\open-creepy.ps1`
- **Created By:** `powershell.exe`
- **Size:** `118 bytes`
- **SHA256:** `1241e16c8e0f018a997cfa8653221bc774108cf6a78c46cd5c8091e513ce9e71`

###  Step 3: Batch File Creation — `launcher.bat`
- **Date/Time:** April 15, 2025, 1:19 AM
- **File Path:** `C:\Users\Ash\Documents\LabPayload\launcher.bat`
- **Created By:** `notepad.exe`

###  Step 4: PowerShell Auto-Run Configuration
- **Date/Time:** April 15, 2025, 1:28 AM
- **Execution Command:**
```powershell
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\Ash\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\open-creepy.ps1"
```
- **Purpose:** Ensures script runs at every login, bypasses PowerShell security policy

###  Step 5: Malicious HTML Execution via Firefox
- **Date/Time:** April 15, 2025, 1:28 AM
- **Command Executed:**
```cmd
firefox.exe C:\Users\Ash\Documents\LabPayload\creepy.html
```
- **Triggered By:** `open-creepy.ps1`
- **Likely Initiated From:** `launcher.bat` in Startup folder

---

## 📅 Chronological Timeline of Events

| Time          | Event Type        | File Name             | Path                                             | Notes |
|---------------|-------------------|------------------------|--------------------------------------------------|-------|
| 12:52 AM      | File Created       | `creepy.html`         | `C:\Users\Ash\Documents\LabPayload`             | Created via `notepad.exe` |
| 1:12 AM       | PowerShell Script  | `open-creepy.ps1`     | `C:\Users\Ash\Documents`                        | Created via `powershell.exe` |
| 1:19 AM       | Batch Script       | `launcher.bat`        | `C:\Users\Ash\Documents\LabPayload`             | Launch helper |
| 1:28 AM       | Script Executed    | `open-creepy.ps1`     | Startup folder                                   | Auto-execution setup |
| 1:28 AM       | Browser Executed   | `firefox.exe creepy.html` | `C:\Users\Ash\Documents\LabPayload`      | Final payload display |

---


## KQL Queries Used

### File Creation Events
```kql
DeviceFileEvents
| where DeviceName =="ash-threathunt"
| where ActionType == "FileCreated"
| where FileName has_any ("creepy.html", "open-creepy.ps1", ".bat")
| order by Timestamp desc

```

![image](https://github.com/user-attachments/assets/8acd3e26-74cb-440f-9f35-159c42b7106c)


![image](https://github.com/user-attachments/assets/c2d07dca-d0ee-40d8-9ff9-ccf0471b6c08)


### PowerShell + Firefox Execution Detection
```kql
DeviceProcessEvents
| where DeviceName == "ash-threathunt"
| where FileName contains "Notepad.exe"
| where ProcessCommandLine has "Start-Process"
| where ProcessCommandLine has "firefox.exe"
| order by Timestamp desc
```

![image](https://github.com/user-attachments/assets/449a5773-1149-47a8-a6e0-f4455519fcd7)


---
## ✅ Summary

- Malicious PowerShell script executed from startup.
- Firefox launched at login to display creepy message.
- Spread vector: ZIP file (`Conference_Toolkit.zip`) shared internally.
- Evaded AV due to trusted user context and benign file origins.
---


##  Response Taken

Upon detection of the anomalous browser behavior reported during the internal cybersecurity conference, the security team initiated an immediate threat hunt across affected and potentially exposed endpoints. Below are the detailed actions taken:

---

### 1. Endpoint Isolation
- **Device Identified:** `ash-threathunt`
- After correlating event logs and confirming suspicious file activity (e.g., creation of `open-creepy.ps1`, `creepy.html`, and `launcher.bat`), the endpoint was isolated from the network using our EDR platform to prevent lateral movement or further payload execution.
- **Isolation timestamp:** April 15, 2025, at 02:10 AM

---

### 2. File Hash Analysis
- The following SHA256 file hashes were extracted and submitted to VirusTotal and internal sandbox analysis:
  - `creepy.html` - `78fc8676c9026c18f98edcb81e6e31a5cc8578e4714f943ddc70d4aa0d78ed6`
  - `open-creepy.ps1` - `1241e16c8e0f018a997cfa8653221bc774108cf6a78c46cd5c8091e513ce9e71`
- None of the hashes had existing detections on public feeds, indicating a novel or low-prevalence threat.
- Behavioral sandboxing confirmed the HTML page opened a fullscreen white screen with embedded audio playback and no external beaconing attempts.

---

### 3. Malicious Startup Entry Cleanup
- Located the malicious script within:
  - `C:\Users\Ash\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\open-creepy.ps1`
- Deleted all associated files: `open-creepy.ps1`, `creepy.html`, `launcher.bat`, and `spooky.mp3`
- Scheduled task manager and autorun utilities were scanned to ensure no additional persistence mechanisms existed.

---

### 4. ZIP File Distribution Traceback
- The shared `Conference_Toolkit.zip` was identified as the source of the infection.
- This file was shared via:
  - Internal Slack workspace
  - SharePoint site titled `\InternalEvents\CyberCon2025\Resources`
- Downloads of this ZIP were traced using cloud app security logs. 17 users downloaded the file.

---

## Recommendations

- Block `.ps1` scripts from unverified sources in Startup folders
- Improve content scanning for internal platforms like Slack and SharePoint
- Enhance user awareness on ZIP/script execution risks
- Integrate script behavioral analysis into endpoint protection tools
- Monitor for use of `-ExecutionPolicy Bypass` in PowerShell logs
