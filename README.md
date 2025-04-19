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

## Timeline of Events

### 1. Creation of `creepy.html`
- **Date/Time:** April 15, 2025, 12:52 AM  
- **Location:** `C:\Users\Ash\Documents\LabPayload`  
- **Process:** `notepad.exe`  
- **SHA256 Hash:** `78fc8676c9026c18f98edcb81e6e31a5cc8578e4714f943ddc70d4aa0d78ed6`

---

### 2. Creation of `open-creepy.ps1`
- **Date/Time:** April 15, 2025, 1:12 AM  
- **Location:** `C:\Users\Ash\Documents`  
- **Process:** `powershell.exe`  
- **Size:** 118 bytes  
- **SHA256 Hash:** `1241e16c8e0f018a997cfa8653221bc774108cf6a78c46cd5c8091e513ce9e71`

---

### 3. Creation of `launcher.bat`
- **Date/Time:** April 15, 2025, 1:19 AM  
- **Location:** `C:\Users\Ash\Documents\LabPayload`  
- **Process:** `notepad.exe`  
- **Purpose:** Batch file to launch the PowerShell script at login

---

### 4. PowerShell Script Auto-Run at Startup
- **Date/Time:** April 15, 2025, 1:28 AM  
- **Command:**
  ```powershell
  powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\Ash\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\open-creepy.ps1"
  ```
- **Details:** Script was configured to auto-execute on user login in hidden mode.

---

### 5. Firefox Launch of `creepy.html`
- **Date/Time:** April 15, 2025, 1:28 AM  
- **Command:**
  ```bash
  "firefox.exe" C:\Users\Ash\Documents\LabPayload\creepy.html
  ```
- **Launched by:** `open-creepy.ps1` (likely triggered via `launcher.bat`)

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

## Response Actions

- **TOR usage** was confirmed on endpoint `_______________`
- Device was **isolated from the network**
- User’s **direct manager was notified**
- Further analysis is ongoing to determine lateral movement and potential data access

---

## Recommendations

- Block `.ps1` scripts from unverified sources in Startup folders
- Improve content scanning for internal platforms like Slack and SharePoint
- Enhance user awareness on ZIP/script execution risks
- Integrate script behavioral analysis into endpoint protection tools
- Monitor for use of `-ExecutionPolicy Bypass` in PowerShell logs
