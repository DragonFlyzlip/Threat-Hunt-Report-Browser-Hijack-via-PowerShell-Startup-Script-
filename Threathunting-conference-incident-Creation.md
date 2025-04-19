# Internal Cybersecurity Conference Incident Report

## Scenario
During a company-hosted internal cybersecurity conference, multiple attendees connected to the secure conference room network using their company-issued laptops. About 30–60 minutes into the sessions, several participants reported a strange incident: after logging in or restarting their computers, their browsers automatically opened and displayed a fullscreen white page with a chilling message:

> **"We see your secrets, and your secrets are safe with us. For now."**

Some say it appeared right after logging in. Others say they weren’t even using their browser when it suddenly launched itself. The message appears to be hosted locally, and in some cases, soft background music plays alongside the text.

The IT support team began investigating and found that the affected systems all had a PowerShell script in the Startup folder that launched a local HTML file with the creepy message.

Initial analysis suggests the attack was performed internally — potentially by someone with access to multiple machines in the conference room ahead of the event, or through a remote execution mechanism exploiting admin rights or software deployment tools.

## Objective
- Hunt for evidence of local file drops and startup persistence
- Confirm if any lateral movement occurred
- Identify the source of the PowerShell script execution
- Contain the threat
- Notify management and review endpoint security policies

---

## Steps the "Bad Actor" Took to Create Logs and IoCs

### 1. Created `creepy.html`:
```html
<html>
<body style="background-color:white; text-align:center; margin-top:20%;">
  <h1 style="color:black; font-size:40px;">We see your secrets,<br> and your secrets are safe with us. For now.</h1>
  <audio autoplay loop>
    <source src="spooky.mp3" type="audio/mpeg">
  </audio>
</body>
</html>
```

### 2. Placed Files:
```
C:\Temp\ConferencePayload\
 ├── creepy.html
 └── spooky.mp3 (optional)
```

### 3. Executed PowerShell:
```powershell
$startup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Copy-Item "C:\Temp\ConferencePayload\creepy.html" "$startup\creepy.html"
Set-Content "$startup\open-creepy.ps1" "Start-Process 'msedge.exe' -ArgumentList '$startup\creepy.html'"
```

---

## Tables Used to Detect IoCs

| Table | Description | Link | Purpose |
|-------|-------------|------|---------|
| `DeviceFileEvents` | File creation/modification/deletion events | [Docs](https://learn.microsoft.com/en-us/defender-xdr/devicefileevents-table) | Detect dropped `creepy.html`, `spooky.mp3`, or `open-creepy.ps1` in Startup |
| `DeviceProcessEvents` | Process creation events | [Docs](https://learn.microsoft.com/en-us/defender-xdr/deviceprocessevents-table) | Detect PowerShell execution and browser launch |
| `DeviceStartupProcessEvents` | Processes triggered at startup | [Docs](https://learn.microsoft.com/en-us/defender-xdr/devicestartupprocessevents-table) | Detect Edge/Chrome/Firefox auto-launching HTML |

---

## Related KQL Queries

### Detect dropped files in Startup:
```kql
DeviceFileEvents
| where FolderPath endswith "Microsoft\\Windows\\Start Menu\\Programs\\Startup"
| where FileName has_any ("creepy.html", "open-creepy.ps1", "spooky.mp3")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
```

### Detect PowerShell script execution:
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "Start-Process" and ProcessCommandLine has "creepy.html"
| project Timestamp, DeviceName, ProcessCommandLine
```

### Detect browser opening with creepy HTML:
```kql
DeviceProcessEvents
| where FileName in~ ("msedge.exe", "chrome.exe", "firefox.exe")
| where ProcessCommandLine has "creepy.html"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

---

## Created By
- **Author Name:** Ashraf 
- **Date:** April 12, 2025  


---

## Additional Notes
- Attack requires minimal permissions — no need for local admin unless deploying across devices.
- Easily simulated in a lab environment for awareness training or red team exercises.
- Use caution when simulating this in production-like environments.
