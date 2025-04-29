<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/abeldemiss/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. File Activity Search
Searched the `DeviceFileEvents` table for any file containing the word "tor". Discovered that user `ademiss` downloaded a TOR installer, which led to many TOR-related files being copied to the desktop and the creation of a file called `tor shopping list.txt` on the desktop at `2025-04-29T01:48:28.0337916Z`. These events began at `2025-04-29T01:36:19.9821953Z`.

**Query Used:**
```kusto
DeviceFileEvents
| where DeviceName == "abel-vm"
| where InitiatingProcessAccountName == "ademiss"
| where FileName contains "tor"
| where  Timestamp >= datetime(2025-04-29T01:01:52.1955592Z)
| order by Timestamp desc
| project  Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
```
![image](https://github.com/user-attachments/assets/9f2b48d5-ab51-49b5-98ad-64c17e536c0d)

---

### 2. Process Execution Search
Searched the `DeviceProcessEvents` table for any `ProcessCommandLine` containing the string `tor-browser-windows-x86_64-portable-14.5`. Logs show that at `2025-04-29T01:39:42.625117Z`, an employee on the `abel-vm` device ran the file from their downloads folder, triggering a silent installation.

**Query Used:**
```kusto
DeviceProcessEvents
| where DeviceName == "abel-vm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/d4ce844a-88fc-477a-8a3e-44e17c36b8a3)

---

### 3. TOR Browser Launch Evidence
Searched the `DeviceProcessEvents` table for any indication that user `ademiss` opened the TOR browser. Evidence shows it was opened at `2025-04-29T01:40:17.1369436Z`, with several instances of `firefox.exe` (TOR) and `tor.exe` spawned afterwards.

**Query Used:**
```kusto
DeviceProcessEvents
| where DeviceName  == "abel-vm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/5b08ea2c-ef4b-4815-a8a6-1726b1035b9f)

---

### 4. Network Activity Search
Searched the `DeviceNetworkEvents` table for any indication the TOR browser established a connection using known TOR ports. At `2025-04-29T01:41:32.5967144Z`, a connection was established to `127.0.0.1` on port `9150` by `tor.exe` in `c:\users\ademiss\desktop\tor browser\browser\firefox.exe`. Other connections to sites over port 443 were also observed.

**Query Used:**
```kusto
DeviceNetworkEvents
| where DeviceName == "abel-vm"
| where InitiatingProcessAccountName != 'system'
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001","9030","9040","9050","9150", "80", "443")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessAccountName, RemoteUrl, InitiatingProcessFolderPath
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/5c4c11d7-c27e-4a68-b647-58d0988b5b4b)

---

## Chronological Events

### 1. Download and Installation of TOR Browser
- **Timestamp:** Apr 28, 2025, 9:36:19 PM
  - **Event:** File renamed to `tor-browser-windows-x86_64-portable-14.5.exe` in `C:\Users\ademiss\Downloads\`.
  - **SHA256:** `3a678091f74517da5d9accd391107ec3732a5707770a61e22c20c5c17e37d19a`
  - **Significance:** TOR Browser installer downloaded and saved to the system.

- **Timestamp:** Apr 28, 2025, 9:39:42 PM
  - **Event:** Silent installation of TOR Browser initiated via command:
    - `tor-browser-windows-x86_64-portable-14.5 /S`
    - **Process:** `tor-browser-windows-x86_64-portable-14.5.exe`
    - **Location:** `C:\Users\ademiss\Downloads\`

- **Timestamp:** Apr 28, 2025, 9:39:59 PM – 9:40:00 PM
  - **Events:**
    - TOR Browser files extracted to `C:\Users\ademiss\Desktop\Tor Browser\`
    - **Key files created:**
      - `tor.exe` (SHA256: `fe6d44cb69780e09c3a39f499e0e668bff9aa54b6cd9f363b753d59af713bea0`)
      - License files (`tor.txt`, `Torbutton.txt`, `Tor-Launcher.txt`)

### 2. Execution of TOR Browser
- **Timestamp:** Apr 28, 2025, 9:40:14 PM
  - **Event:** First instance of `firefox.exe` (TOR Browser) launched from:
    - `C:\Users\ademiss\Desktop\Tor Browser\Browser\firefox.exe`
    - **SHA256:** `3613fc46eab116864d28b7a3af1b7301fc0309bf3ba99c661a8c36ad5c848d02`

- **Timestamp:** Apr 28, 2025, 9:40:17 PM – 9:40:38 PM
  - **Events:**
    - Multiple child processes of `firefox.exe` spawned (content processes for tabs, GPU, utility)
    - `tor.exe` launched with configuration parameters, including:
      - Control port: `127.0.0.1:9151`
      - Socks port: `127.0.0.1:9150`
      - GeoIP files and Torrc configuration loaded

### 3. Network Activity and TOR Connections
- **Timestamp:** Apr 28, 2025, 9:40:52 PM
  - **Event:** Initial failed connection attempt to `127.0.0.1:9150` (TOR proxy port) via `firefox.exe`

- **Timestamp:** Apr 28, 2025, 9:41:22 PM – 9:41:24 PM
  - **Events:** Successful TOR connections established:
    - **Remote IPs/Ports:**
      - `146.70.222.42:443` (URL: https://www.tulpmgpp4dlhp6dwkgj6in2h.com)
      - `84.16.234.150:443` (URL: https://www.ac36qn7car.com)
      - `145.40.195.49:9001` (URL: https://www.nocex.com)
    - **Process:** `tor.exe` (acting as TOR client)

- **Timestamp:** Apr 28, 2025, 9:41:32 PM
  - **Event:** Successful local proxy connection to `127.0.0.1:9150` via `firefox.exe` (TOR Browser)

### 4. User Activity and Artifacts
- **Timestamp:** Apr 28, 2025, 9:48:28 PM
  - **Events:**
    - File created: `tor shopping list.txt` on desktop (SHA256: `e4f88f3c0e7595e03530104f38d57219733fd79b7fe64a973d8a2e520ac71d28`)
    - Shortcut created: `tor shopping list.lnk` in Recent Files
    - **Significance:** Suggests user activity related to TOR browsing (e.g., accessing hidden services or markets)

### 5. Continued TOR Browser Usage
- **Timestamp:** Apr 28, 2025, 9:40:17 PM – 9:44:57 PM
  - **Events:**
    - Repeated spawning of `firefox.exe` content processes (child tabs)
    - No further unique network events, but browser activity persisted

---

## Summary of Findings

### Unauthorized Installation
- User `ademiss` downloaded and silently installed TOR Browser Portable at 9:39:42 PM on Apr 28, 2025.

### TOR Network Usage
- Successful connections to TOR entry nodes (`145.40.195.49:9001`, `146.70.222.42:443`) and proxy (`127.0.0.1:9150`).
- Suspicious domains accessed (e.g., `tulpmgpp4dlhp6dwkgj6in2h.com`).

### User Activity
- Created `tor shopping list.txt`, indicating potential use of TOR for accessing hidden services.

### Persistence
- Multiple instances of `firefox.exe` (TOR) and `tor.exe` running for ~30 minutes.

---

## Summary
The user `ademiss` on the `abel-vm` device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor shopping list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken
- TOR usage was confirmed on the endpoint `abel-vm` by the user employee.
- The device was isolated.
- The user's direct manager was notified. 
