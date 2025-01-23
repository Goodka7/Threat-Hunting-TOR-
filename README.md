<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Goodka7/Threat-Hunting/blob/main/resources/Threat_Hunt_Event(TOR%20Usage).md)

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

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor", ".exe", ".txt", or ".json" in it. 

At 3:39:26 PM on January 20, 2025, the user "labuser" created a file named "tor.exe" on the device "hardmodevm." The file was saved in the folder path: C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe. The file's SHA256 hash is c3b431779278278cda8d2bf5de5d4da38025717630bfeae1a82c927d0703cd28.	

The search yielded other items including the creation of a folder (tor-shopping-list) which held several artifacts of interest: several .txt files and a few .jsons, with names that suggest illicit activity.


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "hardmodevm"
| where FileName contains (“tor”, “.txt” , “.exe” , “.json”)
| where InitiatingProcessAccountName == "labuser"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/6f212b1a-e4f5-40dc-be67-2a0e4bd44c62">
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/db49fe7f-ee5b-468a-bf32-a0affe7b282d">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.4.exe". 

At 3:30:55 PM on January 20, 2025, the user "labuser" created a process called "cmd.exe" on the device "hardmodevm." The process was located in C:\Windows\System32\cmd.exe, with the SHA256 hash of badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0. 

The command executed was:<span style="color: green;">
"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command "Start-Process \"C:\Downloads\tor-browser-windows-x86_64-portable-14.0.4.exe\" -ArgumentList '/S' -NoNewWindow -Wait"</span>, which initiated the installation of the Tor Browser, silently.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName  == "hardmodevm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.4.exe"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, Command = ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/a610791a-0559-410d-881d-397251039bbf">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser.The results showed user “labuser” accessed tor.exe (tor browser), firefox.exe(tor browser) several times:

At 3:42:49 PM on January 20, 2025, the user "labuser" created a process called "tor.exe" on the device "hardmodevm." The process was located at C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe, with the SHA256 hash c3b431779278278cda8d2bf5de5d4da38025717630bfeae1a82c927d0703cd28. 


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName  == "hardmodevm"
| where ProcessCommandLine has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, Command = ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/785257b9-5e7c-4ce6-8bb2-f9f0c8c59f0f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
