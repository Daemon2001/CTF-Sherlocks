
CTF-Sherlocks Walkthrough Page
---

<a href="http://www.linkedin.com/in/daemon-adams">LinkedIn</a>


Welcome to my GitHub portfolio
Here, I document my journey through HTB Sherlocks, TryHackMe challenges, that demonstrate my skills in offensive and defensive security. 
This space serves as both a showcase of my technical capabilities and a reflection of my commitment to continuous learning in the cybersecurity field.

# **Sherlock's**

## Trojan
  Completed: 07/23/25
  
  Analyst: Dae'mon Adams

Scenario: John Grunewald was deleting some old accounting documents when he accidentally deleted an important document he had been working on. He panicked and downloaded software to recover the document, but after installing it, his PC started behaving strangely. 
Feeling even more demoralised and depressed, he alerted the IT department, who immediately locked down the workstation and recovered some forensic evidence. Now it is up to you to analyze the evidence to understand what happened on John's workstation.

**Tools used**:
  - Wireshark
  - FTK Imager
  - Volatility
  
---
Task 1: What is the build version of the operating system?
  Answer: 19041
  Explanation: Using Volatility, the build version 19041 was extracted from the memory image. This indicates the workstation was running Windows 10 version 2004, a key data point for ensuring compatibility with memory analysis tools.
![Image](Image Folder/Screenshot 2025-07-23 191819.png)

Task 2: What is the computer hostname?
  Answer: DESKTOP-38NVPD0
  Explanation: The hostname was retrieved directly from Wireshark, identifying the compromised machine within the organization’s network.
![Image](Image Folder/Screenshot 2025-07-23 194631.png)

Task 3: What is the name of the downloaded ZIP file?
  Answer: Data_Recovery[.]zip
  Explanation: Using FTK Imager, the suspicious ZIP archive downloaded by the user was found in the Downloads directory. It contained the malicious executable responsible for the compromise.
![Image](Image Folder/Screenshot 2025-07-23 193603.png)

Task 4: What is the domain of the website (including the third-level domain) from which the file was downloaded?
  Answer: praetorial-gears[.]000webhostapp[.]com
  Explanation: Using Wireshark's HTTP object list and DNS query logs, this domain was identified as the origin of the downloaded ZIP. It was hosted on a free web hosting provider, commonly abused for malware delivery.
![Image](Image Folder/Screenshot 2025-07-23 195110.png)

Task 5: What is the process PID of the suspicious application?
  Answer:484
  Explanaiton: Volatility’s pslist plugin revealed that the suspicious executable, Recovery_Setup.exe, was running with PID 484, confirming execution of the payload.
![Image](Image Folder/Screenshot 2025-07-23 195931.png)

Task 6: What is the full path of the suspicious process?
  Answer: C:\Users\John\Downloads\Data_Recovery\Recovery_Setup[.]exe
  Explanation: Memory analysis confirmed the exact execution path of the malware, linking it directly to the downloaded ZIP archive.
![Image](Image Folder/Screenshot 2025-07-23 200258.png)

Task 7: What is the SHA-256 hash of the suspicious executable?
  Answer: C34601C5DA3501F6EE0EFCE18DE7E6145153ECFAC2CE2019EC52E1535A4B3193
  Explantaion: Using Wiresharks HTTP Object List, the file hash was downloaded on my Windows VM and cross-referenced on VirusTotal, revealing high detection as a Trojan. This hash served as a key indicator for threat attribution.
![Image](Image Folder/Screenshot 2025-07-23 200828.png)

Task 8: When was the malicious program first executed?
  Answer: 2023-05-30 02:06:29
  Explanation: Execution timestamps were extracted from the Windows Prefetch data. This allowed analysts to determine initial infection time and correlate it with user activity.
![Image](Image Folder/Screenshot 2025-07-23 202944.png)

Task 9: How many times in total has the malicious application been executed?
  Answer: 2
  Explanation: Prefetch artifacts revealed two distinct execution events of the malicious file, reinforcing the persistence or repeated user error.


Task 10: What is the other .TMP file referenced by the malware, aside from IS-NJBAT.TMP?
  Answer: IS-R7RFP.TMP
  Explanation: Both TMP files were found in memory and linked to the malware’s runtime behavior. These likely acted as temporary staging files used during the infection process.
![Image](Image Folder/Screenshot 2025-07-23 203137.png)

Task 11: How many URLs contacted by the malicious application were detected as malicious by VirusTotal?
  Answer: 4
  Explanation: Captured network traffic in the PCAP file, analyzed with Wireshark and verified with VirusTotal, showed four outbound URLs flagged for malicious activity. These were likely C2 servers.
![Image](Image Folder/Screenshot 2025-07-23 203447.png)

Task 12: What is the name of the binary file downloaded by the malware?
  Answer: puk.php
  Explanation: The file puk.php was identified in the HTTP object list and appeared to be downloaded from one of the malicious C2 domains. It could have been a secondary payload or a data exfiltration script.
![Image](Image Folder/Screenshot 2025-07-23 205103.png)

Task 13: What was the name and version of the legitimate software the malware was impersonating?
  Answer: FinalRecovery v3.0.7.0325
  Explanation: By searching the internet with the SHA-256 hash i found a public sandbox reports (e.g., Joe Sandbox), the malware was found to mimic FinalRecovery, a legitimate data recovery application, to gain user trust and avoid suspicion.
<a href="https://www.joesandbox.com/analysis/790730/0/pdf">
