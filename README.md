# SOC-Automation-Project

## Objective

The SOC Automation project aims to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, generating test telemetry to mimic real-world attack scenarios that a SOC analyst will have to deal with. The goal is also to integrate tools like Wazuh instance with SOAR integration along with a case management tool using HIVE. 

### Skills Learned
[Bullet Points - Remove this afterwards]

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used

- Wazuh - SIEM and XDR
- HIVE - Case management 
- Shuffle - SOAR capabilities 

## Steps
### Step 1: Make a diagram 

![map 1](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/00ad35b0-8669-4bba-b2dd-d292ac6536c3)

Ref 1: Network Diagram (made in [draw.io](https://app.diagrams.net/))

Steps in the diagram: 
1. Send an event to Wazuh manager
2. Wazuh manager will look at the event and trigger an alert or perform responsive actions if required
3. Wazuh will then send an alert to Shuffle 
4. Shuffle will receive the Wazuh alert and send responsive actions
5. Shuffle will enrinch the IOCs
6. Shuffle will also send the alert to Hive for case management and send email to SOC analyst

![map 2](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/e64f7b30-ee8c-43d6-8143-a1f907314e37)

Ref 2: Simplified diagram

### Step 2: Install Applications and Virtual Machines 
Necessary items:
* [Windows 10 along with Windows 10 installation media ISO](https://www.microsoft.com/en-us/software-download/windows10)
* Ubuntu 22.04
* [Sysmon](https://www.youtube.com/watch?v=uJ7pv6blyog)
* [Wazuh server](https://www.digitalocean.com/)
* Hive server
* [Virtual Box](https://www.virtualbox.org/)
  
Virtual Box settings:

![Virtual Box settings](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/8ecd93b0-18c4-44ec-aa49-4fcb48b75ff9)

**If you run into any errors because Virtual Box won't work with Windows 11, watch this [video](https://www.youtube.com/watch?v=qWj-n4id9EI&list=LL&index=6&t=17s)

![HomeLab window 11 error](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/2cd92310-b6a0-402e-b9ff-421750322710)

** I had to run Powershell as an admin and enter regedit to get to the image above
