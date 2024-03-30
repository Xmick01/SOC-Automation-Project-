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
* [Windows 10](https://www.microsoft.com/en-us/software-download/windows10)
* Ubuntu 22.04 
* Wazuh server
* Hive server
* [Virtual Box](https://www.virtualbox.org/)
* 

