# SOC-Automation-Project

## Objective

The SOC Automation project aims to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, generating test telemetry to mimic real-world attack scenarios that a SOC analyst will have to deal with. The goal is also to integrate tools like Wazuh instance with SOAR integration along with a case management tool using The Hive. 

### Skills Learned
[Bullet Points - Remove this afterwards]

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used

- Wazuh - SIEM and XDR
- Hive - Case management 
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

* If you run into any errors because Virtual Box won't work with Windows 11, watch this [video](https://www.youtube.com/watch?v=qWj-n4id9EI&list=LL&index=6&t=17s)

![HomeLab window 11 error](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/2cd92310-b6a0-402e-b9ff-421750322710)

* I had to run Powershell as an admin and enter regedit to get to the image above.

Sysmon:
  
![sysmon install](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/b2bbafde-7cd2-4c82-9082-0c479f7b20f7)


* The process to get Sysmon on your PC is a bit... [elaborate](https://www.youtube.com/watch?v=uJ7pv6blyog), so I am linking the video.

Wazuh:

![firewall settings](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/8dfa1112-d0c0-4999-8959-90409942fad2)
* I used DigitalOcean as my cloud provider. Here is the firewall settings used. For the project, you will be using your own IP address as the source. But you will SSH into the IP address of the droplet. To check the IP address, click [here](https://www.whatismyip.com/).
  
There are two ways to access your droplet. You can make a password, or you can SSH. I decided to use SSH to make the connection between my PC and the VM seemless.

To make an SSH key, type in the keyregen command into Linux. This will generate a public and private key. Use the cat command to expand the public key and get the SSH key.
![SSH key](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/0827e8c0-dd2e-464b-931e-f4561885f24d)


![ssh into wazuh part 1](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/c58281ce-38b2-4018-9363-af0cb652ff70)

I used Linux to connect SSH into Wazuh using the ssh root command.

![ssh into wazuh part 2](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/d2f3fc8d-c698-4c43-ab4d-a2f40d229fa6)

After that, succesfully SSH into Wazuh, I downloaded all the updates necessary. Wazuh web interface should be available afterwards and there should be a username and password given. The username is always admin, but the password is unique, so don't lose it!

Wazuh dashboard:

Copy and paste the IP address for droplet into the URL and then enter in the username and password given in the last image. 

![wazuh interface](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/b148fa8d-e3bc-4ca0-8117-aa8bbe60bac7)

Hive:

Just like Wazuh, it will be made in DigitalOcean.

Another droplet is made, so another SSH key is needed. 

![hive ssh](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/ba74b7fe-061a-44dd-83eb-1b262348ede7)

![Hive SSH key](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/e4d82904-adc8-4056-aba9-95b28f9ee982)

Download the pre-requisites for The Hive [here](https://github.com/MyDFIR/SOC-Automation-Project/blob/main/TheHive-Install-Instructions)

### Step 3: Configure TheHive and Wazuh Server

