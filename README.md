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
- thehive - Case management 
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

![wazuh interface](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/aaadd506-1e97-49fb-9907-f87595719216)

Hive:

Just like Wazuh, it will be made in DigitalOcean.

Another droplet is made, so another SSH key is needed. 

![hive ssh](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/ba74b7fe-061a-44dd-83eb-1b262348ede7)

![Hive SSH key](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/e4d82904-adc8-4056-aba9-95b28f9ee982)

Download the pre-requisites for thehive [here](https://github.com/MyDFIR/SOC-Automation-Project/blob/main/TheHive-Install-Instructions)

### Step 3: Configure TheHive and Wazuh Server

Configure thehive with Cassandra. (nano /etc/cassandra/cassandra.yaml

Find the listen_address and replace the IP listed with the public IP of The Hive.
![listen_address](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/9a341b34-eea8-4031-988e-e490f957fff8)

Find the rpc_address and replace the IP listed with the public IP of The Hive.
![rpc_address](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/db775bae-a537-4732-ad9b-90c3ba093342)

Find the seed_provider and replace the IP listed with the public IP of The Hive.
![seed_provider](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/eec96b10-180c-4b11-966f-d21c2fff7c37)

Check the status of Cassandra

![cassandra status (running)](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/7a33e54b-156f-44f5-83bf-d844dea4846c)

Next, configure thehive with elasticsearch. (nano /etc/elasticsearch/elasticsearch.yml)

Find the cluster name and rename it to thehive

![elasticsearch config1](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/727fc8bf-8c94-4004-b5af-82136941eb59)

Replace the network host with the public IP of thehive

![elasticsearch config2](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/fad26346-99cf-406c-a356-fb7f359bd31f)

Check the status or elasticsearch

![elasticsearch status](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/551d8237-55ed-47bb-bf9b-3cb07f9a54fa)

Next, configure thehive itself. The installation step-by-step process is [here](https://docs.thehive-project.org/thehive/installation-and-configuration/installation/step-by-step-guide/)

Replace the hostname with thehive public IP

![thehive config2](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/6af72e1f-160a-4625-bc66-ac01e7b21b48)

Replace the hostname with thehive public IP, but make sure to keep the 9000 port number at the end of the base url

![thehive config 3](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/cb1b8057-5235-4352-9d78-1bd57bc020ab)

Finally, check the status of thehive

![thehive running status](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/2a3d7764-254e-46c7-9734-41e8ff4d5d88)

If all three services are up and running and thehive login credentials work, the dashboard should look like this

![thehive dashboard](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/0fcf08a9-7ccc-40f5-b057-9db4811bfe18)

Finally, it's time to add the Wazuh [agent](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)

![wazuh agent](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/aae77eb3-9b4b-4026-8f79-ae086d67728c)

When done, the agent should be active like this

![wazuh agent2](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/d8e34479-28d9-4dfd-9a1c-61dcdfad4294)

### Step 3: Generate telemetry and ingest into Wazuh

Begin by going to event vewier to get the full name for Sysmon

![event viewer sysmon](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/972799c9-15c4-4429-8d5f-536b9045bac1)

Copy the full name of sysmon into the location under localfile in the ossec.conf file

![Ossec-conf sysmon](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/cdbe8509-5da7-4319-951c-c62784f9827d)


Next, download [mimikatz](https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20220919) (WARNING: mimikatz is malicous and will trigger your computer's security defense)

Run the powershell as an admin and run mimikatz.exe

* Again, mimikatz is a malware program, so proceed with caution.

![mimikatz](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/39eb55d7-1c53-4828-a17a-a5ee8bb17709)

Next, let's configurate the ossec.conf file so that the alert log and json logs are both 'yes'

* This forces Wazuh to archive the logs and put them into a file called archive. (/var/ossec/logs/archives/)

![ossec conf config](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/4212460c-7802-4daa-8a07-6fc314755679)

In order for Wazuh to start ingesting these logs, the filebeat will need to be configured to enable archives.

![filebeat archive enabled](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/49a9791b-fd11-4169-b5f5-fa94455d4373)

* Change archives enabled setting from false to true.

Next, check to make sure Sysmon is capturing mimikatz by visiting the event vewier. Sysmon should be generating on the windows machine, which is configured to push Sysmon data to Wazuh.

![mimikatz sysmon](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/62cdbc28-3bcf-44d7-acfd-511941517a74)

Use cat archives.json | grep -i mimikatz to see data about mimikatz in the archive file. So mimikatz should appear in the Wazuh dashboard.

![mimikatz archives](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/2aa3c3fd-026b-4687-9dd8-799921f40c01)

In order to make sure mimikatz is the only alert shown, the rules have to be customized. 

![custom rule](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/9c71199e-8c20-40ff-8435-ed5afe183bdb)

* mimikatz is a high level threat, so the threat level is set to the highest level.

![mimikatz archives](https://github.com/Xmick01/SOC-Automation-Project-/assets/130627895/2aa3c3fd-026b-4687-9dd8-799921f40c01)
