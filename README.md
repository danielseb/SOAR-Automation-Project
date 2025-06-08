# SOC Automation Pipeline: Real-Time Alert Triage with LimaCharlie & Tines

This project demonstrates how to build a lightweight Security Orchestration, Automation and Response (SOAR) pipeline that connects detection, enrichment, triage, and response workflows across multiple platforms — all without relying on commercial enterprise infrastructure. The end goal is to show how real-world SOC tasks like threat detection, automated enrichment, case creation, analyst notification, and host isolation can be orchestrated end-to-end using LimaCharlie, Tines, TheHive, VirusTotal, and Slack.

At its core, this project simulates a security incident — the execution of Mimikatz on a Windows 10 host — and automatically responds by collecting telemetry, applying custom detection rules, enriching with threat intel, determining severity, and taking action. High severity alerts result in automatic case creation in TheHive, notifications in Slack, and emails to the analyst with embedded options to isolate the host or dismiss the alert as a false positive. Every part of the pipeline has been built and tested manually to reinforce a deep understanding of SOC operations, and to highlight the kind of automation and integration skills required in modern security teams.

---

## Tools Used

- **The Hive** — Security Incident Response Platform for case management  
- **Tines** — Security Orchestration, Automation, and Response (SOAR) platform used for automation workflows  
- **LimaCharlie** — Endpoint Detection and Response (EDR) platform used for detection telemetry and host isolation  
- **VirusTotal** — Threat intelligence enrichment for IOCs  
- **Ubuntu 22.04 VM** — Host environment for The Hive server  
- **Java, Cassandra, Elasticsearch** — Dependencies required to run The Hive server  

---

## Setting up The Hive Server

### Cloud VM Setup

- Provisioned a cloud virtual machine with:  
  - 8GB RAM  
  - 120GB SSD  
  - Ubuntu 22.04 LTS  

- Configured cloud firewall to allow inbound TCP/UDP only from my external IP to reduce attack surface, especially on SSH.

### Initial VM Setup

SSH into the VM and run:

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl software-properties-common python3-pip lsb-release -y
```
Install Java (Amazon Corretto 11):

```bash
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | sudo tee /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk -y
echo 'JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"' | sudo tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```
Install Cassandra:

```bash
wget -qO - https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" | sudo tee /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra -y
```
Install Elasticsearch:

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https -y
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch -y
```
Install The Hive:
```bash
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee /etc/apt/sources.list.d/strangebee.list
sudo apt-get update
sudo apt-get install -y thehive
```

Configure Cassandra

Edit /etc/cassandra/cassandra.yaml and update these parameters to the server’s public IP instead of localhost:
```yaml
listen_address: <your-server-public-ip>
rpc_address: <your-server-public-ip>
seed_provider:
  - class_name: org.apache.cassandra.locator.SimpleSeedProvider
    parameters:
      - seeds: "<your-server-public-ip>"
```

Stop Cassandra, remove old data, restart, and verify service status:
```bash
sudo systemctl stop cassandra.service
sudo rm -rf /var/lib/cassandra/*
sudo systemctl start cassandra.service
sudo systemctl status cassandra.service
```

Configure Elasticsearch

Edit /etc/elasticsearch/elasticsearch.yml and update:

```yaml
cluster.name: thehive
network.host: <your-server-public-ip>
http.port: 9200
cluster.initial_master_nodes: ["<your-server-public-ip>"]  # uncomment and set your IP
```

Start, enable, and check status:

```bash
sudo systemctl start elasticsearch.service
sudo systemctl enable elasticsearch.service
sudo systemctl status elasticsearch.service
```

Set Permissions for The Hive Directory:

```bash
sudo chown -R thehive:thehive /opt/thp
```

Configure The Hive

Edit /etc/thehive/application.conf and update:

- storage.hostname to your server’s public IP
- index.search.hostname to your server’s public IP
- cluster.name to match Cassandra’s cluster name (thehive)
- application.baseURL to http://<your-server-public-ip>:9000

Resolve Elasticsearch Memory Issue

Elasticsearch may crash due to default Java heap size on a VM with 8GB RAM. Create JVM options file to reduce heap:
```bash
sudo vim /etc/elasticsearch/jvm.options.d/jvm.options
```

Paste the following:

-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g

Restart Elasticsearch:
```bash
sudo systemctl restart elasticsearch.service
```
Verify

Visit http://<your-server-public-ip>:9000 in browser. The Hive UI should load (default credentials apply, though authentication errors may occur until config is finalised).

2. Simulating Detection with LimaCharlie and Mimikatz

I deployed the LimaCharlie agent on a test Windows 10 virtual machine.

Installing the LimaCharlie Sensor

From the LimaCharlie web interface:

- Go to Deployments → Add Sensor
- Select Windows → download the appropriate installer
- Run the installer on the Windows 10 host

Executing Mimikatz

I downloaded Mimikatz onto the test system and executed it with ```SEKURLSA::logonpasswords``` to simulate LSASS access. I then studied the telemetry generated by this in LimaCharlie and used this to configure the following detection rules.

**Rule 1: Unsigned Process Spawned by PowerShell**

This rule is designed to detect unsigned executables launched directly by PowerShell. Attackers often use PowerShell to run living-off-the-land binaries (LOLBINs) or drop tools like Mimikatz. Legitimate software is usually signed, so an unsigned binary being run by PowerShell is a strong behavioural indicator of suspicious or malicious activity.

```yaml
events:
  - NEW_PROCESS
op: and
rules:
  - op: is
    path: event/FILE_IS_SIGNED
    value: 0
  - op: ends with
    case sensitive: false
    path: event/PARENT/FILE_PATH
    value: powershell.exe
- action: report
  metadata:
    author: Daniel Sebastian
    description: Detects unsigned binaries launched from PowerShell — a common TTP in LOLBIN and Mimikatz activity.
    tags:
      - attack.execution
      - attack.t1059.001
      - powershell
      - unsigned
    level: medium
    falsepositives:
      - Legitimate unsigned admin tools run via script
  name: Unsigned Process Spawned by PowerShell
```

**Rule 2: Unsigned Process Accessing LSASS**

This rule detects unsigned processes attempting to access `lsass.exe`, the Windows Local Security Authority process. LSASS contains sensitive credential material, and accessing it is a common tactic for tools like Mimikatz during credential dumping. Since legitimate access to LSASS is rare and typically performed by signed system components, this rule helps flag potential credential theft activity.

```yaml
events:
  - SENSITIVE_PROCESS_ACCESS
op: and
rules:
  - op: is
    path: event/EVENTS/[1]/event/SOURCE/FILE_IS_SIGNED
    value: 0
  - case sensitive: false
    op: contains
    path: event/EVENTS/[0]/event/FILE_PATH
    value: lsass.exe
  - op: is windows
- action: report
  metadata:
    author: Daniel Sebastian
    description: Detects unsigned processes attempting to access LSASS, commonly associated with credential dumping (e.g., Mimikatz).
    tags:
      - attack.credential_access
      - attack.t1003.001
      - mimikatz
      - lsass
    level: high
    falsepositives:
      - Debug tools or EDR misconfigurations
  name: Unsigned Process Accessing LSASS
```

**Rule 3: Known Mimikatz Hash Executed**

This rule triggers when a binary with a known Mimikatz SHA-256 file hash is executed. Matching on a confirmed malicious hash provides high confidence that a specific version of Mimikatz was run in the environment, indicating a serious compromise. This rule helps catch cases where the attacker didn’t obfuscate or recompile the tool.

```yaml
events:
  - CODE_IDENTITY
op: and
rules:
  - op: is
    path: event/HASH
    value: 61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1
  - op: is windows
- action: report
  metadata:
    author: Daniel Sebastian
    description: Detects execution of a known Mimikatz binary using its SHA-256 hash.
    tags:
      - attack.execution
      - attack.t1003.001
      - mimikatz
      - hash_ioc
    level: critical
    falsepositives:
      - Very unlikely unless hash collision
  name: Known Mimikatz Hash Executed
```

Overview of Automation Story with Tines

This lab uses Tines to automate detection, enrichment, alerting, and response workflows. The primary goals are to:

- Receive detection alerts from LimaCharlie EDR telemetry
- Enrich suspicious indicators using VirusTotal API
- Calculate alert severity dynamically using custom logic
- Create and update cases in The Hive based on severity
- Notify SOC analysts via Slack and email with detailed incident info
- Enable analysts to isolate compromised hosts directly through email interaction (triggering LimaCharlie host isolation)

Prerequisites

- Accounts and API keys for LimaCharlie, VirusTotal, The Hive, and Tines are assumed to be configured
- API keys should be securely stored as secrets within Tines for use by the story

Tines Story Walkthrough

Ingesting Detections

I created a new Story and added a Webhook called Retrieve Alerts from LimaCharlie. I configured LimaCharlie to forward detections to this Webhook by adding a new Output of type Detections → Tines and pasting in the URL.

Running Mimikatz again confirmed the detections were successfully sent into Tines.

- LimaCharlie EDR is configured to send detection telemetry (e.g., process injection, suspicious command lines) to a Tines webhook endpoint
- Tines receives JSON payloads representing detected events

Snippet of a payload sent from LimaCharlie to the Tines webhook:
```json
{
  "retrive_alerts_from_limacharlie": {
    "body": {
      "author": "analyst@email.com",
      "cat": "Unsigned Process Accessing LSASS",
      "detect": {
        "event": {
          "EVENTS": [
            {
              "event": {
                "BASE_ADDRESS": 140701486022656,
                "COMMAND_LINE": "C:\\Windows\\system32\\lsass.exe",
                "CREATION_TIME": 1749206799169,
                "FILE_IS_SIGNED": 1,
                "FILE_PATH": "C:\\Windows\\system32\\lsass.exe",
                "HASH": "8871c20eaa9b560f41c9b874f9bf00b057128ff8e91bc5664b83dc7ba95a3c9a",
                "MEMORY_USAGE": 17424384,
                "PARENT": {
                  "FILE_IS_SIGNED": 1,
                  "FILE_PATH": "\\Device\\HarddiskVolume1\\Windows\\System32\\wininit.exe",
                  "HASH": "b7c013f81f2e983a50e636a73bd3026cbddea08cba9afb078664fe08132cb8a1",
                  "MEMORY_USAGE": 7454720,
                  "PARENT_PROCESS_ID": 420,
                  "PROCESS_ID": 508,
                  "THIS_ATOM": "c028dd48ef76248f9effffcc6842c71f",
                  "THREADS": 7,
                  "TIMESTAMP": 1749206815912,
                  "USER_NAME": "NT AUTHORITY\\SYSTEM"
                },
                "PARENT_PROCESS_ID": 508,
                "PROCESS_ID": 648,
                "THREADS": 13,
                "USER_NAME": "NT AUTHORITY\\SYSTEM"
              },
              "routing": {
                "arch": 2,
                "did": "",
                "event_id": "a5a8d146-cd15-447a-93f2-ebada3f10235",
                "event_time": 1749206816101,
                "event_type": "EXISTING_PROCESS",
                "ext_ip": "123.123.123.123",
                "hostname": "win10lab.broadband",
                "iid": "45c1a5d4-a35b-4129-bebe-a660d7052d1d",
                "int_ip": "10.0.2.15",
                "latency": 47842,
                "moduleid": 2,
                "oid": "3d1f456e-bca5-441f-a7e9-806bf7dc6276",
                "parent": "c028dd48ef76248f9effffcc6842c71f",
                "plat": 268435456,
                "sid": "4987382d-8de8-4bba-9e8f-2157feeb216a",
                "tags": [],
                "this": "51dd4dec1b414fe8b24a3e716842c720"
              }
            },
            {
              "event": {
                "ACCESS_FLAGS": 4112,
                "PARENT_PROCESS_ID": 7780,
                "PROCESS_ID": 648,
                "SOURCE": {
                  "BASE_ADDRESS": 140696113315840,
                  "COMMAND_LINE": "\"C:\\Users\\bobsmith\\Downloads\\mimikatz_trunk\\x64\\mimikatz.exe\"",
                  "FILE_IS_SIGNED": 0,
                  "FILE_PATH": "C:\\Users\\bobsmith\\Downloads\\mimikatz_trunk\\x64\\mimikatz.exe",
                  "HASH": "61c0810a23580cf492a6ba4f7654566108331e7a4134c968c2d6a05261b2d8a1",
                  "MEMORY_USAGE": 13586432,
                  "PARENT_ATOM": "3e20b20e1a595ff8a3a571e46842c733",
                  "PARENT_PROCESS_ID": 7492,
                  "PROCESS_ID": 7780,
                  "THIS_ATOM": "ed7e43985a6597bd23d5be9e6842c743",
                  "THREADS": 3,
                  "TIMESTAMP": 1749206851253,
                  "USER_NAME": "WIN10LAB\\bobsmith"
                },
                "TARGET": {
                  "BASE_ADDRESS": 140701486022656,
                  "COMMAND_LINE": "C:\\Windows\\system32\\lsass.exe",
                  "CREATION_TIME": 1749206799169,
                  "FILE_IS_SIGNED": 1,
                  "FILE_PATH": "C:\\Windows\\system32\\lsass.exe",
                  "HASH": "8871c20eaa9b560f41c9b874f9bf00b057128ff8e91bc5664b83dc7ba95a3c9a",
                  "MEMORY_USAGE": 17424384,
                  "PARENT_ATOM": "c028dd48ef76248f9effffcc6842c71f",
                  "PARENT_PROCESS_ID": 508,
                  "PROCESS_ID": 648,
                  "THIS_ATOM": "51dd4dec1b414fe8b24a3e716842c720",
                  "THREADS": 13,
                  "TIMESTAMP": 1749206816101,
                  "USER_NAME": "NT AUTHORITY\\SYSTEM"
                }
              }
            }
          ]
        }
      }
    }
  }
}

```

VirusTotal Enrichment

I added a VirusTotal card to the Story and queried it using the hash of the binary that accessed LSASS. I authenticated using my VirusTotal API key and validated the hash as Mimikatz.exe.

Example Tines HTTP Request Action (curl snippet):
```
curl --request GET \
  --url "https://www.virustotal.com/api/v3/files/<file_hash>" \
  --header "x-apikey: YOUR_VT_API_KEY"
```

- Parses VirusTotal response to extract:

  - Number of detections by AV engines
  - Verdict (malicious, suspicious, clean)
  - Related malware family tags

Determining Severity

I added a script to calculate alert severity based on:

- Source process path
- Target process path
- File signature status
- VirusTotal malicious count

Input:

```
{
  "source_process": "<<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[1].event.SOURCE.FILE_PATH>>",
  "target_process": "<<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[1].event.TARGET.FILE_PATH>>",
  "signed": "<<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[1].event.SOURCE.FILE_IS_SIGNED>>",
  "positives": "<<search_file_hash_on_virustotal.body.data[0].attributes.last_analysis_stats.malicious>>"
}
```

Script:

```python
def main(input):
    source = input.get("source_process", "").lower()
    target = input.get("target_process", "").lower()
    signed = input.get("signed", "true").lower()
    try:
        positives = int(input.get("positives", 0))
    except ValueError:
        positives = 0

    severity = "low"

    if positives > 5:
        severity = "high"
    elif "cmd.exe" in source or "powershell.exe" in source:
        severity = "medium"
    elif signed == "false" and "lsass.exe" in target:
        severity = "high"

    return { "severity": severity }
```

Branching Logic

Depending on severity, Tines routes the alert to different workflows:

- High severity: Create a case in The Hive, send a Slack message, send an email with isolate option
- Medium/Low: Just send a Slack message

Automatic Case Creation in The Hive

- Logged in with default credentials
- Created an Org and two accounts: analyst Alice and a service account
- Created API key in the service account
- Added API credentials in Tines → Connected successfully
- Opened firewall port 9000 to allow communication

Example to create a case in The Hive:
```json
{
  "description": "Mimikatz Detected on host: <<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[0].routing.hostname>>",
  "flag": false,
  "pap": 2,
  "time": "<<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[0].routing.event_time>>",
  "title": "Mimikatz Detected",
  "host": "<<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[0].routing.hostname>>",
  "severity": 2,
  "source": "LimaCharlie",
  "sourceRef": "Unsigned-Process-Accessing-LSASS",
  "summary": "Mimikatz detected on host: <<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[0].routing.hostname>>    ProcessID: <<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[1].event.SOURCE.PROCESS_ID>> CommandLine: <<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[1].event.SOURCE.COMMAND_LINE>>",
  "tags": [
    "T1003"
  ],
  "tlp": 2,
  "type": "internal"
}
```

Slack Notification

- Added a Slack card → Connected the Tines bot
- Used channel ID to send alert details
- Slack messages sent via Tines Slack integration contain:
  - Alert summary
  - Severity
  - Link to The Hive case

Email Alert with Isolation Option

- Added a Send Email card
- Email contains alert summary and three buttons (HTML formatted):
  - Isolate Host
  - Mark False Positive
  - View in LimaCharlie

HTML of the email that is automatically generated and sent to the analyst:

```html
LimaCharlie has detected an <b><<retrive_alerts_from_limacharlie.body.cat>></b><br>
<br>The details are as follows:<br>
<br><b>Time:</b> <<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[1].routing.event_time>>
<br><b>Host:</b> <<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[1].routing.hostname>>
<br><b>Source IP:</b> <<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[1].routing.int_ip>>
<br><b>Username:</b> <<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[1].event.SOURCE.USER_NAME>>
<br><b>File Path:</b> <<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[1].event.SOURCE.FILE_PATH>>
<br><b>VirusTotal Positives:</b> <<search_file_hash_on_virustotal.body.data[0].attributes.last_analysis_stats.malicious>>
<br><b>Command Line:</b> <<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[1].event.SOURCE.COMMAND_LINE>>
<br><b>Sensor ID:</b> <<retrive_alerts_from_limacharlie.body.detect.event.EVENTS[1].routing.sid>>
<br><br><b>Actions:</b>


<br><br>
<a href="<<retrive_alerts_from_limacharlie.body.link>>" style="background-color: #0066cc; color: white; padding: 12px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 5px;">🔍 Analyse Detection in LimaCharlie</a>
<br><br>
<a href="<<PROMPT("isolate")>>" style="background-color: #ff4444; color: white; padding: 12px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 5px;">🔒 Isolate Host</a>
<br><br>
<a href="<<PROMPT("false")>>" style="background-color: #6c757d; color: white; padding: 12px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 5px;">❌ Mark False Positive</a>
```

Host Isolation via LimaCharlie

- Created a LimaCharlie card triggered by the isolation button
- Added credential in Tines with Org JWT from LimaCharlie
- Verified the host lost internet connectivity after isolation was triggered

- On analyst clicking Isolate Host in the email, Tines triggers a workflow to call LimaCharlie EDR API:

```curl -X POST "https://api.limacharlie.io/endpoint/isolate" \
  -H "Authorization: Bearer YOUR_LIMACHARLIE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"hostId":"host01","isolate":true}'
```

- Confirmation of isolation status is sent back to the analyst via email or Slack.

Marking as False Positive

- Clicking "Mark as False Positive" button triggers Tines to close the case in The Hive with the status false positive

## Summary

This lab demonstrates practical SOC skills including:

- Secure setup and configuration of The Hive SIEM server
- Integration of multiple security tools for automated alert enrichment and triage
- Developing dynamic severity scoring logic for prioritisation
- Orchestrating analyst notifications and response actions with Tines SOAR
- Using LimaCharlie EDR API to isolate hosts as part of incident response
- Leveraging VirusTotal threat intelligence for enhanced alert context

This project demonstrates how a modern SOC workflow can be built from the ground up using open, cloud-compatible tools. From real-time telemetry collection with LimaCharlie, to enrichment with VirusTotal, to automated response actions via Tines and case management in TheHive — every component has been deliberately chosen and integrated to reflect real-world detection and response pipelines.

What sets this implementation apart is its extensibility. The entire workflow is modular by design: additional enrichment sources, response actions, or case-handling logic can be introduced with minimal friction. Need to add an automated block in a firewall? Swap in a threat intel platform? Triage alerts through a different severity model? The architecture supports it. This flexibility is critical in a real SOC environment, where tooling needs to evolve with emerging threats and changing business priorities.

Above all, this project was built to reflect the kind of work expected from a real SOC analyst. It isn’t just a showcase of tools — it’s a working solution that demonstrates how to triage alerts, enrich them with external data, make decisions based on logic, and take meaningful action. Every component was chosen and configured to simulate practical detection and response, just as it would happen in a live environment.
