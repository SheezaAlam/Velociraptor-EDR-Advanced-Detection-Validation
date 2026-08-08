# Velociraptor EDR — Advanced Detection Validation

A deep-dive validation of Velociraptor as a full-fledged EDR: establishing a clean behavioral baseline, simulating a wide range of MITRE ATT&CK-aligned attacker behaviors, building custom detection artifacts and hunts, tuning out false positives, and testing performance at scale.

**Author:** Sheeza Alam Khan

---

## 📋 Objective

This task demonstrated that Velociraptor EDR is highly effective at detecting attacker-like behaviors using **behavior-based detection** rather than relying on malware signatures. Through multiple safe simulations, Velociraptor consistently captured process execution, PowerShell abuse, persistence mechanisms, and reconnaissance activities.

The creation of reusable artifacts and hunts showed how detection engineering can be applied in real-world environments. Performance testing confirmed that the solution is lightweight, scalable, and suitable for production deployment with proper tuning.

---

## 🖥️ Lab Environment

The lab consisted of one Velociraptor server hosted on the main machine and **four Windows virtual machines** acting as endpoints. All endpoints were successfully connected using the GUI console. System telemetry — process execution, PowerShell logs, file system activity, registry changes, and basic network behavior — was enabled to support detection and investigation. Snapshots were enabled to ensure safe rollback after simulations.

<img src="images/connected-clients-list.png" width="800"/>

---

## Phase 1: Artifact Execution & Baseline Validation

### Client Connectivity Verification

All four Windows endpoints successfully connected to the Velociraptor server and responded correctly to artifact execution requests, confirming deployment and communication were functioning as expected.

<img src="images/hunts-list-overview.png" width="800"/>

### `whoami` / `ipconfig` Hunt Validation

Multiple built-in artifacts (`Windows.System.Cmdshell`) were executed across all clients to validate evidence collection.

| Overview | Clients |
|---|---|
| <img src="images/whoami-hunt-overview.png" width="380"/> | <img src="images/whoami-hunt-clients.png" width="380"/> |

<img src="images/whoami-hunt-params.png" width="450"/>
<img src="images/ipconfig-hunt-clients.png" width="800"/>

All artifacts completed successfully and returned results without errors, confirming the system was ready for detection and investigation tasks.

### 3.1 Baseline: Running Processes (`Windows.System.Pslist`)

Only legitimate, Microsoft-signed Windows system processes (`smss.exe`, `csrss.exe`, `wininit.exe`, `winlogon.exe`, `services.exe`, `lsass.exe`, `svchost.exe`) were observed. No unknown or user-initiated processes — confirming a clean baseline.

<img src="images/pslist-baseline-results.png" width="800"/>

### 3.2 Baseline: Scheduled Tasks

Only standard Windows maintenance/system tasks were present, with no evidence of unauthorized scheduled persistence.

<img src="images/scheduled-tasks-baseline-overview.png" width="700"/>
<img src="images/scheduled-tasks-baseline-results.png" width="800"/>

### 3.3 Baseline: Normal PowerShell Usage

PowerShell operational logs (`Windows.EventLogs.PowershellModule` / `PowershellScriptblock`) were reviewed — no encoded, obfuscated, or suspicious commands detected at baseline.

<img src="images/powershell-baseline-overview.png" width="800"/>
<img src="images/powershell-baseline-results.png" width="800"/>

### 3.4 Baseline: Network Connections

Basic network behavior (`Windows.Network.Netstat`) showed only expected system-related activity — no suspicious external connections.

<img src="images/netstat-baseline-overview.png" width="800"/>
<img src="images/netstat-baseline-results.png" width="800"/>

---

## Phase 2: Attack Behavior Simulation

### A. Encoded PowerShell

A Base64-encoded PowerShell command (`Get-Date`) was executed to simulate suspicious PowerShell usage. Velociraptor successfully captured this activity, demonstrating its ability to log encoded command execution.

<img src="images/encoded-powershell-execution.png" width="700"/>
<img src="images/powershell-command-parameters.png" width="500"/>

### LOLBins Misuse (`whoami`)

The `whoami` command was executed to simulate Living-off-the-Land Binary misuse — mimicking attacker reconnaissance. Execution was logged successfully.

<img src="images/lolbins-whoami-collection.png" width="700"/>
<img src="images/lolbins-whoami-overview.png" width="800"/>
<img src="images/lolbins-whoami-log.png" width="800"/>

### Suspicious EXE in User Path

A fake executable with a system-like name was created in a user-writable directory to simulate malware placement. `Windows.Search.FileFinder` successfully detected the file, collected its hash, and confirmed its presence.

<img src="images/fake-malware-creation.png" width="700"/>
<img src="images/filefinder-collection-list.png" width="800"/>
<img src="images/filefinder-parameters.png" width="500"/>
<img src="images/filefinder-uploaded-file.png" width="800"/>

### B. Persistence

**Registry Run Key Persistence** — A benign registry Run key was manually added (via the Velociraptor remote shell) to simulate persistence. Velociraptor successfully captured the registry modification.

<img src="images/registry-run-key-persistence.png" width="800"/>

**Scheduled Task Persistence** — A scheduled task (`UpdateCheck`) was created to simulate attacker persistence, and was visible in Velociraptor's artifact results.

<img src="images/scheduled-task-persistence-creation.png" width="700"/>
<img src="images/scheduled-task-detection-summary.png" width="500"/>
<img src="images/scheduled-task-detection-results.png" width="800"/>

**Service-Based Persistence** — A fake service (`FakeService`) was created via `sc create`. The activity was logged and visible in the collected artifacts, validating service monitoring capability.

<img src="images/service-persistence-creation.png" width="500"/>
<img src="images/service-persistence-overview.png" width="800"/>
<img src="images/service-persistence-results.png" width="800"/>

### C. Defense Evasion

**Log Tampering Simulation (SAFE)** — A safe log-related interaction (`wevtutil el`) was simulated to represent defense evasion attempts. Velociraptor logged the related activity without system impact.

<img src="images/log-tampering-wevtutil.png" width="450"/>
<img src="images/log-tampering-shell.png" width="800"/>
<img src="images/log-tampering-log.png" width="800"/>

**Obfuscated Command Execution** — An obfuscated command pattern (`$cmd="Get-Process"; powershell -Command $cmd`) was executed. The behavior was detected and recorded under PowerShell artifacts.

<img src="images/obfuscated-command-shell.png" width="800"/>
<img src="images/obfuscated-command-log.png" width="800"/>

### D. Discovery / Credential Access

**Local System Discovery** — System and user discovery commands (`systeminfo`, `whoami`) were executed and logged successfully, demonstrating detection of reconnaissance behavior.

<img src="images/systeminfo-discovery.png" width="500"/>

**Credential Store Access Attempt** — A non-destructive credential access attempt (`cmdkey /list`, without extraction) was simulated. The activity was captured, confirming telemetry coverage without risking system integrity.

<img src="images/credential-access-overview.png" width="800"/>
<img src="images/credential-access-results.png" width="800"/>

### E. Lateral Movement / C2 Simulation

**WMI Remote Execution Simulation** — Remote execution using WMI (`wmic process list brief`) was simulated locally. Velociraptor captured the execution details, showing visibility into lateral movement techniques.

<img src="images/wmi-remote-execution-overview.png" width="800"/>
<img src="images/wmi-remote-execution-results.png" width="600"/>

**Beacon-Like Communication** — A benign periodic communication pattern (`ping` loop with delay) was simulated to represent beaconing behavior. The activity was logged, demonstrating detection capability for repeated communication patterns.

<img src="images/beacon-ping-simulation.png" width="500"/>
<img src="images/beacon-communication-log.png" width="800"/>

---

## Phase 3: Detection Engineering

### Artifact Development: Suspicious Process Activity

`Windows.System.Pslist` was re-executed to establish a clean process baseline on the endpoint. Only core, Microsoft-signed processes were observed — confirming a clean baseline environment.

<img src="images/phase3-pslist-artifact-list.png" width="800"/>
<img src="images/phase3-pslist-results.png" width="800"/>

### Encoded PowerShell Detection

A dedicated detection artifact was configured with regex patterns (`-EncodedCommand`, `FromBase64String`). No matching events were returned, confirming baseline PowerShell activity was clean.

<img src="images/encoded-ps-detection-artifact.png" width="700"/>
<img src="images/encoded-ps-detection-log.png" width="800"/>

### Scheduled Tasks & New Executable Detection

Scheduled task monitoring confirmed the earlier `UpdateCheck` persistence task, and `Windows.Search.FileFinder` re-confirmed detection of the fake executable dropped in `C:\Temp`.

<img src="images/scheduled-task-detection-phase3-list.png" width="700"/>
<img src="images/scheduled-task-detection-phase3-result.png" width="700"/>
<img src="images/new-exe-detection-artifact-list.png" width="800"/>
<img src="images/new-exe-detection-uploaded-file.png" width="800"/>

### Hunts

**Hunt 1 — Encoded PowerShell Detection:** Executed across all endpoints using PowerShell Operational logs. No matching events were returned, confirming the absence of encoded PowerShell execution after tuning and baseline validation.

<img src="images/hunt1-encoded-powershell-detection.png" width="800"/>

**Hunt 2 — New Executables in Sensitive Paths:** Executed successfully across all endpoints. No results were returned, indicating no executable files were found in monitored user-writable paths during the hunt window — confirming a clean baseline and correct hunt logic.

**Hunt 3 — Periodic Beacon-like Traffic:** Analyzed network activity for repeated connection patterns. No periodic or beacon-like traffic was detected, indicating no active command-and-control simulation remained.

### Tuning

Detection tuning was applied by:
- Using allowlists for known legitimate binaries and Microsoft-signed processes
- Applying regex filters for suspicious patterns
- Limiting time windows and execution frequency

This eliminated false positives while maintaining detection coverage — no unnecessary alerts were generated during tuned hunts.

---

## Phase 4: Industry Deployment Readiness

### Performance & Scale Testing

Hunts were executed across all endpoints simultaneously. Observations showed:
- No noticeable performance degradation on endpoints
- Stable server resource usage
- Acceptable query execution times

This indicates the Velociraptor deployment can scale effectively in a small enterprise-like environment.

### Recommendations for Scaling

- Use targeted hunts instead of continuous broad queries
- Schedule heavy hunts during off-peak hours
- Expand artifact tuning for production environments
- Monitor server resources as endpoint count increases

---

## ✅ Conclusion

This task demonstrated that Velociraptor EDR is highly effective at detecting attacker-like behaviors using behavior-based detection rather than relying on malware signatures. Through multiple safe simulations, Velociraptor consistently captured process execution, PowerShell abuse, persistence mechanisms, and reconnaissance activities.

The creation of reusable artifacts and hunts showed how detection engineering can be applied in real-world environments. Performance testing confirmed that the solution is lightweight, scalable, and suitable for production deployment with proper tuning.

Overall, this project provided hands-on experience with real EDR concepts and validated Velociraptor as a powerful open-source detection and response platform.

---

## 📁 Repository Structure

```
.
├── README.md
└── images/
    ├── connected-clients-list.png
    ├── hunts-list-overview.png
    ├── whoami-hunt-overview.png
    ├── whoami-hunt-params.png
    ├── whoami-hunt-clients.png
    ├── ipconfig-hunt-clients.png
    ├── pslist-baseline-results.png
    ├── scheduled-tasks-baseline-overview.png
    ├── scheduled-tasks-baseline-results.png
    ├── powershell-baseline-overview.png
    ├── powershell-baseline-results.png
    ├── netstat-baseline-overview.png
    ├── netstat-baseline-results.png
    ├── encoded-powershell-execution.png
    ├── powershell-command-parameters.png
    ├── lolbins-whoami-collection.png
    ├── lolbins-whoami-overview.png
    ├── lolbins-whoami-log.png
    ├── fake-malware-creation.png
    ├── filefinder-collection-list.png
    ├── filefinder-parameters.png
    ├── filefinder-uploaded-file.png
    ├── registry-run-key-persistence.png
    ├── scheduled-task-persistence-creation.png
    ├── scheduled-task-detection-summary.png
    ├── scheduled-task-detection-results.png
    ├── service-persistence-creation.png
    ├── service-persistence-overview.png
    ├── service-persistence-results.png
    ├── log-tampering-wevtutil.png
    ├── log-tampering-shell.png
    ├── log-tampering-log.png
    ├── obfuscated-command-shell.png
    ├── obfuscated-command-log.png
    ├── systeminfo-discovery.png
    ├── credential-access-overview.png
    ├── credential-access-results.png
    ├── wmi-remote-execution-overview.png
    ├── wmi-remote-execution-results.png
    ├── beacon-ping-simulation.png
    ├── beacon-communication-log.png
    ├── phase3-pslist-artifact-list.png
    ├── phase3-pslist-results.png
    ├── encoded-ps-detection-artifact.png
    ├── encoded-ps-detection-log.png
    ├── scheduled-task-detection-phase3-list.png
    ├── scheduled-task-detection-phase3-result.png
    ├── new-exe-detection-artifact-list.png
    ├── new-exe-detection-uploaded-file.png
    └── hunt1-encoded-powershell-detection.png
```

## 🛠️ Tools Used

- [Velociraptor](https://docs.velociraptor.app/) — Server + Client (EDR platform)
- VMware Workstation (4× Windows 10 endpoints)
- PowerShell / Command Prompt
- Windows Registry Editor (`regedit`), Task Scheduler, Service Control (`sc`)

## 🔍 Artifacts & Techniques Referenced

**Artifacts:** `Windows.System.Cmdshell`, `Windows.System.Pslist`, `Windows.System.TaskScheduler`, `Windows.System.Services`, `Windows.System.PowerShell`, `Windows.EventLogs.PowershellModule`, `Windows.EventLogs.PowershellScriptblock`, `Windows.Search.FileFinder`, `Windows.Network.Netstat`

**MITRE ATT&CK-aligned behaviors simulated:** Execution (PowerShell abuse, LOLBins), Persistence (Registry Run Key, Scheduled Task, Service), Defense Evasion (log tampering, obfuscation), Discovery, Credential Access, Lateral Movement / C2 (WMI, beaconing)

> **Note:** All simulated activity was safe, benign, and non-destructive by design — no real malware, credential extraction, or external C2 infrastructure was used at any point in this exercise.
