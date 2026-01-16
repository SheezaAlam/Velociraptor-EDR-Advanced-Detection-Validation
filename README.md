# Task 03: Velociraptor EDR – Advanced Detection Validation

## Overview

This project focuses on validating **Velociraptor EDR** as a behavior-based detection and investigation platform.
The task demonstrates how Velociraptor can be used to simulate attacker behavior, collect endpoint telemetry, create reusable detections, and prepare the deployment for **industry-grade use**.

The work emphasizes **detection engineering**, **threat hunting**, and **operational readiness**, rather than signature-based malware detection.

---

## Objectives

The primary objectives of this task are:

1. To detect new and evolving attack behaviors using behavior-based telemetry.
2. To design repeatable detection engineering workflows using artifacts and hunts.
3. To evaluate Velociraptor’s readiness for production deployment in real-world environments.

---

## Lab Environment

The lab environment consists of:

* Velociraptor Server with GUI
* Multiple endpoints:

  * Windows 10 / Windows 11 (mandatory)
  * Linux (optional)
* Snapshots enabled for safe rollback
* Telemetry enabled on endpoints:

  * Process execution and command-line logging
  * PowerShell operational logs
  * File system activity
  * Registry monitoring
  * Network connection monitoring

---

## Phase 1: Baseline and Readiness

### Purpose

To ensure all endpoints are properly connected, responsive, and producing clean baseline telemetry before simulating attacks.

### Activities

* Verified that all clients are connected and visible in the Velociraptor GUI.
* Confirmed artifact execution and evidence collection functionality.
* Established baseline behavior for:

  * Running processes
  * Scheduled tasks
  * Registry Run keys
  * Windows services
  * Normal PowerShell usage
  * Common outbound network connections

### Output

* Screenshots of connected endpoints
* Notes distinguishing normal system behavior from potentially suspicious patterns

---

## Phase 2: New Attack Behavior Simulation

### Purpose

To simulate attacker techniques using **safe, non-destructive methods** and validate detection visibility.

### Scenarios Executed

A total of **12 behavior-based attack simulations** were performed.

#### Initial Access / Execution

1. Encoded PowerShell execution variants
2. Living-off-the-Land binaries (LOLBins) misuse
3. Suspicious executable dropped in user-writable directories

#### Persistence

4. Registry Run key persistence
5. Scheduled task persistence
6. Service-based persistence

#### Defense Evasion

7. Log tampering and security control interaction simulation
8. Obfuscated command execution patterns

#### Discovery / Credential Access

9. Local system and user discovery commands
10. Credential store access attempts (no credential extraction)

#### Lateral Movement / C2 Simulation

11. Remote execution using WMI, WinRM, and PowerShell Remoting
12. Beacon-like periodic HTTP communication to a benign local server

### Documentation for Each Scenario

For every scenario, the following were documented:

* Description of the simulated behavior
* Expected telemetry signals
* Velociraptor artifact or hunt used
* Evidence collected
* Detection success or failure
* False positives observed

---

## Phase 3: Detection Engineering

### Artifact Development

Custom and built-in artifacts were used to detect:

* Suspicious parent-child process relationships
* Encoded or obfuscated PowerShell commands
* Persistence mechanisms (Run keys, scheduled tasks, services)
* Newly dropped executables
* File hash, digital signer, and prevalence information
* Network connections and rare destinations

### Threat Hunts Created

The following hunts were configured and executed:

1. Encoded PowerShell detection
2. New executables in sensitive or user-writable paths
3. Persistence change detection
4. Rare or unusual parent-child process chains
5. Periodic beacon-like network traffic

### Tuning and Optimization

* False positives were reduced using allowlists for trusted binaries and system paths.
* Thresholds and frequency checks were applied to avoid noise.
* Tuning logic was documented to explain why certain detections were adjusted.

---

## Phase 4: Industry Deployment Readiness

### Performance and Scale Testing

* Hunts were executed across all connected endpoints.
* Measurements included:

  * Server resource usage
  * Endpoint performance impact
  * Query execution time

### Findings

* Hunts completed within acceptable execution times.
* No noticeable performance degradation was observed on endpoints.
* Recommendations were developed for scaling in larger enterprise environments.

---

## Final Demonstration

Three complete attack-to-detection workflows were demonstrated:

1. Attack behavior simulation
2. Detection using Velociraptor artifacts and hunts
3. Evidence collection and investigation
4. Analyst investigation workflow
5. Containment and remediation recommendations

---

## Final Report Summary

* Detection coverage across execution, persistence, and network behaviors was achieved.
* Most attack simulations were successfully detected through behavior-based telemetry.
* Some low-signal activities required tuning to reduce false positives.
* Velociraptor proved suitable for production use with proper tuning and operational planning.

---

## Key Takeaways

* Behavior-based detection provides strong visibility into attacker techniques.
* Velociraptor supports repeatable detection engineering workflows.
* Proper tuning is essential to balance detection coverage and noise.
* The platform is capable of industry-grade deployment with scaling considerations.

---

## Author

**Sheeza Alam Khan**


