# Detection Engineering

### Contents
1.  What is Detection Engineering
2.  Introduction to This Repository
3.  Atomic Rules
4.  Correlation Rules
5.  Rule Usage & Fine-Tunning Notes


## What is Detection Engineering

Detection Engineering is the practice of designing, building, testing, and maintaining detection logic to identify malicious or suspicious activity within an environment. It plays a critical role in modern cybersecurity by enabling organizations to proactively detect threats rather than only reacting to incidents.

At its core, Detection Engineering focuses on answering two key questions:

Why detect? — Understanding attacker behavior, often guided by frameworks like MITRE ATT&CK, which categorizes adversary tactics and techniques.
How to detect? — Implementing logic using logs, telemetry, and analytics to identify those behaviors.

### Why is it important?
Improves visibility into attacker activity
Reduces dwell time of threats
Enables faster and more accurate incident response
Bridges the gap between threat intelligence and security operations

## Introduction to This Repository

This repository is designed to provide practical, ready-to-use detection content aligned with the MITRE ATT&CK framework.

It covers common techniques (the "how") mapped to tactics (the "why")
Each technique includes detection rules to help identify adversary behavior
The goal is to make detection engineering actionable, standardized, and reusable.
For each rule (Atomic or Correlation), You’ll Find: 

### SIGMA Rule (Standard Format)
A vendor-agnostic rule format that can be converted into queries for different SIEM platforms.

### Elastic EQL Rule (Quick Testing)
Provided for fast validation and testing in Elastic environments.


## Atomic Rules

Atomic rules are simple, single-event detections that identify a specific activity or behavior in isolation. They are the building blocks of detection engineering. These rules typically:

Focus on one log source
Detect a single condition or event
Are easy to test and validate

### Example

### Scenario: Detect execution of PowerShell with encoded commands

### SIGMA (simplified):

title: Suspicious PowerShell Encoded Command
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: '*powershell.exe'
    CommandLine: '*-enc*'
  condition: selection

This rule triggers when PowerShell is executed with encoded arguments, which is commonly used for obfuscation.

## Correlation Rules

Correlation rules combine multiple events across time, users, or systems to detect more complex attack patterns.They are used to:

Identify multi-step attacks
Reduce false positives from isolated events
Provide higher-confidence detections

### Example

### Scenario: Detect a potential account compromise

Logic:

Multiple failed login attempts
Followed by a successful login
From the same user within a short time window

### Pseudo Detection Logic:

IF
  failed_logins > 5
  AND successful_login occurs within 5 minutes
  AND same user
THEN
  alert "Possible Brute Force Success"

This type of rule correlates multiple signals to identify suspicious behavior that would not be obvious from a single event.

## Rule Usage & Fine-Tunning Notes
This repository is intended to help security practitioners:

Build strong detection capabilities
Understand attacker techniques in depth
Quickly deploy and adapt detection logic

Detection Engineering is not a one-time effort — it is a continuous cycle of improvement. Use this repository as a foundation, and adapt it to your environment for maximum effectiveness.

SIGMA rule conversion depends heavily on your environment, including:
Log sources availability
Log parsing and normalization
Field naming conventions

### You should:
Follow tuning guidelines in this repository
Adapt rules to your SIEM schema
Validate detections against real data

Out-of-the-box rules may not work perfectly without customization.

