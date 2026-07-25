# Autonomous SOC Tier-1 Analyst & Incident Triage Agent

An AI-powered Security Operations Center assistant built using NitroStack MCP.

## Problem

SOC analysts receive hundreds of security alerts every day.
Manual alert investigation causes alert fatigue and delays critical threat response.

## Solution

An autonomous AI SOC agent that helps Tier-1 analysts by:

- Analyzing security alerts
- Extracting Indicators of Compromise (IOCs)
- Mapping threats to MITRE ATT&CK techniques
- Performing risk scoring
- Generating incident reports
- Suggesting response actions


## Features

### Security Alert Analysis
Analyzes logs and alerts to identify suspicious behaviour.

### IOC Extraction
Extracts:
- IP addresses
- Domains
- Hashes
- Suspicious commands

### MITRE ATT&CK Mapping
Maps attacker behaviour to known techniques.

### Risk Scoring
Assigns severity:

Low
Medium
High
Critical


### Incident Report Generation
Creates structured incident summaries.


## Tech Stack

- NitroStack MCP
- TypeScript
- Agentic AI
- Cybersecurity Threat Intelligence
- MITRE ATT&CK Framework


## Running the Project

```bash
npm install
npm run dev