# 🔍 IdentityDrift Access Investigation with Sentinel Custom Graphs

![Microsoft Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4?style=for-the-badge&logo=microsoft-azure)
![Security Copilot](https://img.shields.io/badge/Security-Copilot-00A4EF?style=for-the-badge&logo=microsoft)
![Custom Graph API](https://img.shields.io/badge/Custom%20Graph-REST%20API-0078D4?style=for-the-badge)

Investigate high-risk identities accessing infrastructure with critical security alerts using **Microsoft Sentinel Custom Graphs** and **Security Copilot**. This repository provides a complete end-to-end solution for rapid identity compromise investigation.

## 📋 Prerequisites

- ✅ **Microsoft Sentinel** workspace with **Data Lake** enabled
- ✅ **Source tables** from [Microsoft-Sentinel-Labs KQL-Jobs](https://github.com/suchandanreddy/Microsoft-Sentinel-Labs/tree/main/KQL-Jobs):
  - SigninLogs_ID_KQL_CL
  - CommonSecurity_ID_KQL_CL
  - DeviceProcessEvents_KQL_CL
  - SecurityAlerts_KQL_CL
- ✅ **VS Code** with [Microsoft Sentinel extension](https://marketplace.visualstudio.com/items?itemName=ms-azure-tools.vscode-sentinel) and Jupyter extension
- ✅ **Security Copilot** workspace with **Security Operator** role
- ✅ **Azure AD** access for bearer token generation

## 🎯 What This Project Does

This solution enables security analysts to answer critical incident response questions:

> **"What infrastructure did a compromised identity access, and what critical alerts were triggered on those systems?"**

**Capabilities:**
- ✅ Query identity-to-infrastructure access relationships in real-time
- ✅ Correlate access patterns with security alerts and detections
- ✅ Investigate blast radius of high-risk or compromised identities
- ✅ AI-powered investigation via Security Copilot agent

## 🏗️ System Architecture

The solution is organized in **4 layers**:

```
┌─────────────────────────────────────────────┐
│ Layer 4: Security Copilot Agent             │
│ - Interactive investigation interface       │
│ - Analyzes access patterns & alerts         │
└──────────────┬──────────────────────────────┘
               │ GQL Queries (REST API)
┌──────────────▼──────────────────────────────┐
│ Layer 3: Custom Graph Instance              │
│ - IdentityDrift_AccessGraph                 │
│ - 4 node types, 6 edge types                │
│ - Updated daily via scheduled job           │
└──────────────┬──────────────────────────────┘
               │ PySpark GraphSpecBuilder
┌──────────────▼──────────────────────────────┐
│ Layer 2: Graph Notebook & Job               │
│ - IdentityDrift_AccessGraph.ipynb           │
│ - Scheduled daily (configurable)            │
│ - Transforms Sentinel telemetry             │
└──────────────┬──────────────────────────────┘
               │ Spark DataFrame Read
┌──────────────▼──────────────────────────────┐
│ Layer 1: Sentinel Data Lake                 │
│ - SigninLogs_ID_KQL_CL                      │
│ - CommonSecurity_ID_KQL_CL                  │
│ - DeviceProcessEvents_KQL_CL                │
│ - SecurityAlerts_KQL_CL                     │
└─────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Step 1: Review Architecture
Read [Module 02: Architecture & Design](docs/02-architecture.md) to understand the system.

### Step 2: Build Your Graph
1. Open [IdentityDrift_AccessGraph.ipynb](samples/graph-notebooks/IdentityDrift_AccessGraph.ipynb)
2. Set `workspace_name = "YourWorkspace"`
3. Run all cells → Graph builds in ~10 minutes
4. Verify: See "Graph build completed successfully!"

### Step 3: Deploy Agent
1. Go to **https://securitycopilot.microsoft.com**
2. Navigate to **Build** → **Upload a YAML manifest**
3. Upload [IdentityDrift-SecurityCopilot-Agent.yaml](samples/agent-manifests/IdentityDrift-SecurityCopilot-Agent.yaml)
4. Test with: `Investigate u2847@contoso.onmicrosoft.com`

## 📦 What's Included

### 📚 Documentation

| Module | Guide | Purpose |
|--------|-------|---------|
| **01** | [Getting Started](docs/01-getting-started.md) | Prerequisites, 4-node types, 6-edge types |
| **02** | [Architecture & Design](docs/02-architecture.md) | Complete system design, authentication flow, security rules |
| **03** | [Build Custom Graph](docs/03-Build-Custom-Graph.md) | Graph schema design, node/edge definitions, data source mapping |
| **04** | [Deploy Copilot Agent](docs/04-Build-Security-Copilot-Agent.md) | Agent YAML configuration, deployment steps, testing |


### Samples
- **Agent Manifest YAML** – Ready-to-deploy `IdentityDrift-SecurityCopilot-Agent.yaml`
  - Predefined GQL queries with parameter substitution
  - AADDelegated authentication to run Graph REST APIs
  - Suggested prompts for analysts

- **Graph Notebook** – `IdentityDrift_AccessGraph.ipynb`
  - PySpark code for building custom graph
  - Reads 4 Sentinel source tables
  - Creates 4 node types + 6 edge types
  - Uses GraphSpecBuilder API

## 🎯 Investigation Workflow

```
Question: "Investigate u2847@contoso.onmicrosoft.com"

Step 1: Agent extracts riskIdentityId from message
Step 2: Agent substitutes {{riskIdentityId}} in predefined GQL query
Step 3: API executes fresh query (never cached)
Step 4: Agent parses 5-item groups (Identity-Edge-Workload-Edge-Alert)
Step 5: Agent formats investigation table with:
        - Risk identity & risk level
        - Infrastructure workloads accessed
        - Number of access events per workload
        - Critical & high severity alerts triggered
        - Alert types, confidence levels, detection times
        - Source IPs used, last access timestamps
Step 6: Returns structured findings + recommended actions
```

## 📖 Repository Structure

```
.
├── docs/
│   ├── 01-getting-started.md          # Start here: Prerequisites & setup
│   ├── 02-architecture.md             # System design & security
│   ├── 03-Build-Custom-Graph.md       # Graph schema & data sources
│   └── 04-Build-Security-Copilot-Agent.md  # Agent deployment
├── samples/
│   ├── agent-manifests/
│   │   └── IdentityDrift-SecurityCopilot-Agent.yaml  # Ready-to-deploy agent
│   └── graph-notebooks/
│       └──IdentityDrift_AccessGraph.ipynb           # Graph builder
└── README.md

```

