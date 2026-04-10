# Getting Started - IdentityDrift Access Investigation

Investigate high-risk identities accessing infrastructure with critical security alerts using Microsoft Sentinel Custom Graphs and Security Copilot.

**Scenario:** A security analyst needs to rapidly determine what infrastructure a compromised user accessed and what critical alerts were triggered on those systems.

---

## Prerequisites

Before you begin, ensure you have:

### Sentinel Data Lake Setup
- ✅ **Microsoft Sentinel Data Lake** Onboarded. Refer [Sentinel Data Lake Onboarding Steps](https://github.com/suchandanreddy/Microsoft-Sentinel-Labs/blob/main/01-Sentinel-DataLake-Onboarding.md)
- ✅ **Source data in Sentinel** – SigninLogs_ID_KQL_CL, CommonSecurity_ID_KQL_CL, DeviceProcessEvents_KQL_CL, SecurityAlerts_KQL_CL (from [Microsoft-Sentinel-Labs KQL-Jobs](https://github.com/suchandanreddy/Microsoft-Sentinel-Labs/tree/main/KQL-Jobs))

### Development Tools
- ✅ **Visual Studio Code** with [Microsoft Sentinel extension](https://marketplace.visualstudio.com/items?itemName=ms-azure-tools.vscode-sentinel) and **Jupyter extension**

### Security Copilot Setup
- ✅ **Security Copilot Workspace** (Security Operator role to create Agents)

---

## What You'll Build

This guide walks you through building an end-to-end custom graph investigation system with 4 modules:

```
MODULE 03: Build Custom Graph
├─ Source: 4 Sentinel tables
├─ Create: 4 node types + 6 edge relationships  
└─ Output: IdentityDrift_AccessGraph instance

MODULE 04: Build Security Copilot Agent
├─ Create: Agent YAML manifest
├─ Deploy: To Security Copilot workspace
└─ Test: End-to-end investigation
```

---

## Quick Start (35 minutes)

### Step 1: Build Your Graph (Module 03)

1. Open the **IdentityDrift_AccessGraph.ipynb** notebook in VS Code
2. Set `workspace_name = "YourWorkspace"`
3. Run all cells
4. Verify: See "Graph build completed successfully!" with node/edge counts

### Step 2: Deploy Security Copilot Agent (Module 04)

1. Go to **https://securitycopilot.microsoft.com**
2. Navigate to **Build** → **Upload a YAML manifest**
3. Upload: `samples/agent-manifests/IdentityDrift-SecurityCopilot-Agent.yaml`
4. Publish the agent to your workspace
5. Test the agent with sample question:
   ```
   Investigate u1291@contoso.onmicrosoft.com for infrastructure access with critical alerts
   ```

**Result:** Agent returns structured investigation with infrastructure + alerts

---

## Understanding the System

### The 4 Node Types

| Node | Represents | Example |
|------|------------|---------|
| **Identity** | Azure AD users | u1291@contoso.onmicrosoft.com |
| **Workload** | Apps and infrastructure | Azure Portal, prod-aks-eastus |
| **Device** | Client devices | laptop-001, WIN-DESKTOP-001 |
| **Alert** | Security detections | PrivilegeEscalation, SuspiciousActivity |

### The 6 Edge Types

| Edge | Relationship | Example |
|------|-------------|---------|
| **AccessTo** | Identity used app | alice → Azure Portal |
| **AccessedInfrastructure** | Identity accessed infrastructure | alice → prod-aks-eastus |
| **UsedDevice** | Identity used device | alice → laptop-001 |
| **ExecutedProcess** | Identity executed process | alice → powershell.exe |
| **TriggeredAlert** | Identity triggered alert | alice → PrivilegeEscalation |
| **DetectedOn** | Alert detected on workload | PrivilegeEscalation → prod-aks |

### Investigation Workflow

```
Question: "What infrastructure did u1291 access with critical alerts?"

Agent receives question
  ↓
Formulates GQL query:
  MATCH (i:Identity)-[r1:AccessedInfrastructure]->(w:Workload),
        (a:Alert)-[r2:DetectedOn]->(w)
  WHERE i.IdentityId = 'u1291@contoso.onmicrosoft.com'
    AND a.AlertSeverity IN ['High', 'Critical']
  RETURN i, r1, w, r2, a
  ↓
Graph API executes fresh query (never cached)
  ↓
Returns: 2 workloads, 5 critical alerts, 47 access events
  ↓
Agent formats investigation:
  - 2 infrastructure resources accessed
  - 5 critical alerts on those workloads
  - 3 unique source IPs used
  ↓
Agent responds with findings + recommended actions
```

---

## 4 Modules at a Glance

| Module | What | Output |
|--------|------|--------|
| **01** | Getting Started (this page) | Understand prerequisites |
| **02** | Architecture & Design | Understand system design |
| **03** | Build Custom Graph | IdentityDrift_AccessGraph instance |
| **04** | Deploy Security Copilot Agent | Working agent in Security Copilot |

---

## Next Steps

- **Need help?** → Understand the [Architecture](02-architecture.md) first
- **Ready to build?** → Go to [Module 03: Build Custom Graph](03-Build-Custom-Graph.md)
- **Want to deploy agent?** → Go to [Module 04: Build Security Copilot Agent](04-Build-Security-Copilot-Agent.md)