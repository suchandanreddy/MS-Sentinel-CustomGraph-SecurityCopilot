# Architecture & Design - IdentityDrift Access Investigation

## System Overview

This system enables Security Copilot agents to investigate compromised identities by querying pre-computed relationship graphs built on Microsoft Sentinel. The architecture has 4 layers:

```
┌────────────────────────────────────────────────────────────┐
│ Layer 4: Security Copilot Agent                            │
│ - Analyst asks: "What infrastructure did u2847 access?"    │
│ - Agent invokes graph API                                  │
│ - Returns: Structured investigation results                │
└────────────────────┬───────────────────────────────────────┘
                     │ GQL Query (REST API Call)
┌────────────────────▼───────────────────────────────────────┐
│ Layer 3: Custom Graph Instance                             │
│ - Graph: IdentityDrift_AccessGraph                         │
│ - Nodes: Identity, Workload, Device, Alert (4 types)       │
│ - Edges: AccessTo, AccessedInfrastructure, UsedDevice,     │
│          ExecutedProcess, TriggeredAlert, DetectedOn (6)   │
│ - Updated: Daily via scheduled notebook job                │
└────────────────────┬───────────────────────────────────────┘
              PySpark GraphSpecBuilder
┌────────────────────▼───────────────────────────────────────┐
│ Layer 2: Graph Notebook & Job                              │
│ - Python notebook: IdentityDrift_AccessGraph.ipynb         │
│ - scheduled daily job (configurable)                       │
│ - Reads: 4 source tables (1 day lookback)                  │
│ - Builds: 4 node types + 6 edge types                      │
└────────────────────┬───────────────────────────────────────┘
                     │ Spark DataFrame Read
┌────────────────────▼───────────────────────────────────────┐
│ Layer 1: Sentinel Data Lake                                │
│ - SigninLogs_ID_KQL_CL (Entra ID authentication logs)      │
│ - CommonSecurity_ID_KQL_CL (Infrastructure access)         │
│ - DeviceProcessEvents_KQL_CL (Process execution)           │
│ - SecurityAlerts_KQL_CL (Security detections)              │
└────────────────────────────────────────────────────────────┘
```

## Layer 1: Sentinel Data Lake

**Purpose:** Centralized repository of security telemetry

**Source Tables:**

| Table | Source | Key Columns | Use |
|-------|--------|-------------|-----|
| **SigninLogs_ID_KQL_CL** | Entra ID | UserPrincipalName, AppDisplayName, RiskLevelAggregated | Identity → Workload (app access) |
| **CommonSecurity_ID_KQL_CL** | IdentityDrift | SourceUserName, DestinationHostName, DeviceCustomString1 | Identity → Workload (infrastructure) |
| **DeviceProcessEvents_KQL_CL** | Defender for Endpoint | DeviceName, AccountName, FileName, ProcessCommandLine | Identity → Device → Process |
| **SecurityAlerts_KQL_CL** | Defender for Cloud | AlertName, AlertSeverity, CompromisedEntity, Description | Alert → Workload relationships |


## Layer 2: Graph Notebook & Job

**Purpose:** Transform raw telemetry into optimized graph structure

**Tool:** Python/PySpark notebook with MicrosoftSentinelGraphProvider

**Execution:** Scheduled daily job

**Workflow:**

```
Read Data Lake (1 day lookback)
├─ SigninLogs → Extract identities, workloads, access patterns
├─ CommonSecurity → Extract infrastructure access patterns
├─ DeviceProcessEvents → Extract devices & processes
└─ SecurityAlerts → Extract alerts & triggering entities

Build Graph Structure
├─ Node: Identity (IdentityId, RiskLevelAggregated, LastActivity)
├─ Node: Workload (WorkloadId, WorkloadName, WorkloadType)
├─ Node: Device (DeviceId, DeviceName)
├─ Node: Alert (AlertId, DisplayName, AlertSeverity, AlertType, ConfidenceLevel)
├─ Edge: AccessTo (Identity → Workload via SigninLogs)
├─ Edge: AccessedInfrastructure (Identity → Workload via CommonSecurity)
├─ Edge: UsedDevice (Identity → Device)
├─ Edge: ExecutedProcess (Identity → Process)
├─ Edge: TriggeredAlert (Identity → Alert)
└─ Edge: DetectedOn (Alert → Workload)

Publish Graph
└─ Graph instance: IdentityDrift_AccessGraph (available for querying)
```

**Code framework:** GraphSpecBuilder

```python
identity_drift_graph_spec = (GraphSpecBuilder.start()
  .add_node("Identity").from_dataframe(identity_df)...
  .add_node("Workload").from_dataframe(workload_df)...
  .add_edge("AccessedInfrastructure")
    .source(id_column="IdentityId", node_type="Identity")
    .target(id_column="WorkloadId", node_type="Workload")...
).done()

graph = Graph.build(graph_spec)
```

## Layer 3: Custom Graph Instance

**Purpose:** Stores optimized graph structure for fast relationship queries

**Graph Components:**

| Component | Details |
|-----------|---------|
| **Name** | `IdentityDrift_AccessGraph` |
| **Nodes** | 4 types: Identity, Workload, Device, Alert |
| **Edges** | 6 types: AccessTo, AccessedInfrastructure, UsedDevice, ExecutedProcess, TriggeredAlert, DetectedOn |
| **Storage** | Azure-hosted (no infrastructure required) |
| **Update** | Daily via scheduled notebook |

**Node Properties Example:**

```json
{
  "Identity": {
    "IdentityId": "u1291@contoso.onmicrosoft.com",
    "RiskLevelAggregated": "High",
    "LastActivity": "2025-04-09T14:35:00Z"
  },
  "Workload": {
    "WorkloadId": "prod-aks-eastus",
    "WorkloadName": "prod-aks-eastus",
    "WorkloadType": "Infrastructure"
  },
  "Alert": {
    "AlertId": "K8S_RBAC_PrivilegeEscalation",
    "DisplayName": "Privilege Escalation",
    "AlertSeverity": "Critical",
    "AlertType": "PrivilegeEscalation",
    "ConfidenceLevel": 98
  }
}
```

**Edge Properties Example:**

```json
{
  "AccessedInfrastructure": {
    "EventCount": 23,
    "LastActivity": "2025-04-09T14:35:00Z",
    "ActivityTypes": "MFA Approved, Privilege Escalation",
    "SourceIPCount": 3
  },
  "DetectedOn": {
    "DetectionCount": 5,
    "LastDetection": "2025-04-09T14:35:00Z",
    "Severity": "Critical",
    "Description": "RoleBinding created with cluster-admin permissions"
  }
}
```

**Query Language:** GQL (Graph Query Language)

## Layer 4: REST API & Agent

**Purpose:** Query graph and provide investigation results to Copilot

### REST API

**Endpoint:** `POST /graphs/custom-graph-instances/{graphName}/query`

**AuthN:** Azure AD Bearer token (scoped to `https://purview.azure.net/.default`)

**Request:**
```json
{
  "query": "MATCH (i:Identity)-[r1:AccessedInfrastructure]->(w:Workload), (a:Alert)-[r2:DetectedOn]->(w) WHERE i.IdentityId = 'u2847@contoso.onmicrosoft.com' AND a.AlertSeverity IN ['High', 'Critical'] RETURN i, r1, w, r2, a LIMIT 10",
  "queryLanguage": "GQL"
}
```

**Response:**
```json
{
  "RawData": {
    "Rows": [
      {
        "Cols": [
          {
            "Value": "{\n  \"IdentityId\": \"u2847@contoso.onmicrosoft.com\",\n  \"RiskLevelAggregated\": \"high\",\n  ...\n}"
          },
          {
            "Value": "{\n  \"sys_label\": \"AccessedInfrastructure\",\n  \"EventCount\": 1,\n  \"LastActivity\": \"2026-04-05T23:12:26.637Z\",\n  ...\n}"
          },
          {
            "Value": "{\n  \"WorkloadId\": \"prod-aks-eastus\",\n  \"WorkloadType\": \"Infrastructure\",\n  ...\n}"
          },
          {
            "Value": "{\n  \"sys_label\": \"DetectedOn\",\n  \"AlertId\": \"Kubernetes malware execution blocked on node\",\n  \"Severity\": \"High\",\n  ...\n}"
          },
          {
            "Value": "{\n  \"AlertId\": \"Kubernetes malware execution blocked on node\",\n  \"AlertSeverity\": \"High\",\n  \"AlertType\": \"K8S.NODE_MalwareBlocked\",\n  ...\n}"
          }
        ]
      }
    ],
    "ColumnNames": ["i", "r1", "w", "r2", "a"]
  }
}
```

### Security Copilot Agent

**Components:**

- **Instructions:** Defines investigation behavior, critical rules
- **Tools:** OpenAPI spec for graph API (QueryGraphRestAPI)

**Agent Workflow:**

```
1. ANALYST INPUT
   "Investigate user u1291@contoso.onmicrosoft.com 
    for infrastructure access with critical alerts"

2. AGENT PARSING
   - Extracts: riskIdentityId = "u2847@contoso.onmicrosoft.com"

3. QUERY PREPARATION (Parameter Substitution)
   - Uses predefined GQL query from agent instructions:
     MATCH (i:Identity)-[r1:AccessedInfrastructure]->(w:Workload),
           (a:Alert)-[r2:DetectedOn]->(w)
     WHERE i.IdentityId = '{{riskIdentityId}}'
       AND a.AlertSeverity IN ['High', 'Critical']
     RETURN i, r1, w, r2, a LIMIT 10
   - Substitutes: {{riskIdentityId}} with extracted identity
   - Example: "u2847@contoso.onmicrosoft.com"

4. API INVOCATION
   POST /graphs/custom-graph-instances/IdentityDrift_AccessGraph/query
   Headers: Authorization: Bearer {token}
   Body:
   {
     "query": "MATCH (i:Identity)-[r1:AccessedInfrastructure]->(w:Workload), (a:Alert)-[r2:DetectedOn]->(w) WHERE i.IdentityId = 'u2847@contoso.onmicrosoft.com' AND a.AlertSeverity IN ['High', 'Critical'] RETURN i, r1, w, r2, a LIMIT 10",
     "queryLanguage": "GQL"
   }

5. RESULT PROCESSING
   - Parses 5-item groups (Identity, Edge, Workload, Edge, Alert)
   - Extracts: Access events, alert details, risk indicators
   - Formats: Combines Identity + AccessedInfrastructure edge + Workload + DetectedOn edge + Alert data

6. RESPONSE GENERATION
   📊 Infrastructure Workloads with Critical/High Alerts
   
   | Risk Identity | Risk Level | Infrastructure | Type | Events | Activities | IPs | Last Access | Alert Type | Severity | Threat Category | Confidence | Last Detected |
   |---|---|---|---|---|---|---|---|---|---|---|---|---|
   | u2847@co... | high | prod-aks-eastus | Infrastructure | 1 | 1 | 1 | 2026-04-05 23:12:26 | Microsoft Defender for Cloud Kubernetes malware execution blocked | High | K8S.NODE_... | High | 2026-04-05 23:28:35 |
   
   ⚠️ Risk Assessment
   - 1 infrastructure resource accessed by high-risk identity
   - High-severity alert triggered on accessed infrastructure
   - Single source IP detected
   
   🔧 Recommended Actions
   - P0: Revoke sessions, reset password
   - P1: Isolate affected infrastructure resource
```

## Security Architecture

### Authentication & Authorization Flow

**End-to-end authentication chain:**

```
┌──────────────────┐
│ Security Analyst │ (Azure AD User)
│   (AAD User)     │
└────────┬─────────┘
         ▼ Interactive Login
         ▼
┌─────────────────────────────────────────────────────┐
│ Security Copilot Workspace                          │
│ - Agent: IdentityDrift Graph Investigation          │
│ - Auth Type: AADDelegated                           │
│ - Entra Scope: https://purview.azure.net/.default   │
└─────────────────────┬───────────────────────────────┘
                      ▼ Token Request (Analyst Identity)
                      ▼
┌─────────────────────────────────────────────────────┐
│ Azure AD / Entra                                    │
│ Issues Bearer Token                                 │
│ - Scope: https://purview.azure.net/.default         │
└─────────────────────┬───────────────────────────────┘
                      ▼ Bearer Token
                      ▼
┌─────────────────────────────────────────────────────┐
│ Graph REST API (Sentinel)                           │
│ - Validates token                                   │
│ - Executes GQL query                                │
│ - Returns graph results                             │
└─────────────────────┬───────────────────────────────┘
                      ▼ Query Results
                      ▼
┌─────────────────────────────────────────────────────┐
│ Security Copilot Agent                              │
│ - Parses 5-item groups                              │
│ - Formats investigation table                       │
│ - Returns to analyst                                │
└─────────────────────┬───────────────────────────────┘
                      ▼ Investigation Results
                      ▼
┌─────────────────────────────────────────────────────┐
│ Analyst Views Results                               │
│ - Infrastructure access patterns                    │
│ - Alert details                                     │
│ - Risk assessment                                   │
└─────────────────────────────────────────────────────┘
```

### Token & Permission Details

**Token Acquisition:**
- **Type:** AADDelegated (analyst's user context)
- **Scope:** `https://purview.azure.net/.default`
- **Issued by:** Azure AD / Entra ID

### Agent-Enforced Security Rules

The Security Copilot agent is enforced to run fresh-query-every-time to prevent stale data:

```
Rule 1: Fresh Query Every Turn
  - Must re-extract riskIdentityId from CURRENT message
  - Must NOT reuse prior-turn results
  - Each prompt = independent request

Rule 2: Mandatory API Invocation
  - MUST execute QueryGraphRestAPI fresh for every prompt
  - If not executed: respond "I could not execute fresh query"
  - No fallback to cached results

Rule 3: Unique Request IDs
  - Append {{TIMESTAMP}}_{{RANDOM_UUID}} to prevent caching
  - Ensures platform recognizes each request as new
```

## Next Steps

- **Understand the workflow:** [Getting Started](01-getting-started.md)
- **Build your first graph:** [Build Custom Graph](03-Build-Custom-Graph.md)
- **Deploy to production:** [Deploy Copilot Agent](04-Build-Security-Copilot-Agent.md)
