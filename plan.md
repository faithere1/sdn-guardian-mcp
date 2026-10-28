# PROJECT SPECIFICATION & ARCHITECTURE BLUEPRINT
**Project Name:** `sdn-guardian-mcp` (Autonomous Closed-Loop SDN Defense & Safe Policy Execution via MCP and Cisco Open-Weight Models)
**Target Platform:** Cisco DevNet Code Exchange (Categories: AI/MCP, AI Agents, Networking/SDN, Security)
**Execution Environment:** Google Colab (Free Tier T4 / L4 GPU) + Local/Hybrid Lab Support

---

## 1. ROLE & OBJECTIVE FOR THE CODING AGENT
You are a Principal Network Automation & Applied AI Systems Architect. Your objective is to build a production-grade, fully functional, and self-contained repository named **`sdn-guardian-mcp`**. 

### Why This Project Matters for Cisco DevNet Code Exchange
Currently, 95% of MCP (Model Context Protocol) projects on Cisco DevNet Code Exchange are simple, stateless "Read-Only" REST API wrappers configured exclusively for commercial cloud LLMs (Claude Desktop / OpenAI). 
This project fills a massive, unaddressed gap in the Cisco DevNet ecosystem by introducing:
1. **Closed-Loop Safe Mutation (Write/Execute):** Network engineers fear letting AI modify SDN controllers or routers due to hallucination risks. This project implements a deterministic **Pre-Flight Conflict Simulator** and an asynchronous **Dead-Man's Switch (Auto-Rollback)** engine.
2. **Cisco Open-Weight Models First:** Instead of sending sensitive network topologies to external cloud APIs, this architecture runs **Cisco's own open-weight security/networking models (`fdtn-ai/Foundation-Sec-8B-Instruct`)** locally or inside a self-contained Google Colab instance.
3. **Zero-Friction Reproducibility (Colab-Native):** Cisco DevNet reviewers and community engineers can test the entire closed-loop AI-to-SDN workflow in **one click inside Google Colab** without needing expensive local GPUs or complex hardware setups, while still supporting hybrid connections to physical Cisco IOS-XE (RESTCONF) or OpenFlow/SDN controllers.

---

## 2. CORE ARCHITECTURAL PILLARS (THE 4-STAGE CLOSED LOOP)

The system must implement a 4-stage autonomous OODA (Observe-Orient-Decide-Act) loop exposed via `FastMCP` tools:

### Stage 1: OBSERVE — Packet/Syslog Anomaly Summarizer (`get_traffic_anomalies`)
- **Problem:** Small Language Models (SLMs) with 8B parameters get overwhelmed by raw PCAPs, NetFlow dumps, or thousands of Syslog lines.
- **Solution:** A deterministic data-pruning engine that ingests raw telemetry/logs (or simulated attack streams) and compresses them into a high-signal, token-efficient summary (e.g., Top talkers, SYN flood vectors, MAC-to-SwitchPort mappings, and suggested Graduated Response actions).

### Stage 2: ORIENT — Source-of-Truth (SoT) vs. Live SDN Drift Detector (`detect_network_drift`)
- **Problem:** Before an AI agent takes action, it must know if the network state has already been tampered with or drifted from the intended design.
- **Solution:** Compares the "Intended State" (stored in a lightweight SQLite/YAML Source of Truth) against the "Live State" (polled from the SDN Controller / Switch CAM & VLAN tables). Returns an exact diff (e.g., unauthorized VLAN hopping or rogue port states).

### Stage 3: DECIDE — Pre-Flight Flow/ACL Conflict & Shadowing Simulator (`simulate_flow_impact`)
- **Problem:** LLMs frequently write firewall/SDN rules with incorrect priority/sequence numbers, resulting in **Shadowed Rules** (rules that never trigger because a broader rule above them matches first) or accidental blackholing of critical management traffic.
- **Solution:** Before pushing any rule to the network, the agent MUST pass the proposed rule (`priority`, `src_cidr`, `dst_cidr`, `port`, `action`) to this mathematical verification engine using Python's `ipaddress` library.
- **Logic:** 
  - Checks subnet overlaps (`overlaps()`, `subnet_of()`).
  - Detects **Shadowing**: New rule has lower priority than an existing broader rule.
  - Detects **Overriding**: New rule has higher priority and contradicts an existing rule's action.
  - Detects **Management Lockout**: Prevents blocking protected subnets (e.g., Controller/SSH management VLANs).

### Stage 4: ACT — "Dead-Man's Switch" Safe Policy Execution (`push_safe_sdn_policy` & `confirm_commit`)
- **Problem:** If an applied SDN flow or IOS-XE ACL breaks connectivity, the AI agent loses reachability and cannot undo its mistake.
- **Solution:** 
  1. Takes an atomic snapshot of the current flow/ACL table in SQLite.
  2. Applies the new policy in an `EPHEMERAL / PENDING_CONFIRMATION` state and returns a `commit_id`.
  3. Spawns a non-blocking background timer (`asyncio.create_task`, default 30 seconds) and performs simulated/real aliveness checks.
  4. If the AI agent does not verify network health and explicitly call `confirm_commit(commit_id)` before the timer expires, the MCP server **autonomously rolls back** the network to the exact pre-change snapshot.

---

## 3. TARGET REPOSITORY STRUCTURE

Generate the project following strict Cisco DevNet Code Exchange best practices:

```text
sdn-guardian-mcp/
├── README.md                        # DevNet Exchange compliant docs, architecture diagrams, badges
├── LICENSE                          # Apache 2.0 or MIT License
├── requirements.txt                 # Pinned dependencies for reproducibility
├── .env.example                     # Configuration template (Simulation Mode vs. Cisco Sandbox/Live Mode)
├── src/
│   ├── __init__.py
│   ├── mcp_server.py                # FastMCP server exposing the 4 core tools + resources
│   ├── engine/
│   │   ├── telemetry_summarizer.py  # Stage 1: Log/Packet pruning for SLMs
│   │   ├── drift_detector.py        # Stage 2: SQLite SoT vs Live SDN state comparator
│   │   ├── conflict_simulator.py    # Stage 3: IP/CIDR mathematical shadowing & blast-radius analyzer
│   │   └── rollback_manager.py      # Stage 4: Async Dead-Man's Switch & SQLite state snapshots
│   └── adapters/
│       ├── base_adapter.py          # Abstract interface for network backends
│       ├── mock_sdn_adapter.py      # Default zero-dependency emulator for instant Colab testing
│       └── cisco_restconf_adapter.py# Real connector for Cisco IOS-XE Always-On Sandbox / Catalyst / SDN
├── notebooks/
│   └── Cisco_Foundation_Sec_8B_SDN_Guardian_Colab.ipynb  # Flagship interactive Colab notebook
└── tests/
    └── test_closed_loop.py          # Pytest suite verifying shadowing detection and auto-rollback


4. GOOGLE COLAB & CISCO AI MODEL INTEGRATION SPECIFICATION
The flagship deliverable is notebooks/Cisco_Foundation_Sec_8B_SDN_Guardian_Colab.ipynb. Structure this notebook so any user on a free Google Colab T4 GPU can run it top-to-bottom without errors:
Cell Group 1: Environment & Cisco Open-Weight Model Setup
Install vllm or llama-cpp-python / ollama alongside mcp, fastmcp, httpx, and pydantic.
Load Cisco's open-weight security model: fdtn-ai/Foundation-Sec-8B-Instruct (or a 4-bit quantized GGUF/AWQ equivalent for rapid T4 VRAM loading, with automatic fallback if HuggingFace auth is required).
Explain in Markdown cells why Foundation-Sec-8B is ideal: domain-specific pretraining on cybersecurity, CVE/CWE, network telemetry, and incident response without data exfiltration.
Cell Group 2: Embedded SDN State & MCP Server Initialization
Initialize the SQLite database containing:
Intended Topology (Source of Truth VLANs/Subnets).
Active SDN Flow Table (pre-populated with rules that intentionally create a "Shadowing Trap" for the AI).
Simulated DDoS / SYN Flood + Unauthorized VLAN Drift telemetry.
Start src/mcp_server.py over standard I/O (stdio) or local SSE within the Colab environment.
Cell Group 3: Autonomous Agent Orchestration (ReAct / Tool-Calling Loop)
Implement a clean Python MCP Client loop that connects Foundation-Sec-8B-Instruct to the sdn-guardian-mcp server.
The Demo Scenario (Must execute deterministically in output):
Prompt: "Investigate current network anomalies and topology drift. Formulate a mitigation rule to quarantine the attacker, verify it has no rule conflicts, deploy it safely, and commit only if controller reachability remains intact."
Execution Trace:
Model calls get_traffic_anomalies() -> Identifies SYN flood from 10.10.20.45 on port Gi0/2.
Model calls detect_network_drift() -> Discovers Gi0/2 drifted from VLAN 20 to VLAN 99.
Model attempts to block 10.10.20.45/32 with priority=40 via simulate_flow_impact().
Simulator Rejects: Returns [SHADOWED WARNING] because Rule #10 (10.10.20.0/24, priority=100, ALLOW) shadows priority 40.
Self-Correction: Model adjusts priority to 150 and re-runs simulate_flow_impact() -> PASS.
Safe Execution: Model calls push_safe_sdn_policy(priority=150, ...) -> Receives commit_id and 30s countdown warning.
Verification & Commit: Model checks link health and calls confirm_commit(commit_id) -> Change becomes permanent.
Bonus Demo Cell: Demonstrate a failure case where a bad rule cuts off the controller IP, causing the Dead-Man's Switch to trigger after 10 seconds and automatically restore the SQLite snapshot.
5. TECHNICAL IMPLEMENTATION REQUIREMENTS & CONSTRAINTS
Deterministic & Token-Frugal Outputs:
All MCP @mcp.tool() return values MUST be concise, structured Markdown or compact key-value strings. Never dump raw verbose JSON or full YANG trees into the model context.
Dual-Backend Adapter Pattern:
Default to MockSDNAdapter (SQLite-backed in-memory SDN flow table) so the code works offline and in Colab immediately.
Provide a clean CiscoRestconfAdapter (src/adapters/cisco_restconf_adapter.py) pre-configured with standard headers (application/yang-data+json) compatible with Cisco DevNet IOS-XE Always-On Sandboxes or local physical Cisco ISR/Catalyst gear.
Strict Type Hints & Docstrings:
Every MCP tool must have crystal-clear Pydantic/Python type annotations and concise docstrings so 8B-parameter models parse tool schemas with 100% accuracy.
DevNet Code Exchange Quality Bar (README.md):
Include an "Open in Colab" badge at the top.
Include a Mermaid.js architecture diagram showing the Closed-Loop flow between Cisco Foundation-Sec-8B, the FastMCP server, the Pre-Flight Simulator, and the Dead-Man's Switch Rollback engine.
Explicitly include the sections required by Cisco DevNet reviewers: Overview, Problem Statement, How It Works, Installation (Local & Colab), Cisco Sandbox Configuration, and Usage Examples.
6. STEP-BY-STEP GENERATION PLAN FOR THE AGENT
Please build this project sequentially and provide complete, runnable code (no # TODO placeholders):
First, generate requirements.txt, .env.example, and the core SQLite state/adapter layer (src/adapters/).
Second, build the 4 core engines (telemetry_summarizer.py, drift_detector.py, conflict_simulator.py, rollback_manager.py).
Third, assemble src/mcp_server.py using FastMCP.
Fourth, generate the complete, ready-to-run Google Colab structure (Cisco_Foundation_Sec_8B_SDN_Guardian_Colab.ipynb as a clean Python/Jupyter script or .ipynb JSON).
Finally, write the comprehensive
