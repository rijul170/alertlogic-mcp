"""
AlertLogic MCP SOC Playbooks Module.
Provides AI agents with structured SOC-engineer-level knowledge for
incident response, threat hunting, MITRE ATT&CK mapping, and log analysis.

All tools return static structured JSON — no HTTP calls are made.
"""
from typing import Annotated, Literal, Optional
from pydantic import Field
from mcp.server import FastMCP
from alertlogic_mcp.modules.base import BaseModule


class SocPlaybooksModule(BaseModule):
    """Static knowledge-base tools for SOC operations in AlertLogic."""

    def register_tools(self, server: FastMCP):
        self._add_tool(server, self.soc_ir_start, "soc_ir_start",
                       "Get a step-by-step incident response workflow for a specific incident type")
        self._add_tool(server, self.soc_threat_hunt, "soc_threat_hunt",
                       "Get a structured threat hunting workflow with AL-SQL queries and pivot guidance")
        self._add_tool(server, self.soc_mitre_attack_guide, "soc_mitre_attack_guide",
                       "Get AlertLogic detection guidance and AL-SQL queries for a MITRE ATT&CK technique")
        self._add_tool(server, self.soc_alertlogic_tool_guide, "soc_alertlogic_tool_guide",
                       "Get a categorized reference guide to AlertLogic MCP tools for SOC use cases")
        self._add_tool(server, self.soc_log_query_templates, "soc_log_query_templates",
                       "Get ready-to-use AL-SQL query templates for a specific activity type")
        self._add_tool(server, self.soc_incident_severity_guide, "soc_incident_severity_guide",
                       "Get AlertLogic incident severity levels, SLA targets, and MSSP escalation thresholds")

    # ------------------------------------------------------------------
    # Tool 1: soc_ir_start
    # ------------------------------------------------------------------

    def soc_ir_start(
        self,
        incident_type: Annotated[
            Literal[
                "malware_execution", "network_intrusion", "lateral_movement",
                "credential_theft", "data_exfiltration", "ransomware",
                "phishing", "brute_force", "c2_communication",
                "insider_threat", "web_application_attack"
            ],
            Field(description="Incident type to get the IR workflow for")
        ],
    ) -> dict:
        """Return a step-by-step IR workflow for the given incident type."""

        workflows = {
            "malware_execution": {
                "incident_type": "malware_execution",
                "title": "Malware Execution Incident Response",
                "summary": "Detected execution of malicious code on an endpoint. Goal: scope the infection, identify persistence, prevent spread.",
                "steps": [
                    {
                        "step": 1,
                        "action": "Pull the triggering AlertLogic incident to understand scope",
                        "tool": "incidents_get",
                        "parameters": {"incidentId": "<incident_id>"},
                        "look_for": "attackerList (source IPs or process), victimList (affected hosts), incident_attack_summary.techniques (MITRE IDs), threatLevel",
                        "pivot": "Extract all victim hostnames/IPs and malware indicators (hashes, process names) for next steps"
                    },
                    {
                        "step": 2,
                        "action": "Pull elaborations (raw log lines that triggered the detection)",
                        "tool": "incidents_get_elaborations",
                        "parameters": {"incidentId": "<incident_id>"},
                        "look_for": "Process command lines, parent process, user context, file paths dropped, network connections initiated",
                        "pivot": "Extract process name, command line arguments, any dropped file paths or network IOCs"
                    },
                    {
                        "step": 3,
                        "action": "Search logs on the victim host for process execution around the time of the incident",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE source = '<victim_host>' AND (message CONTAINS 'exec' OR message CONTAINS 'spawn' OR message CONTAINS 'CreateProcess') ORDER BY datetime DESC LIMIT 200",
                            "start_time": "<incident_time_minus_30m>",
                            "end_time": "<incident_time_plus_30m>"
                        },
                        "look_for": "Unusual parent-child process relationships (e.g., Word spawning cmd.exe), encoded commands, temp directory executions",
                        "pivot": "If encoded commands found → search for T1059 PowerShell/script activity. If network connection → move to C2 investigation."
                    },
                    {
                        "step": 4,
                        "action": "Search for lateral movement from the infected host",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE source = '<victim_host>' AND (message CONTAINS 'net use' OR message CONTAINS 'psexec' OR message CONTAINS 'wmic' OR message CONTAINS 'RDP') ORDER BY datetime DESC LIMIT 100"
                        },
                        "look_for": "Connections to other internal hosts, admin share access (C$, ADMIN$), remote execution tools",
                        "pivot": "Each destination host becomes a new victim — repeat steps 1-4 for each"
                    },
                    {
                        "step": 5,
                        "action": "Check for persistence mechanisms",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE source = '<victim_host>' AND (message CONTAINS 'schtasks' OR message CONTAINS 'reg add' OR message CONTAINS 'HKCU\\\\Run' OR message CONTAINS 'HKLM\\\\Run' OR message CONTAINS 'startup') ORDER BY datetime DESC LIMIT 100"
                        },
                        "look_for": "Scheduled task creation, registry Run key modifications, startup folder writes",
                        "pivot": "Document all persistence artifacts for remediation. Check assets_query for host exposure status."
                    },
                    {
                        "step": 6,
                        "action": "Query asset details for the infected host",
                        "tool": "assets_query",
                        "parameters": {"filters": "type:host", "query": "<victim_hostname_or_ip>"},
                        "look_for": "Host asset ID, deployment association, network segment, tags",
                        "pivot": "Use deployment info to understand network isolation options. Check assets_get_exposures_post for existing known vulnerabilities."
                    },
                    {
                        "step": 7,
                        "action": "Check for outbound C2 communications from victim",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM idsmsgs WHERE src_ip = '<victim_ip>' AND dst_ip NOT IN (SELECT ip FROM whitelist_hosts) ORDER BY datetime DESC LIMIT 100"
                        },
                        "look_for": "Connections to unusual external IPs, beaconing patterns (regular interval connections), connections to newly registered domains",
                        "pivot": "External IPs become C2 IOCs — add to watchlist via watchlist_add_entry"
                    },
                    {
                        "step": 8,
                        "action": "Add confirmed malicious IPs/domains to watchlist for ongoing monitoring",
                        "tool": "watchlist_add_entry",
                        "parameters": {"entry_type": "ip", "value": "<c2_ip>", "reason": "Malware C2 from incident <incident_id>"},
                        "look_for": "Confirmation of watchlist entry creation",
                        "pivot": "Create a ticket with all findings via ticket_create for customer notification"
                    },
                    {
                        "step": 9,
                        "action": "Create SOAR ticket with incident summary and remediation steps",
                        "tool": "ticket_create",
                        "parameters": {"summary": "Malware Execution on <host> — Incident <incident_id>", "description": "<full findings>", "severity": "High"},
                        "look_for": "Ticket ID for tracking. Attach all IOCs found.",
                        "pivot": "Add incident notes linking to ticket via incidents_add_note"
                    }
                ],
                "containment_checklist": [
                    "Isolate affected host from network (coordinate with customer)",
                    "Reset credentials of any accounts used on the infected host",
                    "Block C2 IPs/domains at perimeter",
                    "Remove persistence artifacts (scheduled tasks, registry keys)",
                    "Scan peer hosts in same subnet for IOC matches"
                ]
            },
            "network_intrusion": {
                "incident_type": "network_intrusion",
                "title": "Network Intrusion Incident Response",
                "summary": "IDS detected network-based attack. Goal: confirm exploitation, scope affected systems, block attacker.",
                "steps": [
                    {
                        "step": 1,
                        "action": "Get incident details from AlertLogic IDS alert",
                        "tool": "incidents_get",
                        "parameters": {"incidentId": "<incident_id>"},
                        "look_for": "attackerList (external IP), victimList (internal host/IP), incident type (e.g., exploit, scan, brute-force), CVE references in summary",
                        "pivot": "Note attacker IP and targeted service/port. Classify as scan, exploitation attempt, or post-exploitation."
                    },
                    {
                        "step": 2,
                        "action": "Review raw IDS elaborations for attack payload",
                        "tool": "incidents_get_elaborations",
                        "parameters": {"incidentId": "<incident_id>"},
                        "look_for": "HTTP requests with exploit payloads, buffer overflow patterns, SQL injection strings, path traversal attempts",
                        "pivot": "Identify targeted vulnerability (CVE). Check vuln_kb_get for that CVE to understand exploitability."
                    },
                    {
                        "step": 3,
                        "action": "Search IDS logs for attacker IP activity across all targets",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime, src_ip, dst_ip, dst_port FROM idsmsgs WHERE src_ip = '<attacker_ip>' ORDER BY datetime DESC LIMIT 200"
                        },
                        "look_for": "Number of distinct destination IPs/ports (scope of scanning/attack), time range of activity, signatures triggered",
                        "pivot": "If multiple victims → mass exploitation. If single target → targeted attack."
                    },
                    {
                        "step": 4,
                        "action": "Check victim host for successful exploitation indicators (post-exploit logs)",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE source = '<victim_host>' AND datetime > '<attack_time>' ORDER BY datetime ASC LIMIT 200"
                        },
                        "look_for": "New process spawning from web server process (apache, nginx, iis), new user account creation, file writes to web directories",
                        "pivot": "If exploitation confirmed → escalate to malware_execution workflow. If only attempt → document and block."
                    },
                    {
                        "step": 5,
                        "action": "Check vulnerability posture of victim asset",
                        "tool": "assets_get_exposures_post",
                        "parameters": {"asset_key": "<victim_host_asset_key>"},
                        "look_for": "Whether the CVE being exploited is listed as an open exposure, CVSS score, patch availability",
                        "pivot": "If confirmed vulnerable → critical remediation. Use remediations_get_item for remediation steps."
                    },
                    {
                        "step": 6,
                        "action": "Check if attacker IP is in whitelist or exclusions",
                        "tool": "whitelist_list_hosts",
                        "parameters": {},
                        "look_for": "Whether attacker IP is a known scanner (Qualys, Rapid7) that was mistakenly not excluded",
                        "pivot": "If whitelisted scanner → false positive. If not → proceed with blocking."
                    },
                    {
                        "step": 7,
                        "action": "Search for attacker IP in historical incidents",
                        "tool": "incidents_list",
                        "parameters": {"attackers": "<attacker_ip>", "limit": 20},
                        "look_for": "Prior incidents from same IP, pattern of targeting (same CVE vs different), time between incidents",
                        "pivot": "Recurring attacker → add to watchlist and create ticket for firewall block request"
                    }
                ],
                "containment_checklist": [
                    "Block attacker IP at network perimeter/WAF",
                    "Patch targeted vulnerability if host is confirmed vulnerable",
                    "Review web server logs for successful web shell uploads",
                    "Check for new accounts created after attack time",
                    "Scan neighboring hosts for same vulnerability"
                ]
            },
            "lateral_movement": {
                "incident_type": "lateral_movement",
                "title": "Lateral Movement Incident Response",
                "summary": "Attacker is moving between internal systems. Goal: map the full movement chain, identify original foothold, isolate compromised hosts.",
                "steps": [
                    {
                        "step": 1,
                        "action": "Get incident and identify source and destination hosts",
                        "tool": "incidents_get",
                        "parameters": {"incidentId": "<incident_id>"},
                        "look_for": "Source host (already compromised), destination host (being attacked), method (RDP/SMB/WMI/SSH), credentials used",
                        "pivot": "The source host is the pivot point — investigate it fully for original compromise vector"
                    },
                    {
                        "step": 2,
                        "action": "Search for all lateral movement from source host",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE source = '<source_host>' AND (message CONTAINS 'Logon Type 3' OR message CONTAINS 'Logon Type 10' OR message CONTAINS 'net use' OR message CONTAINS 'wmic' OR message CONTAINS 'psexec' OR message CONTAINS 'Enter-PSSession') ORDER BY datetime DESC LIMIT 200"
                        },
                        "look_for": "All destination hosts accessed, logon types (3=network, 10=remote interactive), accounts used",
                        "pivot": "Build a movement graph: source → destination1, destination2, etc."
                    },
                    {
                        "step": 3,
                        "action": "Search for pass-the-hash or pass-the-ticket indicators",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE (message CONTAINS 'NtlmSsp' AND message CONTAINS 'Logon Failure') OR message CONTAINS 'Kerberos' AND message CONTAINS 'TGT' ORDER BY datetime DESC LIMIT 100"
                        },
                        "look_for": "NTLM auth with no prior password entry, Kerberos ticket anomalies, overpass-the-hash patterns (Kerberos request after NTLM)",
                        "pivot": "If pass-the-hash confirmed → T1550.002. Reset NTLM hashes for all accounts on compromised hosts."
                    },
                    {
                        "step": 4,
                        "action": "Identify all hosts the attacker has touched",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime, hostname FROM logmsgs WHERE username = '<compromised_account>' AND (message CONTAINS 'Logon' OR message CONTAINS 'authentication') ORDER BY datetime ASC LIMIT 500"
                        },
                        "look_for": "Full list of hosts where the compromised account authenticated, time progression",
                        "pivot": "Each host in the list is potentially compromised — check each for malware/persistence"
                    },
                    {
                        "step": 5,
                        "action": "Check topology to understand network segmentation",
                        "tool": "assets_get_topology",
                        "parameters": {},
                        "look_for": "Whether compromised hosts span multiple network segments, VPC/subnet boundaries crossed, proximity to crown jewel servers",
                        "pivot": "If segment boundaries crossed → critical escalation. If flat network → full scope may be larger."
                    }
                ],
                "containment_checklist": [
                    "Disable or reset all credentials used in lateral movement",
                    "Block SMB/RDP/WMI between segments where not required",
                    "Audit admin shares and remove unnecessary access",
                    "Force reauthentication on all potentially compromised accounts",
                    "Check Domain Controller logs for Golden/Silver Ticket activity"
                ]
            },
            "credential_theft": {
                "incident_type": "credential_theft",
                "title": "Credential Theft Incident Response",
                "summary": "Credentials were stolen or attempts detected. Goal: identify stolen accounts, scope blast radius, force rotation.",
                "steps": [
                    {
                        "step": 1,
                        "action": "Get incident details and identify targeted accounts",
                        "tool": "incidents_get",
                        "parameters": {"incidentId": "<incident_id>"},
                        "look_for": "Account names in victimList, attack technique (T1003 dump, T1110 brute force, T1528 token theft), attacker IP",
                        "pivot": "Classify: credential dumping (post-compromise) vs brute force (pre-compromise)"
                    },
                    {
                        "step": 2,
                        "action": "Search for LSASS access or credential dumping tool execution",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'lsass' OR message CONTAINS 'mimikatz' OR message CONTAINS 'procdump' OR message CONTAINS 'comsvcs.dll' OR message CONTAINS 'sekurlsa' ORDER BY datetime DESC LIMIT 100"
                        },
                        "look_for": "Direct lsass.exe access, use of known dumping tools (mimikatz, procdump, comsvcs), SAM database access",
                        "pivot": "If dumping confirmed → all local accounts on that host are compromised. Expand search to domain controller logs."
                    },
                    {
                        "step": 3,
                        "action": "Search for authentication with stolen credentials (anomalous logons)",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE username IN ('<account1>', '<account2>') AND message CONTAINS 'Logon' AND datetime > '<dump_time>' ORDER BY datetime ASC LIMIT 200"
                        },
                        "look_for": "Logons from new source IPs, logons at unusual hours, logons to sensitive systems not normally accessed by this account",
                        "pivot": "Unusual logon sources → attacker using stolen credentials. Extract new source IPs as attacker IOCs."
                    },
                    {
                        "step": 4,
                        "action": "Check for brute force patterns if credential dumping not confirmed",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT src_ip, COUNT(*) as attempt_count, message FROM logmsgs WHERE message CONTAINS 'failed' AND message CONTAINS 'logon' GROUP BY src_ip ORDER BY attempt_count DESC LIMIT 50"
                        },
                        "look_for": "Source IPs with >50 failures, accounts being targeted (spray vs stuffing), time pattern (distributed vs burst)",
                        "pivot": "Password spray (many accounts, few failures each) → compromised credential list in attacker possession"
                    }
                ],
                "containment_checklist": [
                    "Force password reset on all identified compromised accounts",
                    "Revoke all active sessions for compromised accounts",
                    "Enable MFA if not already present",
                    "Audit privileged account usage for the past 30 days",
                    "Check for new accounts created with compromised admin credentials"
                ]
            },
            "data_exfiltration": {
                "incident_type": "data_exfiltration",
                "title": "Data Exfiltration Incident Response",
                "summary": "Data leaving the environment via unauthorized channel. Goal: quantify data loss, identify exfil path, contain.",
                "steps": [
                    {
                        "step": 1,
                        "action": "Get incident to understand exfil method and destination",
                        "tool": "incidents_get",
                        "parameters": {"incidentId": "<incident_id>"},
                        "look_for": "Destination IPs/domains (external), protocol used (HTTP/S, DNS, FTP, SFTP), source host, volume indicators",
                        "pivot": "Classify exfil channel: T1041 (over C2), T1048 (alt protocol), T1567 (web service like Dropbox/Pastebin)"
                    },
                    {
                        "step": 2,
                        "action": "Search for large outbound data transfers",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT src_ip, dst_ip, dst_port, SUM(bytes_out) as total_bytes FROM idsmsgs WHERE src_ip = '<source_ip>' AND dst_ip NOT IN (SELECT ip FROM internal_ranges) GROUP BY dst_ip ORDER BY total_bytes DESC LIMIT 50"
                        },
                        "look_for": "Unusual volume to single destination, data transfer to cloud storage IPs, DNS query volume spikes",
                        "pivot": "If DNS exfil → search for long DNS query strings. If HTTP → check User-Agent and POST body sizes."
                    },
                    {
                        "step": 3,
                        "action": "Search for file archive/compression before exfiltration",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE source = '<source_host>' AND (message CONTAINS 'compress' OR message CONTAINS 'archive' OR message CONTAINS '7z' OR message CONTAINS 'rar' OR message CONTAINS 'zip' OR message CONTAINS 'tar') ORDER BY datetime DESC LIMIT 100"
                        },
                        "look_for": "Staging and compression activity prior to exfil time, destination of archive files",
                        "pivot": "Archive location tells you what data was targeted. Check file paths for sensitive directories."
                    },
                    {
                        "step": 4,
                        "action": "Identify what data was accessed before exfiltration",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE source = '<source_host>' AND message CONTAINS 'file' AND (message CONTAINS 'read' OR message CONTAINS 'open' OR message CONTAINS 'copy') ORDER BY datetime DESC LIMIT 200"
                        },
                        "look_for": "File access patterns, directories traversed, sensitive file types (*.xlsx, *.docx, *.sql, *.key, *.pem)",
                        "pivot": "Map accessed files to data classification (PII, IP, credentials, financial)"
                    }
                ],
                "containment_checklist": [
                    "Block destination IPs/domains at perimeter immediately",
                    "Preserve forensic evidence (do NOT clean logs before acquisition)",
                    "Engage legal/compliance if PII/PHI/PCI data confirmed exfiltrated",
                    "Check if exfil destination is known data leak site or threat actor infrastructure",
                    "Quantify record count for breach notification thresholds"
                ]
            },
            "ransomware": {
                "incident_type": "ransomware",
                "title": "Ransomware Incident Response",
                "summary": "Ransomware detected encrypting files. CRITICAL. Goal: immediate containment, scope encryption, preserve evidence.",
                "steps": [
                    {
                        "step": 1,
                        "action": "Get incident — confirm ransomware family and scope",
                        "tool": "incidents_get",
                        "parameters": {"incidentId": "<incident_id>"},
                        "look_for": "Ransomware family name (LockBit, BlackCat, Conti, etc.), victim hosts, whether domain admin is compromised",
                        "pivot": "If domain admin compromised → assume all domain-joined hosts are in scope"
                    },
                    {
                        "step": 2,
                        "action": "Search for file encryption activity and ransom note drops",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'README' OR message CONTAINS 'DECRYPT' OR message CONTAINS 'RECOVER' OR message CONTAINS '.encrypted' OR message CONTAINS '.locked' ORDER BY datetime DESC LIMIT 200"
                        },
                        "look_for": "Ransom note filenames, encrypted file extensions, scope of affected directories",
                        "pivot": "Timestamps show encryption progression — use to determine patient zero and containment window"
                    },
                    {
                        "step": 3,
                        "action": "Find patient zero — where ransomware first executed",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE (message CONTAINS 'vssadmin' OR message CONTAINS 'shadow' OR message CONTAINS 'bcdedit' OR message CONTAINS 'wbadmin') ORDER BY datetime ASC LIMIT 100"
                        },
                        "look_for": "VSS deletion commands (vssadmin delete shadows), backup disable commands — these always precede encryption",
                        "pivot": "First host to show VSS deletion is patient zero. Trace backwards to initial access."
                    },
                    {
                        "step": 4,
                        "action": "Check for data exfiltration before encryption (double extortion)",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT src_ip, dst_ip, SUM(bytes_out) as total_bytes FROM idsmsgs WHERE src_ip IN ('<victim_ips>') AND datetime BETWEEN '<72h_before_ransom>' AND '<ransom_time>' GROUP BY dst_ip ORDER BY total_bytes DESC LIMIT 20"
                        },
                        "look_for": "Large outbound transfers to cloud storage or unusual IPs in days before encryption",
                        "pivot": "If exfil detected → double extortion scenario, notify customer of data theft in addition to encryption"
                    },
                    {
                        "step": 5,
                        "action": "Search all hosts for ransomware propagation activity",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, COUNT(*) as hit_count FROM logmsgs WHERE message CONTAINS 'vssadmin' OR message CONTAINS 'wbadmin delete' GROUP BY source ORDER BY hit_count DESC LIMIT 50"
                        },
                        "look_for": "All hosts showing VSS/backup deletion — this is the true scope of encryption",
                        "pivot": "Full host list for customer containment notification. Check assets_get_topology for network proximity to backups."
                    }
                ],
                "containment_checklist": [
                    "IMMEDIATE: Isolate all affected hosts from network",
                    "IMMEDIATE: Isolate backup systems from production network",
                    "Do NOT reboot affected hosts (may aid forensics)",
                    "Disable AD accounts if domain admin is compromised",
                    "Preserve memory dumps before any remediation",
                    "Do NOT pay ransom without legal/executive approval",
                    "Contact cyber insurance carrier"
                ]
            },
            "phishing": {
                "incident_type": "phishing",
                "title": "Phishing Incident Response",
                "summary": "Phishing email or credential harvesting page detected. Goal: identify victims, check for payload execution, contain.",
                "steps": [
                    {
                        "step": 1,
                        "action": "Get incident details and identify phishing indicators",
                        "tool": "incidents_get",
                        "parameters": {"incidentId": "<incident_id>"},
                        "look_for": "Phishing URL or domain, sender address, targeted accounts, whether payload was downloaded",
                        "pivot": "Extract phishing domain/URL and check for DNS queries across all hosts"
                    },
                    {
                        "step": 2,
                        "action": "Search DNS/proxy logs for access to phishing domain",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime, hostname FROM logmsgs WHERE message CONTAINS '<phishing_domain>' ORDER BY datetime ASC LIMIT 200"
                        },
                        "look_for": "Which hosts/users accessed the phishing domain, whether credentials were submitted (POST requests), payload downloads",
                        "pivot": "Each host that connected is potentially compromised. Check for credential submission vs passive visit."
                    },
                    {
                        "step": 3,
                        "action": "Search for any payload execution from the phishing link",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE source IN ('<affected_hosts>') AND (message CONTAINS 'powershell' OR message CONTAINS 'mshta' OR message CONTAINS 'wscript' OR message CONTAINS '.hta' OR message CONTAINS 'macro') ORDER BY datetime DESC LIMIT 100"
                        },
                        "look_for": "Script execution via Office macro, mshta, wscript after phishing email arrival time",
                        "pivot": "If payload executed → escalate to malware_execution workflow"
                    },
                    {
                        "step": 4,
                        "action": "Check for OAuth token theft or credential harvesting success",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'oauth' AND message CONTAINS 'token' AND datetime > '<phishing_time>' ORDER BY datetime DESC LIMIT 100"
                        },
                        "look_for": "New OAuth app consent grants, token issuances to new applications, MFA bypass events",
                        "pivot": "If OAuth consent → T1528 token theft. Revoke granted permissions immediately."
                    }
                ],
                "containment_checklist": [
                    "Block phishing domain at DNS/proxy layer",
                    "Force password reset for all accounts that accessed phishing page",
                    "Revoke active sessions for affected accounts",
                    "Report phishing URL to hosting provider and threat intel feeds",
                    "Search email gateway for all recipients of the phishing campaign"
                ]
            },
            "brute_force": {
                "incident_type": "brute_force",
                "title": "Brute Force Attack Incident Response",
                "summary": "Repeated authentication failures from single or distributed source. Goal: determine if successful, block, harden.",
                "steps": [
                    {
                        "step": 1,
                        "action": "Get incident and characterize the attack",
                        "tool": "incidents_get",
                        "parameters": {"incidentId": "<incident_id>"},
                        "look_for": "Attacker IP(s), targeted service (SSH/RDP/VPN/Web), targeted account(s), failure count and timespan",
                        "pivot": "Classify: credential stuffing (many accounts), password spray (few attempts each), or targeted (single account)"
                    },
                    {
                        "step": 2,
                        "action": "Quantify failures and check for successful authentication",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT src_ip, username, COUNT(*) as attempts, MAX(CASE WHEN message CONTAINS 'success' OR message CONTAINS 'accepted' THEN 1 ELSE 0 END) as had_success FROM logmsgs WHERE message CONTAINS 'authentication' OR message CONTAINS 'login' GROUP BY src_ip, username ORDER BY attempts DESC LIMIT 100"
                        },
                        "look_for": "Any account showing successful auth after failures — that account is compromised",
                        "pivot": "Any success → immediate account disable and investigation as credential_theft"
                    },
                    {
                        "step": 3,
                        "action": "Check if attack is distributed (botnet spray)",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT src_ip, COUNT(*) as attempts FROM logmsgs WHERE message CONTAINS 'failed' AND message CONTAINS 'authentication' AND datetime > '<incident_time_minus_1h>' GROUP BY src_ip HAVING attempts > 10 ORDER BY attempts DESC LIMIT 100"
                        },
                        "look_for": "Number of distinct source IPs, geographic distribution (requires enrichment), whether all targeting same account",
                        "pivot": "If >20 source IPs → botnet/spray campaign. Block /24 CIDR ranges rather than individual IPs."
                    }
                ],
                "containment_checklist": [
                    "Block attacking IP(s) or CIDR ranges",
                    "Implement account lockout policy if not present",
                    "Enable MFA on targeted service",
                    "Rotate credentials for any accounts that had a successful login during attack",
                    "Consider geo-blocking if attack is from unexpected region"
                ]
            },
            "c2_communication": {
                "incident_type": "c2_communication",
                "title": "C2 Communication Incident Response",
                "summary": "Host communicating with known or suspected C2 infrastructure. Goal: confirm C2, identify malware, scope infection, sever channel.",
                "steps": [
                    {
                        "step": 1,
                        "action": "Get incident and extract C2 indicators",
                        "tool": "incidents_get",
                        "parameters": {"incidentId": "<incident_id>"},
                        "look_for": "C2 IP/domain, beacon interval (if captured), protocol (HTTP/S/DNS/custom), beacon size, malware family if identified",
                        "pivot": "Protocol determines investigation path: HTTP→proxy logs, DNS→resolver logs, custom→IDS deep packet"
                    },
                    {
                        "step": 2,
                        "action": "Search for beaconing pattern from infected host",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT src_ip, dst_ip, datetime FROM idsmsgs WHERE src_ip = '<victim_ip>' AND dst_ip = '<c2_ip>' ORDER BY datetime ASC LIMIT 500"
                        },
                        "look_for": "Regular intervals between connections (jitter ±10-20%), consistent payload sizes, timing relative to business hours vs 24/7",
                        "pivot": "Beacon interval and jitter identify C2 framework (Cobalt Strike: 60s±10%, Metasploit: 5s, custom malware varies)"
                    },
                    {
                        "step": 3,
                        "action": "Search for all internal hosts communicating with C2 IP",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT src_ip, COUNT(*) as connection_count, MIN(datetime) as first_seen, MAX(datetime) as last_seen FROM idsmsgs WHERE dst_ip = '<c2_ip>' GROUP BY src_ip ORDER BY connection_count DESC"
                        },
                        "look_for": "All internal IPs communicating with C2 — each one is a compromised host",
                        "pivot": "Full list of compromised hosts. Earliest first_seen = patient zero."
                    },
                    {
                        "step": 4,
                        "action": "Check DNS for C2 domain resolution and DGA patterns",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'DNS' AND message CONTAINS '<c2_domain>' ORDER BY datetime DESC LIMIT 100"
                        },
                        "look_for": "DNS queries to C2 domain, NXDomain responses (DGA enumeration), DNS TXT record queries (DNS C2 data channel)",
                        "pivot": "NXDomain flood → DGA malware (Emotet, Dridex). Capture and decode TXT records for DNS C2."
                    },
                    {
                        "step": 5,
                        "action": "Add C2 indicators to watchlist",
                        "tool": "watchlist_add_entry",
                        "parameters": {"entry_type": "ip", "value": "<c2_ip>", "reason": "Active C2 infrastructure — incident <incident_id>"},
                        "look_for": "Watchlist entry confirmed",
                        "pivot": "Monitor watchlist for new hosts contacting C2. Block C2 IP at perimeter."
                    }
                ],
                "containment_checklist": [
                    "Block C2 IP/domain at DNS and perimeter firewall",
                    "Isolate confirmed infected hosts",
                    "Capture memory from infected hosts before remediation",
                    "Check for secondary C2 channels (malware may have fallback)",
                    "Search for C2 framework artifacts (Cobalt Strike named pipes, Metasploit staging payloads)"
                ]
            },
            "insider_threat": {
                "incident_type": "insider_threat",
                "title": "Insider Threat Incident Response",
                "summary": "Suspicious activity by authorized user. Goal: document activity chain, preserve evidence, involve HR/Legal.",
                "steps": [
                    {
                        "step": 1,
                        "action": "Get incident focusing on user identity and actions",
                        "tool": "incidents_get",
                        "parameters": {"incidentId": "<incident_id>"},
                        "look_for": "Username, department, access level, specific suspicious actions (bulk download, after-hours access, DLP trigger)",
                        "pivot": "Do NOT alert the subject. Coordinate with HR/Legal before any action."
                    },
                    {
                        "step": 2,
                        "action": "Build full timeline of user activity",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime, hostname FROM logmsgs WHERE username = '<suspect_user>' ORDER BY datetime DESC LIMIT 500"
                        },
                        "look_for": "All systems accessed, files read/copied, authentication events, after-hours activity, bulk data access",
                        "pivot": "Timeline shows intent: gradual data collection (pre-meditated) vs reactive (triggered by termination notice)"
                    },
                    {
                        "step": 3,
                        "action": "Search for bulk data access or download",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE username = '<suspect_user>' AND (message CONTAINS 'file' OR message CONTAINS 'copy' OR message CONTAINS 'download' OR message CONTAINS 'export') ORDER BY datetime DESC LIMIT 200"
                        },
                        "look_for": "Volume of data accessed vs normal baseline, sensitive system access (HR, Finance, IP repositories), USB/removable media usage",
                        "pivot": "Cross-reference with DLP alerts if available. Document all files accessed for legal hold."
                    },
                    {
                        "step": 4,
                        "action": "Check for data staging or external transmission",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE username = '<suspect_user>' AND (message CONTAINS 'gmail' OR message CONTAINS 'dropbox' OR message CONTAINS 'wetransfer' OR message CONTAINS 'personal') ORDER BY datetime DESC LIMIT 100"
                        },
                        "look_for": "Personal email/cloud storage access from corporate network, large file uploads to personal services",
                        "pivot": "Any confirmed exfil to personal accounts → legal must be involved immediately"
                    }
                ],
                "containment_checklist": [
                    "Do NOT alert subject — coordinate with HR/Legal first",
                    "Preserve all logs before account is touched",
                    "Place legal hold on email and file access logs",
                    "Do NOT disable account until HR/Legal authorizes",
                    "Document chain of custody for all evidence"
                ]
            },
            "web_application_attack": {
                "incident_type": "web_application_attack",
                "title": "Web Application Attack Incident Response",
                "summary": "Attack targeting web application (SQLi, XSS, RCE, path traversal). Goal: confirm exploitation, identify data exposure, patch.",
                "steps": [
                    {
                        "step": 1,
                        "action": "Get incident and identify attack type and targeted application",
                        "tool": "incidents_get",
                        "parameters": {"incidentId": "<incident_id>"},
                        "look_for": "Attack type (SQLi/XSS/RCE/path traversal/XXE), targeted URL/endpoint, attacker IP, WAF bypass indicators",
                        "pivot": "Attack type determines impact: SQLi → data exposure, RCE → full compromise, XSS → session theft"
                    },
                    {
                        "step": 2,
                        "action": "Pull raw elaborations for attack payload analysis",
                        "tool": "incidents_get_elaborations",
                        "parameters": {"incidentId": "<incident_id>"},
                        "look_for": "Full HTTP request with payload, whether response code was 200 (success) vs 4xx/5xx (blocked), response size",
                        "pivot": "HTTP 200 with large response → likely successful exploitation. Check server logs for command execution."
                    },
                    {
                        "step": 3,
                        "action": "Search web server logs for successful exploitation",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE source = '<web_server>' AND message CONTAINS '<attack_indicator>' AND message CONTAINS '200' ORDER BY datetime DESC LIMIT 100"
                        },
                        "look_for": "Successful 200 responses to attack payloads, data returned in response, subsequent attacker access to other pages",
                        "pivot": "If SQLi success → check what data tables were accessed. If RCE → check for web shell uploads."
                    },
                    {
                        "step": 4,
                        "action": "Check vulnerability exposure for web application",
                        "tool": "vuln_list_exposures",
                        "parameters": {"asset_type": "host", "query": "<web_server_hostname>"},
                        "look_for": "CVEs affecting the web application framework/version, unpatched vulnerabilities being actively exploited",
                        "pivot": "Match CVE from vulnerability scan to attack technique — confirms exploitability"
                    },
                    {
                        "step": 5,
                        "action": "Search for web shell or backdoor uploads",
                        "tool": "search_submit",
                        "parameters": {
                            "sql": "SELECT source, message, datetime FROM logmsgs WHERE source = '<web_server>' AND (message CONTAINS '.php' OR message CONTAINS '.asp' OR message CONTAINS '.jsp') AND message CONTAINS 'POST' AND datetime > '<attack_time>' ORDER BY datetime DESC LIMIT 100"
                        },
                        "look_for": "New script file uploads via POST to web directories, access to newly created script files from attacker IP",
                        "pivot": "If web shell found → escalate to malware_execution workflow, host is fully compromised"
                    }
                ],
                "containment_checklist": [
                    "Block attacker IP at WAF/firewall",
                    "Apply virtual patching rule for exploited vulnerability",
                    "Remove any uploaded web shells",
                    "Check database query logs for data extraction volume",
                    "Rotate database credentials if SQLi was successful",
                    "Review WAF rules for bypass techniques used"
                ]
            }
        }

        return {
            "playbook": workflows.get(incident_type, {"error": f"Unknown incident type: {incident_type}"}),
            "meta": {
                "tool": "soc_ir_start",
                "incident_type": incident_type,
                "note": "Follow steps in order. Each step's 'pivot' field guides your next action. Adjust parameters to match your actual incident values."
            }
        }

    # ------------------------------------------------------------------
    # Tool 2: soc_threat_hunt
    # ------------------------------------------------------------------

    def soc_threat_hunt(
        self,
        hypothesis: Annotated[str, Field(description="Threat hunting hypothesis to investigate (e.g., 'attacker using living-off-the-land binaries for persistence')")],
        mitre_technique_id: Annotated[Optional[str], Field(description="Optional MITRE ATT&CK technique ID to focus the hunt (e.g., 'T1059.001')")] = None,
    ) -> dict:
        """Return a structured threat hunting workflow with AL-SQL queries and pivot guidance."""

        # Generic hunt framework — always returned
        hunt_framework = {
            "hypothesis": hypothesis,
            "mitre_technique": mitre_technique_id,
            "validation_approach": {
                "step_1_define_scope": {
                    "action": "Establish baseline of normal activity before hunting for anomalies",
                    "tools": ["search_submit", "incidents_list"],
                    "note": "Run a 7-day historical search first. AlertLogic search has max 7-day time window per query — chain queries for longer periods."
                },
                "step_2_pull_recent_incidents": {
                    "action": "Search existing incidents related to the hypothesis",
                    "tool": "incidents_list",
                    "parameters": {
                        "sql": f"threatLevel:High OR threatLevel:Critical",
                        "limit": 50
                    },
                    "note": "AlertLogic may already have detections related to your hypothesis"
                },
                "step_3_run_hunt_queries": {
                    "action": "Execute the hunt queries below in sequence, pivoting on each finding",
                    "tool": "search_submit",
                    "note": "Submit each query, poll with search_status, retrieve with search_results, release with search_release"
                },
                "step_4_enrich_iocs": {
                    "action": "For each IOC found, check watchlist and cross-reference incidents",
                    "tools": ["watchlist_list_entries", "incidents_list"],
                },
                "step_5_asset_correlation": {
                    "action": "Map findings to assets to understand blast radius",
                    "tools": ["assets_query", "assets_get_topology"]
                }
            },
            "ioc_types_to_pivot_on": [
                "Source IPs — search for all activity from that IP",
                "Hostnames — search all events on that host ±2 hours around anomaly",
                "Usernames — search full auth history for that user",
                "Process names — search all hosts for that process execution",
                "File hashes — search for that hash across all endpoint logs",
                "Domains — search DNS logs for all internal resolvers",
                "Network ports — search idsmsgs for unusual port usage"
            ],
            "completion_criteria": {
                "nothing_found": [
                    "All hunt queries return 0 results for the specific IOC patterns",
                    "No incidents in the past 30 days match the MITRE technique",
                    "Asset exposure scan shows no exploitable vulnerabilities for this technique",
                    "Normal baseline established with no statistical anomalies",
                    "Document 'hunted and cleared' with query evidence"
                ],
                "inconclusive": [
                    "Queries return results but context is ambiguous",
                    "Insufficient log coverage (agent not deployed on suspected hosts)",
                    "Log retention gap for the relevant time period"
                ]
            },
            "escalation_trigger": {
                "confirmed_compromise": [
                    "Hunt query returns IOC pattern AND corroborating event (e.g., process exec + network connection)",
                    "Same IOC appears on multiple hosts (lateral movement indicator)",
                    "Newly discovered host communicating with known-bad infrastructure",
                    "Privileged account used from anomalous source IP or time",
                    "Log gap on a host that should have continuous coverage (potential log tampering)"
                ],
                "action_on_confirmation": "Immediately pivot to soc_ir_start with the relevant incident type. Create AlertLogic incident note via incidents_add_note. Create ticket via ticket_create."
            }
        }

        # Add technique-specific hunt queries if MITRE ID provided
        technique_hunts = {
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "hunt_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'powershell' AND (message CONTAINS '-enc' OR message CONTAINS '-EncodedCommand' OR message CONTAINS 'bypass') ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'cmd.exe' AND message CONTAINS '/c' AND datetime > '<7_days_ago>' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'wscript' OR message CONTAINS 'cscript' OR message CONTAINS '.vbs' OR message CONTAINS '.js' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'bash' AND message CONTAINS '-i' AND (message CONTAINS '/dev/tcp' OR message CONTAINS 'nc ') ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'mshta' OR message CONTAINS 'rundll32' AND message CONTAINS 'javascript' ORDER BY datetime DESC LIMIT 50"
                ]
            },
            "T1059.001": {
                "name": "PowerShell",
                "hunt_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'powershell' AND message CONTAINS '-enc' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'IEX' OR message CONTAINS 'Invoke-Expression' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'DownloadString' OR message CONTAINS 'DownloadFile' OR message CONTAINS 'WebClient' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'AMSI' OR message CONTAINS 'amsiInitFailed' OR message CONTAINS 'AmsiScanBuffer' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'powershell' AND (message CONTAINS 'hidden' OR message CONTAINS 'NonInteractive' OR message CONTAINS 'WindowStyle') ORDER BY datetime DESC LIMIT 100"
                ]
            },
            "T1003": {
                "name": "OS Credential Dumping",
                "hunt_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'lsass' AND (message CONTAINS 'access' OR message CONTAINS 'dump' OR message CONTAINS 'read') ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'mimikatz' OR message CONTAINS 'sekurlsa' OR message CONTAINS 'logonpasswords' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'comsvcs.dll' OR message CONTAINS 'MiniDump' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'procdump' AND message CONTAINS 'lsass' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'reg save' AND (message CONTAINS 'HKLM\\\\SAM' OR message CONTAINS 'HKLM\\\\SECURITY' OR message CONTAINS 'HKLM\\\\SYSTEM') ORDER BY datetime DESC LIMIT 50"
                ]
            },
            "T1021": {
                "name": "Remote Services",
                "hunt_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Logon Type 10' OR (message CONTAINS 'RDP' AND message CONTAINS 'connection') ORDER BY datetime DESC LIMIT 200",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Logon Type 3' AND message CONTAINS 'NTLMSSP' ORDER BY datetime DESC LIMIT 200",
                    "SELECT src_ip, dst_ip, dst_port, COUNT(*) as connections FROM idsmsgs WHERE dst_port IN (3389, 22, 445, 5985, 5986) GROUP BY src_ip, dst_ip ORDER BY connections DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'psexec' OR message CONTAINS 'PSEXESVC' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'WinRM' OR message CONTAINS 'WSMan' ORDER BY datetime DESC LIMIT 50"
                ]
            },
            "T1078": {
                "name": "Valid Accounts",
                "hunt_queries": [
                    "SELECT username, src_ip, COUNT(*) as logon_count, MIN(datetime) as first_seen FROM logmsgs WHERE message CONTAINS 'Logon' AND message CONTAINS 'success' GROUP BY username, src_ip HAVING logon_count > 1 ORDER BY first_seen DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'logon' AND datetime BETWEEN '00:00' AND '05:00' ORDER BY datetime DESC LIMIT 100",
                    "SELECT username, COUNT(DISTINCT src_ip) as source_count FROM logmsgs WHERE message CONTAINS 'authentication' GROUP BY username HAVING source_count > 3 ORDER BY source_count DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'service account' OR (message CONTAINS 'svc' AND message CONTAINS 'interactive logon') ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE username IN ('<known_service_accounts>') AND message CONTAINS 'interactive' ORDER BY datetime DESC LIMIT 50"
                ]
            },
            "T1071": {
                "name": "Application Layer Protocol C2",
                "hunt_queries": [
                    "SELECT src_ip, dst_ip, COUNT(*) as connections, STDDEV(datetime) as time_jitter FROM idsmsgs WHERE dst_port IN (80, 443, 8080, 8443) GROUP BY src_ip, dst_ip HAVING connections > 50 ORDER BY connections DESC LIMIT 50",
                    "SELECT src_ip, dst_ip, datetime FROM idsmsgs WHERE dst_port NOT IN (80, 443, 8080, 22, 25, 53) AND dst_ip NOT IN (SELECT ip FROM known_internal_ranges) ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'DNS' AND LENGTH(message) > 200 ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'User-Agent' AND (message CONTAINS 'curl' OR message CONTAINS 'python-requests' OR message CONTAINS 'Go-http') ORDER BY datetime DESC LIMIT 100",
                    "SELECT src_ip, dst_ip, MIN(datetime) as first_beacon, MAX(datetime) as last_beacon, COUNT(*) as beacon_count FROM idsmsgs WHERE dst_ip NOT IN (SELECT ip FROM known_safe_ips) GROUP BY src_ip, dst_ip HAVING beacon_count > 100 ORDER BY beacon_count DESC LIMIT 50"
                ]
            },
            "T1110": {
                "name": "Brute Force",
                "hunt_queries": [
                    "SELECT src_ip, COUNT(*) as failures FROM logmsgs WHERE message CONTAINS 'failed' AND (message CONTAINS 'password' OR message CONTAINS 'authentication') GROUP BY src_ip HAVING failures > 20 ORDER BY failures DESC LIMIT 50",
                    "SELECT username, COUNT(*) as failures FROM logmsgs WHERE message CONTAINS 'failed' AND message CONTAINS 'logon' GROUP BY username HAVING failures > 10 ORDER BY failures DESC LIMIT 50",
                    "SELECT src_ip, COUNT(DISTINCT username) as accounts_targeted FROM logmsgs WHERE message CONTAINS 'failed' AND message CONTAINS 'logon' GROUP BY src_ip HAVING accounts_targeted > 5 ORDER BY accounts_targeted DESC LIMIT 50",
                    "SELECT src_ip, username, MIN(datetime) as first_attempt, MAX(datetime) as last_attempt, COUNT(*) as attempts FROM logmsgs WHERE message CONTAINS 'authentication' GROUP BY src_ip, username HAVING attempts > 5 ORDER BY attempts DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Account locked' OR message CONTAINS 'account lockout' ORDER BY datetime DESC LIMIT 100"
                ]
            },
            "T1486": {
                "name": "Data Encrypted for Impact (Ransomware)",
                "hunt_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'vssadmin' OR message CONTAINS 'wbadmin delete' OR message CONTAINS 'bcdedit /set' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, COUNT(*) as rename_count FROM logmsgs WHERE message CONTAINS 'rename' OR message CONTAINS 'MoveFile' GROUP BY source HAVING rename_count > 100 ORDER BY rename_count DESC LIMIT 20",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'README' AND (message CONTAINS 'DECRYPT' OR message CONTAINS 'RECOVER' OR message CONTAINS 'RESTORE') ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'cipher' OR (message CONTAINS 'encrypt' AND message CONTAINS 'file') ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE (message CONTAINS 'taskkill' OR message CONTAINS 'net stop') AND (message CONTAINS 'sql' OR message CONTAINS 'backup' OR message CONTAINS 'veeam') ORDER BY datetime DESC LIMIT 50"
                ]
            }
        }

        # Look up technique (try exact match then prefix match)
        technique_data = None
        if mitre_technique_id:
            technique_data = technique_hunts.get(mitre_technique_id)
            if not technique_data:
                # Try parent technique (e.g., T1059.003 → T1059)
                parent = mitre_technique_id.split(".")[0]
                technique_data = technique_hunts.get(parent)

        result = {
            "playbook": hunt_framework,
            "meta": {
                "tool": "soc_threat_hunt",
                "hypothesis": hypothesis,
                "mitre_technique": mitre_technique_id,
                "search_workflow": "1. search_submit(sql) → 2. search_status(uuid) [poll until complete] → 3. search_results(uuid) → 4. search_release(uuid)",
                "time_format_note": "AlertLogic search start_time/end_time accepts epoch seconds or ISO 8601. Max 7-day span per query.",
                "note": "Run hunt queries from specific to broad. A negative result across all queries with adequate log coverage is a valid 'hunted and cleared' finding."
            }
        }

        if technique_data:
            result["technique_specific_hunt"] = {
                "technique_id": mitre_technique_id,
                "technique_name": technique_data["name"],
                "ready_to_run_queries": technique_data["hunt_queries"],
                "usage": "Submit each query via search_submit. Use start_time/end_time to set a 7-day window. Replace placeholders like <victim_host> with actual values from your environment."
            }
        elif mitre_technique_id:
            result["technique_specific_hunt"] = {
                "note": f"No pre-built hunt queries for {mitre_technique_id}. Use soc_mitre_attack_guide('{mitre_technique_id}') for technique-specific queries.",
                "fallback": "Use the generic hunt framework above with the IOC types relevant to this technique"
            }

        return result

    # ------------------------------------------------------------------
    # Tool 3: soc_mitre_attack_guide
    # ------------------------------------------------------------------

    def soc_mitre_attack_guide(
        self,
        technique_id: Annotated[str, Field(description="MITRE ATT&CK technique ID (e.g., 'T1059', 'T1059.001')")],
    ) -> dict:
        """Return AlertLogic detection guidance, AL-SQL queries, and investigation steps for a MITRE technique."""

        techniques = {
            # ── INITIAL ACCESS ────────────────────────────────────────────
            "T1566": {
                "technique_id": "T1566", "name": "Phishing", "tactic": "Initial Access",
                "description": "Adversaries send malicious emails to gain initial access. Payloads include macro-enabled documents, links to credential harvesting pages, or direct malware attachments. Detection focuses on email gateway logs, web proxy access to phishing domains, and macro execution events.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'macro' AND (message CONTAINS 'enable' OR message CONTAINS 'execute') ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'mshta' OR message CONTAINS 'wscript' OR message CONTAINS '.hta' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'outlook' AND message CONTAINS 'spawn' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list", "incidents_get_elaborations"],
                "ioc_types_to_extract": ["sender_domain", "phishing_url", "attachment_hash", "victim_hostname"],
                "severity_indicators": ["Office app spawning cmd.exe or powershell.exe", "mshta or wscript executed from email temp folder", "Credential submission to external domain"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1059.001 PowerShell execution", "T1078 Valid Accounts if credential harvest", "T1204 User Execution"],
            },
            "T1566.001": {
                "technique_id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access",
                "description": "Malicious file attachment in targeted phishing email. Common payloads: macro-enabled Office docs, ISO/LNK files, PDF with embedded exploit, or HTML smuggling.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'winword' AND message CONTAINS 'cmd' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS '.iso' OR message CONTAINS '.lnk' AND message CONTAINS 'temp' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'AutoOpen' OR message CONTAINS 'Document_Open' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_get_elaborations"],
                "ioc_types_to_extract": ["attachment_name", "process_tree", "dropped_file_path"],
                "severity_indicators": ["Office child process execution", "Script file written to %TEMP%", "Network connection from Office process"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1059 Command execution", "T1055 Process injection"],
            },
            "T1566.002": {
                "technique_id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access",
                "description": "Email contains link to malicious site for credential harvest or drive-by download. Often uses lookalike domains or compromised legitimate sites.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'http' AND message CONTAINS 'login' AND message CONTAINS 'external' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'credential' AND message CONTAINS 'POST' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["phishing_domain", "redirect_chain", "victim_username"],
                "severity_indicators": ["POST to external login page from corporate network", "Browser spawning unexpected child process after link click"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1078 Valid Accounts", "T1528 Steal App Access Token"],
            },
            "T1190": {
                "technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access",
                "description": "Adversaries exploit vulnerabilities in internet-facing services (web apps, VPNs, mail servers). Successful exploitation often leads to web shell upload or RCE.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM idsmsgs WHERE message CONTAINS 'exploit' AND dst_port IN (80, 443, 8080, 8443) ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE source IN ('<web_servers>') AND message CONTAINS 'exception' AND datetime > '<7_days_ago>' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS '../' OR message CONTAINS '%2e%2e' OR message CONTAINS 'etc/passwd' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_get_elaborations", "vuln_list_exposures", "assets_get_exposures_post"],
                "ioc_types_to_extract": ["attacker_ip", "targeted_endpoint", "cve_id", "exploit_payload"],
                "severity_indicators": ["HTTP 200 response to exploit payload", "Web server spawning OS shell process", "New file created in webroot after exploit attempt"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1505.003 Web Shell", "T1059 Command execution", "vuln_kb_get for CVE details"],
            },
            "T1133": {
                "technique_id": "T1133", "name": "External Remote Services", "tactic": "Initial Access",
                "description": "Adversaries leverage VPN, RDP, Citrix, or other remote access services with valid or stolen credentials to gain initial access without triggering traditional intrusion detections.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'VPN' AND message CONTAINS 'logon' AND src_ip NOT IN ('<known_corp_ranges>') ORDER BY datetime DESC LIMIT 100",
                    "SELECT src_ip, username, COUNT(*) as sessions FROM logmsgs WHERE message CONTAINS 'RDP' AND message CONTAINS 'connected' GROUP BY src_ip, username ORDER BY sessions DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Citrix' AND message CONTAINS 'authentication' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["src_ip", "username", "vpn_gateway", "session_duration"],
                "severity_indicators": ["VPN login from new country/IP", "RDP from residential IP range", "Multiple concurrent VPN sessions for one user"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1078 Valid Accounts", "T1021 Remote Services for lateral movement"],
            },
            "T1078": {
                "technique_id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access",
                "description": "Adversaries use compromised legitimate credentials to access systems. Can be initial access, persistence, or privilege escalation. Anomalous logon patterns (new IP, time, service) are the primary detection signal.",
                "alertlogic_search_queries": [
                    "SELECT username, src_ip, datetime FROM logmsgs WHERE message CONTAINS 'Logon' AND message CONTAINS 'success' ORDER BY datetime DESC LIMIT 200",
                    "SELECT username, COUNT(DISTINCT src_ip) as source_count FROM logmsgs WHERE message CONTAINS 'authentication' GROUP BY username HAVING source_count > 3 ORDER BY source_count DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'logon' AND datetime BETWEEN '2000-01-01 00:00:00' AND '2000-01-01 05:00:00' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["username", "src_ip", "logon_time", "target_system"],
                "severity_indicators": ["Logon from new country", "Service account with interactive logon", "Account active during off-hours with no prior history"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1110 Brute Force if failures precede success", "T1021 Lateral Movement"],
            },
            "T1195": {
                "technique_id": "T1195", "name": "Supply Chain Compromise", "tactic": "Initial Access",
                "description": "Adversaries compromise software suppliers, build pipelines, or hardware to deliver malicious code to targets. Detection is difficult at initial access; focus on post-compromise anomalies from trusted software.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'update' AND message CONTAINS 'network connection' AND message CONTAINS 'unexpected' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'solarwinds' OR message CONTAINS 'orion' OR message CONTAINS 'kaseya' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list", "assets_query"],
                "ioc_types_to_extract": ["software_name", "version", "network_connections", "child_processes"],
                "severity_indicators": ["Trusted software making anomalous network connections", "Software update binary spawning shell", "C2 beacon from vendor management software process"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1071 C2 communication", "T1059 Command execution from trusted process"],
            },

            # ── EXECUTION ─────────────────────────────────────────────────
            "T1059": {
                "technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution",
                "description": "Adversaries abuse command interpreters (PowerShell, cmd, bash, Python, WMI) to execute malicious code. Living-off-the-land techniques use built-in interpreters to evade AV. Detection focuses on unusual parent processes, encoded commands, and download cradles.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'cmd.exe' AND message CONTAINS '/c' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'powershell' AND (message CONTAINS '-enc' OR message CONTAINS 'hidden' OR message CONTAINS 'bypass') ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'wscript' OR message CONTAINS 'cscript' OR message CONTAINS 'mshta' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["process_name", "command_line", "parent_process", "username"],
                "severity_indicators": ["Encoded commands (-enc, -EncodedCommand)", "Download cradle (DownloadString, wget, curl in script)", "Interpreter spawned by Office or browser process"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1003 Credential Dumping", "T1071 C2 Communication", "T1547 Persistence"],
            },
            "T1059.001": {
                "technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution",
                "description": "PowerShell is heavily abused for fileless malware execution, C2 staging, credential dumping, and lateral movement. Encoded commands, AMSI bypass, and download cradles are high-fidelity indicators.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'powershell' AND message CONTAINS '-enc' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'IEX' OR message CONTAINS 'Invoke-Expression' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'DownloadString' OR message CONTAINS 'WebClient' OR message CONTAINS 'Net.WebClient' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'AMSI' OR message CONTAINS 'amsiInitFailed' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["command_line", "base64_payload", "download_url", "username"],
                "severity_indicators": ["Base64 encoded commands", "AMSI bypass attempts", "Download cradle (IEX + WebClient)", "PowerShell running with -WindowStyle Hidden -NonInteractive"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1003 Credential Dumping", "T1055 Process Injection", "T1021 Lateral Movement"],
            },
            "T1059.003": {
                "technique_id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution",
                "description": "cmd.exe used for command execution, batch scripts, and chaining shell commands. Often spawned by malware or exploits as a first execution step.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'cmd.exe' AND message CONTAINS '/c' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'cmd' AND message CONTAINS 'echo' AND message CONTAINS '>' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["command_line", "parent_process", "username"],
                "severity_indicators": ["cmd.exe spawned by web server process", "Batch file execution from temp directory", "cmd /c with net or sc commands"],
                "false_positive_rate": "High",
                "pivot_to": ["T1059.001 PowerShell", "T1136 Create Account", "T1547 Persistence"],
            },
            "T1059.004": {
                "technique_id": "T1059.004", "name": "Unix Shell", "tactic": "Execution",
                "description": "Bash, sh, zsh abuse on Linux/macOS. Reverse shells, cron persistence, and privilege escalation via shell scripts. Web server RCE commonly drops to bash.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS '/bin/bash' AND message CONTAINS '-i' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS '/dev/tcp/' OR message CONTAINS 'mkfifo' AND message CONTAINS 'bash' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'curl' AND message CONTAINS '|' AND message CONTAINS 'bash' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["command_line", "parent_process", "src_ip", "username"],
                "severity_indicators": ["Reverse shell via /dev/tcp", "curl|bash download-and-exec pattern", "Web server spawning bash with -i flag"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1071 C2 Communication", "T1136 Create Account on Linux"],
            },
            "T1047": {
                "technique_id": "T1047", "name": "Windows Management Instrumentation", "tactic": "Execution",
                "description": "WMI used for remote execution, lateral movement, and persistence. wmic.exe and PowerShell WMI cmdlets are commonly abused. WMI subscriptions provide fileless persistence.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'wmic' AND message CONTAINS 'process call create' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'WMI' AND message CONTAINS 'remote' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS '__EventFilter' OR message CONTAINS 'CommandLineEventConsumer' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["command_line", "target_host", "username", "wmi_query"],
                "severity_indicators": ["wmic process call create with encoded payload", "WMI subscription creation for persistence", "WMI remote execution from non-admin workstation"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1021.006 WinRM", "T1546 WMI Event Subscription persistence"],
            },
            "T1053": {
                "technique_id": "T1053", "name": "Scheduled Task/Job", "tactic": "Execution",
                "description": "Scheduled tasks (Windows Task Scheduler, cron) used for execution and persistence. Attackers create tasks to run malicious payloads at reboot, login, or intervals.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'schtasks' AND message CONTAINS '/create' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Task Scheduler' AND message CONTAINS 'registered' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'crontab' AND message CONTAINS 'added' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["task_name", "task_command", "schedule", "username"],
                "severity_indicators": ["Task created by non-admin account", "Task executing from %TEMP% or %APPDATA%", "Task pointing to encoded PowerShell"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1059 Command execution", "T1547 Boot Autostart persistence"],
            },
            "T1053.005": {
                "technique_id": "T1053.005", "name": "Scheduled Task", "tactic": "Execution",
                "description": "Windows Task Scheduler specifically. Remote task creation via RPC is a common lateral movement technique. Tasks created by SYSTEM account without corresponding service are suspicious.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'schtasks /create' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'TASK_SCHEDULER' AND message CONTAINS 'created' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'at.exe' OR message CONTAINS 'taskeng.exe' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["task_name", "run_as_user", "trigger", "action_command"],
                "severity_indicators": ["Task created remotely via RPC", "Task running as SYSTEM with no prior baseline", "schtasks /create with /ru SYSTEM by non-admin"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1021 Lateral Movement", "T1078 Valid Accounts"],
            },
            "T1204": {
                "technique_id": "T1204", "name": "User Execution", "tactic": "Execution",
                "description": "Adversaries rely on user actions (opening attachments, clicking links, running scripts) for code execution. Often the execution step following a phishing initial access.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'winword' OR message CONTAINS 'excel' OR message CONTAINS 'powerpnt' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'macro' AND message CONTAINS 'executed' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_get_elaborations"],
                "ioc_types_to_extract": ["file_name", "parent_process", "child_process", "username"],
                "severity_indicators": ["Office macro execution spawning network connection", "Double-extension file executed (invoice.pdf.exe)", "User executed script from Downloads folder"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1566 Phishing for initial access context", "T1059 Command execution"],
            },
            "T1106": {
                "technique_id": "T1106", "name": "Native API", "tactic": "Execution",
                "description": "Direct use of Windows Native API (NtCreateProcess, NtAllocateVirtualMemory) to execute code, bypassing higher-level monitoring hooks. Common in advanced malware and process injection.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'NtCreateProcess' OR message CONTAINS 'NtAllocateVirtualMemory' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM idsmsgs WHERE message CONTAINS 'process hollowing' OR message CONTAINS 'native API abuse' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["process_name", "api_call", "target_process"],
                "severity_indicators": ["Direct syscall from non-system process", "NtWriteVirtualMemory called cross-process", "Process created with suspended flag then resumed"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1055 Process Injection", "T1134 Token Manipulation"],
            },
            "T1569": {
                "technique_id": "T1569", "name": "System Services", "tactic": "Execution",
                "description": "Adversaries abuse Windows services (sc.exe, Service Control Manager) to execute malicious payloads with SYSTEM privileges. PsExec creates a service for remote execution.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'sc create' OR message CONTAINS 'sc start' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'PSEXESVC' OR message CONTAINS 'psexec' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'service installed' AND message CONTAINS 'temp' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["service_name", "binary_path", "username", "remote_host"],
                "severity_indicators": ["Service binary in temp/appdata directory", "PSEXESVC service creation", "Service created by non-admin user"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1021 Remote Services", "T1078 Valid Accounts"],
            },

            # ── PERSISTENCE ───────────────────────────────────────────────
            "T1136": {
                "technique_id": "T1136", "name": "Create Account", "tactic": "Persistence",
                "description": "Adversaries create local or domain accounts for persistent access. Often follows privilege escalation. Net user or domain admin account creation by non-IT accounts is highly suspicious.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'net user' AND message CONTAINS '/add' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'user account created' OR message CONTAINS 'New user' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'New-ADUser' OR message CONTAINS 'Add-ADGroupMember' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["new_username", "created_by", "hostname", "group_membership"],
                "severity_indicators": ["Account added to Domain Admins group", "Account created outside IT provisioning hours", "Account creation followed immediately by logon"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1078 Valid Accounts", "T1098 Account Manipulation"],
            },
            "T1547": {
                "technique_id": "T1547", "name": "Boot/Logon Autostart Execution", "tactic": "Persistence",
                "description": "Adversaries configure malware to execute automatically on boot or logon via registry Run keys, startup folders, services, or scheduled tasks.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'startup folder' AND message CONTAINS 'created' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'reg add' AND message CONTAINS 'Run' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["registry_key", "binary_path", "username", "hostname"],
                "severity_indicators": ["Non-standard binary in Run key", "Startup folder item created by non-admin", "Run key pointing to %TEMP% or %APPDATA%"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1059 Command execution on next boot", "T1036 Masquerading (renamed binary)"],
            },
            "T1547.001": {
                "technique_id": "T1547.001", "name": "Registry Run Keys / Startup Folder", "tactic": "Persistence",
                "description": "Run/RunOnce registry keys and startup folders are the most common Windows persistence mechanisms. Any modification outside software installation deserves investigation.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'CurrentVersion\\\\Run' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Startup' AND message CONTAINS 'lnk' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["registry_value_name", "registry_value_data", "username", "hostname"],
                "severity_indicators": ["Run key pointing to powershell or cmd with encoded payload", "Startup LNK file created in user profile", "RunOnce key set to delete after execution (anti-forensics)"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1036 Masquerading", "T1059.001 PowerShell"],
            },
            "T1098": {
                "technique_id": "T1098", "name": "Account Manipulation", "tactic": "Persistence",
                "description": "Adversaries manipulate existing accounts to maintain access — adding to privileged groups, changing passwords, adding SSH keys, or modifying email forwarding rules.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'added to group' AND message CONTAINS 'admin' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'password changed' AND message CONTAINS 'admin' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'authorized_keys' AND message CONTAINS 'modified' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["target_account", "modified_by", "change_type", "new_permissions"],
                "severity_indicators": ["Standard user added to Domain Admins", "SSH authorized_keys modified on server", "Admin password changed outside change management"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1136 Create Account", "T1078 Valid Accounts"],
            },
            "T1505": {
                "technique_id": "T1505", "name": "Server Software Component", "tactic": "Persistence",
                "description": "Adversaries install malicious server-side components (web shells, IIS modules, Exchange transport agents) to maintain persistent access to servers.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'new file' AND (message CONTAINS '.php' OR message CONTAINS '.asp' OR message CONTAINS '.jsp') AND message CONTAINS 'webroot' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'IIS module' AND message CONTAINS 'registered' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["file_path", "file_hash", "server_hostname"],
                "severity_indicators": ["Script file written to webroot by non-deployment process", "IIS native module loaded from non-standard path", "Exchange transport agent added outside maintenance"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1190 Exploit Public-Facing App (how it was planted)", "T1059 Execution via web shell"],
            },
            "T1505.003": {
                "technique_id": "T1505.003", "name": "Web Shell", "tactic": "Persistence",
                "description": "A script uploaded to a web server to provide persistent remote code execution. Web shells allow the attacker to execute OS commands via HTTP requests, bypassing firewall rules.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'POST' AND message CONTAINS '.php' AND message CONTAINS 'cmd' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'web shell' OR message CONTAINS 'webshell' OR message CONTAINS 'chopper' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'eval(' OR message CONTAINS 'base64_decode' AND message CONTAINS 'webroot' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_get_elaborations", "incidents_list"],
                "ioc_types_to_extract": ["shell_url", "attacker_ip", "commands_executed", "server_hostname"],
                "severity_indicators": ["PHP/ASP file executing system commands via POST", "Web server process spawning cmd/bash", "Small PHP file written to webroot shortly after exploit attempt"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1059 Command execution via shell", "T1105 Tool Transfer via shell"],
            },

            # ── PRIVILEGE ESCALATION ──────────────────────────────────────
            "T1055": {
                "technique_id": "T1055", "name": "Process Injection", "tactic": "Privilege Escalation",
                "description": "Injecting malicious code into legitimate processes to evade detection and inherit elevated privileges. Common techniques: DLL injection, process hollowing, reflective loading.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM idsmsgs WHERE message CONTAINS 'process injection' OR message CONTAINS 'process hollowing' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'WriteProcessMemory' OR message CONTAINS 'VirtualAllocEx' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'CreateRemoteThread' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["source_process", "target_process", "injected_dll", "technique"],
                "severity_indicators": ["CreateRemoteThread into lsass.exe or svchost.exe", "Unsigned code executing from svchost memory space", "Process with no disk binary (fileless/reflective)"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1003 Credential Dumping (lsass injection)", "T1134 Token Manipulation"],
            },
            "T1134": {
                "technique_id": "T1134", "name": "Access Token Manipulation", "tactic": "Privilege Escalation",
                "description": "Adversaries manipulate Windows access tokens to escalate privileges or impersonate other users. Token impersonation, token duplication, and make-token techniques are common.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'ImpersonateLoggedOnUser' OR message CONTAINS 'DuplicateTokenEx' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'token' AND message CONTAINS 'privilege' AND message CONTAINS 'elevated' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'SeDebugPrivilege' AND message CONTAINS 'enabled' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["process_name", "token_type", "impersonated_user"],
                "severity_indicators": ["SeDebugPrivilege enabled on non-admin process", "Token impersonation to SYSTEM from user process", "Incognito or token manipulation tool signatures"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1055 Process Injection", "T1003 Credential Dumping"],
            },
            "T1068": {
                "technique_id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation",
                "description": "Exploiting local vulnerabilities (kernel exploits, unpatched drivers, service misconfigurations) to escalate from user to SYSTEM/root.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM idsmsgs WHERE message CONTAINS 'privilege escalation' OR message CONTAINS 'local exploit' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'kernel' AND message CONTAINS 'exploit' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'PrintNightmare' OR message CONTAINS 'PrintSpooler' AND message CONTAINS 'exploit' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list", "vuln_list_exposures"],
                "ioc_types_to_extract": ["exploit_name", "cve_id", "target_host", "result"],
                "severity_indicators": ["Known exploit tool name in process list", "CVE being actively exploited on unpatched host", "Unexpected SYSTEM process creation from user process"],
                "false_positive_rate": "Low",
                "pivot_to": ["vuln_list_exposures for patch status", "T1055 Process Injection post-escalation"],
            },

            # ── DEFENSE EVASION ───────────────────────────────────────────
            "T1070": {
                "technique_id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion",
                "description": "Adversaries delete logs, clear event logs, remove artifacts, and modify timestamps to cover their tracks after compromise.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'wevtutil cl' OR message CONTAINS 'Clear-EventLog' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'event log' AND message CONTAINS 'cleared' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'del' AND message CONTAINS 'prefetch' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["log_cleared", "cleared_by", "hostname", "timestamp"],
                "severity_indicators": ["Security event log cleared", "All prefetch files deleted", "Timestomping (file timestamps modified to past dates)"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1562.001 Disable Security Tools", "Check for log gaps (no events for period)"],
            },
            "T1070.001": {
                "technique_id": "T1070.001", "name": "Clear Windows Event Logs", "tactic": "Defense Evasion",
                "description": "Clearing Windows Security, System, or Application event logs to remove forensic evidence. A Security log clear event (ID 1102) is itself a high-confidence indicator.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'EventID 1102' OR message CONTAINS 'audit log cleared' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'wevtutil' AND message CONTAINS 'cl' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Clear-EventLog' OR message CONTAINS 'Remove-EventLog' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["cleared_by_account", "hostname", "log_name", "time_of_clear"],
                "severity_indicators": ["Security log clear (Event ID 1102)", "Log clear by non-admin or service account", "Log clear immediately before or after suspicious activity"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1070 other indicator removal", "Reconstruct timeline from remaining logs"],
            },
            "T1036": {
                "technique_id": "T1036", "name": "Masquerading", "tactic": "Defense Evasion",
                "description": "Adversaries rename malicious binaries to mimic legitimate system tools (svchost.exe, lsass.exe, explorer.exe) to avoid detection. Running from wrong directory is the key tell.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'svchost.exe' AND message NOT CONTAINS 'System32' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'lsass.exe' AND message NOT CONTAINS 'System32' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'explorer.exe' AND message CONTAINS 'Temp' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["process_name", "process_path", "process_hash", "parent_process"],
                "severity_indicators": ["svchost.exe running from non-System32 path", "Binary named after system tool with different hash", "Process with legitimate name spawned by unusual parent"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1059 Command execution via masqueraded binary", "T1547 Persistence using masqueraded name"],
            },
            "T1112": {
                "technique_id": "T1112", "name": "Modify Registry", "tactic": "Defense Evasion",
                "description": "Registry modifications used to disable security features, store malware configuration, establish persistence, or manipulate system behavior. Combined with T1562 for defense evasion.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'reg add' AND message CONTAINS 'HKLM' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'DisableAntiSpyware' OR message CONTAINS 'DisableRealtimeMonitoring' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'registry' AND message CONTAINS 'modified' AND message CONTAINS 'security' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["registry_key", "registry_value", "modified_by", "previous_value"],
                "severity_indicators": ["DisableAntiSpyware or DisableRealtimeMonitoring set to 1", "UAC disabled via registry", "Defender exclusion path added via registry"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1562.001 Impair Defenses", "T1547 Autostart persistence"],
            },
            "T1562": {
                "technique_id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion",
                "description": "Adversaries disable or tamper with security tools (AV, EDR, SIEM agents, firewalls) to reduce detection capability before or during an attack.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'service stopped' AND (message CONTAINS 'defender' OR message CONTAINS 'carbon black' OR message CONTAINS 'crowdstrike') ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'firewall' AND message CONTAINS 'disabled' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'tamper protection' OR message CONTAINS 'tamper alert' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["disabled_tool", "disabled_by", "hostname", "method"],
                "severity_indicators": ["AV/EDR service stopped", "Firewall disabled via netsh or Group Policy", "SIEM/log agent service stopped"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1070 Log clearing to follow", "T1486 Ransomware (AV disable is a precursor)"],
            },
            "T1562.001": {
                "technique_id": "T1562.001", "name": "Disable or Modify Tools", "tactic": "Defense Evasion",
                "description": "Specific security tool disabling — Windows Defender, third-party AV/EDR, audit policies, or logging agents. A critical pre-ransomware step.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Set-MpPreference' AND message CONTAINS 'Disable' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'sc stop' AND (message CONTAINS 'WinDefend' OR message CONTAINS 'MsMpEng') ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'auditpol' AND message CONTAINS 'disable' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["disabled_component", "method_used", "hostname", "username"],
                "severity_indicators": ["Windows Defender real-time protection disabled", "Audit policy cleared or disabled", "EDR agent service stopped by non-admin process"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1486 Ransomware", "T1003 Credential Dumping (Defender blocks mimikatz)"],
            },
            "T1027": {
                "technique_id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion",
                "description": "Malware and scripts are obfuscated using encoding, encryption, compression, or steganography to evade signature detection. Base64, XOR, and custom encoders are common.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS '-EncodedCommand' OR message CONTAINS '-enc ' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'base64' AND message CONTAINS 'decode' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'XOR' AND (message CONTAINS 'payload' OR message CONTAINS 'decode') ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["obfuscation_type", "encoded_payload_snippet", "process_name"],
                "severity_indicators": ["Long base64 strings in PowerShell arguments", "Multiple layers of encoding (base64 inside base64)", "Executable content hidden in image file (steganography)"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1059.001 PowerShell for decoding", "Decode the payload manually for IOC extraction"],
            },

            # ── CREDENTIAL ACCESS ─────────────────────────────────────────
            "T1003": {
                "technique_id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access",
                "description": "Extracting credentials from OS memory (LSASS), registry (SAM/SECURITY), or disk. Most common technique in enterprise breaches. Mimikatz is the canonical tool.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'lsass' AND (message CONTAINS 'access' OR message CONTAINS 'dump') ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'mimikatz' OR message CONTAINS 'sekurlsa' OR message CONTAINS 'logonpasswords' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'procdump' AND message CONTAINS 'lsass' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'comsvcs.dll' OR message CONTAINS 'MiniDump' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list", "incidents_get_elaborations"],
                "ioc_types_to_extract": ["tool_used", "hostname", "username_used", "dump_file_path"],
                "severity_indicators": ["lsass.exe memory read by non-system process", "procdump -ma lsass.exe command", "comsvcs.dll MiniDump via rundll32", "mimikatz tool name or function names in logs"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1021 Lateral Movement with stolen creds", "T1078 Valid Accounts", "T1550 Pass-the-Hash"],
            },
            "T1003.001": {
                "technique_id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access",
                "description": "Direct dumping of LSASS process memory to extract plaintext passwords, NTLM hashes, and Kerberos tickets. Highest-value credential access technique in Windows environments.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'lsass.exe' AND message CONTAINS 'handle' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'OpenProcess' AND message CONTAINS 'lsass' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM idsmsgs WHERE message CONTAINS 'LSASS dump' OR message CONTAINS 'credential dump' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["accessing_process", "access_flags", "hostname"],
                "severity_indicators": ["Non-system process opening lsass.exe with PROCESS_VM_READ", "Dump file (.dmp) created in temp directory matching lsass size", "WerFault.exe invoked against lsass (living-off-the-land dump)"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1550.002 Pass-the-Hash", "T1021 Lateral Movement"],
            },
            "T1110": {
                "technique_id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
                "description": "Repeated authentication attempts to guess passwords. Variants include online brute force, password spray, and credential stuffing. Detection focuses on failure volume and pattern.",
                "alertlogic_search_queries": [
                    "SELECT src_ip, COUNT(*) as failures FROM logmsgs WHERE message CONTAINS 'failed' AND message CONTAINS 'logon' GROUP BY src_ip HAVING failures > 20 ORDER BY failures DESC LIMIT 50",
                    "SELECT username, COUNT(*) as failures FROM logmsgs WHERE message CONTAINS 'failed' AND message CONTAINS 'authentication' GROUP BY username HAVING failures > 10 ORDER BY failures DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Account locked' OR message CONTAINS 'account lockout' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["src_ip", "targeted_accounts", "failure_count", "success_after_failure"],
                "severity_indicators": ["Success after >10 failures from same IP", "Account lockout wave across multiple accounts", ">1000 failures per hour from single source"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1078 Valid Accounts if success found", "T1110.003 Password Spray"],
            },
            "T1110.003": {
                "technique_id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access",
                "description": "One or few common passwords tried against many accounts to avoid lockouts. Particularly effective against organizations with weak password policies.",
                "alertlogic_search_queries": [
                    "SELECT src_ip, COUNT(DISTINCT username) as accounts_targeted FROM logmsgs WHERE message CONTAINS 'failed' AND message CONTAINS 'logon' GROUP BY src_ip HAVING accounts_targeted > 10 ORDER BY accounts_targeted DESC LIMIT 50",
                    "SELECT username, src_ip, datetime FROM logmsgs WHERE message CONTAINS 'failed' AND message CONTAINS 'logon' ORDER BY datetime ASC LIMIT 500",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'password spray' OR (message CONTAINS 'failed' AND message CONTAINS 'logon' AND message CONTAINS 'multiple accounts') ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["src_ip", "accounts_targeted", "password_attempted", "time_window"],
                "severity_indicators": ["Single IP failing against >20 distinct accounts with 1 attempt each", "Failed logons spread evenly across accounts (spray pattern)", "Spray timed to avoid lockout policy (1 attempt per account per 30 min)"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1078 Valid Accounts after successful spray", "Block src_ip and investigate for botnet"],
            },
            "T1528": {
                "technique_id": "T1528", "name": "Steal Application Access Token", "tactic": "Credential Access",
                "description": "Stealing OAuth tokens, SAML assertions, or API keys to access cloud services or applications without credentials. Often follows phishing for OAuth consent.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'oauth' AND message CONTAINS 'token' AND message CONTAINS 'new app' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'consent' AND message CONTAINS 'granted' AND message CONTAINS 'third-party' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["application_id", "scopes_granted", "user_account", "src_ip"],
                "severity_indicators": ["OAuth consent granted to app with Mail.Read and Files.Read scopes", "Token issued to previously unseen application", "API access from unusual IP using valid token"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1567 Exfil to Web Service using token", "Revoke token via identity provider"],
            },
            "T1539": {
                "technique_id": "T1539", "name": "Steal Web Session Cookie", "tactic": "Credential Access",
                "description": "Stealing browser session cookies to bypass MFA and hijack authenticated sessions. Browser stealer malware and adversary-in-the-middle (AiTM) phishing kits are common vectors.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'cookie' AND message CONTAINS 'stolen' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'session hijack' OR message CONTAINS 'impossible travel' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'login' AND message CONTAINS 'new location' AND message CONTAINS 'same session' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["session_id", "original_src_ip", "hijack_src_ip", "account"],
                "severity_indicators": ["Same session token used from two different countries within minutes", "MFA bypassed via session replay", "Browser stealer process accessing cookie database files"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1078 Valid Accounts using hijacked session", "T1566 Phishing (AiTM kit for cookie harvest)"],
            },
            "T1555": {
                "technique_id": "T1555", "name": "Credentials from Password Stores", "tactic": "Credential Access",
                "description": "Extracting credentials from browser password stores, credential managers (Windows Credential Manager, macOS Keychain), or password manager databases.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Login Data' AND message CONTAINS 'Chrome' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Credential Manager' AND message CONTAINS 'access' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'vaultcmd' OR message CONTAINS 'keychainaccess' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["accessed_store", "process_accessing", "hostname", "username"],
                "severity_indicators": ["Non-browser process reading Chrome Login Data SQLite file", "Windows Credential Manager accessed by suspicious process", "Browser password export by unknown tool"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1078 Valid Accounts with harvested creds", "T1021 Lateral Movement"],
            },

            # ── DISCOVERY ─────────────────────────────────────────────────
            "T1082": {
                "technique_id": "T1082", "name": "System Information Discovery", "tactic": "Discovery",
                "description": "Adversaries enumerate OS version, hardware, domain membership, and installed software to plan subsequent attack phases. Often the first activity after initial foothold.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'systeminfo' OR message CONTAINS 'Get-ComputerInfo' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'whoami' OR message CONTAINS 'hostname' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'ipconfig' OR message CONTAINS 'netstat' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["hostname", "username", "commands_run", "source_process"],
                "severity_indicators": ["Rapid succession of recon commands within 60 seconds", "systeminfo + net user + ipconfig run by non-admin", "Recon from suspicious process (e.g., mshta, wscript)"],
                "false_positive_rate": "High",
                "pivot_to": ["T1069 Permission Groups Discovery", "T1016 Network Config Discovery"],
            },
            "T1083": {
                "technique_id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery",
                "description": "Enumerating filesystem structure to find sensitive files (credentials, configs, databases). Often combined with data collection.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'dir /s' OR message CONTAINS 'ls -R' OR message CONTAINS 'Get-ChildItem' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'find' AND (message CONTAINS '.config' OR message CONTAINS '.pem' OR message CONTAINS 'password') ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["search_path", "file_types_sought", "username", "hostname"],
                "severity_indicators": ["Recursive dir search targeting credential or config file paths", "Search for .key, .pem, .pfx files by non-admin", "Bulk file enumeration from sensitive share"],
                "false_positive_rate": "High",
                "pivot_to": ["T1005 Data from Local System", "T1039 Data from Network Share"],
            },
            "T1016": {
                "technique_id": "T1016", "name": "System Network Configuration Discovery", "tactic": "Discovery",
                "description": "Enumerating network configuration to map the environment — IP ranges, routing, DNS servers, proxy settings, ARP tables.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'ipconfig' OR message CONTAINS 'ifconfig' OR message CONTAINS 'ip addr' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'route print' OR message CONTAINS 'netstat -r' OR message CONTAINS 'arp -a' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["commands_run", "hostname", "username"],
                "severity_indicators": ["ipconfig /all + arp -a + route print in rapid succession", "Network recon from newly created account", "Network discovery from web server process"],
                "false_positive_rate": "High",
                "pivot_to": ["T1135 Network Share Discovery", "T1021 Lateral Movement planning"],
            },
            "T1135": {
                "technique_id": "T1135", "name": "Network Share Discovery", "tactic": "Discovery",
                "description": "Enumerating network shares on other hosts to find accessible data stores. Often precedes data collection from network shares.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'net view' OR message CONTAINS 'Get-SmbShare' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'net share' OR message CONTAINS 'showmount' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["src_host", "queried_hosts", "username"],
                "severity_indicators": ["net view /domain scanning all hosts", "Share enumeration from workstation at unusual hour", "SMB share listing against server with sensitive shares"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1039 Data from Network Share", "T1021.002 SMB/Windows Admin Shares"],
            },
            "T1069": {
                "technique_id": "T1069", "name": "Permission Groups Discovery", "tactic": "Discovery",
                "description": "Enumerating local and domain group memberships to identify privileged accounts for targeting in credential theft or lateral movement.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'net group' AND message CONTAINS 'domain admins' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Get-ADGroupMember' OR message CONTAINS 'net localgroup administrators' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["queried_groups", "src_host", "username"],
                "severity_indicators": ["Domain Admins group enumerated from non-admin workstation", "LDAP query for all privileged group members", "Group enumeration preceding credential access activity"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1003 Credential Dumping of identified admin accounts", "T1078 Valid Accounts targeting"],
            },

            # ── LATERAL MOVEMENT ──────────────────────────────────────────
            "T1021": {
                "technique_id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement",
                "description": "Using remote access protocols (RDP, SMB, SSH, WinRM, VNC) to move between systems in the network. Requires valid credentials or pass-the-hash/ticket.",
                "alertlogic_search_queries": [
                    "SELECT src_ip, dst_ip, dst_port, COUNT(*) as connections FROM idsmsgs WHERE dst_port IN (3389, 445, 22, 5985, 5986) GROUP BY src_ip, dst_ip ORDER BY connections DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Logon Type 3' OR message CONTAINS 'Logon Type 10' ORDER BY datetime DESC LIMIT 200",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'psexec' OR message CONTAINS 'PSEXESVC' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list", "assets_get_topology"],
                "ioc_types_to_extract": ["src_host", "dst_host", "protocol", "username", "logon_type"],
                "severity_indicators": ["Workstation-to-workstation RDP (admin should use jump server)", "Network logon with NTLM to multiple hosts in short time", "psexec usage across multiple hosts in succession"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1550 Pass-the-Hash/Ticket", "T1003 Credential Dumping for auth material"],
            },
            "T1021.001": {
                "technique_id": "T1021.001", "name": "Remote Desktop Protocol", "tactic": "Lateral Movement",
                "description": "RDP used for interactive lateral movement. Provides GUI access to target systems. Often used by ransomware operators to manually execute payloads.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Logon Type 10' ORDER BY datetime DESC LIMIT 200",
                    "SELECT src_ip, dst_ip, COUNT(*) as sessions FROM idsmsgs WHERE dst_port = 3389 GROUP BY src_ip, dst_ip ORDER BY sessions DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'TerminalServices' AND message CONTAINS 'logon' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["src_ip", "dst_host", "username", "session_duration"],
                "severity_indicators": ["RDP from server to workstation (reverse direction)", "RDP chain: workstation → server1 → server2 (hop through)"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1086 Ransomware deployment via RDP", "T1003 Credential Dumping on RDP target"],
            },
            "T1021.002": {
                "technique_id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement",
                "description": "Using SMB admin shares (C$, ADMIN$, IPC$) for lateral movement. PsExec, wmic, and manual file copy all use SMB. Logon Type 3 (network) with NTLM.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Logon Type 3' AND message CONTAINS 'NTLMSSP' ORDER BY datetime DESC LIMIT 200",
                    "SELECT src_ip, dst_ip, COUNT(*) as connections FROM idsmsgs WHERE dst_port = 445 GROUP BY src_ip, dst_ip ORDER BY connections DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'ADMIN$' OR message CONTAINS 'C$' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["src_host", "dst_host", "share_accessed", "username"],
                "severity_indicators": ["Access to ADMIN$ or C$ from non-admin workstation", "Rapid SMB connections to many hosts (worm-like spread)", "File copy to ADMIN$ immediately followed by service creation"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1569 System Services for execution via SMB", "T1550.002 Pass-the-Hash"],
            },
            "T1021.004": {
                "technique_id": "T1021.004", "name": "SSH", "tactic": "Lateral Movement",
                "description": "SSH used for lateral movement in Linux/Unix environments. Key-based auth means no password needed if attacker has stolen or planted SSH keys.",
                "alertlogic_search_queries": [
                    "SELECT src_ip, dst_ip, COUNT(*) as sessions FROM idsmsgs WHERE dst_port = 22 GROUP BY src_ip, dst_ip ORDER BY sessions DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'sshd' AND message CONTAINS 'Accepted' ORDER BY datetime DESC LIMIT 200",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'authorized_keys' AND message CONTAINS 'added' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["src_ip", "dst_host", "username", "auth_method"],
                "severity_indicators": ["SSH key auth from new/unknown key fingerprint", "SSH between internal servers not in baseline", "authorized_keys modified before lateral movement begins"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1098 Account Manipulation (new SSH key)", "T1059.004 Unix Shell via SSH"],
            },
            "T1534": {
                "technique_id": "T1534", "name": "Internal Spearphishing", "tactic": "Lateral Movement",
                "description": "Using compromised internal email account to send phishing to other employees, leveraging trust in the sender's identity.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'internal' AND message CONTAINS 'phishing' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'email' AND message CONTAINS 'bulk send' AND message CONTAINS 'internal' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["sender_account", "recipients", "attachment_or_link", "email_subject"],
                "severity_indicators": ["Internal account sending >50 emails in 10 minutes", "Internal email with external phishing link to all staff", "Compromised account sending credential harvest link internally"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1566 Phishing workflow for recipients", "T1078 Valid Accounts (sender is compromised)"],
            },
            "T1550": {
                "technique_id": "T1550", "name": "Use Alternate Authentication Material", "tactic": "Lateral Movement",
                "description": "Using credential artifacts other than passwords — NTLM hashes (pass-the-hash), Kerberos tickets (pass-the-ticket), or web session cookies — to authenticate.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'NtlmSsp' AND message CONTAINS 'Logon' AND message NOT CONTAINS 'password' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Kerberos' AND message CONTAINS 'TGT' AND message CONTAINS 'unusual' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'overpass-the-hash' OR message CONTAINS 'pass-the-ticket' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["auth_type", "src_host", "dst_host", "username"],
                "severity_indicators": ["NTLM auth to many hosts from single workstation rapidly", "Kerberos TGT for account used on host where account never logged on", "Golden/Silver Ticket indicators (anomalous Kerberos ticket lifetime)"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1003 Credential Dumping (how hashes were obtained)", "T1021 Remote Services"],
            },
            "T1563": {
                "technique_id": "T1563", "name": "Remote Service Session Hijacking", "tactic": "Lateral Movement",
                "description": "Hijacking existing remote sessions (RDP, SSH) rather than creating new ones. On Windows, disconnected RDP sessions can be taken over by SYSTEM via tscon.exe.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'tscon' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'session' AND message CONTAINS 'hijack' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'disconnected session' AND message CONTAINS 'taken over' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["session_id", "hijacked_username", "hijacker_process"],
                "severity_indicators": ["tscon.exe executed by non-admin or from unusual process", "Disconnected admin RDP session showing activity with no new logon", "SSH session command injection"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1021.001 RDP", "T1078 Valid Accounts using hijacked session"],
            },

            # ── COLLECTION ────────────────────────────────────────────────
            "T1005": {
                "technique_id": "T1005", "name": "Data from Local System", "tactic": "Collection",
                "description": "Collecting data from the local filesystem — documents, configuration files, credential files, databases. Often staged before exfiltration.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'copy' AND (message CONTAINS '.xlsx' OR message CONTAINS '.docx' OR message CONTAINS '.pdf') ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'file access' AND message CONTAINS 'sensitive' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'compress' AND message CONTAINS 'documents' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["files_accessed", "staging_path", "username", "hostname"],
                "severity_indicators": ["Mass file copy to staging directory", "Bulk read of credential or config files", "Data compression preceding network transfer"],
                "false_positive_rate": "High",
                "pivot_to": ["T1560 Archive Collected Data", "T1041 Exfiltration"],
            },
            "T1039": {
                "technique_id": "T1039", "name": "Data from Network Share", "tactic": "Collection",
                "description": "Collecting data from network-accessible shares. Allows collection across multiple systems without installing tools on each. Bulk SMB reads are detectable.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'net use' AND message CONTAINS 'copy' ORDER BY datetime DESC LIMIT 100",
                    "SELECT src_ip, dst_ip, COUNT(*) as file_ops FROM idsmsgs WHERE dst_port = 445 AND message CONTAINS 'read' GROUP BY src_ip, dst_ip ORDER BY file_ops DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["src_host", "share_path", "files_copied", "username"],
                "severity_indicators": ["Thousands of file reads from share in short period", "Workstation reading from file server via script", "SMB read pattern matching bulk data staging"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1048 Exfiltration", "T1560 Archive Collected Data"],
            },
            "T1119": {
                "technique_id": "T1119", "name": "Automated Collection", "tactic": "Collection",
                "description": "Using scripts or tools to automatically collect and aggregate data across a system or network. Often faster collection than manual and harder to detect.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'robocopy' OR message CONTAINS 'xcopy /s' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'PowerShell' AND message CONTAINS 'Get-ChildItem' AND message CONTAINS 'Copy-Item' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["tool_used", "collection_scope", "staging_location"],
                "severity_indicators": ["robocopy or xcopy of entire share to staging directory", "PowerShell script collecting all files matching *.docx *.xlsx", "Collection speed exceeding human manual operation"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1041 Exfiltration", "T1560 Archive"],
            },
            "T1560": {
                "technique_id": "T1560", "name": "Archive Collected Data", "tactic": "Collection",
                "description": "Compressing and/or encrypting collected data before exfiltration to reduce transfer size and evade content inspection. 7z, zip, rar, tar are common tools.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE (message CONTAINS '7z' OR message CONTAINS 'winrar' OR message CONTAINS 'zip') AND message CONTAINS 'compress' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'tar czf' OR message CONTAINS 'zip -r' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'archive created' AND message CONTAINS 'temp' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["archive_name", "archive_path", "source_data", "archive_tool"],
                "severity_indicators": ["Large archive created in temp or staging directory", "Password-protected archive containing sensitive file types", "Archive created immediately followed by network transfer"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1041 or T1048 Exfiltration", "T1005 Data from Local System (what was archived)"],
            },

            # ── COMMAND AND CONTROL ───────────────────────────────────────
            "T1071": {
                "technique_id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control",
                "description": "Using standard application protocols (HTTP/S, DNS, SMTP, LDAP) for C2 to blend with legitimate traffic and bypass network controls.",
                "alertlogic_search_queries": [
                    "SELECT src_ip, dst_ip, COUNT(*) as connections FROM idsmsgs WHERE dst_port IN (80, 443) GROUP BY src_ip, dst_ip HAVING connections > 100 ORDER BY connections DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'beacon' OR message CONTAINS 'C2 traffic' ORDER BY datetime DESC LIMIT 50",
                    "SELECT src_ip, dst_ip, datetime FROM idsmsgs WHERE dst_ip NOT IN (SELECT ip FROM known_safe_ips) AND dst_port IN (80, 443) ORDER BY datetime DESC LIMIT 200",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list", "watchlist_add_entry"],
                "ioc_types_to_extract": ["c2_ip", "c2_domain", "beacon_interval", "protocol"],
                "severity_indicators": ["Regular interval connections to single IP (beaconing)", "HTTP POST with unusual user-agent to non-CDN IP", "HTTPS to IP address (no SNI/no domain)"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1071.001 HTTP", "T1071.004 DNS", "watchlist_add_entry for C2 IP"],
            },
            "T1071.001": {
                "technique_id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control",
                "description": "HTTP/HTTPS C2 channels. Malware beacons to C2 server mimicking web traffic. Indicators include regular timing, small consistent payload sizes, unusual user-agents.",
                "alertlogic_search_queries": [
                    "SELECT src_ip, dst_ip, COUNT(*) as hits, MIN(datetime) as first, MAX(datetime) as last FROM idsmsgs WHERE dst_port IN (80, 443) GROUP BY src_ip, dst_ip HAVING hits > 50 ORDER BY hits DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'User-Agent' AND (message CONTAINS 'Go-http-client' OR message CONTAINS 'python-requests' OR message CONTAINS 'curl/') ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'HTTPS' AND message CONTAINS 'self-signed' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["c2_ip", "user_agent", "beacon_interval", "payload_size"],
                "severity_indicators": ["Beaconing pattern (regular interval ±jitter)", "HTTPS to IP with self-signed cert", "Anomalous User-Agent from non-browser process"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1573 Encrypted Channel", "T1105 Ingress Tool Transfer via HTTP"],
            },
            "T1071.004": {
                "technique_id": "T1071.004", "name": "DNS", "tactic": "Command and Control",
                "description": "DNS used for C2 — commands encoded in DNS queries/responses, or domain generation algorithms (DGA) for resilient C2. TXT record queries and long subdomain strings are indicators.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'DNS' AND LENGTH(message) > 150 ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'TXT record' AND message CONTAINS 'DNS' ORDER BY datetime DESC LIMIT 50",
                    "SELECT message, COUNT(*) as nxdomain_count FROM logmsgs WHERE message CONTAINS 'NXDOMAIN' GROUP BY message HAVING nxdomain_count > 20 ORDER BY nxdomain_count DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["queried_domain", "query_type", "response", "src_host"],
                "severity_indicators": ["Long DNS subdomains (>30 chars) suggesting data encoding", "High NXDOMAIN rate suggesting DGA enumeration", "DNS TXT record queries to non-standard domains"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1048 Exfiltration over DNS", "Decode subdomain data for embedded commands/data"],
            },
            "T1095": {
                "technique_id": "T1095", "name": "Non-Application Layer Protocol", "tactic": "Command and Control",
                "description": "Using raw TCP/UDP, ICMP, or custom protocols for C2 to evade application-layer inspection. ICMP tunneling and raw socket communication are examples.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM idsmsgs WHERE message CONTAINS 'ICMP tunnel' OR message CONTAINS 'non-standard protocol' ORDER BY datetime DESC LIMIT 50",
                    "SELECT src_ip, dst_ip, COUNT(*) as packets FROM idsmsgs WHERE message CONTAINS 'ICMP' GROUP BY src_ip, dst_ip HAVING packets > 100 ORDER BY packets DESC LIMIT 50",
                    "SELECT src_ip, dst_ip, COUNT(*) as connections FROM idsmsgs WHERE dst_port NOT IN (80, 443, 22, 25, 53, 3389) GROUP BY src_ip, dst_ip ORDER BY connections DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["protocol", "src_ip", "dst_ip", "payload_size"],
                "severity_indicators": ["ICMP echo requests with large or variable payload sizes", "Custom port usage with regular beaconing pattern", "Raw TCP to unusual port with encoded data"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1071 Application Layer Protocol (fallback channel)", "T1572 Protocol Tunneling"],
            },
            "T1105": {
                "technique_id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control",
                "description": "Downloading attacker tools (additional malware, exploitation tools, utilities) from external sources to the compromised host.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE (message CONTAINS 'DownloadFile' OR message CONTAINS 'wget' OR message CONTAINS 'curl') AND message CONTAINS 'external' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'certutil' AND message CONTAINS 'urlcache' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'bitsadmin' AND message CONTAINS 'transfer' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["download_url", "local_save_path", "process_name", "file_hash"],
                "severity_indicators": ["certutil.exe used to download file from internet", "bitsadmin downloading executable from external IP", "PowerShell downloading .exe or .dll to temp directory"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1059 Execution of downloaded tool", "T1036 Masquerading of downloaded binary"],
            },
            "T1573": {
                "technique_id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control",
                "description": "Using encryption to protect C2 communications from inspection. TLS (HTTPS) is most common. Custom symmetric encryption is used by advanced actors.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM idsmsgs WHERE message CONTAINS 'suspicious TLS' OR message CONTAINS 'self-signed certificate' ORDER BY datetime DESC LIMIT 100",
                    "SELECT src_ip, dst_ip, COUNT(*) as sessions FROM idsmsgs WHERE dst_port = 443 AND message CONTAINS 'cert' GROUP BY src_ip, dst_ip ORDER BY sessions DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["c2_ip", "certificate_fingerprint", "cipher_suite", "ja3_hash"],
                "severity_indicators": ["Self-signed certificate on C2 server", "JA3/JA3S hash matching known C2 framework", "TLS to IP without SNI extension from non-browser process"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1071.001 Web Protocols", "JA3 hash lookup against threat intel"],
            },
            "T1572": {
                "technique_id": "T1572", "name": "Protocol Tunneling", "tactic": "Command and Control",
                "description": "Encapsulating C2 traffic inside legitimate protocols (SSH, DNS, HTTP) to bypass firewalls. Tools like iodine (DNS tunnel), Chisel (HTTP tunnel), and plink are commonly used.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'iodine' OR message CONTAINS 'dns2tcp' OR message CONTAINS 'dnscat' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'chisel' OR message CONTAINS 'ngrok' OR message CONTAINS 'frp' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'plink' AND message CONTAINS '-R' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["tunnel_tool", "tunnel_endpoint", "forwarded_port"],
                "severity_indicators": ["ngrok, chisel, or frp binary executed on server", "plink.exe used with -R flag to expose internal port externally", "DNS query volume 10x baseline from single host"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1071 C2 traffic over tunnel", "T1048 Exfiltration via tunnel"],
            },
            "T1102": {
                "technique_id": "T1102", "name": "Web Service", "tactic": "Command and Control",
                "description": "Using legitimate web services (Pastebin, GitHub, Discord, Telegram) as C2 channels or dead-drop resolvers to blend with normal traffic.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'pastebin.com' AND message NOT CONTAINS 'browser' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'raw.githubusercontent.com' AND message CONTAINS 'powershell' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'api.telegram.org' OR message CONTAINS 'discord.com/api' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["service_domain", "url_path", "process_name", "src_ip"],
                "severity_indicators": ["Non-browser process polling pastebin.com at fixed interval", "Telegram Bot API called by script or binary", "discord.com/api/webhooks called by non-user process"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1071.001 HTTP C2", "T1041 Exfil over C2 channel"],
            },

            # ── EXFILTRATION ──────────────────────────────────────────────
            "T1048": {
                "technique_id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration",
                "description": "Exfiltrating data via protocols other than HTTP/C2 — DNS, FTP, SFTP, ICMP, email — to bypass egress filters. DNS exfiltration encodes data in subdomains.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'DNS' AND message CONTAINS 'exfil' ORDER BY datetime DESC LIMIT 50",
                    "SELECT src_ip, dst_ip, COUNT(*) as transfers FROM idsmsgs WHERE dst_port = 21 GROUP BY src_ip, dst_ip ORDER BY transfers DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'smtp' AND message CONTAINS 'attachment' AND message CONTAINS 'external' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["dst_ip", "protocol", "bytes_transferred", "domain"],
                "severity_indicators": ["FTP to external IP from internal host", "DNS queries with base64-encoded subdomains", "Outbound SMTP with large attachment from workstation"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1560 Archive Collected Data (what was sent)", "Block protocol at perimeter"],
            },
            "T1041": {
                "technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration",
                "description": "Exfiltrating data using the same C2 channel (HTTP/S POST). Large upload spikes following collection activity are key indicators.",
                "alertlogic_search_queries": [
                    "SELECT src_ip, dst_ip, SUM(bytes_sent) as total_upload FROM idsmsgs WHERE dst_ip IN ('<c2_ips>') GROUP BY src_ip, dst_ip ORDER BY total_upload DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'HTTP POST' AND message CONTAINS 'large body' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM idsmsgs WHERE message CONTAINS 'data exfiltration' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["c2_ip", "bytes_uploaded", "upload_time", "src_host"],
                "severity_indicators": ["HTTP POST upload >50MB to C2 host", "Outbound HTTPS volume 10x baseline from compromised host", "Upload immediately after archive creation"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1048 Alt protocol if HTTP blocked", "T1560 Archive for staging evidence"],
            },
            "T1567": {
                "technique_id": "T1567", "name": "Exfiltration to Cloud Storage", "tactic": "Exfiltration",
                "description": "Exfiltrating data to legitimate cloud storage (Dropbox, Google Drive, OneDrive, Box, Mega) to blend with normal business traffic and avoid DLP.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'dropbox.com' AND message CONTAINS 'upload' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'drive.google.com' AND message CONTAINS 'PUT' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'mega.nz' OR message CONTAINS 'anonfiles' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["cloud_service", "bytes_uploaded", "process_name", "src_ip"],
                "severity_indicators": ["Non-browser process uploading to cloud storage API", "curl/PowerShell uploading to Dropbox API", "Upload to anonymous file sharing site"],
                "false_positive_rate": "Medium",
                "pivot_to": ["T1048 Alt protocol if cloud blocked", "Notify legal if data volume suggests PII breach"],
            },
            "T1030": {
                "technique_id": "T1030", "name": "Data Transfer Size Limits", "tactic": "Exfiltration",
                "description": "Chunking exfiltration transfers to stay below DLP thresholds. Data sent in small pieces over extended time. Aggregate volume analysis required for detection.",
                "alertlogic_search_queries": [
                    "SELECT src_ip, dst_ip, COUNT(*) as transfer_count, SUM(bytes_sent) as total_bytes FROM idsmsgs WHERE dst_ip NOT IN (SELECT ip FROM known_safe_ips) GROUP BY src_ip, dst_ip HAVING total_bytes > 100000000 ORDER BY total_bytes DESC LIMIT 20",
                    "SELECT source, message, datetime FROM idsmsgs WHERE message CONTAINS 'chunked transfer' AND message CONTAINS 'external' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["dst_ip", "chunk_size", "transfer_count", "total_bytes_aggregated"],
                "severity_indicators": ["Repeated fixed-size transfers to same destination sustained over hours", "Cumulative upload >500MB via small increments", "Transfer pattern just below DLP threshold repeatedly"],
                "false_positive_rate": "High",
                "pivot_to": ["T1041 Exfil over C2", "T1567 Exfil to cloud storage"],
            },

            # ── IMPACT ────────────────────────────────────────────────────
            "T1486": {
                "technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact",
                "description": "Ransomware encrypts files to deny access and extort victims. Always preceded by shadow copy deletion and often by defense evasion. Any VSS deletion is a critical-priority precursor.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'vssadmin delete shadows' OR message CONTAINS 'wbadmin delete' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS '.encrypted' OR message CONTAINS '.locked' OR message CONTAINS 'DECRYPT' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, COUNT(*) as rename_count FROM logmsgs WHERE message CONTAINS 'rename' GROUP BY source HAVING rename_count > 100 ORDER BY rename_count DESC LIMIT 20",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'README' AND (message CONTAINS 'DECRYPT' OR message CONTAINS 'RECOVER') ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list", "incidents_get_elaborations"],
                "ioc_types_to_extract": ["patient_zero_host", "ransom_extension", "ransom_note_path", "scope_of_hosts"],
                "severity_indicators": ["vssadmin delete shadows — ALL shadow copies destroyed", "Mass file rename events (thousands per minute)", "Ransom note creation in multiple directories", "VSS deletion by non-admin process"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1490 Inhibit System Recovery", "T1562.001 AV disabled (precursor)", "IMMEDIATE: isolate all affected hosts"],
            },
            "T1490": {
                "technique_id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact",
                "description": "Deleting VSS shadow copies, backup catalogs, and boot recovery data before ransomware execution. Any shadow copy deletion is a critical immediate escalation trigger.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'vssadmin' AND message CONTAINS 'delete' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'bcdedit' AND message CONTAINS 'recoveryenabled' ORDER BY datetime DESC LIMIT 50",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'wbadmin delete catalog' OR message CONTAINS 'wmic shadowcopy delete' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["hostname", "command_executed", "username"],
                "severity_indicators": ["vssadmin delete shadows /all /quiet", "bcdedit /set {default} recoveryenabled No", "wbadmin delete catalog -quiet", "wmic shadowcopy delete"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1486 Ransomware encryption (imminent)", "IMMEDIATE: isolate host and protect backups"],
            },
            "T1489": {
                "technique_id": "T1489", "name": "Service Stop", "tactic": "Impact",
                "description": "Stopping database, backup, AV, and security services before ransomware execution to release file locks and disable protection.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'net stop' AND (message CONTAINS 'sql' OR message CONTAINS 'backup' OR message CONTAINS 'veeam') ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'sc stop' OR (message CONTAINS 'taskkill' AND message CONTAINS '/f') ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'service stopped' AND message CONTAINS 'backup' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["stopped_services", "hostname", "username", "command_line"],
                "severity_indicators": ["Batch service stop (SQL + backup + AV in sequence)", "Veeam or Windows Backup service stopped outside maintenance", "More than 5 services killed in 60 seconds by same process"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1486 Ransomware (imminent after service stop)", "T1490 Shadow copy deletion"],
            },
            "T1498": {
                "technique_id": "T1498", "name": "Network Denial of Service", "tactic": "Impact",
                "description": "Volumetric or protocol-based DDoS attacks against target networks. Detection relies on traffic volume anomalies and IDS signatures.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM idsmsgs WHERE message CONTAINS 'DDoS' OR message CONTAINS 'flood attack' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM idsmsgs WHERE message CONTAINS 'SYN flood' OR message CONTAINS 'UDP flood' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM idsmsgs WHERE message CONTAINS 'amplification attack' OR message CONTAINS 'reflection attack' ORDER BY datetime DESC LIMIT 100",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["attack_type", "src_ips", "dst_ip", "pps_rate", "bps_rate"],
                "severity_indicators": ["Inbound volume 10x baseline from distributed IPs", "SYN flood: high incomplete TCP handshake rate", "DNS/NTP amplification from internal misconfig"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1491 Defacement (often combined)", "Engage upstream ISP for scrubbing"],
            },
            "T1491": {
                "technique_id": "T1491", "name": "Defacement", "tactic": "Impact",
                "description": "Modifying website or system content to send a message or damage reputation. Detection focuses on unexpected webroot file changes and file integrity alerts.",
                "alertlogic_search_queries": [
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'index.html' AND message CONTAINS 'modified' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'webroot' AND message CONTAINS 'file changed' ORDER BY datetime DESC LIMIT 100",
                    "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'HTTP PUT' AND message CONTAINS 'webroot' ORDER BY datetime DESC LIMIT 50",
                ],
                "alertlogic_tools": ["search_submit", "incidents_list"],
                "ioc_types_to_extract": ["modified_file", "attacker_ip", "server_hostname", "modification_time"],
                "severity_indicators": ["index.html replaced outside deployment window", "Web file modified by process other than deployment agent", "HTTP PUT to webroot from external IP"],
                "false_positive_rate": "Low",
                "pivot_to": ["T1505.003 Web Shell (how attacker accessed server)", "T1190 Exploit (initial access)"],
            },
        }

        tid = technique_id.strip().upper()
        technique_data = techniques.get(tid)
        if technique_data is None:
            parent_id = tid.split(".")[0]
            technique_data = techniques.get(parent_id)
        if technique_data is not None:
            return {
                "guide": technique_data,
                "meta": {
                    "tool": "soc_mitre_attack_guide",
                    "technique_id": technique_id,
                    "note": "Use alertlogic_search_queries with search_submit. Poll with search_status, retrieve with search_results, release with search_release."
                }
            }
        return {
            "error": "Technique not in database",
            "technique_id": technique_id,
            "covered_techniques": sorted(techniques.keys()),
            "hint": "Try the parent technique ID (e.g., 'T1059' instead of 'T1059.007') or call soc_alertlogic_tool_guide for general investigation guidance."
        }

    # ------------------------------------------------------------------
    # Tool 4: soc_alertlogic_tool_guide
    # ------------------------------------------------------------------

    def soc_alertlogic_tool_guide(
        self,
        category: Annotated[
            Literal["incidents", "search_logs", "assets", "vulnerabilities", "soar", "all"],
            Field(description="Category of AlertLogic tools to get guidance for")
        ],
    ) -> dict:
        """Return a categorized reference guide to AlertLogic MCP tools for SOC use cases."""

        guides = {
            "incidents": {
                "category": "Incidents",
                "description": "Tools for managing and investigating AlertLogic-generated security incidents",
                "tools": {
                    "incidents_list": {
                        "what_it_does": "Retrieve a paginated list of incidents with filtering. The primary triage starting point.",
                        "when_to_use": ["Start of any investigation to find related incidents", "Threat hunting to find existing detections for a technique", "Periodic review of open/unresolved incidents"],
                        "key_parameters": {
                            "threat_level": "Filter by Low/Medium/High/Critical — always set to High,Critical for triage",
                            "status": "open/closed/investigating — use 'open' for active triage",
                            "attackers": "IP address to find all incidents from a specific attacker",
                            "victims": "Hostname/IP to find all incidents affecting a specific asset",
                            "start_time/end_time": "Epoch seconds — required for time-bounded searches"
                        },
                        "key_output_fields": {
                            "incidentId": "UUID — use for subsequent incidents_get, incidents_get_elaborations calls",
                            "threatLevel": "Low/Medium/High/Critical — SLA driver",
                            "summary": "Human-readable description of what AlertLogic detected",
                            "attackerList": "List of source IPs or attacker indicators",
                            "victimList": "List of affected hosts/IPs",
                            "incident_attack_summary.techniques": "MITRE ATT&CK technique IDs"
                        },
                        "gotchas": [
                            "Default limit is 25 — always set limit=100 for comprehensive triage",
                            "Timestamps are epoch seconds, not ISO 8601",
                            "attackerList may contain internal IPs for post-compromise lateral movement detections"
                        ]
                    },
                    "incidents_get": {
                        "what_it_does": "Get full details for a single incident by ID. Use after incidents_list to drill into a specific incident.",
                        "when_to_use": ["After identifying an incident ID from incidents_list", "When you need full incident context before searching logs"],
                        "key_parameters": {"incidentId": "UUID from incidents_list output"},
                        "key_output_fields": {
                            "summary": "Detection description",
                            "incident_attack_summary": "Full MITRE mapping and kill chain stage",
                            "attackerList / victimList": "IOCs for pivoting",
                            "recommendations": "AlertLogic's suggested response actions"
                        },
                        "gotchas": ["Always call this before incidents_get_elaborations to understand context first"]
                    },
                    "incidents_get_elaborations": {
                        "what_it_does": "Retrieve the raw log lines or IDS events that triggered the detection. The forensic evidence behind the incident.",
                        "when_to_use": ["After incidents_get to see exact attack payload", "When you need the specific log lines for IOC extraction", "Before submitting a search to understand what fields are available"],
                        "key_parameters": {"incidentId": "UUID"},
                        "key_output_fields": {
                            "elaborations": "Array of raw log events",
                            "message": "Full log line text",
                            "datetime": "Exact event timestamp",
                            "source": "Originating host"
                        },
                        "gotchas": [
                            "May return large payloads for high-volume detections — focus on first/last few elaborations",
                            "Elaborations are the ground truth — always check before concluding false positive"
                        ]
                    },
                    "incidents_get_notes": {
                        "what_it_does": "Retrieve analyst notes attached to an incident.",
                        "when_to_use": ["Check if another analyst has already investigated", "Review investigation history before starting fresh analysis"],
                        "key_parameters": {"incidentId": "UUID"},
                        "gotchas": ["Notes are freeform — quality varies by analyst"]
                    },
                    "incidents_add_note": {
                        "what_it_does": "Add an analyst note to an incident for investigation tracking.",
                        "when_to_use": ["Document findings during investigation", "Record IOCs found, containment steps taken, tickets created"],
                        "key_parameters": {"incidentId": "UUID", "note": "Markdown text — include timestamp, IOCs, actions taken"},
                        "gotchas": ["Notes are permanent — write clearly and include context"]
                    },
                    "incidents_list_partner": {
                        "what_it_does": "List incidents across managed accounts (MSSP use case).",
                        "when_to_use": ["Cross-tenant incident review in MSSP context", "Identifying attack campaigns targeting multiple customers"],
                        "gotchas": ["Requires MSSP-level permissions. Never mix tenant data in analysis."]
                    },
                    "incidents_list_filters": {
                        "what_it_does": "Get available filter options for incidents_list (valid threat levels, statuses, types).",
                        "when_to_use": ["Before constructing complex incidents_list queries", "Discovering available incident types for a deployment"],
                        "gotchas": []
                    }
                }
            },
            "search_logs": {
                "category": "Search / Logs",
                "description": "AL-SQL based log search against logmsgs (syslog/agent) and idsmsgs (network IDS) tables",
                "tools": {
                    "search_submit": {
                        "what_it_does": "Submit an AL-SQL query for async execution. Returns a search UUID for polling.",
                        "when_to_use": ["Any time you need to search historical logs", "Threat hunting queries", "IOC pivoting across all logs"],
                        "key_parameters": {
                            "sql": "AL-SQL string — use SELECT source, message, datetime FROM logmsgs WHERE ...",
                            "start_time": "Epoch seconds (e.g., int(time.time()) - 604800 for 7 days ago). Required.",
                            "end_time": "Epoch seconds. Defaults to now if omitted.",
                            "search_type": "'batch' (default), 'interactive' (faster, shorter timeout), 'report'"
                        },
                        "key_output_fields": {"uuid": "Search ID — use with search_status and search_results"},
                        "gotchas": [
                            "MAX 7-day time window per query — chain queries for longer periods",
                            "start_time/end_time are epoch seconds NOT ISO 8601",
                            "Always release searches with search_release after retrieving results to free server resources",
                            "logmsgs = syslog/agent logs; idsmsgs = network IDS alerts",
                            "CONTAINS is case-insensitive substring match; use for most text searches",
                            "GROUP BY requires that non-aggregated SELECT columns are in GROUP BY",
                            "No JOINs across tables — run separate queries and correlate manually"
                        ],
                        "example_queries": [
                            "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'failed' ORDER BY datetime DESC LIMIT 100",
                            "SELECT source, message, datetime FROM idsmsgs WHERE src_ip = '10.1.2.3' ORDER BY datetime DESC LIMIT 100",
                            "SELECT src_ip, COUNT(*) as hits FROM logmsgs WHERE message CONTAINS 'error' GROUP BY src_ip ORDER BY hits DESC LIMIT 20"
                        ]
                    },
                    "search_status": {
                        "what_it_does": "Poll the status of a running search. Call repeatedly until status is 'complete' or 'suspended'.",
                        "when_to_use": ["After search_submit to check completion before calling search_results"],
                        "key_parameters": {"uuid": "From search_submit response"},
                        "key_output_fields": {
                            "status": "'running', 'complete', 'suspended', 'failed'",
                            "progress": "0-100 percent complete"
                        },
                        "gotchas": ["Poll every 2-5 seconds — avoid hammering the API", "'suspended' means partial results available — use search_complete to force finish or retrieve partial results"]
                    },
                    "search_results": {
                        "what_it_does": "Retrieve the results of a completed search.",
                        "when_to_use": ["After search_status returns 'complete'"],
                        "key_parameters": {"uuid": "From search_submit"},
                        "key_output_fields": {"results": "Array of rows matching your query"},
                        "gotchas": ["Results are only available while search is not released — call search_release after you have the data you need"]
                    },
                    "search_release": {
                        "what_it_does": "Cancel and free server resources for a search. Always call after retrieving results.",
                        "when_to_use": ["After retrieving results with search_results", "To cancel a long-running search you no longer need"],
                        "gotchas": ["Failing to release searches accumulates resource quota — always release"]
                    },
                    "search_validate": {
                        "what_it_does": "Validate AL-SQL syntax without running a search. Use for query development.",
                        "when_to_use": ["Before submitting complex queries to catch syntax errors early"],
                        "gotchas": ["Validates syntax only — does not validate field names or data existence"]
                    },
                    "search_get_grammar": {
                        "what_it_does": "Fetch the complete AL-SQL grammar reference with all supported functions, keywords, and operators.",
                        "when_to_use": ["When building complex queries", "To discover supported aggregation functions"],
                        "gotchas": []
                    },
                    "search_convert_from_v1": {
                        "what_it_does": "Convert a legacy v1 search query to v2 AL-SQL syntax.",
                        "when_to_use": ["When migrating old saved searches to new format"],
                        "gotchas": []
                    }
                }
            },
            "assets": {
                "category": "Assets",
                "description": "Tools for querying the AlertLogic asset inventory — hosts, networks, deployments, topology",
                "tools": {
                    "assets_query": {
                        "what_it_does": "Query assets by type and filter criteria. Translates hostnames/IPs to asset records with metadata.",
                        "when_to_use": ["Convert a victim IP/hostname to an AlertLogic asset record", "List all hosts in a subnet", "Find assets by tag or deployment"],
                        "key_parameters": {
                            "asset_type": "host, network, subnet, vpc, region, external-ip, appliance",
                            "filters": "Key:value filter pairs (e.g., 'tag:production')",
                            "query": "Search term for hostname or IP"
                        },
                        "key_output_fields": {
                            "key": "Asset key (e.g., /aws/us-east-1/host/i-abc123) — use for assets_get_details",
                            "name": "Hostname or resource name",
                            "type": "Asset type",
                            "deployment_id": "Which deployment this asset belongs to"
                        },
                        "gotchas": [
                            "Asset keys contain slashes — must URL-encode when used in API paths",
                            "Returns current state only — no historical asset inventory"
                        ]
                    },
                    "assets_get_topology": {
                        "what_it_does": "Get network topology map showing how assets are connected — VPCs, subnets, hosts.",
                        "when_to_use": ["Understanding network segmentation", "Identifying if compromised hosts span segments", "Mapping east-west movement blast radius"],
                        "gotchas": ["Large environments may return truncated topology — filter by deployment"]
                    },
                    "assets_query_all": {
                        "what_it_does": "Paginated query of all assets of a given type.",
                        "when_to_use": ["Full asset inventory export", "Building a complete host list for a hunt"],
                        "gotchas": ["Can be slow for large deployments — use pagination parameters"]
                    },
                    "assets_find": {
                        "what_it_does": "Find assets by specific search criteria (hostname, IP, tag).",
                        "when_to_use": ["Quick lookup of a specific host by IP or hostname"],
                        "gotchas": []
                    },
                    "assets_get_details": {
                        "what_it_does": "Get full details for a specific asset by its key.",
                        "when_to_use": ["After getting asset key from assets_query to retrieve full metadata"],
                        "key_parameters": {"asset_key": "URL-encoded asset key from assets_query"},
                        "gotchas": ["Asset key must be URL-encoded including the leading slash"]
                    },
                    "assets_get_exposures_post": {
                        "what_it_does": "Get all vulnerability exposures for a specific asset.",
                        "when_to_use": ["Check if an asset being attacked has known vulnerabilities", "Confirm exploitability of CVE being used in attack"],
                        "key_output_fields": {
                            "exposures": "List of CVEs with CVSS scores",
                            "remediation_id": "Link to remediation guidance"
                        },
                        "gotchas": ["Only shows vulnerabilities from most recent scan — may not be current"]
                    }
                }
            },
            "vulnerabilities": {
                "category": "Vulnerabilities",
                "description": "Vulnerability exposure management, remediation tracking, and risk scoring",
                "tools": {
                    "vuln_list_exposures": {
                        "what_it_does": "List vulnerability exposures across the deployment with filtering by severity, asset, or CVE.",
                        "when_to_use": ["Assess vulnerability posture after identifying attacked asset", "Find all assets affected by a specific CVE", "Pre-hunt vulnerability baseline"],
                        "key_parameters": {
                            "asset_type": "Filter by asset type",
                            "severity": "info/low/medium/high/critical",
                            "cve_id": "Filter by specific CVE"
                        },
                        "gotchas": ["Based on last scan results — may lag behind actual patch state by days/weeks"]
                    },
                    "remediations_get_risk_summary": {
                        "what_it_does": "Get risk score summary for the account — overall vulnerability risk posture.",
                        "when_to_use": ["Executive reporting", "Before/after patching to measure improvement"],
                        "gotchas": []
                    },
                    "remediations_get_health_by_type": {
                        "what_it_does": "Get collection health metrics by deployment type to verify scanning coverage.",
                        "when_to_use": ["Verify that hosts are being scanned before concluding 'no vulnerabilities'", "Troubleshoot scan coverage gaps"],
                        "gotchas": ["A host not appearing in vuln results may mean it was never scanned, not that it's clean"]
                    },
                    "remediations_list_items": {
                        "what_it_does": "List open remediation items (grouped vulnerabilities requiring action).",
                        "when_to_use": ["Prioritizing patching work", "Finding all assets needing a specific patch"],
                        "gotchas": []
                    },
                    "remediations_get_item": {
                        "what_it_does": "Get detailed remediation guidance for a specific remediation item.",
                        "when_to_use": ["After identifying a vulnerability being exploited — get patch/mitigation steps"],
                        "gotchas": []
                    },
                    "vuln_kb_get": {
                        "what_it_does": "Get knowledge base entry for a CVE — description, CVSS score, exploit availability, affected software.",
                        "when_to_use": ["Understanding a CVE being exploited in an incident", "Assessing exploitability before escalating"],
                        "key_parameters": {"cve_id": "e.g., 'CVE-2021-44228'"},
                        "gotchas": ["KB may not have entries for very new CVEs"]
                    },
                    "remediations_conclude": {
                        "what_it_does": "Mark a remediation item as completed.",
                        "when_to_use": ["After confirming a patch has been applied"],
                        "gotchas": ["Verify patch actually applied before concluding — do not close prematurely"]
                    },
                    "remediations_dispose": {
                        "what_it_does": "Disposition a remediation item as accepted risk or false positive.",
                        "when_to_use": ["Risk acceptance for vulnerabilities that cannot be patched", "Marking scanner false positives"],
                        "gotchas": ["Requires justification — document reason clearly for audit trail"]
                    }
                }
            },
            "soar": {
                "category": "SOAR / Tickets / Watchlist",
                "description": "Automated response playbooks, action execution, watchlist management, and ticket tracking",
                "tools": {
                    "responder_list_playbooks": {
                        "what_it_does": "List available SOAR playbooks for automated response actions.",
                        "when_to_use": ["Find available automated response actions for an incident type", "Discover what automation is available before manual investigation"],
                        "gotchas": ["Playbook availability depends on deployment configuration and integrations"]
                    },
                    "responder_list_actions": {
                        "what_it_does": "List available SOAR response actions (block IP, isolate host, reset password, etc.).",
                        "when_to_use": ["After confirming a threat — identify available response actions", "During containment phase"],
                        "gotchas": ["Actions have impact — confirm intent before executing. Some actions are irreversible."]
                    },
                    "responder_list_inquiries": {
                        "what_it_does": "List pending SOAR inquiries requiring analyst input to proceed.",
                        "when_to_use": ["Check for pending automated actions awaiting approval", "Review SOAR workflow checkpoints"],
                        "gotchas": []
                    },
                    "responder_query_executions": {
                        "what_it_does": "Query history of SOAR playbook executions.",
                        "when_to_use": ["Audit what automated responses have already fired", "Check if automated containment has already occurred"],
                        "gotchas": []
                    },
                    "watchlist_list_entries": {
                        "what_it_does": "List all IOCs in the watchlist (IPs, domains, etc.) being monitored for alerts.",
                        "when_to_use": ["Check if a suspicious IP is already being watched", "Review current threat indicators being tracked"],
                        "gotchas": []
                    },
                    "watchlist_add_entry": {
                        "what_it_does": "Add an IOC to the watchlist for ongoing monitoring and alerting.",
                        "when_to_use": ["After confirming a malicious IP/domain — add for continuous monitoring", "Tracking attacker infrastructure across incidents"],
                        "key_parameters": {
                            "entry_type": "ip, domain, hostname, url",
                            "value": "The IOC value",
                            "reason": "Why this was added — include incident ID"
                        },
                        "gotchas": ["Always include reason with incident ID for audit trail", "Watchlist entries generate ongoing alerts — only add confirmed malicious indicators"]
                    },
                    "watchlist_delete_entry": {
                        "what_it_does": "Remove an IOC from the watchlist.",
                        "when_to_use": ["After false positive confirmation", "When attacker infrastructure is taken down and no longer active"],
                        "gotchas": []
                    },
                    "ticket_list": {
                        "what_it_does": "List tickets created in AlertLogic for incident tracking.",
                        "when_to_use": ["Check if a ticket already exists for an incident", "Review open tickets for a customer"],
                        "gotchas": []
                    },
                    "ticket_create": {
                        "what_it_does": "Create a ticket to track an incident, finding, or customer notification.",
                        "when_to_use": ["When a confirmed incident requires customer notification", "Tracking remediation work", "Escalations that need manager visibility"],
                        "key_parameters": {
                            "summary": "Short clear title including asset and incident type",
                            "description": "Full findings: IOCs, timeline, impact, recommended actions",
                            "severity": "Low/Medium/High/Critical — should match incident threatLevel"
                        },
                        "gotchas": ["Include all IOCs and evidence in description — this is the customer-facing record"]
                    },
                    "suggestions_v2_list": {
                        "what_it_does": "List AlertLogic recommendations for tuning, improvements, or actions.",
                        "when_to_use": ["Periodic review of AlertLogic recommendations", "Before closing an investigation to check for related suggestions"],
                        "gotchas": []
                    },
                    "informant_get_account_messages": {
                        "what_it_does": "Get account-level informational messages from AlertLogic (service notices, configuration warnings).",
                        "when_to_use": ["Check for any AlertLogic service issues that might affect investigation", "Review configuration warnings"],
                        "gotchas": []
                    },
                    "informant_get_deployment_messages": {
                        "what_it_does": "Get deployment-specific messages from AlertLogic.",
                        "when_to_use": ["Check deployment health before concluding log gaps are suspicious"],
                        "gotchas": ["Log gaps that appear suspicious may be caused by deployment connectivity issues — always check here first"]
                    },
                    "aetuner_list_analytics": {
                        "what_it_does": "List AlertLogic analytics (detection rules) available for the account.",
                        "when_to_use": ["Understanding what detection coverage exists", "Finding which analytic triggered an incident"],
                        "gotchas": []
                    },
                    "aetuner_get_analytic": {
                        "what_it_does": "Get details of a specific detection analytic.",
                        "when_to_use": ["Understanding detection logic behind an incident", "Tuning false positives"],
                        "gotchas": []
                    },
                    "aecontent_list_analytics": {
                        "what_it_does": "List available analytics content including threat detection rules.",
                        "when_to_use": ["Discovery of available detection capabilities", "Mapping detection coverage to MITRE ATT&CK"],
                        "gotchas": []
                    },
                    "exclusions_list": {
                        "what_it_does": "List network or asset exclusions from scanning/monitoring.",
                        "when_to_use": ["Verify an attacking IP is not an excluded scanner before escalating", "Review monitoring gaps"],
                        "gotchas": ["Always check this before concluding an alert from a legitimate scanner is malicious"]
                    },
                    "whitelist_list_hosts": {
                        "what_it_does": "List whitelisted hosts excluded from IDS alerting.",
                        "when_to_use": ["Check if attacking IP is a known scanner (Qualys, Rapid7, Tenable)", "Investigating IDS alerts that may be authorized scanning"],
                        "gotchas": ["Whitelisted scanner IPs should not generate incidents — if they do, investigate why"]
                    }
                }
            }
        }

        if category == "all":
            return {
                "guide": {cat: data for cat, data in guides.items()},
                "meta": {"tool": "soc_alertlogic_tool_guide", "category": "all"}
            }

        guide_data = guides.get(category)
        if not guide_data:
            return {
                "error": f"Unknown category: {category}",
                "available_categories": list(guides.keys())
            }

        return {
            "guide": guide_data,
            "meta": {"tool": "soc_alertlogic_tool_guide", "category": category}
        }

    # ------------------------------------------------------------------
    # Tool 5: soc_log_query_templates
    # ------------------------------------------------------------------

    def soc_log_query_templates(
        self,
        activity_type: Annotated[
            Literal[
                "authentication", "privilege_escalation", "lateral_movement",
                "c2_communication", "exfiltration", "malware_execution",
                "persistence", "reconnaissance", "web_attacks", "insider_threat"
            ],
            Field(description="Activity type to get AL-SQL query templates for")
        ],
    ) -> dict:
        """Return 5-8 ready-to-use AL-SQL query templates for the specified activity type."""

        templates = {
            "authentication": {
                "activity_type": "authentication",
                "description": "Queries for investigating authentication events — successful logons, failures, account lockouts, and anomalous access patterns",
                "queries": [
                    {
                        "name": "Failed logon count by source IP",
                        "sql": "SELECT src_ip, COUNT(*) as failure_count FROM logmsgs WHERE message CONTAINS 'failed' AND (message CONTAINS 'logon' OR message CONTAINS 'authentication') GROUP BY src_ip HAVING failure_count > 10 ORDER BY failure_count DESC LIMIT 50",
                        "purpose": "Identify brute force sources — any IP with >10 failures is suspicious"
                    },
                    {
                        "name": "Successful logons after failures (possible compromise)",
                        "sql": "SELECT source, username, src_ip, message, datetime FROM logmsgs WHERE message CONTAINS 'success' AND (message CONTAINS 'logon' OR message CONTAINS 'authentication') ORDER BY datetime DESC LIMIT 200",
                        "purpose": "Correlate with failure query — an IP that failed then succeeded is a key indicator"
                    },
                    {
                        "name": "Account lockouts",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'account locked' OR message CONTAINS 'account lockout' OR message CONTAINS 'locked out' ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Lockout wave across multiple accounts = password spray"
                    },
                    {
                        "name": "After-hours logons (midnight to 6am)",
                        "sql": "SELECT source, username, src_ip, datetime FROM logmsgs WHERE message CONTAINS 'logon' AND message CONTAINS 'success' AND (datetime LIKE '%T00:%' OR datetime LIKE '%T01:%' OR datetime LIKE '%T02:%' OR datetime LIKE '%T03:%' OR datetime LIKE '%T04:%' OR datetime LIKE '%T05:%') ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Legitimate users rarely log in between midnight and 6am — any hit warrants review"
                    },
                    {
                        "name": "Single account logging on from multiple source IPs",
                        "sql": "SELECT username, COUNT(DISTINCT src_ip) as source_count FROM logmsgs WHERE message CONTAINS 'logon' AND message CONTAINS 'success' GROUP BY username HAVING source_count > 3 ORDER BY source_count DESC LIMIT 30",
                        "purpose": "Account used from >3 IPs may indicate credential sharing, VPN pool, or compromise"
                    },
                    {
                        "name": "Service account interactive logon (anomalous)",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Logon Type 2' AND username CONTAINS 'svc' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "Service accounts should never have interactive logons (Type 2 = console)"
                    },
                    {
                        "name": "Kerberos authentication events",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Kerberos' AND (message CONTAINS 'TGT' OR message CONTAINS 'TGS') ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Baseline normal Kerberos activity; anomalies suggest pass-the-ticket or golden ticket"
                    },
                    {
                        "name": "Failed SSH authentication by source",
                        "sql": "SELECT src_ip, COUNT(*) as attempts FROM logmsgs WHERE message CONTAINS 'sshd' AND (message CONTAINS 'Failed' OR message CONTAINS 'Invalid') GROUP BY src_ip HAVING attempts > 5 ORDER BY attempts DESC LIMIT 50",
                        "purpose": "SSH brute force sources — block IPs with high failure counts"
                    }
                ],
                "field_reference": {
                    "logon_types": "Type 2=Interactive/console, Type 3=Network/SMB, Type 7=Unlock, Type 10=RemoteInteractive/RDP, Type 11=CachedInteractive"
                }
            },
            "privilege_escalation": {
                "activity_type": "privilege_escalation",
                "description": "Queries for detecting privilege escalation — UAC bypass, sudo abuse, SUID execution, token manipulation, exploit attempts",
                "queries": [
                    {
                        "name": "UAC bypass attempts",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'UAC' AND (message CONTAINS 'bypass' OR message CONTAINS 'elevated') ORDER BY datetime DESC LIMIT 100",
                        "purpose": "UAC bypass is a prerequisite for many Windows privilege escalation paths"
                    },
                    {
                        "name": "Sudo usage on Linux systems",
                        "sql": "SELECT source, username, message, datetime FROM logmsgs WHERE message CONTAINS 'sudo' ORDER BY datetime DESC LIMIT 200",
                        "purpose": "Review sudo usage — unexpected accounts or commands are suspicious"
                    },
                    {
                        "name": "SUID binary execution (Linux PrivEsc)",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'SUID' OR (message CONTAINS 'setuid' AND message CONTAINS 'executed') ORDER BY datetime DESC LIMIT 50",
                        "purpose": "SUID binaries used in privilege escalation exploits"
                    },
                    {
                        "name": "SeDebugPrivilege or high-privilege token grants",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'SeDebugPrivilege' OR message CONTAINS 'SeTakeOwnershipPrivilege' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "SeDebugPrivilege enables LSASS access — granted only to admins normally"
                    },
                    {
                        "name": "Token impersonation events",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'impersonate' OR message CONTAINS 'ImpersonateLoggedOnUser' OR message CONTAINS 'DuplicateToken' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "Token impersonation is the mechanism for privilege escalation via T1134"
                    },
                    {
                        "name": "New user added to privileged group",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'added to group' AND (message CONTAINS 'admin' OR message CONTAINS 'root' OR message CONTAINS 'sudo') ORDER BY datetime DESC LIMIT 50",
                        "purpose": "Unauthorized addition to admin group is a critical escalation indicator"
                    },
                    {
                        "name": "Exploit tool patterns",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE (message CONTAINS 'PrintNightmare' OR message CONTAINS 'CVE-' OR message CONTAINS 'exploit') AND message CONTAINS 'privilege' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "Known exploit tool signatures in logs"
                    }
                ]
            },
            "lateral_movement": {
                "activity_type": "lateral_movement",
                "description": "Queries for detecting attacker movement between systems — RDP, SMB, WMI, SSH, PsExec, and credential reuse",
                "queries": [
                    {
                        "name": "Network logons (SMB/lateral movement indicator)",
                        "sql": "SELECT source, username, src_ip, datetime FROM logmsgs WHERE message CONTAINS 'Logon Type 3' ORDER BY datetime DESC LIMIT 200",
                        "purpose": "Type 3 (network) logons across many hosts from single source = lateral movement"
                    },
                    {
                        "name": "RDP sessions (remote interactive logons)",
                        "sql": "SELECT source, username, src_ip, datetime FROM logmsgs WHERE message CONTAINS 'Logon Type 10' ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Type 10 = RDP or remote interactive — workstation-to-workstation is unusual"
                    },
                    {
                        "name": "PsExec service creation (remote execution)",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'PSEXESVC' OR message CONTAINS 'psexec' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "PsExec creates PSEXESVC service on target — high-confidence lateral movement"
                    },
                    {
                        "name": "WMI remote execution",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'wmic' AND message CONTAINS 'node:' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "wmic /node: syntax indicates remote WMI execution"
                    },
                    {
                        "name": "SSH connections between internal hosts",
                        "sql": "SELECT src_ip, dst_ip, COUNT(*) as connections FROM idsmsgs WHERE dst_port = 22 AND src_ip LIKE '10.%' AND dst_ip LIKE '10.%' GROUP BY src_ip, dst_ip ORDER BY connections DESC LIMIT 50",
                        "purpose": "Internal SSH between servers — unexpected paths indicate lateral movement"
                    },
                    {
                        "name": "Admin share access (C$, ADMIN$)",
                        "sql": "SELECT source, username, message, datetime FROM logmsgs WHERE message CONTAINS 'ADMIN$' OR message CONTAINS 'C$' OR message CONTAINS 'IPC$' ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Admin share access is used for file staging and remote execution in lateral movement"
                    },
                    {
                        "name": "Compromised account used on multiple hosts",
                        "sql": "SELECT source, username, datetime FROM logmsgs WHERE username = '<compromised_account>' AND message CONTAINS 'logon' ORDER BY datetime ASC LIMIT 500",
                        "purpose": "Full timeline of where this account authenticated — map the movement chain"
                    },
                    {
                        "name": "Pass-the-hash indicator (NTLM from unusual host)",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'NtlmSsp' AND message CONTAINS 'Logon' ORDER BY datetime DESC LIMIT 100",
                        "purpose": "NTLM auth without prior credential entry may indicate pass-the-hash"
                    }
                ]
            },
            "c2_communication": {
                "activity_type": "c2_communication",
                "description": "Queries for detecting command and control channels — beaconing, DNS C2, unusual outbound connections",
                "queries": [
                    {
                        "name": "Beaconing pattern (high-frequency connections to single external IP)",
                        "sql": "SELECT src_ip, dst_ip, COUNT(*) as connection_count, MIN(datetime) as first_seen, MAX(datetime) as last_seen FROM idsmsgs WHERE dst_ip NOT LIKE '10.%' AND dst_ip NOT LIKE '172.16.%' AND dst_ip NOT LIKE '192.168.%' GROUP BY src_ip, dst_ip HAVING connection_count > 50 ORDER BY connection_count DESC LIMIT 30",
                        "purpose": "High connection count to single external IP = beaconing. Cobalt Strike default: ~60s interval."
                    },
                    {
                        "name": "Connections on non-standard ports",
                        "sql": "SELECT src_ip, dst_ip, dst_port, COUNT(*) as connections FROM idsmsgs WHERE dst_port NOT IN (80, 443, 8080, 8443, 22, 25, 53, 110, 143, 993, 995, 3389) AND dst_ip NOT LIKE '10.%' GROUP BY src_ip, dst_ip, dst_port ORDER BY connections DESC LIMIT 50",
                        "purpose": "C2 on unusual ports to avoid standard firewall rules"
                    },
                    {
                        "name": "DNS beaconing / DGA detection (high NXDOMAIN rate)",
                        "sql": "SELECT source, message, COUNT(*) as nxdomain_count FROM logmsgs WHERE message CONTAINS 'NXDOMAIN' GROUP BY source, message HAVING nxdomain_count > 5 ORDER BY nxdomain_count DESC LIMIT 50",
                        "purpose": "DGA malware tries many random domains — most return NXDOMAIN. High NXDOMAIN rate = DGA."
                    },
                    {
                        "name": "DNS TXT record queries (DNS C2 data channel)",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'TXT' AND message CONTAINS 'DNS' ORDER BY datetime DESC LIMIT 100",
                        "purpose": "DNS TXT records used to embed commands in C2 over DNS"
                    },
                    {
                        "name": "Suspicious User-Agent strings from non-browser processes",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'User-Agent' AND (message CONTAINS 'Go-http-client' OR message CONTAINS 'python-requests' OR message CONTAINS 'curl/' OR message CONTAINS 'libwww-perl') ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Automated C2 tools often use default HTTP library user-agents"
                    },
                    {
                        "name": "HTTPS connections to IP addresses (no domain/SNI)",
                        "sql": "SELECT source, message, datetime FROM idsmsgs WHERE dst_port = 443 AND message CONTAINS 'no SNI' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "Legitimate HTTPS almost always has a domain name; IP-only HTTPS = likely C2"
                    },
                    {
                        "name": "All hosts talking to a known C2 IP",
                        "sql": "SELECT src_ip, COUNT(*) as connections, MIN(datetime) as first_seen FROM idsmsgs WHERE dst_ip = '<c2_ip>' GROUP BY src_ip ORDER BY connections DESC",
                        "purpose": "Scope the infection — all hosts connecting to C2 are compromised"
                    }
                ]
            },
            "exfiltration": {
                "activity_type": "exfiltration",
                "description": "Queries for detecting data theft — large outbound transfers, archive creation, cloud storage uploads, DNS exfil",
                "queries": [
                    {
                        "name": "Large outbound transfers to external IPs",
                        "sql": "SELECT src_ip, dst_ip, SUM(bytes_sent) as total_bytes FROM idsmsgs WHERE dst_ip NOT LIKE '10.%' AND dst_ip NOT LIKE '172.16.%' AND dst_ip NOT LIKE '192.168.%' GROUP BY src_ip, dst_ip ORDER BY total_bytes DESC LIMIT 20",
                        "purpose": "Top outbound data volumes — anomalous destinations with high volumes = exfil"
                    },
                    {
                        "name": "File compression/archiving activity",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS '7z' OR message CONTAINS 'winrar' OR (message CONTAINS 'zip' AND message CONTAINS 'compress') ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Data staging before exfil — archive in temp directory is suspicious"
                    },
                    {
                        "name": "Cloud storage uploads from non-browser processes",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE (message CONTAINS 'dropbox' OR message CONTAINS 'drive.google' OR message CONTAINS 'onedrive' OR message CONTAINS 'mega.nz') AND message CONTAINS 'upload' ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Exfil to cloud storage blends with legitimate traffic — process context is key"
                    },
                    {
                        "name": "FTP/SFTP outbound connections",
                        "sql": "SELECT src_ip, dst_ip, dst_port, datetime FROM idsmsgs WHERE dst_port IN (21, 22) AND dst_ip NOT LIKE '10.%' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "Outbound FTP to unexpected external IP = likely exfiltration channel"
                    },
                    {
                        "name": "DNS query length anomaly (DNS exfil)",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'DNS' AND LENGTH(message) > 200 ORDER BY datetime DESC LIMIT 100",
                        "purpose": "DNS exfil encodes data in long subdomain queries — long DNS messages = suspicious"
                    },
                    {
                        "name": "Outbound SMTP with large attachments (email exfil)",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'smtp' AND message CONTAINS 'attachment' AND message CONTAINS 'external' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "Email exfiltration sends data as attachments to external addresses"
                    },
                    {
                        "name": "Bulk file copy to external destination",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE (message CONTAINS 'robocopy' OR message CONTAINS 'xcopy') AND message CONTAINS 'external' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "Automated bulk file transfer tools used for staging or direct exfil"
                    }
                ]
            },
            "malware_execution": {
                "activity_type": "malware_execution",
                "description": "Queries for detecting malware execution — suspicious process chains, script execution, encoded commands, in-memory execution",
                "queries": [
                    {
                        "name": "PowerShell encoded command execution",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'powershell' AND (message CONTAINS '-enc' OR message CONTAINS '-EncodedCommand') ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Encoded PowerShell is the most common malware delivery mechanism — any hit is high priority"
                    },
                    {
                        "name": "Office application spawning shell processes",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE (message CONTAINS 'winword' OR message CONTAINS 'excel' OR message CONTAINS 'outlook') AND (message CONTAINS 'cmd.exe' OR message CONTAINS 'powershell' OR message CONTAINS 'wscript') ORDER BY datetime DESC LIMIT 50",
                        "purpose": "Office spawning cmd/PowerShell = macro malware execution"
                    },
                    {
                        "name": "Script execution from temp directories",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE (message CONTAINS '%TEMP%' OR message CONTAINS 'AppData\\\\Local\\\\Temp' OR message CONTAINS '/tmp/') AND (message CONTAINS '.exe' OR message CONTAINS '.ps1' OR message CONTAINS '.vbs') ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Malware typically executes from temp directories — legitimate software rarely does"
                    },
                    {
                        "name": "Certutil download cradle (LOLBin abuse)",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'certutil' AND (message CONTAINS 'urlcache' OR message CONTAINS '-decode') ORDER BY datetime DESC LIMIT 50",
                        "purpose": "certutil.exe abused to download malware and decode base64 payloads"
                    },
                    {
                        "name": "Rundll32 executing unusual DLLs",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'rundll32' AND message NOT CONTAINS 'System32' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "rundll32 executing DLLs from non-system paths = malware"
                    },
                    {
                        "name": "MSHTA executing remote scripts",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'mshta' AND message CONTAINS 'http' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "mshta.exe fetching remote HTA scripts = fileless malware staging"
                    },
                    {
                        "name": "Regsvr32 executing remote code (Squiblydoo)",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'regsvr32' AND (message CONTAINS 'http' OR message CONTAINS 'scrobj') ORDER BY datetime DESC LIMIT 50",
                        "purpose": "regsvr32 /s /u /i:http:// scrobj.dll = Squiblydoo AppLocker bypass"
                    },
                    {
                        "name": "New executable dropped in suspicious location",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'created' AND (message CONTAINS '.exe' OR message CONTAINS '.dll') AND (message CONTAINS 'Temp' OR message CONTAINS 'AppData' OR message CONTAINS 'Downloads') ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Executable dropped in user-writable directories = malware staging"
                    }
                ]
            },
            "persistence": {
                "activity_type": "persistence",
                "description": "Queries for detecting persistence mechanisms — registry keys, scheduled tasks, services, startup folders, web shells, cron jobs",
                "queries": [
                    {
                        "name": "Registry Run key modifications",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'CurrentVersion\\\\Run' ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Run/RunOnce registry keys are the most common Windows persistence mechanism"
                    },
                    {
                        "name": "Scheduled task creation",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'schtasks' AND message CONTAINS '/create' ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Task creation by non-admin account or executing from temp directory is suspicious"
                    },
                    {
                        "name": "New service installation",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE (message CONTAINS 'sc create' OR message CONTAINS 'service installed') ORDER BY datetime DESC LIMIT 50",
                        "purpose": "New service installations outside change management windows are suspicious"
                    },
                    {
                        "name": "Startup folder file creation",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'Startup' AND message CONTAINS 'created' AND message CONTAINS '.lnk' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "Files in startup folder execute at user logon — LNK files in startup = persistence"
                    },
                    {
                        "name": "Crontab modification (Linux persistence)",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'crontab' ORDER BY datetime DESC LIMIT 100",
                        "purpose": "crontab modifications for persistent task execution on Linux"
                    },
                    {
                        "name": "WMI event subscription (fileless persistence)",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS '__EventFilter' OR message CONTAINS 'CommandLineEventConsumer' OR message CONTAINS 'ActiveScriptEventConsumer' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "WMI subscriptions survive reboots and are difficult to detect — fileless persistence"
                    },
                    {
                        "name": "New web shell file created in webroot",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'webroot' AND message CONTAINS 'created' AND (message CONTAINS '.php' OR message CONTAINS '.asp' OR message CONTAINS '.jsp') ORDER BY datetime DESC LIMIT 50",
                        "purpose": "Script files created in web directories by non-deployment process = web shell"
                    }
                ]
            },
            "reconnaissance": {
                "activity_type": "reconnaissance",
                "description": "Queries for detecting internal reconnaissance — network scanning, host enumeration, share discovery, user/group enumeration",
                "queries": [
                    {
                        "name": "Internal network scanning (many hosts, few ports)",
                        "sql": "SELECT src_ip, COUNT(DISTINCT dst_ip) as hosts_scanned FROM idsmsgs WHERE src_ip LIKE '10.%' GROUP BY src_ip HAVING hosts_scanned > 20 ORDER BY hosts_scanned DESC LIMIT 20",
                        "purpose": "Internal host scanning many distinct IPs = reconnaissance or worm"
                    },
                    {
                        "name": "Port scanning (single host, many ports)",
                        "sql": "SELECT src_ip, dst_ip, COUNT(DISTINCT dst_port) as ports_scanned FROM idsmsgs WHERE src_ip LIKE '10.%' GROUP BY src_ip, dst_ip HAVING ports_scanned > 20 ORDER BY ports_scanned DESC LIMIT 20",
                        "purpose": "Many distinct ports to single host = port scan"
                    },
                    {
                        "name": "System information gathering commands",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'systeminfo' OR message CONTAINS 'whoami /all' OR (message CONTAINS 'ipconfig' AND message CONTAINS '/all') ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Rapid-fire recon commands within minutes = attacker orientation after initial access"
                    },
                    {
                        "name": "Domain and group enumeration",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE (message CONTAINS 'net group' AND message CONTAINS 'domain') OR message CONTAINS 'Get-ADGroupMember' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "Enumerating domain groups (especially Domain Admins) for targeting"
                    },
                    {
                        "name": "Network share discovery",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'net view' OR message CONTAINS 'Get-SmbShare' ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Share enumeration to find data stores for collection"
                    },
                    {
                        "name": "LDAP queries for user/computer enumeration",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'LDAP' AND (message CONTAINS 'samAccountName' OR message CONTAINS 'objectClass=user') ORDER BY datetime DESC LIMIT 50",
                        "purpose": "LDAP enumeration of all users/computers from workstation = AD recon tool"
                    },
                    {
                        "name": "ARP scan / neighbor discovery",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'arp-scan' OR (message CONTAINS 'arp' AND message CONTAINS 'scan') ORDER BY datetime DESC LIMIT 50",
                        "purpose": "ARP scanning reveals all live hosts on subnet without generating ICMP"
                    }
                ]
            },
            "web_attacks": {
                "activity_type": "web_attacks",
                "description": "Queries for detecting web application attacks — SQLi, XSS, path traversal, command injection, web shell activity",
                "queries": [
                    {
                        "name": "SQL injection attempts",
                        "sql": "SELECT source, message, datetime FROM idsmsgs WHERE message CONTAINS 'SQL injection' OR message CONTAINS 'sqli' OR message CONTAINS 'union select' ORDER BY datetime DESC LIMIT 100",
                        "purpose": "IDS SQLi signatures — combine with web server log analysis"
                    },
                    {
                        "name": "Path traversal attempts",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS '../' OR message CONTAINS '%2e%2e%2f' OR message CONTAINS '..%2f' OR message CONTAINS 'etc/passwd' ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Directory traversal attempts against web applications"
                    },
                    {
                        "name": "Command injection indicators in HTTP requests",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'cmd=' OR (message CONTAINS 'exec(' AND message CONTAINS 'http') OR message CONTAINS ';cat ' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "Command injection payloads in HTTP parameters"
                    },
                    {
                        "name": "Successful 200 responses to attack payloads",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE (message CONTAINS '../' OR message CONTAINS 'union select' OR message CONTAINS 'exec(') AND message CONTAINS ' 200 ' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "HTTP 200 response to attack payload = likely successful exploitation"
                    },
                    {
                        "name": "Web scanner user-agent strings",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'User-Agent' AND (message CONTAINS 'sqlmap' OR message CONTAINS 'nikto' OR message CONTAINS 'nessus' OR message CONTAINS 'burp') ORDER BY datetime DESC LIMIT 50",
                        "purpose": "Known web scanner signatures — confirm if authorized scan or unauthorized attack"
                    },
                    {
                        "name": "Web shell execution (POST to script files)",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'POST' AND (message CONTAINS '.php' OR message CONTAINS '.asp') AND message CONTAINS 'cmd' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "POST requests executing commands via web shell"
                    },
                    {
                        "name": "Large number of 4xx errors from single IP (scanning)",
                        "sql": "SELECT src_ip, COUNT(*) as error_count FROM logmsgs WHERE message CONTAINS '404' OR message CONTAINS '403' GROUP BY src_ip HAVING error_count > 50 ORDER BY error_count DESC LIMIT 20",
                        "purpose": "High 404/403 rate from single IP = directory/file enumeration"
                    },
                    {
                        "name": "XXE or SSRF payload indicators",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE message CONTAINS 'SYSTEM' AND message CONTAINS 'DOCTYPE' OR message CONTAINS 'file:///' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "XXE payloads in XML-accepting endpoints or SSRF attempts"
                    }
                ]
            },
            "insider_threat": {
                "activity_type": "insider_threat",
                "description": "Queries for detecting insider threat activity — bulk data access, after-hours activity, unauthorized system access, data staging",
                "queries": [
                    {
                        "name": "User activity volume baseline (current vs historical)",
                        "sql": "SELECT username, COUNT(*) as event_count, MIN(datetime) as first_event, MAX(datetime) as last_event FROM logmsgs WHERE username = '<suspect_user>' ORDER BY event_count DESC LIMIT 1",
                        "purpose": "Establish activity baseline for the suspect user before anomaly hunting"
                    },
                    {
                        "name": "After-hours system access by specific user",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE username = '<suspect_user>' AND (datetime LIKE '%T00:%' OR datetime LIKE '%T01:%' OR datetime LIKE '%T02:%' OR datetime LIKE '%T03:%' OR datetime LIKE '%T04:%' OR datetime LIKE '%T05:%') ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Legitimate employees rarely access systems in the early hours"
                    },
                    {
                        "name": "Bulk file access or download events",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE username = '<suspect_user>' AND (message CONTAINS 'file' OR message CONTAINS 'download' OR message CONTAINS 'copy' OR message CONTAINS 'read') ORDER BY datetime DESC LIMIT 300",
                        "purpose": "Volume of file access — compare to baseline to identify bulk collection"
                    },
                    {
                        "name": "Access to sensitive systems not normally accessed",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE username = '<suspect_user>' AND source IN ('<sensitive_servers>') ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Access to HR, Finance, or IP systems by user without business need"
                    },
                    {
                        "name": "Data upload to personal cloud services",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE username = '<suspect_user>' AND (message CONTAINS 'gmail' OR message CONTAINS 'yahoo' OR message CONTAINS 'dropbox' OR message CONTAINS 'wetransfer' OR message CONTAINS 'personal') ORDER BY datetime DESC LIMIT 100",
                        "purpose": "Personal webmail/cloud storage access from corporate network for data exfil"
                    },
                    {
                        "name": "USB or removable media usage",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE username = '<suspect_user>' AND (message CONTAINS 'removable' OR message CONTAINS 'USB' OR message CONTAINS 'external drive') ORDER BY datetime DESC LIMIT 50",
                        "purpose": "Removable media is a classic data exfiltration channel for insiders"
                    },
                    {
                        "name": "Printing sensitive documents",
                        "sql": "SELECT source, message, datetime FROM logmsgs WHERE username = '<suspect_user>' AND message CONTAINS 'print' ORDER BY datetime DESC LIMIT 50",
                        "purpose": "High print volume of sensitive documents can indicate physical data theft"
                    }
                ],
                "important_note": "Do NOT alert the subject during insider threat investigation. Preserve all logs. Coordinate with HR/Legal before any account action."
            }
        }

        data = templates.get(activity_type)
        if not data:
            return {"error": f"Unknown activity_type: {activity_type}", "available": list(templates.keys())}

        return {
            "playbook": data,
            "meta": {
                "tool": "soc_log_query_templates",
                "activity_type": activity_type,
                "usage": "Paste SQL into search_submit. Replace <placeholders> with actual values. Set start_time/end_time as epoch seconds. Max 7-day window per query.",
                "search_workflow": "search_submit → search_status (poll) → search_results → search_release"
            }
        }

    # ------------------------------------------------------------------
    # Tool 6: soc_incident_severity_guide
    # ------------------------------------------------------------------

    def soc_incident_severity_guide(self) -> dict:
        """Return AlertLogic incident severity levels, SLA targets, escalation thresholds, and MSSP notification guidance."""
        return {
            "guide": {
                "title": "AlertLogic Incident Severity Guide for MSSP Operations",
                "severity_levels": {
                    "Critical": {
                        "alertlogic_threat_level": "Critical",
                        "description": "Active high-impact attack confirmed or near-certain. Examples: confirmed ransomware, active data exfiltration, domain controller compromise, active C2 on critical asset.",
                        "mssp_sla": {
                            "initial_triage": "15 minutes from detection",
                            "customer_notification": "30 minutes from detection",
                            "containment_recommendation": "1 hour from detection",
                            "escalation_path": "SOC Lead → CISO/Account Manager → Customer CISO immediately"
                        },
                        "auto_escalation_triggers": [
                            "Ransomware encryption activity detected (vssadmin delete + mass file rename)",
                            "Domain Controller compromise (DA account used from anomalous host)",
                            "Active exfiltration of >1GB confirmed",
                            "Destructive malware (wiper) signatures",
                            "Cloud account root/admin compromise",
                            "Critical infrastructure asset compromise (OT/ICS)",
                            "Confirmed breach of PII/PHI/PCI data"
                        ],
                        "customer_notification_required": True,
                        "regulatory_notification_potential": True,
                        "analyst_actions": [
                            "Immediately call customer security contact — do not rely on email alone",
                            "Open P1 ticket and alert SOC Lead simultaneously",
                            "Begin incident documentation in real-time",
                            "Coordinate containment with customer before implementing to avoid disruption"
                        ]
                    },
                    "High": {
                        "alertlogic_threat_level": "High",
                        "description": "Serious attack with significant risk of impact. Examples: confirmed lateral movement, credential dumping on servers, web shell active, suspicious admin account usage.",
                        "mssp_sla": {
                            "initial_triage": "30 minutes from detection",
                            "customer_notification": "2 hours from detection (or sooner if escalating to Critical)",
                            "containment_recommendation": "4 hours from detection",
                            "escalation_path": "SOC Analyst → SOC Lead (auto-escalate if no response in 15min)"
                        },
                        "auto_escalation_triggers": [
                            "High-severity incident with no analyst action in 30 minutes",
                            "High incident count on single customer in 1 hour (attack campaign)",
                            "High incident involving privileged account (admin, svc account with broad access)",
                            "High incident + open Critical CVE on affected host",
                            "Lateral movement confirmed across >3 hosts",
                            "High incident outside business hours with no on-call response"
                        ],
                        "customer_notification_required": True,
                        "regulatory_notification_potential": False,
                        "analyst_actions": [
                            "Triage within 30 minutes",
                            "Pull elaborations and perform initial IOC analysis",
                            "Notify customer via ticket + email",
                            "Escalate to Critical if exploitation confirmed during investigation"
                        ]
                    },
                    "Medium": {
                        "alertlogic_threat_level": "Medium",
                        "description": "Moderate risk requiring investigation. Examples: brute force with no success, reconnaissance scanning, suspicious script execution, policy violations.",
                        "mssp_sla": {
                            "initial_triage": "4 hours from detection",
                            "customer_notification": "Next business day (or sooner if escalating)",
                            "containment_recommendation": "24 hours from detection",
                            "escalation_path": "SOC Analyst → Standard queue. Escalate to High if evidence of success."
                        },
                        "auto_escalation_triggers": [
                            "Brute force with subsequent successful logon from same IP",
                            "Recon activity followed by exploitation attempt within 24h",
                            "Medium incident count >10 on same host in 1 hour",
                            "Medium incident involving previously whitelisted/known-good source that is no longer expected"
                        ],
                        "customer_notification_required": False,
                        "regulatory_notification_potential": False,
                        "analyst_actions": [
                            "Triage during current shift",
                            "Determine if false positive or true positive",
                            "Document analysis in incident notes",
                            "Escalate to High if evidence of actual compromise found"
                        ]
                    },
                    "Low": {
                        "alertlogic_threat_level": "Low",
                        "description": "Informational or low-risk activity. Examples: vulnerability scan findings, policy violations, single failed logon, informational IDS signatures.",
                        "mssp_sla": {
                            "initial_triage": "24 hours from detection",
                            "customer_notification": "Weekly summary report",
                            "containment_recommendation": "Best effort / next scheduled maintenance",
                            "escalation_path": "SOC Analyst → Queue. Escalate only if context changes."
                        },
                        "auto_escalation_triggers": [
                            "Low incident volume spike (>50 in 1 hour from same source) — may indicate automated attack",
                            "Low incident from previously escalated IOC (attacker reuse)"
                        ],
                        "customer_notification_required": False,
                        "regulatory_notification_potential": False,
                        "analyst_actions": [
                            "Review during next available shift slot",
                            "Batch similar low-severity incidents into summary",
                            "Close as false positive with note if confirmed benign"
                        ]
                    }
                },
                "escalation_matrix": {
                    "severity_escalation_path": "Low → Medium → High → Critical",
                    "escalation_conditions": {
                        "Low_to_Medium": ["Confirmed true positive", "More than 10 events in 1 hour", "IOC match with threat intel"],
                        "Medium_to_High": ["Evidence of successful exploitation", "Privileged account involved", "Multiple hosts affected"],
                        "High_to_Critical": ["Confirmed data exfiltration", "Domain admin compromised", "Ransomware precursors (VSS delete, mass encryption)", "Active ongoing attack"]
                    }
                },
                "mssp_special_considerations": {
                    "tenant_isolation": "NEVER share customer IOCs or incident details across tenant boundaries. Each customer's incidents must be handled in isolation.",
                    "data_residency": "AlertLogic data is region-specific. US-2 data stays in US-2 context. EU-1 data stays in EU-1 context.",
                    "customer_contact_hierarchy": [
                        "Primary security contact (SOC/CISO)",
                        "Secondary security contact (backup)",
                        "Account manager (for business escalations)",
                        "Incident response retainer (if customer has one)"
                    ],
                    "regulatory_notification_thresholds": {
                        "GDPR": "72 hours from awareness of breach affecting EU personal data",
                        "HIPAA": "60 days from discovery for covered entities; breaches >500 records require HHS notification",
                        "PCI_DSS": "Immediately notify acquiring bank and card brands upon compromise",
                        "US_State_Laws": "Varies by state (30-90 days typically) — consult legal when PII breach confirmed"
                    }
                },
                "false_positive_handling": {
                    "process": [
                        "1. Document why the incident is a false positive in incident notes",
                        "2. Close incident with status 'false_positive' and reason code",
                        "3. If recurring FP — create exclusion via exclusions_list / whitelist review",
                        "4. If systemic FP (many customers seeing same FP) — escalate to SecEng for analytic tuning via aetuner_get_analytic"
                    ],
                    "common_false_positives": [
                        "Authorized vulnerability scanners (Qualys, Rapid7, Tenable) — verify against whitelist_list_hosts",
                        "IT admin running legitimate recon/audit tools — verify with customer",
                        "Pentest activity — customer should notify in advance",
                        "Backup software accessing files in bulk — resembles collection/exfil",
                        "Security tools scanning their own infrastructure"
                    ]
                },
                "alertlogic_specific_notes": {
                    "incident_sources": {
                        "IDS": "Network-based detection from AlertLogic appliances. Fast but can have false positives for legitimate scanners.",
                        "Log_Analytics": "Log-based detections from AlertLogic analytics engine. Generally higher fidelity — log context is rich.",
                        "User_Reported": "Incidents created by customers or analysts manually. Vary in quality."
                    },
                    "incident_status_lifecycle": "open → investigating → remediation → closed",
                    "search_time_limits": "AlertLogic search max 7-day window. Chain searches for longer periods.",
                    "log_retention": "Default 12 months. Confirm customer retention policy for forensic timelines."
                }
            },
            "meta": {"tool": "soc_incident_severity_guide"}
        }


def setup(server: FastMCP):
    mod = SocPlaybooksModule()
    mod.register_tools(server)
