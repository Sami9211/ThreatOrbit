'use client'

import { useState, useMemo, useEffect, useCallback, useRef, type ReactNode } from 'react'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Activity, Search, ChevronDown, X, Shield,
  User, Server, Terminal, Zap, Eye,
  BarChart2, Database, CheckCircle, 
  ArrowUpRight, 
  Network, FileText, Copy, 
  RefreshCw, Lock, Gauge, Loader2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import ReportButton from '@/components/dashboard/ReportButton'
import AnimatedNumber from '@/components/dashboard/AnimatedNumber'
import { Skeleton, SkeletonRows } from '@/components/dashboard/Skeleton'
import SavedViewsButton from '@/components/dashboard/SavedViewsButton'
import { useWindowedRows } from '@/lib/useWindowedRows'
import { useExperienceMode } from '@/lib/useExperienceMode'
import { fetchSiemAlerts, fetchSiemKpis, fetchCorrelations, fetchMitreDistribution, fetchSiemTrends, fetchEntityDetail, patchAlert, createCase, createSuppression, fetchPlaybooks, runPlaybook, fetchAlertFpAssessment, fetchFpTriage, bulkDismissAlerts, type SiemKpis, type Correlation, type FpAssessment, type FpTriageAlert, type SiemTrendDay, type EntityDetail } from '@/lib/api'
import { fadeInUp, listContainer, listItem } from '@/lib/motion'
import { tk } from '@/lib/colors'

/* -- Types ---------------------------------------------------------- */
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
type AlertStatus = 'new' | 'assigned' | 'in-progress' | 'pending' | 'resolved' | 'closed'
type Disposition = 'undetermined' | 'true-positive' | 'false-positive' | 'benign' | 'duplicate'

/* Responsive grid for the alert queue. MITRE/Entity/Status columns drop out below
   md/lg/sm; their fixed tracks must drop with them or the remaining cells shift
   into the wrong tracks and the row overflows. Track count tracks visible cells. */
const ALERT_GRID =
  'grid gap-3 items-center ' +
  'grid-cols-[16px_minmax(0,1fr)_auto_auto] ' +              // mobile: dot Alert Risk Time
  'sm:grid-cols-[16px_1fr_60px_80px_80px] ' +                 // +Status
  'md:grid-cols-[16px_1fr_80px_60px_80px_80px] ' +            // +MITRE
  'lg:grid-cols-[16px_1fr_80px_100px_60px_80px_80px]'         // +Entity

type SiemAlert = {
  id: string
  ts: string
  title: string
  severity: Severity
  status: AlertStatus
  disposition: Disposition
  owner: string | null
  riskScore: number
  ruleId: string
  ruleName: string
  mitreTactic: string
  mitreTacticId: string
  mitreTech: string
  mitreTechId: string
  srcIp: string
  srcCountry: string
  srcPort: number
  srcHostname: string
  srcAsn: string
  destIp: string
  destPort: number
  destService: string
  username: string | null
  hostname: string | null
  hostCriticality: 'critical' | 'high' | 'medium' | 'low'
  processName: string | null
  cmdLine: string | null
  description: string
  rawLog: string
  eventCount: number
  tiHits: number
  bytesOut: number
}

/* -- Static alert dataset ------------------------------------------- */
const ALERTS: SiemAlert[] = [
  {
    id: 'a001', ts: '2024-11-12T14:22:00Z',
    title: 'Ransomware file encryption pattern detected - mass rename activity',
    severity: 'critical', status: 'in-progress', disposition: 'true-positive', owner: 'j.chen',
    riskScore: 98,
    ruleId: 'EDR-9001', ruleName: 'Ransomware File Encryption Indicator',
    mitreTactic: 'Impact', mitreTacticId: 'TA0040',
    mitreTech: 'Data Encrypted for Impact', mitreTechId: 'T1486',
    srcIp: '10.44.0.87', srcCountry: 'Internal', srcPort: 0, srcHostname: 'DESKTOP-FIN-087', srcAsn: 'Internal',
    destIp: '10.44.0.87', destPort: 0, destService: 'Local FileSystem',
    username: 'msmith', hostname: 'DESKTOP-FIN-087', hostCriticality: 'high',
    processName: 'svchost.exe', cmdLine: 'C:\\Windows\\Temp\\svchost.exe --encrypt --ext .locked',
    description: 'EDR detected mass file renaming consistent with ransomware encryption. 1,247 files renamed with .locked extension in under 60 seconds. Process spawned from user context without elevation.',
    rawLog: 'Nov 12 14:22:01 DESKTOP-FIN-087 EDR[4421]: ALERT type=ransomware_indicator host=DESKTOP-FIN-087 user=msmith process=svchost.exe(pid=9823) parent=explorer.exe(pid=3401) cmdline="C:\\Windows\\Temp\\svchost.exe --encrypt --ext .locked" files_renamed=1247 path=C:\\Users\\msmith\\Documents\\ rule=EDR-9001 severity=CRITICAL',
    eventCount: 1247, tiHits: 3, bytesOut: 0,
  },
  {
    id: 'a002', ts: '2024-11-12T14:18:00Z',
    title: 'Root SSH login from untrusted external IP - Lazarus Group C2 IOC match',
    severity: 'critical', status: 'assigned', disposition: 'true-positive', owner: 'a.patel',
    riskScore: 96,
    ruleId: 'SIEM-1042', ruleName: 'External SSH Root Login',
    mitreTactic: 'Initial Access', mitreTacticId: 'TA0001',
    mitreTech: 'External Remote Services', mitreTechId: 'T1133',
    srcIp: '45.95.147.236', srcCountry: 'Russia', srcPort: 52847, srcHostname: 'unknown', srcAsn: 'AS9009 M247 Ltd',
    destIp: '192.168.10.44', destPort: 22, destService: 'SSH',
    username: 'root', hostname: 'PROD-API-04', hostCriticality: 'critical',
    processName: 'sshd', cmdLine: null,
    description: 'Successful root authentication via SSH from IP matching Lazarus Group infrastructure (AS9009). Target host is a production API server. IP has 3 TI feed hits: Recorded Future, Crowdstrike Intel, MISP.',
    rawLog: 'Nov 12 14:18:34 PROD-API-04 sshd[1842]: Accepted publickey for root from 45.95.147.236 port 52847 ssh2: RSA SHA256:xyz... Nov 12 14:18:34 PROD-API-04 sshd[1842]: pam_unix(sshd:session): session opened for user root by (uid=0)',
    eventCount: 1, tiHits: 3, bytesOut: 142000,
  },
  {
    id: 'a003', ts: '2024-11-12T14:15:00Z',
    title: 'PowerShell AMSI bypass + encoded payload - living-off-the-land execution',
    severity: 'critical', status: 'new', disposition: 'undetermined', owner: null,
    riskScore: 91,
    ruleId: 'EDR-4421', ruleName: 'PowerShell AMSI Bypass Detected',
    mitreTactic: 'Defense Evasion', mitreTacticId: 'TA0005',
    mitreTech: 'Impair Defenses: AMSI Bypass', mitreTechId: 'T1562.001',
    srcIp: '10.8.1.45', srcCountry: 'Internal', srcPort: 0, srcHostname: 'WS-HR-045', srcAsn: 'Internal',
    destIp: '185.220.101.1', destPort: 443, destService: 'HTTPS',
    username: 'jdoe', hostname: 'WS-HR-045', hostCriticality: 'medium',
    processName: 'powershell.exe', cmdLine: 'powershell.exe -EncodedCommand JABhAD0AJABlAG4AdgA6AEMAbwBtAHAAdQB0AGUAcgBOAGEAbQBlAA==',
    description: 'PowerShell executed with Base64-encoded payload immediately after AMSI bypass string detected in memory. Subsequent outbound HTTPS connection to known C2 infrastructure. User has no legitimate reason to run encoded PowerShell.',
    rawLog: 'Nov 12 14:15:22 WS-HR-045 EDR: ALERT rule=EDR-4421 process=powershell.exe pid=7742 user=jdoe cmdline="-EncodedCommand JABhAD0AJABlAG4A..." amsi_bypass=detected connection=185.220.101.1:443',
    eventCount: 4, tiHits: 2, bytesOut: 48200,
  },
  {
    id: 'a004', ts: '2024-11-12T14:10:00Z',
    title: 'IAM privilege escalation: Lambda service account granted AdministratorAccess',
    severity: 'high', status: 'in-progress', disposition: 'true-positive', owner: 'j.chen',
    riskScore: 85,
    ruleId: 'AWS-3421', ruleName: 'IAM Policy Escalation to Admin',
    mitreTactic: 'Privilege Escalation', mitreTacticId: 'TA0004',
    mitreTech: 'Valid Accounts: Cloud Accounts', mitreTechId: 'T1078.004',
    srcIp: '54.239.28.85', srcCountry: 'United States', srcPort: 443, srcHostname: 'lambda.amazonaws.com', srcAsn: 'AS16509 Amazon',
    destIp: '10.0.1.1', destPort: 443, destService: 'AWS IAM',
    username: 'lambda-svc', hostname: null, hostCriticality: 'high',
    processName: null, cmdLine: null,
    description: 'AWS CloudTrail detected AttachUserPolicy granting AdministratorAccess to lambda-svc service account. This action was performed outside normal business hours by the account itself (self-escalation via assumed role).',
    rawLog: '{"eventTime":"2024-11-12T14:10:01Z","eventName":"AttachUserPolicy","userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::123456789:assumed-role/lambda-exec/lambda-svc"},"requestParameters":{"userName":"lambda-svc","policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}}',
    eventCount: 1, tiHits: 0, bytesOut: 0,
  },
  {
    id: 'a005', ts: '2024-11-12T14:04:00Z',
    title: 'Bulk data exfiltration query: 500K records from customer DB',
    severity: 'critical', status: 'new', disposition: 'undetermined', owner: null,
    riskScore: 93,
    ruleId: 'DB-8801', ruleName: 'Bulk Database Exfiltration Pattern',
    mitreTactic: 'Exfiltration', mitreTacticId: 'TA0010',
    mitreTech: 'Exfiltration Over Alternative Protocol', mitreTechId: 'T1048',
    srcIp: '10.0.5.22', srcCountry: 'Internal', srcPort: 49200, srcHostname: 'APP-SVC-02', srcAsn: 'Internal',
    destIp: '104.26.10.32', destPort: 443, destService: 'HTTPS',
    username: 'app_user', hostname: 'APP-SVC-02', hostCriticality: 'critical',
    processName: 'mysqldump', cmdLine: 'mysqldump -u app_user -p customers --all-databases > /tmp/dump.sql',
    description: 'Application server executed mysqldump for entire customers database (500K+ records). Data subsequently transferred via HTTPS to unrecognized external IP. Total egress: 4.2 GB in 8 minutes.',
    rawLog: 'Nov 12 14:04:11 APP-SVC-02 auditd: syscall=execve exe=/usr/bin/mysqldump user=app_user cmd="mysqldump -u app_user customers --all-databases" Nov 12 14:04:44 APP-SVC-02 net: 4396MB transferred to 104.26.10.32:443',
    eventCount: 2, tiHits: 1, bytesOut: 4200000000,
  },
  {
    id: 'a006', ts: '2024-11-12T13:55:00Z',
    title: 'Multiple failed MFA attempts - push fatigue attack on alice@corp.com',
    severity: 'high', status: 'assigned', disposition: 'undetermined', owner: 'r.osei',
    riskScore: 72,
    ruleId: 'AUTH-6621', ruleName: 'MFA Push Fatigue Detection',
    mitreTactic: 'Credential Access', mitreTacticId: 'TA0006',
    mitreTech: 'Multi-Factor Authentication Request Generation', mitreTechId: 'T1621',
    srcIp: '91.108.56.0', srcCountry: 'Russia', srcPort: 0, srcHostname: 'unknown', srcAsn: 'AS62041 Telegram',
    destIp: '10.0.0.1', destPort: 443, destService: 'Azure AD',
    username: 'alice', hostname: null, hostCriticality: 'medium',
    processName: null, cmdLine: null,
    description: 'Okta detected 23 MFA push requests sent to alice@corp.com within 5 minutes from Russian IP. Valid password used (credential stuffing). User has not approved any push. Attack pattern consistent with MFA fatigue/push bombing.',
    rawLog: 'Nov 12 13:55:01 okta: event=user.authentication.auth_via_mfa actor=alice@corp.com outcome=FAILURE reason=PUSH_REJECTED ip=91.108.56.0 [repeated 23 times in 5 minutes]',
    eventCount: 23, tiHits: 0, bytesOut: 0,
  },
  {
    id: 'a007', ts: '2024-11-12T13:40:00Z',
    title: 'DNS request to known malware C2 domain - CobaltStrike beacon pattern',
    severity: 'high', status: 'resolved', disposition: 'true-positive', owner: 'j.chen',
    riskScore: 78,
    ruleId: 'DNS-2201', ruleName: 'DNS C2 Beacon Domain Match',
    mitreTactic: 'Command and Control', mitreTacticId: 'TA0011',
    mitreTech: 'Application Layer Protocol: DNS', mitreTechId: 'T1071.004',
    srcIp: '10.50.3.12', srcCountry: 'Internal', srcPort: 53, srcHostname: 'WS-SALES-112', srcAsn: 'Internal',
    destIp: '8.8.8.8', destPort: 53, destService: 'DNS',
    username: 'bwilson', hostname: 'WS-SALES-112', hostCriticality: 'medium',
    processName: 'chrome.exe', cmdLine: null,
    description: 'Workstation issued DNS query for s3cr3t-update[.]kz (Recorded Future: CobaltStrike team server). 847-byte A record response. Beacon heartbeat pattern detected: query every 58 seconds. Host remediated.',
    rawLog: 'Nov 12 13:40:02 dns-fw: BLOCKED qname=s3cr3t-update.kz qtype=A client=10.50.3.12 policy=threat-intel-block feed=RecordedFuture category=c2 confidence=97',
    eventCount: 14, tiHits: 4, bytesOut: 12800,
  },
  {
    id: 'a008', ts: '2024-11-12T13:22:00Z',
    title: 'Admin account creation outside business hours by svc-deploy',
    severity: 'high', status: 'closed', disposition: 'benign', owner: 'a.patel',
    riskScore: 61,
    ruleId: 'AD-5510', ruleName: 'Privileged Account Created After Hours',
    mitreTactic: 'Persistence', mitreTacticId: 'TA0003',
    mitreTech: 'Create Account: Domain Account', mitreTechId: 'T1136.002',
    srcIp: '10.1.0.50', srcCountry: 'Internal', srcPort: 0, srcHostname: 'DEPLOY-SRV-01', srcAsn: 'Internal',
    destIp: '10.1.0.5', destPort: 389, destService: 'LDAP/AD',
    username: 'svc-deploy', hostname: 'DEPLOY-SRV-01', hostCriticality: 'high',
    processName: null, cmdLine: null,
    description: 'Service account svc-deploy created new domain account backup-admin-2024 at 23:44 UTC. Confirmed benign: authorized deployment pipeline action. Change request CR-2024-8841 on record.',
    rawLog: 'Nov 12 23:44:12 DC-01 Security[4720]: Account created: backup-admin-2024 by svc-deploy from 10.1.0.50 groups=[Domain Admins]',
    eventCount: 1, tiHits: 0, bytesOut: 0,
  },
  {
    id: 'a009', ts: '2024-11-12T13:10:00Z',
    title: 'SQL injection attempt: 847 payloads on /api/v2/users - WAF partially blocked',
    severity: 'high', status: 'new', disposition: 'undetermined', owner: null,
    riskScore: 67,
    ruleId: 'WAF-2231', ruleName: 'SQL Injection Attack Pattern',
    mitreTactic: 'Initial Access', mitreTacticId: 'TA0001',
    mitreTech: 'Exploit Public-Facing Application', mitreTechId: 'T1190',
    srcIp: '91.92.251.103', srcCountry: 'Iran', srcPort: 39847, srcHostname: 'unknown', srcAsn: 'AS44477 STARK INDUSTRIES',
    destIp: '198.51.100.44', destPort: 443, destService: 'HTTPS/API',
    username: null, hostname: 'api-gateway-01', hostCriticality: 'critical',
    processName: null, cmdLine: null,
    description: "847 SQL injection payloads targeting /api/v2/users endpoint. WAF blocked 832/847. 15 requests bypassed WAF and reached application server. Application logs show 2 queries returning 200 OK responses.",
    rawLog: "Nov 12 13:10:01 waf-01: BLOCKED src=91.92.251.103 dst=198.51.100.44 method=POST uri=/api/v2/users payload=\"' OR 1=1--\" rule=SQLI-001 [847 events in 4 minutes, 15 bypass]",
    eventCount: 847, tiHits: 1, bytesOut: 4400,
  },
  {
    id: 'a010', ts: '2024-11-12T12:55:00Z',
    title: 'Large outbound transfer 4.2 GB to Azure Blob Storage - unusual destination',
    severity: 'medium', status: 'new', disposition: 'undetermined', owner: null,
    riskScore: 54,
    ruleId: 'NET-3312', ruleName: 'Large Outbound Data Transfer',
    mitreTactic: 'Exfiltration', mitreTacticId: 'TA0010',
    mitreTech: 'Transfer Data to Cloud Account', mitreTechId: 'T1537',
    srcIp: '10.22.0.10', srcCountry: 'Internal', srcPort: 58234, srcHostname: 'FILE-SRV-01', srcAsn: 'Internal',
    destIp: '52.239.210.180', destPort: 443, destService: 'Azure Blob Storage',
    username: null, hostname: 'FILE-SRV-01', hostCriticality: 'high',
    processName: 'azcopy.exe', cmdLine: 'azcopy copy C:\\Shares\\Finance\\ https://unknown-tenant.blob.core.windows.net/backup/',
    description: 'File server transferred 4.2 GB to an Azure Blob Storage account in an unrecognized tenant. azcopy.exe was executed interactively (not via scheduled task). Investigation pending to confirm if authorized backup.',
    rawLog: 'Nov 12 12:55:03 FILE-SRV-01 sysmon[1]: ProcessCreate process=azcopy.exe cmdline="azcopy copy C:\\Shares\\Finance\\ https://unknown-tenant.blob.core.windows.net/backup/" user=NT AUTHORITY\\SYSTEM',
    eventCount: 1, tiHits: 0, bytesOut: 4200000000,
  },
  {
    id: 'a011', ts: '2024-11-12T12:40:00Z',
    title: 'VPN login from Singapore - impossible travel (last login: New York 47 min ago)',
    severity: 'medium', status: 'pending', disposition: 'undetermined', owner: 'r.osei',
    riskScore: 48,
    ruleId: 'VPN-0012', ruleName: 'Impossible Travel - VPN Authentication',
    mitreTactic: 'Initial Access', mitreTacticId: 'TA0001',
    mitreTech: 'Valid Accounts', mitreTechId: 'T1078',
    srcIp: '103.245.12.44', srcCountry: 'Singapore', srcPort: 0, srcHostname: 'unknown', srcAsn: 'AS132203 Tencent Cloud',
    destIp: '10.0.0.1', destPort: 1194, destService: 'OpenVPN',
    username: 'alice', hostname: null, hostCriticality: 'low',
    processName: null, cmdLine: null,
    description: 'User alice authenticated to VPN from Singapore (103.245.12.44) 47 minutes after successful login from New York (98.245.200.11). Physical travel is impossible. Either credential compromise or split-tunneling anomaly.',
    rawLog: 'Nov 12 12:40:18 vpn-gw: AUTH_SUCCESS user=alice src=103.245.12.44 country=SG device=unknown Nov 12 11:53:02 vpn-gw: AUTH_SUCCESS user=alice src=98.245.200.11 country=US device=MacBook-Alice',
    eventCount: 1, tiHits: 0, bytesOut: 0,
  },
  {
    id: 'a012', ts: '2024-11-12T12:30:00Z',
    title: 'Phishing email with macro-laced attachment delivered to 14 executives',
    severity: 'high', status: 'in-progress', disposition: 'true-positive', owner: 'a.patel',
    riskScore: 76,
    ruleId: 'MAIL-8812', ruleName: 'Phishing Attachment Delivered',
    mitreTactic: 'Initial Access', mitreTacticId: 'TA0001',
    mitreTech: 'Phishing: Spearphishing Attachment', mitreTechId: 'T1566.001',
    srcIp: '185.220.101.42', srcCountry: 'North Korea', srcPort: 25, srcHostname: 'mail-srv[.]kz', srcAsn: 'AS60068 CDC Online',
    destIp: '10.0.0.25', destPort: 25, destService: 'SMTP',
    username: null, hostname: 'mail-gw-01', hostCriticality: 'high',
    processName: null, cmdLine: null,
    description: 'Spearphishing campaign targeting C-suite executives. 14 emails with Q4_Budget_Final.xlsm attachment delivered before quarantine rule activated. File contains VBA macro that downloads Cobalt Strike stager. 3 recipients opened the file.',
    rawLog: 'Nov 12 12:30:02 mail-gw: DELIVERED from=noreply@m1crosoft-reports.kz to=ceo@corp.com,cfo@corp.com,[+12] subject="Q4 Budget Review" attachment=Q4_Budget_Final.xlsm(SHA256:abc123def) verdict=ALLOWED policy=bypass_exec',
    eventCount: 14, tiHits: 5, bytesOut: 0,
  },
  {
    id: 'a013', ts: '2024-11-12T12:15:00Z',
    title: 'Brute-force SSH - 4,219 attempts from 14 IPs in 8 minutes',
    severity: 'medium', status: 'resolved', disposition: 'true-positive', owner: 'j.chen',
    riskScore: 42,
    ruleId: 'FW-9821', ruleName: 'SSH Brute Force from Multiple Sources',
    mitreTactic: 'Credential Access', mitreTacticId: 'TA0006',
    mitreTech: 'Brute Force: Password Spraying', mitreTechId: 'T1110.003',
    srcIp: '192.241.0.0/16', srcCountry: 'China', srcPort: 0, srcHostname: 'Multiple', srcAsn: 'Multiple',
    destIp: '198.51.100.22', destPort: 22, destService: 'SSH',
    username: null, hostname: 'DMZ-JUMP-01', hostCriticality: 'high',
    processName: 'sshd', cmdLine: null,
    description: '14 source IPs across 3 Chinese ASNs coordinated SSH brute-force against jump host. 4,219 attempts in 8 minutes, all rejected. IPs blocked at perimeter firewall. No successful authentication. Coordinated timing suggests automated tooling.',
    rawLog: 'Nov 12 12:15:00 fw-01: BLOCK-COUNTRY src=103.83.128.0 dst=198.51.100.22 dport=22 reason=brute-force-threshold hits=300/min [14 source IPs]',
    eventCount: 4219, tiHits: 0, bytesOut: 0,
  },
  {
    id: 'a014', ts: '2024-11-12T11:55:00Z',
    title: 'Network reconnaissance: Nmap OS fingerprint + port scan from internal workstation',
    severity: 'medium', status: 'new', disposition: 'undetermined', owner: null,
    riskScore: 38,
    ruleId: 'NET-4401', ruleName: 'Internal Network Reconnaissance',
    mitreTactic: 'Discovery', mitreTacticId: 'TA0007',
    mitreTech: 'Network Service Discovery', mitreTechId: 'T1046',
    srcIp: '10.5.0.88', srcCountry: 'Internal', srcPort: 0, srcHostname: 'WS-DEV-088', srcAsn: 'Internal',
    destIp: '10.0.0.0/8', destPort: 0, destService: 'Multiple',
    username: 'dev_user3', hostname: 'WS-DEV-088', hostCriticality: 'low',
    processName: 'nmap', cmdLine: 'nmap -A -sV -O -p 1-65535 10.0.0.0/8',
    description: 'Developer workstation ran full-range Nmap scan with OS detection and service version enumeration across the entire 10.0.0.0/8 internal subnet. Atypical behavior for this account - may indicate lateral movement reconnaissance.',
    rawLog: 'Nov 12 11:55:12 ids-01: SCAN_DETECTED src=10.5.0.88 dst=10.0.0.0/8 type=NMAP_OS_FINGERPRINT packets=127422 scan_duration=120s',
    eventCount: 127422, tiHits: 0, bytesOut: 0,
  },
  {
    id: 'a015', ts: '2024-11-12T11:40:00Z',
    title: 'Security patch application failed: CVE-2024-6387 on 23 servers',
    severity: 'low', status: 'closed', disposition: 'benign', owner: 'a.patel',
    riskScore: 21,
    ruleId: 'PATCH-0040', ruleName: 'Critical Patch Application Failure',
    mitreTactic: 'Initial Access', mitreTacticId: 'TA0001',
    mitreTech: 'Exploit Public-Facing Application', mitreTechId: 'T1190',
    srcIp: '10.0.0.1', srcCountry: 'Internal', srcPort: 0, srcHostname: 'PATCH-SRV', srcAsn: 'Internal',
    destIp: 'Multiple', destPort: 0, destService: 'Patch Management',
    username: 'svc-patch', hostname: 'PATCH-SRV', hostCriticality: 'medium',
    processName: null, cmdLine: null,
    description: 'WSUS/SCCM patch deployment for CVE-2024-6387 (OpenSSH RCE) failed on 23 servers due to dependency conflict with libssl. Manual remediation completed; all servers now patched.',
    rawLog: 'Nov 12 11:40:01 patch-mgr: DEPLOYMENT_FAILED kb=CVE-2024-6387 target_count=23 failed_reason=libssl_conflict status=MANUAL_REMEDIATION_REQUIRED',
    eventCount: 23, tiHits: 0, bytesOut: 0,
  },
]

/* -- Correlation rules ---------------------------------------------- */
type CorrelationRule = {
  id: string
  name: string
  source: string
  mitreTactic: string
  mitreTechId: string
  severity: Severity
  enabled: boolean
  firedLast7d: number
  lastFired: string
  fpRate: number
  description: string
}

const RULES: CorrelationRule[] = [
  { id: 'EDR-9001', name: 'Ransomware File Encryption Indicator',   source: 'EDR',      mitreTactic: 'Impact',               mitreTechId: 'T1486',     severity: 'critical', enabled: true,  firedLast7d: 2,    lastFired: '2h ago',    fpRate: 5,  description: 'Detects mass file renaming/encryption consistent with ransomware activity (>500 renames/60s).' },
  { id: 'SIEM-1042', name: 'External SSH Root Login',               source: 'Auth',     mitreTactic: 'Initial Access',       mitreTechId: 'T1133',     severity: 'critical', enabled: true,  firedLast7d: 8,    lastFired: '4h ago',    fpRate: 8,  description: 'Successful root/admin SSH authentication from external (non-RFC1918) IP addresses.' },
  { id: 'EDR-4421', name: 'PowerShell AMSI Bypass Detected',        source: 'EDR',      mitreTactic: 'Defense Evasion',      mitreTechId: 'T1562.001', severity: 'critical', enabled: true,  firedLast7d: 14,   lastFired: '6h ago',    fpRate: 12, description: 'Memory scan detects AMSI bypass string followed by encoded PowerShell execution.' },
  { id: 'AWS-3421', name: 'IAM Policy Escalation to Admin',         source: 'Cloud',    mitreTactic: 'Privilege Escalation', mitreTechId: 'T1078.004', severity: 'high',     enabled: true,  firedLast7d: 3,    lastFired: '8h ago',    fpRate: 20, description: 'CloudTrail event: AttachPolicy or CreatePolicy granting AdministratorAccess detected.' },
  { id: 'DB-8801',  name: 'Bulk Database Exfiltration Pattern',     source: 'Database', mitreTactic: 'Exfiltration',         mitreTechId: 'T1048',     severity: 'critical', enabled: true,  firedLast7d: 1,    lastFired: '10h ago',   fpRate: 3,  description: 'Database query returning >100K rows from customer/PII tables followed by outbound transfer.' },
  { id: 'AUTH-6621', name: 'MFA Push Fatigue Detection',            source: 'Auth',     mitreTactic: 'Credential Access',   mitreTechId: 'T1621',     severity: 'high',     enabled: true,  firedLast7d: 22,   lastFired: '12h ago',   fpRate: 15, description: '>10 MFA push requests to same user within 5 minutes from external IP.' },
  { id: 'DNS-2201', name: 'DNS C2 Beacon Domain Match',             source: 'DNS',      mitreTactic: 'Command & Control',   mitreTechId: 'T1071.004', severity: 'high',     enabled: true,  firedLast7d: 44,   lastFired: '1h ago',    fpRate: 7,  description: 'DNS query matches known C2 infrastructure from Recorded Future, CrowdStrike, or MISP TI feeds.' },
  { id: 'AD-5510',  name: 'Privileged Account Created After Hours', source: 'AD/LDAP',  mitreTactic: 'Persistence',          mitreTechId: 'T1136.002', severity: 'high',     enabled: true,  firedLast7d: 5,    lastFired: '1d ago',    fpRate: 42, description: 'Domain admin or group admin account created between 20:00-06:00 UTC local time.' },
  { id: 'FW-9821',  name: 'SSH Brute Force from Multiple Sources',  source: 'Firewall', mitreTactic: 'Credential Access',   mitreTechId: 'T1110.003', severity: 'medium',   enabled: true,  firedLast7d: 182,  lastFired: '30m ago',   fpRate: 5,  description: '>3 distinct source IPs attacking same destination port 22 within 5-minute window.' },
  { id: 'WAF-2231', name: 'SQL Injection Attack Pattern',           source: 'WAF',      mitreTactic: 'Initial Access',       mitreTechId: 'T1190',     severity: 'high',     enabled: true,  firedLast7d: 2847, lastFired: '15m ago',   fpRate: 2,  description: 'WAF ModSecurity rule set: SQL injection payloads in POST body or query parameters.' },
  { id: 'NET-3312', name: 'Large Outbound Data Transfer',           source: 'Network',  mitreTactic: 'Exfiltration',         mitreTechId: 'T1537',     severity: 'medium',   enabled: true,  firedLast7d: 28,   lastFired: '2h ago',    fpRate: 35, description: 'Single host transfers >2 GB to external IP outside known cloud backup windows.' },
  { id: 'VPN-0012', name: 'Impossible Travel - VPN Authentication', source: 'VPN',      mitreTactic: 'Initial Access',       mitreTechId: 'T1078',     severity: 'medium',   enabled: true,  firedLast7d: 11,   lastFired: '3h ago',    fpRate: 28, description: 'Same user authenticates from geographically impossible locations within 90 minutes.' },
  { id: 'MAIL-8812', name: 'Phishing Attachment Delivered',         source: 'Email',    mitreTactic: 'Initial Access',       mitreTechId: 'T1566.001', severity: 'high',     enabled: true,  firedLast7d: 67,   lastFired: '4h ago',    fpRate: 10, description: 'Email gateway delivered attachment matching malicious file hash or suspicious macro signature.' },
  { id: 'NET-4401', name: 'Internal Network Reconnaissance',        source: 'IDS',      mitreTactic: 'Discovery',            mitreTechId: 'T1046',     severity: 'medium',   enabled: true,  firedLast7d: 9,    lastFired: '6h ago',    fpRate: 22, description: 'Nmap or similar tool detected conducting service/OS discovery of internal subnets.' },
  { id: 'PATCH-0040', name: 'Critical Patch Application Failure',   source: 'WSUS',     mitreTactic: 'Initial Access',       mitreTechId: 'T1190',     severity: 'low',      enabled: false, firedLast7d: 0,    lastFired: '3d ago',    fpRate: 60, description: 'Critical or high CVSS patch fails to deploy within 72 hours of release. Disabled: too noisy.' },
]

/* -- Data source health --------------------------------------------- */
const DATA_SOURCES = [
  { name: 'Windows EDR',      type: 'EDR',      eps: 4821, status: 'healthy', lastEvent: '< 1s', events7d: '41.2M'  },
  { name: 'AWS CloudTrail',   type: 'Cloud',    eps: 843,  status: 'healthy', lastEvent: '< 1s', events7d: '7.2M'   },
  { name: 'Palo Alto FW',     type: 'Firewall', eps: 2241, status: 'healthy', lastEvent: '< 1s', events7d: '19.4M'  },
  { name: 'Okta Identity',    type: 'Auth',     eps: 124,  status: 'healthy', lastEvent: '2s',   events7d: '1.07M'  },
  { name: 'Exchange Online',  type: 'Email',    eps: 312,  status: 'healthy', lastEvent: '1s',   events7d: '2.7M'   },
  { name: 'Cisco FTD IDS',    type: 'IDS/IPS',  eps: 1847, status: 'healthy', lastEvent: '< 1s', events7d: '15.9M'  },
  { name: 'Zscaler Proxy',    type: 'Proxy',    eps: 3241, status: 'healthy', lastEvent: '< 1s', events7d: '28.1M'  },
  { name: 'Splunk HEC',       type: 'SIEM',     eps: 892,  status: 'degraded',lastEvent: '14s',  events7d: '5.2M'   },
  { name: 'MySQL DB Audit',   type: 'Database', eps: 221,  status: 'healthy', lastEvent: '3s',   events7d: '1.9M'   },
  { name: 'CrowdStrike TI',   type: 'TI Feed',  eps: 42,   status: 'healthy', lastEvent: '22s',  events7d: '362K'   },
  { name: 'Windows WSUS',     type: 'Patch',    eps: 8,    status: 'offline', lastEvent: '4m',   events7d: '68K'    },
  { name: 'Azure Sentinel',   type: 'SIEM',     eps: 1102, status: 'healthy', lastEvent: '< 1s', events7d: '9.5M'   },
]

/* Format a duration given in minutes as "Xm YYs" (the SOC convention used here). */
function fmtMins(minutes: number): string {
  const totalSecs = Math.round(minutes * 60)
  const m = Math.floor(totalSecs / 60)
  const s = totalSecs % 60
  return `${m}m ${String(s).padStart(2, '0')}s`
}

/* -- Static metric calculations ------------------------------------ */
const METRICS = {
  totalAlerts: 2847,
  critical: 43,
  high: 81,
  medium: 224,
  mttd: '4m 12s',
  mttr: '23m 41s',
  mtta: '8m 03s',
  fpRate: 22,
  automationRate: 68,
  totalEps: 14713,
  daysData: 7,
}

// First-load-offline fallback ONLY (same policy as ALERTS): the analytics
// trend cards render live per-day buckets from /siem/analytics/trends, show
// skeletons until the first answer, and fall back to this demo shape solely
// when that first fetch fails (genuinely offline).
const SPARKLINE_DATA = {
  alertVolume: [2241, 3108, 1987, 2854, 3344, 2102, 2847],
  mttd: [7.2, 6.8, 5.1, 6.4, 4.8, 5.9, 4.2],
  mttr: [28.4, 31.2, 22.8, 27.5, 24.1, 19.3, 23.7],
  fpRate: [28, 31, 25, 27, 24, 21, 22],
}

// MITRE tactic distribution
const MITRE_DIST = [
  { tactic: 'Initial Access',     count: 847, color: tk('magenta')  },
  { tactic: 'Credential Access',  count: 412, color: tk('threat')  },
  { tactic: 'Exfiltration',       count: 298, color: tk('amber')  },
  { tactic: 'Defense Evasion',    count: 387, color: tk('violet')  },
  { tactic: 'Command & Control',  count: 523, color: tk('safe')  },
  { tactic: 'Discovery',          count: 189, color: tk('teal')  },
  { tactic: 'Privilege Escalation', count: 142, color: '#FF9B2E'},
  { tactic: 'Persistence',        count: 49,  color: '#A78BFA'  },
]

/* -- ATT&CK coverage matrix data ----------------------------------- */
const COVERED_TECH_IDS = new Set(RULES.map((r) => r.mitreTechId))

const MITRE_MATRIX = [
  { tacticId: 'TA0001', tactic: 'Initial Access',      color: tk('magenta'), techniques: [
    { id: 'T1190',     name: 'Exploit Public-Facing Application' },
    { id: 'T1133',     name: 'External Remote Services' },
    { id: 'T1566.001', name: 'Spearphishing Attachment' },
    { id: 'T1078',     name: 'Valid Accounts' },
    { id: 'T1566.002', name: 'Spearphishing via Service' },
    { id: 'T1195',     name: 'Supply Chain Compromise' },
  ]},
  { tacticId: 'TA0002', tactic: 'Execution',            color: tk('threat'), techniques: [
    { id: 'T1059.001', name: 'PowerShell' },
    { id: 'T1059.003', name: 'Windows Command Shell' },
    { id: 'T1204',     name: 'User Execution' },
    { id: 'T1047',     name: 'WMI' },
    { id: 'T1053.005', name: 'Scheduled Task/Job' },
    { id: 'T1059.007', name: 'JavaScript' },
  ]},
  { tacticId: 'TA0003', tactic: 'Persistence',          color: '#A78BFA', techniques: [
    { id: 'T1136.002', name: 'Create Domain Account' },
    { id: 'T1098',     name: 'Account Manipulation' },
    { id: 'T1547',     name: 'Boot Autostart Execution' },
    { id: 'T1505',     name: 'Server Software Component' },
    { id: 'T1053.005', name: 'Scheduled Task/Job' },
  ]},
  { tacticId: 'TA0004', tactic: 'Privilege Escalation', color: '#FF9B2E', techniques: [
    { id: 'T1078.004', name: 'Valid Accounts: Cloud' },
    { id: 'T1068',     name: 'Exploit for PrivEsc' },
    { id: 'T1055',     name: 'Process Injection' },
    { id: 'T1548',     name: 'Abuse Elevation Control' },
    { id: 'T1134',     name: 'Access Token Manipulation' },
  ]},
  { tacticId: 'TA0005', tactic: 'Defense Evasion',      color: tk('violet'), techniques: [
    { id: 'T1562.001', name: 'Impair Defenses: AMSI Bypass' },
    { id: 'T1070',     name: 'Indicator Removal' },
    { id: 'T1036',     name: 'Masquerading' },
    { id: 'T1027',     name: 'Obfuscated Files / Info' },
    { id: 'T1218',     name: 'System Binary Proxy Exec.' },
    { id: 'T1140',     name: 'Deobfuscate / Decode' },
  ]},
  { tacticId: 'TA0006', tactic: 'Credential Access',    color: tk('threat'), techniques: [
    { id: 'T1621',     name: 'MFA Request Generation' },
    { id: 'T1110.003', name: 'Brute Force: Password Spray' },
    { id: 'T1003.001', name: 'LSASS Memory' },
    { id: 'T1555',     name: 'Credentials from Stores' },
    { id: 'T1552',     name: 'Unsecured Credentials' },
    { id: 'T1056',     name: 'Input Capture' },
  ]},
  { tacticId: 'TA0007', tactic: 'Discovery',            color: tk('teal'), techniques: [
    { id: 'T1046',     name: 'Network Service Discovery' },
    { id: 'T1083',     name: 'File & Directory Discovery' },
    { id: 'T1082',     name: 'System Info Discovery' },
    { id: 'T1087',     name: 'Account Discovery' },
    { id: 'T1069',     name: 'Permission Groups Discovery' },
  ]},
  { tacticId: 'TA0008', tactic: 'Lateral Movement',     color: tk('safe'), techniques: [
    { id: 'T1021',     name: 'Remote Services' },
    { id: 'T1550',     name: 'Use Alt. Auth Material' },
    { id: 'T1534',     name: 'Internal Spearphishing' },
    { id: 'T1570',     name: 'Lateral Tool Transfer' },
  ]},
  { tacticId: 'TA0010', tactic: 'Exfiltration',         color: tk('amber'), techniques: [
    { id: 'T1048',     name: 'Exfil Over Alt Protocol' },
    { id: 'T1537',     name: 'Transfer to Cloud Account' },
    { id: 'T1567',     name: 'Exfil Over Web Service' },
    { id: 'T1020',     name: 'Automated Exfiltration' },
    { id: 'T1041',     name: 'Exfil Over C2 Channel' },
  ]},
  { tacticId: 'TA0011', tactic: 'Command & Control',    color: tk('safe'), techniques: [
    { id: 'T1071.004', name: 'App Layer Protocol: DNS' },
    { id: 'T1071.001', name: 'App Layer Protocol: HTTP' },
    { id: 'T1573',     name: 'Encrypted Channel' },
    { id: 'T1090',     name: 'Proxy' },
    { id: 'T1095',     name: 'Non-App Layer Protocol' },
  ]},
  { tacticId: 'TA0040', tactic: 'Impact',               color: tk('magenta'), techniques: [
    { id: 'T1486',     name: 'Data Encrypted for Impact' },
    { id: 'T1485',     name: 'Data Destruction' },
    { id: 'T1490',     name: 'Inhibit System Recovery' },
    { id: 'T1499',     name: 'Endpoint Denial of Service' },
    { id: 'T1496',     name: 'Resource Hijacking' },
  ]},
]

/* -- Shared helpers ------------------------------------------------- */
const SEV: Record<Severity, { bg: string; text: string; border: string; dot: string }> = {
  critical: { bg: 'bg-magenta/15', text: 'text-magenta', border: 'border-magenta/30', dot: tk('magenta') },
  high:     { bg: 'bg-threat/15',  text: 'text-threat',  border: 'border-threat/30',  dot: tk('threat') },
  medium:   { bg: 'bg-amber/15',   text: 'text-amber',   border: 'border-amber/30',   dot: tk('amber') },
  low:      { bg: 'bg-safe/15',    text: 'text-safe',    border: 'border-safe/30',    dot: tk('safe') },
  info:     { bg: 'bg-violet/15',  text: 'text-violet',  border: 'border-violet/30',  dot: tk('violet') },
}

const STATUS_LABEL: Record<AlertStatus, { label: string; color: string }> = {
  'new':         { label: 'New',         color: 'text-magenta' },
  'assigned':    { label: 'Assigned',    color: 'text-amber' },
  'in-progress': { label: 'In Progress', color: 'text-violet' },
  'pending':     { label: 'Pending',     color: 'text-ink-400' },
  'resolved':    { label: 'Resolved',    color: 'text-safe' },
  'closed':      { label: 'Closed',      color: 'text-ink-600' },
}

const FP_BAND_STYLE: Record<string, { color: string; label: string }> = {
  'likely-fp':   { color: tk('safe'),    label: 'Likely false positive' },
  'uncertain':   { color: tk('amber'),   label: 'Uncertain' },
  'likely-real': { color: tk('magenta'), label: 'Likely real' },
}

function timeAgo(ts: string): string {
  const diff = (Date.now() - new Date(ts).getTime()) / 1000
  if (diff < 60) return `${Math.floor(diff)}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  return `${Math.floor(diff / 3600)}h ago`
}

function fmtBytes(b: number): string {
  if (b === 0) return '-'
  if (b < 1024) return `${b} B`
  if (b < 1048576) return `${(b / 1024).toFixed(0)} KB`
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`
  return `${(b / 1073741824).toFixed(2)} GB`
}

/* -- Alert detail panel --------------------------------------------- */
function AlertDetail({ alert, onClose, simplified, onUpdate }: {
  alert: SiemAlert; onClose: () => void; simplified?: boolean
  onUpdate: (id: string, patch: Partial<SiemAlert>) => void
}) {
  const [tab, setTab] = useState<'overview' | 'network' | 'identity' | 'host' | 'raw'>('overview')
  // Toasts can carry a link straight to the record an action just created
  // (case, suppression) - the user never has to go search for it afterwards.
  const [toast, setToast] = useState<{ text: string; href?: string; hrefLabel?: string } | null>(null)
  const [fpAssessment, setFpAssessment] = useState<FpAssessment | null>(null)
  const [fpChecking, setFpChecking] = useState(false)
  // Real UEBA context for the identity/host tabs (fetched lazily when the tab
  // opens; these replaced hardcoded demo rows - "Domain CORP", "UEBA 44/100").
  const [userEntity, setUserEntity] = useState<EntityDetail | null>(null)
  const [hostEntity, setHostEntity] = useState<EntityDetail | null>(null)
  const s = SEV[alert.severity]
  const st = STATUS_LABEL[alert.status]

  const flash = (text: string, href?: string, hrefLabel?: string) => {
    setToast({ text, href, hrefLabel })
    setTimeout(() => setToast(null), href ? 10_000 : 2200)  // links need time to click
  }

  // Reset the (advisory, never auto-acted-on) FP assessment when the
  // selected alert changes so a stale score from a different alert can't
  // linger on screen.
  useEffect(() => { setFpAssessment(null); setUserEntity(null); setHostEntity(null) }, [alert.id])

  useEffect(() => {
    if (tab === 'identity' && alert.username && !userEntity) {
      fetchEntityDetail('user', alert.username).then(setUserEntity).catch(() => {})
    }
    if (tab === 'host' && alert.hostname && !hostEntity) {
      fetchEntityDetail('host', alert.hostname).then(setHostEntity).catch(() => {})
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, alert.id])

  function checkFp() {
    if (fpChecking) return
    setFpChecking(true)
    fetchAlertFpAssessment(alert.id).then(setFpAssessment).catch(() => flash('Could not fetch FP assessment'))
      .finally(() => setFpChecking(false))
  }

  const TABS = simplified
    ? (['overview'] as const)
    : (['overview', 'network', 'identity', 'host', 'raw'] as const)

  return (
    <motion.div
      initial={{ x: '100%', opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: '100%', opacity: 0 }}
      transition={{ type: 'spring', stiffness: 280, damping: 28 }}
      className="fixed right-0 top-0 bottom-0 z-60 w-full max-w-xl flex flex-col bg-surface border-l border-white/8 shadow-2xl overflow-hidden"
    >
      {/* Header */}
      <div className="p-4 border-b border-white/8">
        <div className="flex items-start gap-3">
          <div className={cn('mt-0.5 px-2 py-0.5 rounded-sm text-[10px] font-bold uppercase shrink-0', s.bg, s.text, `border ${s.border}`)}>
            {alert.severity}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-white leading-snug">{alert.title}</p>
            <div className="flex items-center gap-3 mt-1 text-[10px] text-ink-500">
              <span suppressHydrationWarning>{timeAgo(alert.ts)}</span>
              <span>·</span>
              <span className={st.color}>{st.label}</span>
              <span>·</span>
              <span>{alert.ruleId}</span>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-ink-500 hover:text-white hover:bg-white/5 transition-colors shrink-0">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Risk score + MITRE */}
        <div className="flex items-center gap-3 mt-3">
          <div className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-surface-2 border border-white/8">
            <div className="text-[10px] text-ink-500">Risk</div>
            <div className="text-sm font-bold" style={{ color: alert.riskScore >= 90 ? tk('magenta') : alert.riskScore >= 70 ? tk('threat') : tk('amber') }}>
              {alert.riskScore}
            </div>
          </div>
          <div className="px-2 py-1 rounded-lg bg-violet/10 border border-violet/20 text-[10px] font-mono text-violet">
            {alert.mitreTacticId} · {alert.mitreTechId}
          </div>
          <div className="text-[10px] text-ink-500 truncate">{alert.mitreTech}</div>
        </div>

        {/* Action bar */}
        <div className="flex items-center gap-2 mt-3 flex-wrap">
          {[
            { label: 'Assign to Me', icon: User, color: 'text-amber',
              run: () => { onUpdate(alert.id, { owner: 'you', status: alert.status === 'new' ? 'assigned' : alert.status }); flash('Assigned to you') } },
            { label: 'Escalate', icon: ArrowUpRight, color: 'text-threat',
              run: () => { onUpdate(alert.id, { status: 'in-progress' }); flash('Escalated - status set to In Progress') } },
            { label: 'Create Case', icon: FileText, color: 'text-violet',
              run: () => {
                createCase({
                  title: alert.title,
                  severity: ['critical', 'high', 'medium', 'low'].includes(alert.severity) ? alert.severity : 'medium',
                  type: 'Investigation',
                  description: `Escalated from SIEM alert ${alert.id} (${alert.ruleName}). ${alert.description}`,
                  alertCount: 1,
                  entities: [
                    ...(alert.srcIp ? [{ type: 'ip', value: alert.srcIp }] : []),
                    ...(alert.hostname ? [{ type: 'host', value: alert.hostname }] : []),
                    ...(alert.username ? [{ type: 'user', value: alert.username }] : []),
                  ],
                })
                  .then((c) => flash(`SOAR case ${c.id} created from this alert`,
                    `/dashboard/soar?case=${encodeURIComponent(c.id)}`, 'Open case →'))
                  .catch(() => flash('Could not create case - is the dashboard API running?'))
              } },
            { label: 'Suppress', icon: Lock, color: 'text-ink-400',
              run: () => {
                // Real alert-tuning: mark this alert FP (bumps the rule's FP rate)
                // AND create a suppression that retro-closes siblings and drops
                // future matches for this entity.
                onUpdate(alert.id, { status: 'closed', disposition: 'false-positive' })
                const ent = alert.srcIp ? { field: 'src_ip', value: alert.srcIp }
                  : alert.hostname ? { field: 'hostname', value: alert.hostname }
                  : alert.username ? { field: 'username', value: alert.username }
                  : null
                if (!ent) { flash('Alert closed as false-positive'); return }
                createSuppression({ value: ent.value, field: ent.field,
                  reason: `From alert ${alert.id} · ${alert.ruleName}` })
                  .then(() => flash(`Suppression added for ${ent.field}=${ent.value} - future matches dropped`,
                    '/dashboard/siem/rules#suppressions', 'Manage / undo →'))
                  .catch(() => flash('Could not create suppression - is the dashboard API running?'))
              } },
            { label: 'Run Playbook', icon: Zap, color: 'text-safe',
              run: () => {
                onUpdate(alert.id, { status: 'in-progress' })
                // Pick the most relevant enabled playbook for this alert and
                // actually execute it in SOAR (bumps runs / last_run, audited).
                fetchPlaybooks()
                  .then((pbs) => {
                    const needle = `${alert.mitreTactic} ${alert.title}`.toLowerCase()
                    const match = pbs.find((p) =>
                      (p.trigger ?? '').toLowerCase().split(/\s+/).some((w) => w.length > 4 && needle.includes(w)))
                      ?? pbs[0]
                    if (!match) throw new Error('no playbook')
                    return runPlaybook(match.id).then((run) => flash(`Playbook "${run.name}" executed in SOAR`))
                  })
                  .catch(() => flash('Could not run a playbook - is the dashboard API running?'))
              } },
          ].map(({ label, icon: Icon, color, run }) => (
            <button key={label} onClick={run}
              className={cn('flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] border border-white/8 hover:border-white/15 bg-surface-2 hover:bg-surface-3 transition-colors active:scale-95', color)}>
              <Icon className="w-3 h-3" />
              {label}
            </button>
          ))}
          <button onClick={checkFp} disabled={fpChecking}
            className="flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] border border-white/8 hover:border-white/15 bg-surface-2 hover:bg-surface-3 transition-colors active:scale-95 text-violet">
            {fpChecking ? <Loader2 className="w-3 h-3 animate-spin" /> : <Gauge className="w-3 h-3" />}
            FP Likelihood
          </button>
        </div>

        {/* Triage controls - status + disposition */}
        <div className="flex items-center gap-2 mt-2.5">
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-ink-600">Status</span>
            <select
              value={alert.status}
              onChange={(e) => { onUpdate(alert.id, { status: e.target.value as AlertStatus }); flash(`Status → ${STATUS_LABEL[e.target.value as AlertStatus].label}`) }}
              className="appearance-none bg-surface-2 border border-white/10 rounded-md text-[10px] text-ink-200 px-2 py-1 focus:outline-hidden focus:border-magenta/40 cursor-pointer"
            >
              {(['new','assigned','in-progress','pending','resolved','closed'] as AlertStatus[]).map((s) => (
                <option key={s} value={s} className="bg-[#100A1C]">{STATUS_LABEL[s].label}</option>
              ))}
            </select>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-ink-600">Disposition</span>
            <select
              value={alert.disposition}
              onChange={(e) => { onUpdate(alert.id, { disposition: e.target.value as Disposition }); flash('Disposition recorded') }}
              className="appearance-none bg-surface-2 border border-white/10 rounded-md text-[10px] text-ink-200 px-2 py-1 capitalize focus:outline-hidden focus:border-magenta/40 cursor-pointer"
            >
              {(['undetermined','true-positive','false-positive','benign','duplicate'] as Disposition[]).map((d) => (
                <option key={d} value={d} className="bg-[#100A1C]">{d.replace('-', ' ')}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Toast */}
        <AnimatePresence>
          {toast && (
            <motion.div
              initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
              className="mt-2.5 flex items-center gap-1.5 text-[10px] text-safe bg-safe/10 border border-safe/20 rounded-lg px-2.5 py-1.5">
              <CheckCircle className="w-3 h-3 shrink-0" />
              {toast.text}
              {toast.href && (
                <Link href={toast.href}
                  className="ml-1 text-magenta underline underline-offset-2 hover:text-white shrink-0">
                  {toast.hrefLabel ?? 'Open →'}
                </Link>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Tabs */}
      {!simplified && (
      <div className="flex border-b border-white/5 px-4 gap-4 shrink-0">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)} className={cn('py-2.5 text-[11px] capitalize border-b-2 transition-colors',
            tab === t ? 'border-magenta text-white' : 'border-transparent text-ink-500 hover:text-ink-200')}>
            {t === 'raw' ? 'Raw Log' : t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>
      )}

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {tab === 'overview' && (
          <>
            <Section title="Description">
              <p className="text-xs text-ink-300 leading-relaxed">{alert.description}</p>
            </Section>
            {fpAssessment && (
              <Section title="False-Positive Likelihood">
                <div className="p-3 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-ink-500">Advisory only - never auto-closes an alert</span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full uppercase font-semibold"
                      style={{ color: FP_BAND_STYLE[fpAssessment.band].color, background: `${FP_BAND_STYLE[fpAssessment.band].color}18` }}>
                      {FP_BAND_STYLE[fpAssessment.band].label} · {fpAssessment.score}
                    </span>
                  </div>
                  <div className="h-1.5 rounded-full bg-white/8 overflow-hidden relative">
                    <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${fpAssessment.score}%`, background: FP_BAND_STYLE[fpAssessment.band].color }} />
                  </div>
                  {fpAssessment.evidence.length === 0 && (
                    <p className="text-[10px] text-ink-600">No corroborating or contradicting evidence found - treat as unassessed, not benign.</p>
                  )}
                  {fpAssessment.evidence.map((e) => (
                    <div key={e.signal} className="flex items-start gap-2.5">
                      <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0"
                        style={{ background: e.weight >= 0 ? tk('safe') : tk('magenta') }} />
                      <p className="text-[10px] text-ink-300 flex-1">{e.detail}</p>
                      <span className="text-[10px] font-mono shrink-0" style={{ color: e.weight >= 0 ? tk('safe') : tk('magenta') }}>
                        {e.weight >= 0 ? '+' : ''}{e.weight}
                      </span>
                    </div>
                  ))}
                </div>
              </Section>
            )}
            <Section title="Detection Details">
              <Row label="Rule" value={`${alert.ruleId} - ${alert.ruleName}`} />
              <Row label="MITRE Tactic" value={`${alert.mitreTacticId} ${alert.mitreTactic}`} />
              <Row label="MITRE Technique" value={`${alert.mitreTechId} ${alert.mitreTech}`} />
              <Row label="Matched Events" value={alert.eventCount.toLocaleString()} />
              <Row label="TI Feed Hits" value={alert.tiHits > 0 ? `${alert.tiHits} feeds matched` : 'No TI hits'} highlight={alert.tiHits > 0 ? 'threat' : undefined} />
              <Row label="Bytes Egressed" value={fmtBytes(alert.bytesOut)} highlight={alert.bytesOut > 1000000 ? 'threat' : undefined} />
            </Section>
            <Section title="Triage">
              <Row label="Status" value={STATUS_LABEL[alert.status].label} />
              <Row label="Owner" value={alert.owner ?? 'Unassigned'} highlight={!alert.owner ? 'amber' : undefined} />
              <Row label="Disposition" value={alert.disposition} />
              <Row label="Risk Score" value={`${alert.riskScore} / 100`} highlight={alert.riskScore >= 90 ? 'threat' : 'amber'} />
            </Section>
          </>
        )}

        {tab === 'network' && (
          <>
            <Section title="Source">
              <Row label="IP Address" value={alert.srcIp} mono />
              <Row label="Hostname" value={alert.srcHostname} mono />
              <Row label="Country" value={alert.srcCountry} />
              <Row label="ASN" value={alert.srcAsn} mono />
              <Row label="Port" value={alert.srcPort > 0 ? `${alert.srcPort}` : '-'} mono />
            </Section>
            <Section title="Destination">
              <Row label="IP Address" value={alert.destIp} mono />
              <Row label="Port" value={`${alert.destPort}`} mono />
              <Row label="Service" value={alert.destService} />
              <Row label="Bytes Out" value={fmtBytes(alert.bytesOut)} highlight={alert.bytesOut > 1000000 ? 'threat' : undefined} />
            </Section>
          </>
        )}

        {tab === 'identity' && (
          <>
            {/* Real UEBA context from /siem/entities/detail - deviation from
                the user's OWN learned baseline, not invented directory data */}
            <Section title="User Context">
              {alert.username ? (
                <>
                  <Row label="Username" value={alert.username} mono />
                  {userEntity ? (
                    <>
                      <Row label="UEBA Risk Score" value={`${userEntity.risk} / 100`}
                        highlight={userEntity.risk >= 70 ? 'threat' : userEntity.risk >= 45 ? 'amber' : undefined} />
                      <Row label="Related Alerts" value={`${userEntity.alertCount}`} />
                      <Row label="Daily Volume"
                        value={userEntity.baseline.confidence === 'insufficient-history'
                          ? `${userEntity.baseline.current} today (baseline needs ≥3 days)`
                          : `${userEntity.baseline.current} today · norm ${userEntity.baseline.mean} ± ${userEntity.baseline.stdDev}`} />
                      {userEntity.baseline.confidence !== 'insufficient-history' && (
                        <Row label="Baseline Deviation"
                          value={`z = ${userEntity.baseline.zScore}${userEntity.baseline.deviating ? ' - DEVIATING' : ' (normal)'}`}
                          highlight={userEntity.baseline.deviating ? 'threat' : undefined} />
                      )}
                      {userEntity.topTechniques.length > 0 && (
                        <Row label="Top Techniques"
                          value={userEntity.topTechniques.slice(0, 3).map((t) => `${t.technique} ×${t.count}`).join(' · ')} mono />
                      )}
                    </>
                  ) : (
                    <Row label="UEBA Risk Score" value="Loading…" />
                  )}
                </>
              ) : (
                <p className="text-xs text-ink-600 italic">No user identity extracted from this alert</p>
              )}
            </Section>
            <p className="text-[10px] text-ink-600 italic px-1">
              Directory / IdP attributes (department, sessions, MFA) require an
              identity-provider integration - only activity-derived context is shown.
            </p>
          </>
        )}

        {tab === 'host' && (
          <>
            {/* Real host context: fields carried by the alert + this host's
                UEBA record (replaced hardcoded demo rows - fake OS build,
                vuln counts, patch age) */}
            <Section title="Asset Profile">
              {alert.hostname ? (
                <>
                  <Row label="Hostname" value={alert.hostname} mono />
                  <Row label="IP Address" value={alert.srcIp} mono />
                  <Row label="Asset Criticality" value={alert.hostCriticality.toUpperCase()} highlight={alert.hostCriticality === 'critical' ? 'threat' : alert.hostCriticality === 'high' ? 'amber' : undefined} />
                  {hostEntity ? (
                    <>
                      <Row label="Host Risk Score" value={`${hostEntity.risk} / 100`}
                        highlight={hostEntity.risk >= 70 ? 'threat' : hostEntity.risk >= 45 ? 'amber' : undefined} />
                      <Row label="Related Alerts" value={`${hostEntity.alertCount}`} />
                      {hostEntity.baseline.confidence !== 'insufficient-history' && (
                        <Row label="Baseline Deviation"
                          value={`z = ${hostEntity.baseline.zScore}${hostEntity.baseline.deviating ? ' - DEVIATING' : ' (normal)'}`}
                          highlight={hostEntity.baseline.deviating ? 'threat' : undefined} />
                      )}
                    </>
                  ) : (
                    <Row label="Host Risk Score" value="Loading…" />
                  )}
                  <div className="pt-1">
                    <Link href="/dashboard/assets/vulns" className="text-[11px] text-magenta hover:underline">
                      View fleet vulnerabilities →
                    </Link>
                  </div>
                </>
              ) : (
                <p className="text-xs text-ink-600 italic">No host context available</p>
              )}
            </Section>
            {alert.processName && (
              <Section title="Process">
                <Row label="Process" value={alert.processName} mono />
                <Row label="Command Line" value={alert.cmdLine ?? '-'} mono />
              </Section>
            )}
          </>
        )}

        {tab === 'raw' && (
          <div>
            <div className="flex items-center justify-between mb-2">
              <p className="text-[10px] text-ink-500 uppercase tracking-wide">Raw Log</p>
              <button className="flex items-center gap-1 text-[10px] text-ink-500 hover:text-white transition-colors">
                <Copy className="w-3 h-3" /> Copy
              </button>
            </div>
            <pre className="bg-surface-2 rounded-xl p-4 text-[10px] font-mono text-ink-300 leading-relaxed overflow-x-auto border border-white/5 whitespace-pre-wrap break-all">
              {alert.rawLog}
            </pre>
          </div>
        )}
      </div>
    </motion.div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-[10px] font-semibold text-ink-600 uppercase tracking-widest mb-2">{title}</p>
      <div className="bg-surface-2/60 rounded-xl border border-white/5 overflow-hidden">
        {children}
      </div>
    </div>
  )
}

function Row({ label, value, mono, highlight }: { label: string; value: string; mono?: boolean; highlight?: 'threat' | 'amber' | 'safe' }) {
  const vc = highlight === 'threat' ? 'text-threat' : highlight === 'amber' ? 'text-amber' : highlight === 'safe' ? 'text-safe' : 'text-ink-200'
  return (
    <div className="flex items-start justify-between gap-4 px-3 py-2 border-b border-white/4 last:border-b-0">
      <span className="text-[11px] text-ink-500 shrink-0">{label}</span>
      <span className={cn('text-[11px] text-right break-all', mono && 'font-mono', vc)}>{value}</span>
    </div>
  )
}

/* -- Metrics minibar (sparkline) ----------------------------------- */
function MiniSparkline({ data, color }: { data: number[]; color: string }) {
  const max = Math.max(...data)
  const min = Math.min(...data)
  const range = max - min || 1
  const H_PX = 28, W_PX = 80
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * W_PX
    const y = H_PX - ((v - min) / range) * H_PX
    return `${x},${y}`
  }).join(' ')
  return (
    <svg width={W_PX} height={H_PX} viewBox={`0 0 ${W_PX} ${H_PX}`}>
      {/* draw-in from the left on mount; MotionConfig handles reduced motion */}
      <motion.polyline
        points={pts} fill="none" stroke={color} strokeWidth={1.5}
        strokeLinecap="round" strokeLinejoin="round" opacity={0.8}
        initial={{ pathLength: 0 }} animate={{ pathLength: 1 }}
        transition={{ duration: 0.8, ease: 'easeOut' }}
      />
    </svg>
  )
}

/* -- Threat hunting ---------------------------------------------------
   The real, full-featured hunt workspace lives at /dashboard/siem/hunt and
   runs live queries against the event store (POST /siem/search). This in-page
   tab links to it rather than duplicating it with a second (previously mocked)
   results table. */
function ThreatHunt() {
  return (
    <div className="flex flex-col items-center justify-center h-full text-center p-8 gap-4">
      <div className="w-14 h-14 rounded-2xl bg-magenta/10 border border-magenta/20 flex items-center justify-center">
        <Terminal className="w-6 h-6 text-magenta" />
      </div>
      <div>
        <p className="text-sm font-semibold text-white">Threat Hunting Workspace</p>
        <p className="text-xs text-ink-500 mt-1 max-w-md leading-relaxed">
          Run live KQL queries against your event store with saved hunts, time
          ranges, and real matched events - in the full hunt workspace.
        </p>
      </div>
      <Link
        href="/dashboard/siem/hunt"
        className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-medium bg-magenta/15 border border-magenta/30 text-magenta hover:bg-magenta/25 transition-colors"
      >
        <Search className="w-3.5 h-3.5" /> Open Hunt Workspace
      </Link>
    </div>
  )
}

/* -- ATT&CK coverage matrix component ------------------------------ */
function MitreCoverageMatrix() {
  const [hoveredTech, setHoveredTech] = useState<string | null>(null)
  const allTechs = MITRE_MATRIX.flatMap((r) => r.techniques)
  const totalCovered = allTechs.filter((t) => COVERED_TECH_IDS.has(t.id)).length
  const pct = Math.round((totalCovered / allTechs.length) * 100)

  return (
    <div className="bg-surface-2/40 rounded-xl border border-white/5">
      <div className="px-4 py-3 border-b border-white/5 flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-xs font-semibold text-white">ATT&CK Coverage Matrix</p>
          <p className="text-[10px] text-ink-600 mt-0.5">Detection rule coverage across MITRE ATT&CK Enterprise - hover a technique cell for detail</p>
        </div>
        <div className="flex items-center gap-4 text-[10px] text-ink-400">
          <span className="flex items-center gap-1.5"><span className="inline-block w-2.5 h-2.5 rounded-sm bg-safe/20 border border-safe/50" />Covered</span>
          <span className="flex items-center gap-1.5"><span className="inline-block w-2.5 h-2.5 rounded-sm bg-threat/15 border border-threat/40" />Gap</span>
          <span className="text-safe font-semibold">{totalCovered}/{allTechs.length} covered</span>
        </div>
      </div>
      <div className="p-4 space-y-3">
        {MITRE_MATRIX.map((row) => {
          const rowCovered = row.techniques.filter((t) => COVERED_TECH_IDS.has(t.id)).length
          return (
            <div key={row.tacticId} className="flex items-start gap-4">
              <div className="w-36 shrink-0 pt-0.5">
                <p className="text-[10px] font-semibold leading-tight" style={{ color: row.color }}>{row.tactic}</p>
                <p className="text-[9px] font-mono text-ink-700 mt-0.5">{row.tacticId}</p>
                <p className="text-[9px] text-ink-600">{rowCovered}/{row.techniques.length} covered</p>
              </div>
              <div className="flex flex-wrap gap-1.5 flex-1">
                {row.techniques.map((tech) => {
                  const isCovered = COVERED_TECH_IDS.has(tech.id)
                  const rule = isCovered ? RULES.find((r) => r.mitreTechId === tech.id) : null
                  const isHov = hoveredTech === tech.id
                  return (
                    <div
                      key={tech.id}
                      onMouseEnter={() => setHoveredTech(tech.id)}
                      onMouseLeave={() => setHoveredTech(null)}
                      className="relative"
                    >
                      <div className={cn(
                        'px-2 py-1 rounded-sm text-[9px] font-mono border cursor-default select-none transition-all',
                        isCovered
                          ? 'bg-safe/10 border-safe/35 text-safe hover:bg-safe/20'
                          : 'bg-threat/5 border-threat/20 text-threat/60 hover:bg-threat/15',
                        isHov ? (isCovered ? 'ring-1 ring-safe/50' : 'ring-1 ring-threat/40') : '',
                      )}>
                        {tech.id}
                      </div>
                      {isHov && (
                        <div className="absolute z-30 top-full left-0 mt-1 w-56 bg-surface border border-white/15 rounded-lg p-2.5 shadow-2xl pointer-events-none">
                          <p className="text-[10px] font-semibold text-white leading-snug">{tech.name}</p>
                          <p className="text-[9px] font-mono text-ink-600 mt-0.5">{tech.id}</p>
                          {rule ? (
                            <div className="mt-2 pt-2 border-t border-white/8">
                              <p className="text-[9px] text-safe font-semibold mb-0.5">✓ Detection active</p>
                              <p className="text-[9px] text-ink-400">{rule.id}: {rule.name}</p>
                              <p className="text-[9px] text-ink-600 mt-0.5">Fired {rule.firedLast7d}× last 7d · FP rate {rule.fpRate}%</p>
                            </div>
                          ) : (
                            <div className="mt-2 pt-2 border-t border-white/8">
                              <p className="text-[9px] text-threat/80 font-semibold">✗ Coverage gap</p>
                              <p className="text-[9px] text-ink-600 mt-0.5">No active detection rule - consider adding one</p>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>
      <div className="px-4 py-3 border-t border-white/5 flex items-center gap-3">
        <div className="flex-1 h-1.5 bg-white/8 rounded-full overflow-hidden">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${pct}%` }}
            transition={{ duration: 0.9, delay: 0.2 }}
            className="h-full rounded-full bg-safe"
          />
        </div>
        <p className="text-[10px] shrink-0">
          <span className="text-safe font-semibold">{pct}% coverage</span>
          <span className="text-ink-700 mx-1.5">·</span>
          <span className="text-threat">{allTechs.length - totalCovered} gaps identified</span>
        </p>
      </div>
    </div>
  )
}

/* -- Normal Mode: Alert Triage Board ------------------------------- */
function NormalSIEM({
  alerts,
  onUpdate,
}: {
  alerts: SiemAlert[]
  onUpdate: (id: string, patch: Partial<SiemAlert>) => void
}) {
  // The triage board shows alerts that still need a decision (untriaged).
  // Acknowledging (→assigned) or dismissing (→closed) removes the card, so both
  // actions visibly take effect.
  const open = alerts.filter((a) => a.status === 'new')
  const critical = open.filter((a) => a.severity === 'critical')
  const high = open.filter((a) => a.severity === 'high')
  const medium = open.filter((a) => a.severity === 'medium')

  const COLS = [
    { key: 'critical', label: 'Critical', items: critical, color: tk('magenta'), border: 'border-magenta/25', header: 'bg-magenta/10 text-magenta' },
    { key: 'high',     label: 'High',     items: high,     color: tk('threat'), border: 'border-threat/25',  header: 'bg-threat/10 text-threat'   },
    { key: 'medium',   label: 'Medium',   items: medium,   color: tk('amber'), border: 'border-amber/25',   header: 'bg-amber/10 text-amber'     },
  ]

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-white/5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between shrink-0">
        <div>
          <h1 className="font-display text-xl font-bold text-white">Alert Triage</h1>
          <p className="text-xs text-ink-500 mt-0.5">
            {open.length} open alert{open.length !== 1 ? 's' : ''} · review and action by severity
          </p>
        </div>
        <span className="flex items-center gap-1.5 text-[10px] px-2.5 py-1.5 rounded-full border border-safe/25 bg-safe/10 text-safe font-medium self-start">
          <Eye className="w-3 h-3" /> Normal mode
        </span>
      </div>

      {/* Board */}
      <div className="flex-1 overflow-y-auto p-6 space-y-5">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {COLS.map(({ key, label, items, color, border, header }) => (
            <div key={key} className={cn('glass border rounded-xl overflow-hidden flex flex-col', border)}>
              {/* Column header */}
              <div className={cn('flex items-center justify-between px-4 py-3', header)}>
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full" style={{ background: color }} />
                  <span className="text-sm font-semibold">{label}</span>
                </div>
                <span className="text-sm font-bold">{items.length}</span>
              </div>

              {/* Cards */}
              <div className="flex-1 overflow-y-auto p-3 space-y-2.5 min-h-[180px]">
                <AnimatePresence initial={false}>
                  {items.length === 0 ? (
                    <div className="py-10 text-center text-xs text-ink-600">
                      No {label.toLowerCase()} alerts
                    </div>
                  ) : (
                    items.map((a) => (
                      <motion.div
                        key={a.id}
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, height: 0 }}
                        className="glass border border-white/5 rounded-lg p-3.5 space-y-2.5 group"
                      >
                        <p className="text-sm text-ink-100 leading-snug group-hover:text-white transition-colors">{a.title}</p>
                        <div className="flex items-center gap-2 text-[10px] text-ink-500 font-mono flex-wrap">
                          <span>{a.srcIp}</span>
                          <span>·</span>
                          <span suppressHydrationWarning>
                            {new Date(a.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </span>
                          {a.hostname && <><span>·</span><span className="truncate">{a.hostname}</span></>}
                        </div>
                        <div className="flex gap-2">
                          <button
                            onClick={() => onUpdate(a.id, { status: 'assigned', owner: 'analyst' })}
                            className="flex-1 py-1.5 rounded-lg text-xs font-medium bg-safe/10 text-safe hover:bg-safe/20 transition-colors border border-safe/20"
                          >
                            Acknowledge
                          </button>
                          <button
                            onClick={() => onUpdate(a.id, { status: 'closed', disposition: 'false-positive' })}
                            className="py-1.5 px-3 rounded-lg text-xs text-ink-400 hover:text-ink-200 hover:bg-white/5 transition-colors border border-white/8"
                          >
                            Dismiss
                          </button>
                        </div>
                      </motion.div>
                    ))
                  )}
                </AnimatePresence>
              </div>
            </div>
          ))}
        </div>

        {/* Power mode CTA */}
        <div className="glass border border-white/5 rounded-xl p-4 flex items-center gap-4">
          <div className="p-2 rounded-lg bg-magenta/10 shrink-0">
            <Zap className="w-4 h-4 text-magenta" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-white">Need deeper analysis? Switch to Power User mode</p>
            <p className="text-[10px] text-ink-400 mt-0.5">
              Access KQL search, raw logs, correlation rules, threat hunting, MITRE ATT&CK coverage, and detailed alert timelines
            </p>
          </div>
          <span className="text-[10px] text-ink-500 shrink-0 hidden sm:block">Toggle in top bar →</span>
        </div>
      </div>
    </div>
  )
}

/* -- Main page ------------------------------------------------------ */
export default function SIEMPage() {
  const [mode] = useExperienceMode()
  const isNormal = mode === 'normal'
  const [tab, setTab] = useState<'queue' | 'analytics' | 'rules' | 'sources' | 'hunt' | 'fp-triage'>('queue')
  // Empty until the API answers - the alert queue is the API's to fill. An empty
  // queue on a real deployment is honest ("nothing detected yet"), not a cue to
  // show demo alerts. ALERTS is a first-load-offline fallback only (see loadSiem).
  const [alerts, setAlerts] = useState<SiemAlert[]>([])
  const loadedRef = useRef(false)
  // Separate render state for "first answer pending": the queue shows
  // skeleton rows instead of flashing "No alerts match" while loading.
  const [alertsPending, setAlertsPending] = useState(true)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const selectedAlert = alerts.find((a) => a.id === selectedId) ?? null

  const [apiKpis, setApiKpis] = useState<SiemKpis | null>(null)
  const [correlations, setCorrelations] = useState<Correlation[]>([])
  const [mitreDist, setMitreDist] = useState<typeof MITRE_DIST>([])
  // null = first answer still pending (analytics shows skeletons, never the
  // demo numbers); real data replaces it; SPARKLINE_DATA only ever appears
  // via the first-load-offline fallback below (same policy as ALERTS).
  const [trends, setTrends] = useState<SiemTrendDay[] | null>(null)
  const trendsLoadedRef = useRef(false)

  // Bulk FP-triage (Phase 3) - loaded on demand when the tab is opened, not
  // on every page load, since it's a heavier scored-working-set query.
  const [fpTriageItems, setFpTriageItems] = useState<FpTriageAlert[]>([])
  const [fpTriageLoading, setFpTriageLoading] = useState(false)
  const [fpTriageBand, setFpTriageBand] = useState<'all' | FpAssessment['band']>('all')
  const [fpSelected, setFpSelected] = useState<Set<string>>(new Set())
  const [fpDismissing, setFpDismissing] = useState(false)

  const loadFpTriage = useCallback((band: 'all' | FpAssessment['band']) => {
    setFpTriageLoading(true)
    fetchFpTriage({ band: band === 'all' ? undefined : band, limit: 200 })
      .then(({ items }) => { setFpTriageItems(items); setFpSelected(new Set()) })
      .catch(() => setFpTriageItems([]))
      .finally(() => setFpTriageLoading(false))
  }, [])

  useEffect(() => {
    if (tab === 'fp-triage') loadFpTriage(fpTriageBand)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab])

  function toggleFpSelected(id: string) {
    setFpSelected((s) => {
      const next = new Set(s)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  function dismissSelectedFp() {
    if (fpSelected.size === 0 || fpDismissing) return
    setFpDismissing(true)
    bulkDismissAlerts(Array.from(fpSelected))
      .then(() => { loadFpTriage(fpTriageBand); loadSiem() })
      .catch(() => {})
      .finally(() => setFpDismissing(false))
  }

  // Load alerts from API
  // Live refresh: the engine produces new alerts continuously, so poll the
  // queue and KPIs. Lifted to a callback so the Refresh button reuses it.
  const loadSiem = useCallback(() => {
    fetchSiemAlerts({ limit: '140', sort: 'ts', order: 'desc' })
      // The API answered → show its queue, even empty. Real deployment: honest.
      .then(({ items }) => { setAlerts(items as unknown as SiemAlert[]); loadedRef.current = true })
      // Only a FIRST-load failure (genuinely offline) falls back to the demo
      // set; a transient poll failure after a good load must not fabricate.
      .catch(() => { if (!loadedRef.current) setAlerts(ALERTS) })
      .finally(() => setAlertsPending(false))
    fetchSiemKpis().then(setApiKpis).catch(() => {})
    fetchCorrelations(2).then(setCorrelations).catch(() => {})
    fetchMitreDistribution()
      .then((rows) => setMitreDist(rows))
      .catch(() => { if (!loadedRef.current) setMitreDist(MITRE_DIST) })
    fetchSiemTrends()
      .then(({ days }) => { setTrends(days); trendsLoadedRef.current = true })
      // First-load-offline only: keep real data through transient poll failures
      .catch(() => {
        if (!trendsLoadedRef.current) {
          setTrends(SPARKLINE_DATA.alertVolume.map((v, i) => ({
            day: '', alerts: v, severe: 0,
            mttd: SPARKLINE_DATA.mttd[i], mttr: SPARKLINE_DATA.mttr[i],
            fpRate: SPARKLINE_DATA.fpRate[i],
          })))
        }
      })
  }, [])

  useEffect(() => {
    loadSiem()
    // Real-time push: refresh the moment the engine emits a tick or a new
    // alert; a slower poll remains as a safety net if the stream drops.
    const onLive = () => loadSiem()
    window.addEventListener('live:tick', onLive)
    window.addEventListener('live:alert.created', onLive)
    const t = setInterval(loadSiem, 30000)
    return () => {
      clearInterval(t)
      window.removeEventListener('live:tick', onLive)
      window.removeEventListener('live:alert.created', onLive)
    }
  }, [loadSiem])

  // Prefer live KPIs from the API; fall back to the static demo values.
  const metrics = useMemo(() => {
    if (!apiKpis) return METRICS
    return {
      ...METRICS,
      totalAlerts: apiKpis.totalAlerts,
      critical: apiKpis.critical,
      high: apiKpis.high,
      medium: apiKpis.medium,
      mttd: fmtMins(apiKpis.mttd),
      mttr: fmtMins(apiKpis.mttr),
      mtta: fmtMins(apiKpis.mtta),
      fpRate: apiKpis.fpRate,
      automationRate: apiKpis.automationRate,
      totalEps: apiKpis.totalEps,
      daysData: apiKpis.daysData,
    }
  }, [apiKpis])

  // Honest KPI-strip annotations, derived from real data (they were static
  // demo strings - "-12% vs yesterday", "+4 in last hour" - shown unchanged
  // next to live values). null on any piece means "not enough data": the
  // cell then shows an em-dash instead of inventing a movement.
  const kpiDerived = useMemo(() => {
    const t = trends
    const today = t && t.length >= 1 ? t[t.length - 1] : null
    const yday = t && t.length >= 2 ? t[t.length - 2] : null
    const alertsDeltaPct = today && yday && yday.alerts > 0
      ? Math.round(((today.alerts - yday.alerts) / yday.alerts) * 100)
      : null
    // 7-day averages over days that actually have telemetry (a 0 bucket means
    // "no data that day", not "instant response" - including it would fake an
    // improvement).
    const avgOf = (sel: (d: SiemTrendDay) => number) => {
      const vals = (t ?? []).map(sel).filter((v) => v > 0)
      return vals.length ? vals.reduce((s, v) => s + v, 0) / vals.length : null
    }
    const mttdAvg = avgOf((d) => d.mttd)
    const mttrAvg = avgOf((d) => d.mttr)
    const volume = (t ?? []).reduce((s, d) => s + d.alerts, 0)
    const fpAvg = volume > 0
      ? (t ?? []).reduce((s, d) => s + d.fpRate * d.alerts, 0) / volume
      : null
    const hourAgo = Date.now() - 3600_000
    const severeLastHour = alerts.filter((a) =>
      (a.severity === 'critical' || a.severity === 'high')
      && new Date(a.ts).getTime() >= hourAgo).length
    return { today, alertsDeltaPct, mttdAvg, mttrAvg, fpAvg, severeLastHour }
  }, [trends, alerts])

  // Mutate a single alert's triage fields (status/owner/disposition) in place
  async function updateAlert(id: string, patch: Partial<SiemAlert>) {
    setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, ...patch } : a)))
    try {
      await patchAlert(id, patch as Parameters<typeof patchAlert>[1])
    } catch { /* UI is already updated optimistically */ }
  }

  // Normal mode only exposes the alert queue; force tab back if a hidden one is active
  useEffect(() => { if (isNormal && tab !== 'queue') setTab('queue') }, [isNormal, tab])

  // Escape closes the alert detail panel
  useEffect(() => {
    if (!selectedId) return
    function onKey(e: KeyboardEvent) { if (e.key === 'Escape') setSelectedId(null) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [selectedId])
  const [search, setSearch] = useState('')
  // Deep-link: a ?q= param (from search, the detail drawer, or the ATT&CK
  // navigator) pre-filters the alert queue.
  useEffect(() => {
    const q = new URLSearchParams(window.location.search).get('q')
    if (q) setSearch(q)
  }, [])
  // Deep-link: ?alert=<id> opens that alert's detail drawer directly - case
  // and asset drawers link specific related alerts, and "go to the SIEM
  // module" is not an answer to "show me THIS alert". Runs once alerts are
  // loaded; if the id isn't in the loaded queue window, fall back to
  // filtering by it so the target is still findable.
  const alertDeepLinked = useRef(false)
  useEffect(() => {
    if (alertDeepLinked.current || alerts.length === 0) return
    alertDeepLinked.current = true
    const id = new URLSearchParams(window.location.search).get('alert')
    if (!id) return
    if (alerts.some((a) => a.id === id)) setSelectedId(id)
    else setSearch(id)
  }, [alerts])
  const [filterSev, setFilterSev] = useState<Severity | 'all'>('all')
  const [filterStatus, setFilterStatus] = useState<AlertStatus | 'all'>('all')
  const [filterTactic, setFilterTactic] = useState('All')
  const [ruleSearch, setRuleSearch] = useState('')
  // Alert table sorting (client-side over the loaded queue).
  const [alertSort, setAlertSort] = useState<{ col: 'ts' | 'riskScore'; dir: 'asc' | 'desc' }>({ col: 'ts', dir: 'desc' })
  function toggleSort(col: 'ts' | 'riskScore') {
    setAlertSort((s) => s.col === col ? { col, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { col, dir: 'desc' })
  }

  const filteredAlerts = useMemo(() => {
    const rows = alerts.filter((a) => {
      // Normal mode: only actionable alerts - open status, critical/high severity
      if (isNormal) {
        if (!['new', 'assigned', 'in-progress'].includes(a.status)) return false
        if (!['critical', 'high'].includes(a.severity)) return false
      }
      if (filterSev !== 'all' && a.severity !== filterSev) return false
      if (filterStatus !== 'all' && a.status !== filterStatus) return false
      if (filterTactic !== 'All' && a.mitreTactic !== filterTactic) return false
      if (search && !a.title.toLowerCase().includes(search.toLowerCase()) &&
          !a.ruleId.toLowerCase().includes(search.toLowerCase()) &&
          !(a.srcIp).includes(search)) return false
      return true
    })
    const dir = alertSort.dir === 'asc' ? 1 : -1
    return [...rows].sort((a, b) => {
      if (alertSort.col === 'riskScore') return (a.riskScore - b.riskScore) * dir
      return (Date.parse(a.ts) - Date.parse(b.ts)) * dir  // ts
    })
  }, [alerts, search, filterSev, filterStatus, filterTactic, isNormal, alertSort])

  // Windowing for very large queues (no-op under 150 rows; row ≈ 57px).
  const alertWindow = useWindowedRows(filteredAlerts, { rowHeight: 57 })

  const filteredRules = useMemo(() => RULES.filter((r) =>
    !ruleSearch || r.name.toLowerCase().includes(ruleSearch.toLowerCase()) || r.id.toLowerCase().includes(ruleSearch.toLowerCase())
  ), [ruleSearch])

  const openCount = alerts.filter((a) => ['new', 'assigned', 'in-progress'].includes(a.status)).length
  const criticalOpen = alerts.filter((a) => a.severity === 'critical' && ['new', 'assigned', 'in-progress'].includes(a.status)).length

  if (isNormal) return <NormalSIEM alerts={alerts} onUpdate={updateAlert} />

  return (
    <div className="flex h-full overflow-hidden">
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Page header */}
        <div className="px-6 py-4 border-b border-white/5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between shrink-0">
          <div>
            <h1 className="font-display text-xl font-bold text-white">Security Information & Event Management</h1>
            <p className="text-xs text-ink-500 mt-0.5">
              <span className="text-safe">{metrics.totalEps.toLocaleString()} EPS</span>
              <span className="text-ink-700 mx-1.5">·</span>
              <span>{openCount} open alerts</span>
              <span className="text-ink-700 mx-1.5">·</span>
              <span className="text-magenta">{criticalOpen} critical</span>
              <span className="text-ink-700 mx-1.5">·</span>
              <span>MTTD {metrics.mttd}</span>
              <span className="text-ink-700 mx-1.5">·</span>
              <span>MTTR {metrics.mttr}</span>
            </p>
          </div>
          <div className="flex items-center gap-2">
            <SavedViewsButton
              section="siem"
              filters={{ q: search, severity: filterSev, status: filterStatus, tactic: filterTactic }}
              onApply={(f) => {
                setSearch(f.q ?? '')
                setFilterSev((f.severity as Severity) ?? 'all')
                setFilterStatus((f.status as AlertStatus) ?? 'all')
                setFilterTactic(f.tactic ?? 'All')
                setTab('queue')
              }}
            />
            <ReportButton kind="siem" label="SIEM Detection" />
            <button onClick={loadSiem}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border border-white/10 text-ink-400 hover:text-white hover:border-white/20 bg-surface-2 transition-colors">
              <RefreshCw className="w-3 h-3" /> Refresh
            </button>
          </div>
        </div>

        {/* KPI strip - values count up; sub-annotations are computed from the
            trends buckets / live queue (previously static demo strings) */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-0 border-b border-white/5 shrink-0">
          {([
            {
              label: 'Total Alerts Today', color: 'text-white',
              value: <AnimatedNumber value={kpiDerived.today ? kpiDerived.today.alerts : metrics.totalAlerts} />,
              sub: kpiDerived.alertsDeltaPct !== null
                ? `${kpiDerived.alertsDeltaPct > 0 ? '+' : ''}${kpiDerived.alertsDeltaPct}% vs yesterday` : '-',
              up: (kpiDerived.alertsDeltaPct ?? 0) > 0,
            },
            {
              label: 'Critical / High', color: 'text-magenta',
              value: <><AnimatedNumber value={metrics.critical} /> / <AnimatedNumber value={metrics.high} /></>,
              sub: `+${kpiDerived.severeLastHour} in last hour`,
              up: kpiDerived.severeLastHour > 0,
            },
            {
              label: 'MTTD', color: 'text-safe', value: metrics.mttd,
              sub: kpiDerived.mttdAvg !== null ? `7d avg ${fmtMins(kpiDerived.mttdAvg)}` : '-',
              up: kpiDerived.mttdAvg !== null && !!apiKpis && apiKpis.mttd > kpiDerived.mttdAvg,
            },
            {
              label: 'MTTR', color: 'text-amber', value: metrics.mttr,
              sub: kpiDerived.mttrAvg !== null ? `7d avg ${fmtMins(kpiDerived.mttrAvg)}` : '-',
              up: kpiDerived.mttrAvg !== null && !!apiKpis && apiKpis.mttr > kpiDerived.mttrAvg,
            },
            {
              label: 'MTTA', color: 'text-safe', value: metrics.mtta,
              sub: apiKpis ? `< 15m target ${apiKpis.mtta < 15 ? '✓' : '✗'}` : '< 15m target',
              up: !!apiKpis && apiKpis.mtta >= 15,
            },
            {
              label: 'False Positive Rate', color: 'text-violet',
              value: <><AnimatedNumber value={metrics.fpRate} format={(v) => `${Math.round(v * 10) / 10}`} />%</>,
              sub: kpiDerived.fpAvg !== null ? `7d avg ${kpiDerived.fpAvg.toFixed(1)}%` : '-',
              up: kpiDerived.fpAvg !== null && !!apiKpis && apiKpis.fpRate > kpiDerived.fpAvg,
            },
          ] as Array<{ label: string; color: string; value: ReactNode; sub: string; up: boolean }>).map((k) => (
            <div key={k.label} className="px-4 py-3 border-r border-white/5 last:border-r-0">
              <p className="text-[10px] text-ink-600 uppercase tracking-wide">{k.label}</p>
              <p className={cn('text-lg font-bold mt-0.5', k.color)}>{k.value}</p>
              <p className={cn('text-[10px] mt-0.5', k.up ? 'text-threat' : 'text-safe')}>{k.sub}</p>
            </div>
          ))}
        </div>

        {/* Tab bar */}
        <div className="flex gap-6 px-6 border-b border-white/5 shrink-0 items-center">
          {([
            ['queue',      'Alert Queue',     Activity],
            ['fp-triage',  'FP Triage',       Gauge],
            ['hunt',       'Threat Hunting',  Terminal],
            ['analytics',  'Analytics',       BarChart2],
            ['rules',      'Detection Rules', Shield],
            ['sources',    'Data Sources',    Database],
          ] as const)
            .filter(([id]) => !isNormal || id === 'queue')
            .map(([id, label, Icon]) => (
            <button key={id} onClick={() => setTab(id as typeof tab)}
              className={cn('flex items-center gap-2 py-3 text-xs border-b-2 transition-colors',
                tab === id ? 'border-magenta text-white' : 'border-transparent text-ink-500 hover:text-ink-200')}>
              <Icon className="w-3.5 h-3.5" />
              {label}
              {id === 'queue' && openCount > 0 && (
                <span className="px-1.5 py-0.5 rounded-full text-[9px] font-bold bg-magenta/15 text-magenta border border-magenta/25">
                  {openCount}
                </span>
              )}
            </button>
          ))}
          <span className={cn('ml-auto flex items-center gap-1.5 text-[10px] px-2 py-1 rounded-full border',
            isNormal ? 'border-safe/25 bg-safe/10 text-safe' : 'border-magenta/25 bg-magenta/10 text-magenta')}>
            {isNormal ? <User className="w-3 h-3" /> : <Zap className="w-3 h-3" />}
            {isNormal ? 'Normal mode' : 'Power User'}
          </span>
        </div>

        {/* Tab content - keyed on the tab so switching replays a smooth
            fade-up enter (shared tokens from lib/motion). */}
        <div className="flex-1 overflow-hidden">
          <motion.div key={tab} variants={fadeInUp} initial="hidden" animate="show" className="h-full">
          {/* -- ALERT QUEUE ------------------------------------------- */}
          {tab === 'queue' && (
            <div className="flex flex-col h-full">
              {/* Filters */}
              <div className="flex flex-wrap items-center gap-2 px-4 py-2.5 border-b border-white/5 shrink-0">
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-2 border border-white/8 flex-1 min-w-[160px] max-w-xs">
                  <Search className="w-3 h-3 text-ink-500 shrink-0" />
                  <input value={search} onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search alerts, IPs, rules…"
                    className="flex-1 bg-transparent text-xs text-ink-200 placeholder-ink-600 focus:outline-hidden" />
                  {search && <button onClick={() => setSearch('')}><X className="w-3 h-3 text-ink-500" /></button>}
                </div>
                <MiniFilter label="Severity" value={filterSev}
                  options={['all', 'critical', 'high', 'medium', 'low', 'info']}
                  onChange={(v) => setFilterSev(v as Severity | 'all')} />
                <MiniFilter label="Status" value={filterStatus}
                  options={['all', 'new', 'assigned', 'in-progress', 'pending', 'resolved', 'closed']}
                  onChange={(v) => setFilterStatus(v as AlertStatus | 'all')} />
                <MiniFilter label="Tactic" value={filterTactic}
                  options={['All', ...Array.from(new Set(ALERTS.map((a) => a.mitreTactic)))]}
                  onChange={setFilterTactic} />
                <span className="text-[10px] text-ink-600 ml-auto">{filteredAlerts.length} alerts</span>
              </div>

              {/* Table header */}
              <div className={cn(ALERT_GRID, 'px-4 py-2 border-b border-white/5 text-[10px] text-ink-600 uppercase tracking-wide shrink-0')}>
                <span />
                <span>Alert / Rule</span>
                <span className="hidden md:block">MITRE</span>
                <span className="hidden lg:block">Entity</span>
                <button onClick={() => toggleSort('riskScore')}
                  className={cn('flex items-center gap-0.5 uppercase tracking-wide hover:text-ink-300 transition-colors',
                    alertSort.col === 'riskScore' && 'text-ink-300')}>
                  Risk
                  {alertSort.col === 'riskScore' && (
                    <ChevronDown className={cn('w-3 h-3 transition-transform', alertSort.dir === 'asc' && 'rotate-180')} />
                  )}
                </button>
                <span className="hidden sm:block">Status</span>
                <button onClick={() => toggleSort('ts')}
                  className={cn('flex items-center gap-0.5 uppercase tracking-wide hover:text-ink-300 transition-colors',
                    alertSort.col === 'ts' && 'text-ink-300')}>
                  Time
                  {alertSort.col === 'ts' && (
                    <ChevronDown className={cn('w-3 h-3 transition-transform', alertSort.dir === 'asc' && 'rotate-180')} />
                  )}
                </button>
              </div>

              {/* Rows - windowed above 150 alerts so huge queues stay smooth
                  (spacer padding preserves the scrollbar; no-op below that) */}
              <div className="flex-1 overflow-y-auto" {...alertWindow.containerProps}>
                {filteredAlerts.length === 0 ? (
                  alertsPending ? (
                    <SkeletonRows rows={10} />
                  ) : (
                    <div className="flex flex-col items-center justify-center h-32 text-xs text-ink-600">
                      No alerts match the current filters
                    </div>
                  )
                ) : (
                  <>
                    {alertWindow.topPad > 0 && <div style={{ height: alertWindow.topPad }} />}
                    {alertWindow.visible.map(({ item: alert, index: i }) => (
                      <AlertRow key={alert.id} alert={alert}
                        idx={alertWindow.virtualized ? 0 : i}
                        selected={selectedId === alert.id}
                        onClick={() => setSelectedId((id) => id === alert.id ? null : alert.id)} />
                    ))}
                    {alertWindow.bottomPad > 0 && <div style={{ height: alertWindow.bottomPad }} />}
                  </>
                )}
              </div>
            </div>
          )}

          {/* -- FP TRIAGE (bulk, Phase 3) ---------------------------- */}
          {tab === 'fp-triage' && (
            <div className="flex flex-col h-full">
              <div className="flex flex-wrap items-center gap-2 px-4 py-2.5 border-b border-white/5 shrink-0">
                <MiniFilter label="Band" value={fpTriageBand}
                  options={['all', 'likely-fp', 'uncertain', 'likely-real']}
                  onChange={(v) => { const b = v as typeof fpTriageBand; setFpTriageBand(b); loadFpTriage(b) }} />
                <span className="text-[10px] text-ink-600">
                  {fpTriageLoading ? 'Scoring…' : `${fpTriageItems.length} scored, advisory only`}
                </span>
                <button onClick={() => loadFpTriage(fpTriageBand)}
                  className="p-1.5 rounded-lg text-ink-500 hover:text-magenta hover:bg-magenta/10 transition-colors">
                  <RefreshCw className={cn('w-3.5 h-3.5', fpTriageLoading && 'animate-spin')} />
                </button>
                <button
                  onClick={() => setFpSelected(new Set(
                    fpSelected.size === fpTriageItems.length ? [] : fpTriageItems.map((a) => a.id)))}
                  className="text-[10px] text-ink-500 hover:text-ink-200 ml-2">
                  {fpSelected.size === fpTriageItems.length && fpTriageItems.length > 0 ? 'Deselect all' : 'Select all'}
                </button>
                <button onClick={dismissSelectedFp} disabled={fpSelected.size === 0 || fpDismissing}
                  className="ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-semibold
                    bg-safe/15 border border-safe/30 text-safe hover:bg-safe/25 transition-colors
                    disabled:opacity-40 disabled:cursor-not-allowed">
                  {fpDismissing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle className="w-3.5 h-3.5" />}
                  Dismiss selected ({fpSelected.size})
                </button>
              </div>
              {/* keyed on band + count: the items arrive async, and children
                  mounting into an already-"show" parent don't animate - the
                  remount on data arrival is what makes the stagger play. */}
              <motion.div key={`${fpTriageBand}-${fpTriageItems.length}`}
                variants={listContainer()} initial="hidden" animate="show"
                className="flex-1 overflow-y-auto divide-y divide-white/4">
                {fpTriageLoading && fpTriageItems.length === 0 && <SkeletonRows rows={8} />}
                {!fpTriageLoading && fpTriageItems.length === 0 && (
                  <p className="text-xs text-ink-600 text-center py-10">
                    No open alerts matched this band in the scored working set.
                  </p>
                )}
                {fpTriageItems.map((a) => (
                  <motion.label key={a.id} variants={listItem}
                    className="flex items-center gap-3 px-4 py-2.5 hover:bg-white/3 transition-colors cursor-pointer">
                    <input type="checkbox" checked={fpSelected.has(a.id)}
                      onChange={() => toggleFpSelected(a.id)}
                      className="w-3.5 h-3.5 rounded-sm accent-magenta shrink-0" />
                    <span className={cn('px-1.5 py-0.5 rounded-sm text-[9px] font-bold uppercase shrink-0', SEV[a.severity].bg, SEV[a.severity].text)}>
                      {a.severity}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs text-ink-200 truncate">{a.title}</p>
                      <p className="text-[10px] text-ink-600 truncate">{a.ruleName} · {timeAgo(a.ts)}</p>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded-full uppercase font-semibold shrink-0"
                      style={{ color: FP_BAND_STYLE[a.fpBand].color, background: `${FP_BAND_STYLE[a.fpBand].color}18` }}>
                      {FP_BAND_STYLE[a.fpBand].label} · {a.fpScore}
                    </span>
                  </motion.label>
                ))}
              </motion.div>
            </div>
          )}

          {/* -- THREAT HUNTING --------------------------------------- */}
          {tab === 'hunt' && <ThreatHunt />}

          {/* -- ANALYTICS -------------------------------------------- */}
          {tab === 'analytics' && (
            <div className="overflow-y-auto h-full p-6 space-y-6">
              {/* Metric trend row - live per-day buckets from
                  /siem/analytics/trends; skeletons until the first answer */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                {trends === null ? (
                  ['Alert Volume (7d)', 'MTTD (min)', 'MTTR (min)', 'False Positive %'].map((label) => (
                    <div key={label} className="bg-surface-2/40 rounded-xl p-4 border border-white/5">
                      <p className="text-[11px] text-ink-500">{label}</p>
                      <Skeleton className="h-6 w-20 mt-1.5" />
                      <Skeleton className="h-7 w-full mt-3" />
                      <div className="flex justify-between text-[9px] text-ink-700 mt-1">
                        <span>7 days ago</span><span>Today</span>
                      </div>
                    </div>
                  ))
                ) : (
                  [
                    { label: 'Alert Volume (7d)', data: trends.map((d) => d.alerts), color: tk('threat'), unit: 'alerts/day' },
                    { label: 'MTTD (min)',        data: trends.map((d) => d.mttd),   color: tk('safe'), unit: 'minutes' },
                    { label: 'MTTR (min)',        data: trends.map((d) => d.mttr),   color: tk('amber'), unit: 'minutes' },
                    { label: 'False Positive %',  data: trends.map((d) => d.fpRate), color: tk('violet'), unit: 'percent' },
                  ].map((m) => (
                    <div key={m.label} className="bg-surface-2/40 rounded-xl p-4 border border-white/5">
                      <p className="text-[11px] text-ink-500">{m.label}</p>
                      <p className="text-xl font-bold text-white mt-1">{m.data[m.data.length - 1]}<span className="text-[11px] text-ink-600 ml-1">{m.unit}</span></p>
                      <div className="mt-2"><MiniSparkline data={m.data} color={m.color} /></div>
                      <div className="flex justify-between text-[9px] text-ink-700 mt-1">
                        <span>7 days ago</span><span>Today</span>
                      </div>
                    </div>
                  ))
                )}
              </div>

              {/* MITRE distribution */}
              <div className="bg-surface-2/40 rounded-xl p-4 border border-white/5">
                <p className="text-xs font-semibold text-white mb-4">Alert Volume by MITRE ATT&CK Tactic (last 7 days)</p>
                <div className="space-y-2.5">
                  {mitreDist.map((t) => (
                    <div key={t.tactic} className="flex items-center gap-3">
                      <span className="text-[11px] text-ink-400 w-44 shrink-0">{t.tactic}</span>
                      <div className="flex-1 h-2.5 bg-white/5 rounded-full overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${(t.count / mitreDist[0].count) * 100}%` }}
                          transition={{ duration: 0.6, delay: 0.1 }}
                          className="h-full rounded-full"
                          style={{ background: t.color }}
                        />
                      </div>
                      <span className="text-[11px] font-mono text-ink-500 w-12 text-right">{t.count.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Live alert correlations (grouped by shared pivot) */}
              {correlations.length > 0 && (
                <div className="bg-surface-2/40 rounded-xl p-4 border border-white/5">
                  <div className="flex items-center justify-between mb-4">
                    <p className="text-xs font-semibold text-white">Correlated Alert Clusters</p>
                    <span className="text-[10px] text-ink-600">
                      {correlations.length} cluster{correlations.length === 1 ? '' : 's'} · grouped by shared entity
                    </span>
                  </div>
                  <div className="space-y-2">
                    {correlations.slice(0, 8).map((c) => {
                      const PivotIcon = c.pivot === 'src_ip' ? Network : c.pivot === 'hostname' ? Server : User
                      const sev = SEV[c.severity]
                      return (
                        <div key={`${c.pivot}:${c.value}`} className="flex items-center gap-3 p-2.5 rounded-lg bg-white/2 border border-white/5">
                          <div className="p-1.5 rounded-lg shrink-0" style={{ background: `${sev.dot}18` }}>
                            <PivotIcon className="w-3.5 h-3.5" style={{ color: sev.dot }} />
                          </div>
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2">
                              <span className="text-[11px] font-mono text-ink-200 truncate">{c.value}</span>
                              <span className="text-[9px] text-ink-600 uppercase tracking-wide shrink-0">{c.pivot.replace('_', ' ')}</span>
                            </div>
                            <p className="text-[10px] text-ink-500 truncate mt-0.5">
                              {c.alerts.slice(0, 3).map((a) => a.title).join(' · ')}
                              {c.alerts.length > 3 && ` +${c.alerts.length - 3} more`}
                            </p>
                          </div>
                          <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full border font-semibold shrink-0 uppercase', sev.bg, sev.text, sev.border)}>
                            {c.severity}
                          </span>
                          <span className="text-[11px] font-mono text-ink-300 w-14 text-right shrink-0">
                            {c.alertCount} <span className="text-ink-600">hits</span>
                          </span>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* Alert funnel + severity breakdown */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="bg-surface-2/40 rounded-xl p-4 border border-white/5">
                  <p className="text-xs font-semibold text-white mb-4">Alert Triage Funnel</p>
                  {[
                    { stage: 'Total Alerts',    count: alerts.length, color: tk('violet') },
                    { stage: 'Acknowledged',    count: alerts.filter(a => a.status !== 'new').length, color: tk('amber') },
                    { stage: 'Investigated',    count: alerts.filter(a => ['in-progress','resolved','closed'].includes(a.status)).length, color: tk('teal') },
                    { stage: 'Escalated',       count: alerts.filter(a => ['resolved','closed'].includes(a.status)).length, color: tk('threat') },
                    { stage: 'True Positives',  count: alerts.filter(a => a.disposition === 'true-positive').length, color: tk('magenta') },
                  ].map((f, i, arr) => (
                    <div key={f.stage} className="flex items-center gap-3 mb-2">
                      <span className="text-[11px] text-ink-400 w-36 shrink-0">{f.stage}</span>
                      <div className="flex-1 h-5 bg-white/5 rounded-lg overflow-hidden relative">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${(f.count / arr[0].count) * 100}%` }}
                          transition={{ duration: 0.5, delay: i * 0.07 }}
                          className="h-full rounded-lg flex items-center justify-end pr-2"
                          style={{ background: f.color + '40' }}
                        >
                          <span className="text-[9px] font-bold" style={{ color: f.color }}>{f.count.toLocaleString()}</span>
                        </motion.div>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="bg-surface-2/40 rounded-xl p-4 border border-white/5">
                  <p className="text-xs font-semibold text-white mb-4">Severity Distribution</p>
                  {(() => {
                    const sevs = [
                      { sev: 'Critical', key: 'critical', color: tk('magenta') },
                      { sev: 'High',     key: 'high',     color: tk('threat') },
                      { sev: 'Medium',   key: 'medium',   color: tk('amber') },
                      { sev: 'Low',      key: 'low',      color: tk('safe') },
                      { sev: 'Info',     key: 'info',     color: tk('violet') },
                    ].map((s) => ({ ...s, count: alerts.filter(a => a.severity === s.key).length }))
                    const max = Math.max(1, ...sevs.map(s => s.count))
                    return sevs.map((s, i) => (
                    <div key={s.sev} className="flex items-center gap-3 mb-2">
                      <span className="text-[11px] w-16 shrink-0" style={{ color: s.color }}>{s.sev}</span>
                      <div className="flex-1 h-3 bg-white/5 rounded-full overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${(s.count / max) * 100}%` }}
                          transition={{ duration: 0.5, delay: i * 0.07 }}
                          className="h-full rounded-full"
                          style={{ background: s.color }}
                        />
                      </div>
                      <span className="text-[11px] font-mono text-ink-500 w-10 text-right">{s.count.toLocaleString()}</span>
                    </div>
                    ))
                  })()}
                </div>
              </div>

              {/* KPI table */}
              <div className="bg-surface-2/40 rounded-xl border border-white/5">
                <div className="px-4 py-3 border-b border-white/5">
                  <p className="text-xs font-semibold text-white">SOC KPI Summary</p>
                </div>
                <div className="divide-y divide-white/5">
                  {[
                    { metric: 'Mean Time to Detect (MTTD)',      value: metrics.mttd, target: '< 10m', status: apiKpis ? (apiKpis.mttd < 10 ? 'good' : 'warn') : 'good' },
                    { metric: 'Mean Time to Acknowledge (MTTA)', value: metrics.mtta, target: '< 15m', status: apiKpis ? (apiKpis.mtta < 15 ? 'good' : 'warn') : 'good' },
                    { metric: 'Mean Time to Respond (MTTR)',     value: metrics.mttr, target: '< 30m', status: apiKpis ? (apiKpis.mttr < 30 ? 'good' : 'warn') : 'good' },
                    { metric: 'False Positive Rate',             value: `${metrics.fpRate}%`, target: '< 20%', status: apiKpis ? (apiKpis.fpRate < 20 ? 'good' : 'warn') : 'warn' },
                    { metric: 'Alert-to-Incident Escalation',
                      value: `${alerts.length ? Math.round(alerts.filter(a => ['resolved','closed'].includes(a.status)).length / alerts.length * 100) : 0}%`,
                      target: '1-10%', status: 'good' },
                    { metric: 'Automation Rate (SOAR)',          value: `${metrics.automationRate}%`, target: '> 60%', status: apiKpis ? (apiKpis.automationRate > 60 ? 'good' : 'warn') : 'good' },
                  ].map((row) => (
                    <div key={row.metric} className="grid grid-cols-3 px-4 py-2.5 text-xs">
                      <span className="text-ink-300">{row.metric}</span>
                      <span className={cn('font-mono', row.status === 'good' ? 'text-safe' : 'text-amber')}>{row.value}</span>
                      <span className="text-ink-600">Target: {row.target}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* ATT&CK coverage matrix - Power User */}
              <MitreCoverageMatrix />
            </div>
          )}

          {/* -- DETECTION RULES --------------------------------------- */}
          {tab === 'rules' && (
            <div className="flex flex-col h-full">
              <div className="flex items-center gap-3 px-4 py-2.5 border-b border-white/5 shrink-0">
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-2 border border-white/8 flex-1 max-w-xs">
                  <Search className="w-3 h-3 text-ink-500 shrink-0" />
                  <input value={ruleSearch} onChange={(e) => setRuleSearch(e.target.value)}
                    placeholder="Search rules…"
                    className="flex-1 bg-transparent text-xs text-ink-200 placeholder-ink-600 focus:outline-hidden" />
                </div>
                <span className="text-[10px] text-ink-600 ml-auto">{filteredRules.length} rules</span>
              </div>
              <div className="grid grid-cols-[1fr_80px_90px_60px_60px_50px_60px_48px] gap-3 px-4 py-2 border-b border-white/5 text-[10px] text-ink-600 uppercase tracking-wide shrink-0">
                <span>Rule Name</span>
                <span>Source</span>
                <span className="hidden lg:block">Tactic</span>
                <span>Severity</span>
                <span>Fired 7d</span>
                <span>FP%</span>
                <span>Last Fired</span>
                <span>State</span>
              </div>
              <div className="flex-1 overflow-y-auto">
                {filteredRules.map((rule, i) => (
                  <RuleRow key={rule.id} rule={rule} idx={i} />
                ))}
              </div>
            </div>
          )}

          {/* -- DATA SOURCES ------------------------------------------ */}
          {tab === 'sources' && (
            <div className="overflow-y-auto h-full p-4">
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                {DATA_SOURCES.map((src) => (
                  <div key={src.name} className="bg-surface-2/40 rounded-xl p-4 border border-white/5 flex items-start gap-3">
                    <div className={cn('mt-0.5 w-2 h-2 rounded-full shrink-0',
                      src.status === 'healthy' ? 'bg-safe' : src.status === 'degraded' ? 'bg-amber animate-pulse' : 'bg-threat')} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 justify-between">
                        <p className="text-xs font-medium text-white">{src.name}</p>
                        <span className={cn('text-[9px] px-1.5 py-0.5 rounded-sm font-semibold uppercase',
                          src.status === 'healthy' ? 'bg-safe/10 text-safe' : src.status === 'degraded' ? 'bg-amber/10 text-amber' : 'bg-threat/10 text-threat')}>
                          {src.status}
                        </span>
                      </div>
                      <p className="text-[10px] text-ink-600 mt-0.5">{src.type}</p>
                      <div className="grid grid-cols-3 gap-2 mt-2 text-[10px]">
                        <div><p className="text-ink-600">EPS</p><p className="text-ink-300 font-mono">{src.eps.toLocaleString()}</p></div>
                        <div><p className="text-ink-600">Last Event</p><p className={cn('font-mono', src.status !== 'healthy' ? 'text-amber' : 'text-safe')}>{src.lastEvent}</p></div>
                        <div><p className="text-ink-600">7d Events</p><p className="text-ink-300 font-mono">{src.events7d}</p></div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          </motion.div>
        </div>
      </div>

      {/* Alert detail side panel */}
      <AnimatePresence>
        {selectedAlert && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-50 bg-black/40 backdrop-blur-xs"
              onClick={() => setSelectedId(null)}
            />
            <AlertDetail alert={selectedAlert} onClose={() => setSelectedId(null)} simplified={isNormal} onUpdate={updateAlert} />
          </>
        )}
      </AnimatePresence>
    </div>
  )
}

/* -- Alert table row ------------------------------------------------ */
function AlertRow({ alert, idx, selected, onClick }: {
  alert: SiemAlert; idx: number; selected: boolean; onClick: () => void
}) {
  const s = SEV[alert.severity]
  const st = STATUS_LABEL[alert.status]

  return (
    <motion.div
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: idx * 0.025, duration: 0.25 }}
      onClick={onClick}
      className={cn(
        ALERT_GRID, 'px-4 py-2.5 border-b border-white/4 cursor-pointer transition-colors',
        selected ? 'bg-magenta/8 border-l-2 border-l-magenta' : 'hover:bg-white/3',
        alert.status === 'closed' || alert.status === 'resolved' ? 'opacity-50' : '',
      )}
    >
      {/* Severity dot */}
      <span className="w-2 h-2 rounded-full shrink-0" style={{ background: s.dot }} />

      {/* Title + rule */}
      <div className="min-w-0">
        <p className="text-xs text-ink-200 truncate">{alert.title}</p>
        <div className="flex items-center gap-2 mt-0.5">
          <span className="text-[10px] font-mono text-ink-700">{alert.ruleId}</span>
          {alert.tiHits > 0 && (
            <span className="text-[9px] px-1 py-0.5 rounded-sm bg-threat/10 text-threat border border-threat/20 font-semibold">
              {alert.tiHits} TI
            </span>
          )}
        </div>
      </div>

      {/* MITRE */}
      <div className="hidden md:block text-[10px] font-mono text-violet truncate">{alert.mitreTechId}</div>

      {/* Entity */}
      <div className="hidden lg:block text-[10px] text-ink-500 truncate font-mono">
        {alert.username ?? alert.hostname ?? alert.srcIp}
      </div>

      {/* Risk score */}
      <div className="flex items-center">
        <span className={cn('text-xs font-bold',
          alert.riskScore >= 90 ? 'text-magenta' : alert.riskScore >= 70 ? 'text-threat' :
          alert.riskScore >= 50 ? 'text-amber' : 'text-safe')}>
          {alert.riskScore}
        </span>
      </div>

      {/* Status */}
      <span className={cn('hidden sm:block text-[10px] capitalize', st.color)}>{st.label}</span>

      {/* Time */}
      <span suppressHydrationWarning className="text-[10px] text-ink-600 truncate">{timeAgo(alert.ts)}</span>
    </motion.div>
  )
}

/* -- Rule table row ------------------------------------------------- */
function RuleRow({ rule }: { rule: CorrelationRule; idx: number }) {
  const [enabled, setEnabled] = useState(rule.enabled)
  const s = SEV[rule.severity]

  return (
    <div className={cn(
      'grid grid-cols-[1fr_80px_90px_60px_60px_50px_60px_48px] gap-3 items-center px-4 py-2.5 border-b border-white/4 hover:bg-white/2 transition-colors text-xs',
      !enabled && 'opacity-40',
    )}>
      <div className="min-w-0">
        <p className="text-ink-200 truncate">{rule.name}</p>
        <p className="text-[10px] font-mono text-ink-700 mt-0.5">{rule.id}</p>
      </div>
      <span className="text-[11px] text-ink-500">{rule.source}</span>
      <span className="hidden lg:block text-[11px] text-violet truncate">{rule.mitreTactic}</span>
      <span className={cn('text-[10px] font-semibold uppercase', s.text)}>{rule.severity}</span>
      <span className="text-[11px] font-mono text-ink-400">{rule.firedLast7d.toLocaleString()}</span>
      <span className={cn('text-[11px] font-mono', rule.fpRate > 30 ? 'text-threat' : rule.fpRate > 15 ? 'text-amber' : 'text-safe')}>{rule.fpRate}%</span>
      <span className="text-[10px] text-ink-600">{rule.lastFired}</span>
      <button onClick={() => setEnabled((e) => !e)}
        className={cn('w-8 h-5 rounded-full transition-colors relative', enabled ? 'bg-safe/30' : 'bg-white/10')}>
        <span className={cn('absolute top-0.5 w-3.5 h-3.5 rounded-full transition-all',
          enabled ? 'bg-safe right-0.5' : 'bg-ink-600 left-0.5')} />
      </button>
    </div>
  )
}

/* -- Mini filter select --------------------------------------------- */
function MiniFilter({ value, options, onChange }: {
  label: string; value: string; options: string[]; onChange: (v: string) => void
}) {
  return (
    <div className="relative">
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={cn(
          'appearance-none px-3 py-1.5 pr-6 rounded-lg text-xs border bg-surface-2 focus:outline-hidden cursor-pointer transition-colors',
          value !== 'all' && value !== 'All'
            ? 'border-magenta/30 text-magenta bg-magenta/5'
            : 'border-white/8 text-ink-400 hover:text-ink-200 hover:border-white/15',
        )}
      >
        {options.map((o) => (
          <option key={o} value={o} className="bg-[#100A1C] text-ink-200 capitalize">
            {o.charAt(0).toUpperCase() + o.slice(1).replace('-', ' ')}
          </option>
        ))}
      </select>
      <ChevronDown className="w-3 h-3 text-ink-500 absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none" />
    </div>
  )
}
