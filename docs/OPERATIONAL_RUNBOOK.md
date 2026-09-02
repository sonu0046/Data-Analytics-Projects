# 📘 Vendor Bank-Change Fraud Guardian — Operational Runbook & Production Deployment Guide
**PRD Version:** v1.1  
**Architecture:** 4-Brothers Multi-Tenant Zero-Trust Defense-in-Depth  
**Target Environment:** DEV ➔ STAGING ➔ PRODUCTION  

---

## 1. System Overview & Core Guardrails

The Vendor Bank-Change Fraud Guardian provides multi-layered protection against unauthorized and fraudulent vendor bank account modifications.

### 🛡️ Non-Negotiable Invariants:
1. **Zero Client Trust:** All financial state transitions, validations, and audit logs execute exclusively via PostgreSQL Security Definer RPCs and Row Level Security (RLS).
2. **Dual-Control Separation:** A Maker who performs out-of-band phone verification can NEVER approve the request. Checker approval requires Step-Up MFA (AAL2).
3. **Deterministic 48-Hour Cooling-Off:** Bank account activation is strictly delayed by 48 authoritative hours from checker approval.
4. **Immutable Append-Only Audit:** `audit_logs`, `notification_deliveries`, and `incident_transitions` tables permanently reject `UPDATE` and `DELETE` operations via database triggers.
5. **PII Masking by Default:** Raw bank account numbers, IFSC, PAN, and GSTIN are masked prior to notification delivery or LLM inference.

---

## 2. Deployment & Environment Configuration

### Environment Topology:
- **DEV:** Local development with mock SMTP/SMS adapters.
- **STAGING:** Full Supabase staging environment with end-to-end integration tests.
- **PRODUCTION:** High-availability deployment with strict CORS, HSTS, and SIEM webhooks.

### Production Environment Variables (`.env`):
```ini
ENVIRONMENT=PRODUCTION
SUPABASE_URL=https://<your-project-ref>.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<secure-backend-service-key>
SUPABASE_ANON_KEY=<public-anon-key>
JWT_SECRET_KEY=<secure-jwt-signing-key>
ALLOWED_ORIGINS=https://app.fraudguardian.internal,https://console.fraudguardian.internal
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USER=apikey
SMTP_PASSWORD=<production-sendgrid-key>
SMTP_FROM_EMAIL=security@fraudguardian.internal
TWILIO_ACCOUNT_SID=<production-twilio-sid>
TWILIO_AUTH_TOKEN=<production-twilio-token>
```

---

## 3. Database Migration Runbook (Supabase SQL)

Deploy migrations in numerical sequence:
1. `20260830000001_step1_database_foundation.sql` — Base tables, RLS policies, indexes.
2. `20260902000001_intake_change_request_rpc.sql` — Atomic ingestion RPC.
3. `20260902000002_maker_verify_request_rpc.sql` — Maker phone verification RPC.
4. `20260902000003_checker_approve_request_rpc.sql` — Checker MFA approval & cooling-off RPC.
5. `20260902000004_notifications_schema.sql` — Notification queue & immutable delivery ledger.
6. `20260902000005_monitoring_alerts_schema.sql` — Alerts, incidents, and transition state machine.

---

## 4. Disaster Recovery & Backup Procedures

### RPO & RTO Targets:
- **Recovery Point Objective (RPO):** < 5 Minutes (Continuous WAL replication).
- **Recovery Time Objective (RTO):** < 15 Minutes.

### Recovery Execution:
1. Run automated schema manifest integrity check:
   ```bash
   python scripts/backup_and_recovery.py
   ```
2. Verify table point-in-time state.
3. If primary database region fails, redirect traffic to secondary Supabase standby.

---

## 5. Rollback Runbook (Zero Financial Data Loss)

If a release defect is detected post-deployment:
1. **Application Rollback:** Revert container image to previous tag:
   ```bash
   docker service update --image fraud-guardian:v1.0.9 fraud_guardian_app
   ```
2. **Database Backward Compatibility:** All Step 1–8 migrations are backward compatible (additive columns & non-breaking RPC signatures).
3. **Fail-Closed Fallback:** In the event of an infrastructure anomaly, the Deterministic Risk Engine defaults to `MANUAL_SYS_OVERRIDE` (Fail-Secure).

---

## 6. Incident Triage & Emergency Response Runbook

| Severity | Event Type | Response SLA | Action Required |
| :--- | :--- | :---: | :--- |
| **P1 — CRITICAL** | `CRITICAL_SPOOF_BLOCK` / `VELOCITY_ANOMALY` | < 15 Mins | Freeze affected vendor account; notify Chief Risk Officer. |
| **P2 — HIGH** | `MAKER_CHECKER_MISMATCH` / `MFA_FAILURE_SPIKE` | < 1 Hour | Review audit logs; initiate vendor out-of-band contact check. |
| **P3 — WARNING** | `ANTI_STORM_THROTTLE` / `NOTIFICATION_RETRY` | < 4 Hours | Inspect SMTP connectivity; review delivery ledger logs. |

---

## 7. Emergency Contacts & Sign-Off Matrix

- **1st Brother (Architecture & Governance):** Final Go-Live Clearance
- **2nd Brother (Security & Code Audit):** Independent Penetration Sign-Off
- **3rd Brother (Risk & Logic Integrity):** Compliance & Anti-Fraud Verification
- **4th Brother (Antigravity):** Live Implementation, Telemetry & SRE Execution
