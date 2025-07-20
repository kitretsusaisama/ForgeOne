# ForgeOne Agile Retrospectives (End-User, Production-Ready)

*Retrospectives in ForgeOne are a structured, auditable process for continuous improvement, security, and user value. Every session is designed for traceability, compliance, and actionable outcomes that directly impact end users and production reliability.*

## 1. Retrospective Process (Step-by-Step)
1. **Preparation**
   - Gather sprint metrics, user feedback, incident reports, and compliance/audit logs.
   - Schedule session with all relevant roles (see below).
2. **Session Kickoff**
   - Review sprint goal, delivered value, and production incidents.
   - Reiterate end-user and compliance priorities.
3. **What Went Well**
   - Identify successes in user experience, security, compliance, and delivery.
   - Highlight production wins (e.g., zero downtime, audit pass, user praise).
4. **What Needs Improvement**
   - Analyze user pain points, security/compliance gaps, and production issues.
   - Use real data: incident logs, user tickets, audit findings.
5. **Root Cause Analysis**
   - For each issue, perform a blameless RCA (5 Whys, Fishbone, etc.).
   - Document findings for traceability.
6. **Action Items & Owners**
   - Define concrete, measurable actions (with owners, deadlines, and KPIs).
   - Actions must address user value, security, compliance, and production readiness.
7. **Review of Previous Actions**
   - Check completion and effectiveness of last retrospective's actions.
   - Audit for traceability and compliance.
8. **Session Close & Documentation**
   - Summarize outcomes, decisions, and next steps.
   - Store minutes in an immutable, auditable log (see compliance).

## 2. Roles & Responsibilities
- **Scrum Master/Facilitator:** Guides process, ensures focus on user and compliance outcomes.
- **Product Owner:** Brings user feedback, sets priorities.
- **Dev Team:** Provides technical insights, root cause analysis, and action proposals.
- **Security/Compliance Lead:** Ensures all actions meet regulatory and audit requirements.
- **SRE/DevOps:** Reports on production incidents, reliability, and monitoring.

## 3. Integration with Compliance & Security
- All retrospectives are logged and auditable (SOC2, ISO 27001, GDPR).
- Action items must include security, compliance, and documentation tasks.
- Evidence of improvement is collected for audits.

## 4. Real-World Example
- **Incident:** User login outage detected in production.
- **Analysis:** Root cause traced to expired certificate, not caught by monitoring.
- **Action:** Implement automated cert expiry checks, update runbooks, add alerting.
- **Owner:** SRE, deadline next sprint.
- **Audit:** Action completion and effectiveness reviewed in next retrospective.

## 5. Traceability & Audit
- All findings, actions, and outcomes are stored in a versioned, immutable log.
- Each action is linked to a user story, compliance requirement, or production incident.
- Retrospective effectiveness is measured by reduction in repeat issues and improved user KPIs.

## 6. Continuous Improvement Loop
- Retrospectives are held at the end of every sprint and after major incidents.
- Lessons learned are fed into sprint planning, documentation, and compliance processes.
- Continuous feedback from users and audits drives ongoing improvement.
