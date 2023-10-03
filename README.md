# Security Expert Samenvatting


## Week 2 - AppSec - DevSecOps Principles

- Basic CICD Opfrissing
- In welke omgevingen zijn DevecOps belangrijk? Banking, Social media, ECommerce
- Security Policies detection tools, training van dev
- Shift Left Security
- Holistic Automation
- Continuous Security Testing
- Security as Code
- Traceability, Auditability, Visibility
- Continuous Improvement


## Week 3 - AppSec - DevSecOps Practices

## Week 4 - AppSec - DevSecOps Practices SIEM vs SOAR
### Overview & Description
Logging and monitoring can be challenging to test. There isn't much CVE/CVSS data for this category, but detecting and responding to breaches is critical. Still, it can be very impactful for accountability, visibility, incident alerting, and forensics.

This category is to help detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs any time:

    - Auditable events, such as logins, failed logins, and high-value transactions, are not logged.
    - Warnings and errors generate no, inadequate, or unclear log messages.
    - Logs of applications and APIs are not monitored for suspicious activity.
    - Logs are only stored locally.
    - Appropriate alerting thresholds and response escalation processes are not in place or effective.
    - Penetration testing and scans by dynamic application security testing (DAST) tools (such as OWASP ZAP) do not trigger alerts.
    - The application cannot detect, escalate, or alert for active attacks in real-time or near real-time.

![overview_photo](./assets/images/intro_picture.png)
### How to Prevent
Developers should implement some or all the following controls, depending on the risk of the application:

	- Ensure all login, access control, and server-side input validation failures can be logged **with sufficient user context** to identify suspicious or malicious accounts and **held for enough time** to allow delayed forensic analysis.
	- Ensure that logs are generated in a format that log management solutions can easily consume.
	- Ensure log data is encoded correctly to prevent injections or attacks on the logging or monitoring systems.
	- Ensure high-value transactions have an audit trail with integrity controls to prevent tampering or deletion, such as append-only database tables or similar.
	- DevSecOps teams should establish effective monitoring and alerting such that suspicious activities are detected and responded to quickly.
	- Establish or adopt an incident response and recovery plan, such as National Institute of Standards and Technology (NIST) 800-61r2 or later.
	- There are commercial and open-source application protection frameworks such as the OWASP ModSecurity Core Rule Set, and open-source log correlation software, such as the Elasticsearch, Logstash, Kibana (ELK) stack, that feature custom dashboards and alerting.

### Example of an attack
**Scenario #1:** A health plan provider's website operator couldn't detect a breach due to a lack of monitoring and logging. An external party informed the health plan provider that an attacker had accessed and modified thousands of sensitive health records of more than 3.5 million patients. As there was no logging or monitoring of the system, the data breach could have been in progress for many years.

### EDR
![edr](./assets/images/edr.png)
### SIEM
Security information and event management `(SIEM)` is an approach to security management that combines security information management `(SIM)` and security event management (SEM) functions into one security management system.

![siem](./assets/images/siem.png)
### XDR

![xdr](./assets/images/xdr.png)
### SOAR

![soar](./assets/images/soar.png)

![bottom_line](./assets/images/bottom_line.png)

## Week 5 - InfraSec - Layered Security

## Week 6 - InfraSec - AD Security: Initial flaws

## Week 7 - InfraSec - AD Security: Passwords & Hashes

## Week 8 - InfraSec - AD Security: Kerberos

## Week 9 - InfraSec - AD Security: Azure AD

## Week 10 - InfraSec - AD Security: APT


## Sources

### Week 4
- [Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
- [SIEM](https://www.techtarget.com/searchsecurity/definition/security-information-and-event-management-SIEM)
- [EDR vs XDR SIEM vs MDR vs SOAR](https://sysdig.com/learn-cloud-native/detection-and-response/edr-vs-xdr-siem-vs-mdr-vs-sor/)
- [SIEM best practices](https://www.digitalguardian.com/blog/what-siem-how-it-works-best-practices-implementation-more)
- [Best SIEM solutions 2023](https://www.exabeam.com/explainers/siem-tools/siem-solutions/)
- [Datadog SIEM](https://docs.datadoghq.com/security/cloud_siem/)
- [Exabeam SIEM](https://www.exabeam.com/siem/introducing-exabeam-siem-a-hyperscale-cloud-native-siem/)
- [Heimdal Threat Hunting and Action Centre](https://heimdalsecurity.com/enterprise-security/products/threat-hunting-action-center)
- [IBM Qradar SIEM](https://www.ibm.com/products/qradar-siem)
- [Best SOAR tools 2023](https://geekflare.com/best-soar-tools/)
- [Integrating SIEM with CICD](https://floqast.com/engineering-blog/post/integrating-siem-with-ci-cd/)
