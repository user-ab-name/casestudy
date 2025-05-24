# Web Application Vulnerability Scan Report

**Tool Used:** OWASP ZAP  
**Date of Scan:** 2025-05-22  
**Scanned By:** The Jannah Seekers  
**Target Application:** https://ihealth.iium.edu.my  
**Scan Type:** Active  
**Scan Duration:** 3.30PM – 3.40PM  

---

## 1. Executive Summary

| Metric                         | Value            |
|-------------------------------|------------------|
| Total Issues Identified       | 13    |
| Critical Issues               | 0     |
| High-Risk Issues              | 0     |
| Medium-Risk Issues            | 3     |
| Low-Risk/Informational Issues | 10    |
| Remediation Status            |Pending|

**Key Takeaway:**  
The scan identified 3 medium-risk vulnerabilities & 10 low/informational findings that require immediate attention. No critical issues were found.  

---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability          |
|------------|------------------|--------------------------------|
| Critical   | 0                | -  |
| High       | 0                | -  |
| Medium     | 3                | Absence of Anti-CSRF Tokens |
|            |                  | Content Security Policy (CSP) Header Not Set |
|            |                  | Vulnerable JS Library |
| Low        | 6                | Cookie No HttpOnly Flag |
|            |                  | Cookie Without Secure Flag |
|            |                  | Cookie without SameSite Attribute |
|            |                  | Server Leaks Version Information via "Server" HTTP Response Header Field |
|            |                  | Strict-Transport-Security Header Not Set |
|            |                  | X-Content-Type-Options Header Missing |
| Info       | 4                | Information Disclosure - Suspicious Comments |
|            |                  | Modern Web Application |
|            |                  | Session Management Response Identified |
|            |                  | User Agent Fuzzer |

---

## 3. Detailed Findings

### Content Security Policy (CSP) Header Not Set

- **Severity:** Medium 
- **Description:**  
  The server does not set a Content Security Policy (CSP) header. This increases the risk of XSS attacks.

- **Affected URLs:**  
  - https://ihealth.iium.edu.my(#)

- **Business Impact:**  
  May allow attackers to inject malicious scripts, leading to session hijacking or data theft.

- **OWASP Reference:**  
  (https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)(#)

- **Recommendation:**  
  [Suggested fix, e.g., "Validate user inputs using allow-lists."]

- **Prevention Strategy:**  
  - Enforce input validation.
  - Use secure HTTP headers.
  - Apply regular code reviews and testing.

> **Responsible Team:** [e.g., DevOps]  
> **Target Remediation Date:** [YYYY-MM-DD]

---

(Repeat for each major vulnerability)

---

## 4. Recommendations & Next Steps

- Address **Critical** and **High** vulnerabilities **immediately**.
- Re-test application after remediation.
- Integrate secure coding standards.
- Schedule periodic scans (e.g., monthly or post-deployment).
- Consider a penetration test for in-depth analysis.

---

## Appendix (Optional)

- Scan configuration details  
- List of all scanned URLs  
- Full technical findings (for security team)

---

**Prepared by:**  
[Your Name]  
[Your Role / Department]  
[Email / Contact]  
[Date]
