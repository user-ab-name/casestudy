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

### 1. Absence of Anti-CSRF Tokens

- **Severity:** Medium 
- **Description:**  
  No CSRF tokens were detected in forms or headers. This could allow attackers to perform actions on behalf of an authenticated user.

- **Affected URLs:**  
  - https://ihealth.iium.edu.my

- **Business Impact:**  
  Could lead to unauthorized actions such as changing passwords or making transactions.

- **OWASP Reference:**  
- [OWASP A01 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control)  
  
- **Recommendation:**  
  Implement CSRF tokens for all state-changing requests.

- **Prevention Strategy:**  
  - Use frameworks with built-in CSRF protection
  - Validate tokens server-side

> **Responsible Team:** Backend    
> **Target Remediation Date:** 2025-06-15  

---

### 2. Content Security Policy (CSP) Header Not Set

- **Severity:** Medium 
- **Description:**  
  No CSP header is set to restrict where resources can be loaded from.

- **Affected URLs:**  
  -  https://ihealth.iium.edu.my

- **Business Impact:**  
  Increases risk of XSS and data injection attacks.

- **OWASP Reference:**  
  - [OWASP A05 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

- **Recommendation:**  
  Set a strict CSP header to control allowed sources.

- **Prevention Strategy:**  
  - Define a strong CSP
  - Regularly audit headers and script sources

> **Responsible Team:** DevOps Team    
> **Target Remediation Date:** 2025-06-15  

---

### 3. Vulnerable JS Library (Bootstrap v3.3.0)

- **Severity:** Medium 
- **Description:**  
  The version in use has known vulnerabilities (e.g., CVE-2018-14041, CVE-2019-8331).

- **Affected URLs:**  
  -  /public/js/plugins/bootstrap/bootstrap.min.js

- **Business Impact:**  
  May lead to XSS or client-side logic bypass.

- **OWASP Reference:**  
  - [OWASP A06 - Using Vulnerable Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)

- **Recommendation:**  
  Upgrade to the latest Bootstrap version.

- **Prevention Strategy:**  
  - Monitor NVD (National Vulnerability Database)
  - Use dependency management tools

> **Responsible Team:** Frontend Team    
> **Target Remediation Date:** 2025-06-15 

---

### 4. Cookie Without HttpOnly Flag

- **Severity:** Low 
- **Description:**  
  Cookies are accessible via JavaScript, increasing the risk of theft via XSS.

- **Affected URLs:**  
  -  https://ihealth.iium.edu.my

- **Business Impact:**  
  May result in session hijacking.

- **OWASP Reference:**  
  - [OWASP A05 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

- **Recommendation:**  
  Add HttpOnly attribute to all cookies.

- **Prevention Strategy:**  
  - Configure application to use secure cookie attributes

> **Responsible Team:** Backend Team    
> **Target Remediation Date:** 2025-06-15 

---

### 5. Cookie Without Secure Flag

- **Severity:** Low 
- **Description:**
  Some cookies are transmitted over non-secure connections.

- **Affected URLs:**  
  -  https://ihealth.iium.edu.my

- **Business Impact:**  
  Interception via network sniffing.

- **OWASP Reference:**  
  - [WSTG-SESS-02](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes)

- **Recommendation:**  
  Ensure all cookies use the Secure flag.

- **Prevention Strategy:**  
  - Configure application to use secure cookie attributes

> **Responsible Team:** Backend Team    
> **Target Remediation Date:** 2025-06-15

---

### 6. Cookie Without SameSite Attribute

- **Severity:** Low 
- **Description:**  
  Cookies without SameSite can be sent on cross-origin requests.

- **Affected URLs:**  
  -  https://ihealth.iium.edu.my

- **Business Impact:**  
  Increases CSRF risk.

- **OWASP Reference:**  
  - [Session Management Cheat Sheet] (https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#samesite-cookie-attribute)

- **Recommendation:**  
  Set SameSite=Strict or Lax for session cookies.

- **Prevention Strategy:**  
  - Modify cookie settings in application config.
  - Ensure compatibility across browsers.
  - Use Secure flag with SameSite=None when required.

> **Responsible Team:** Backend Team    
> **Target Remediation Date:** 2025-06-15

---

### 7. Server Version Disclosure via HTTP Header

- **Severity:** Low 
- **Description:**  
  The server reveals its software version in the Server header.

- **Affected URLs:**  
  -  https://ihealth.iium.edu.my

- **Business Impact:**  
  Helps attackers identify vulnerabilities specific to the server version.

- **OWASP Reference:**  
  - [OWASP Info Leak](https://owasp.org/www-project-top-10-infrastructure-security-risks/docs/2023/INT08_2023-Information_Leakage)

- **Recommendation:**  
  Remove or modify the Server header to hide version info.

- **Prevention Strategy:**  
  - Disable version headers in server config.
  - Use reverse proxies to sanitize headers.

> **Responsible Team:** DevOps    
> **Target Remediation Date:** 2025-06-15

---

### 8. Strict-Transport-Security (HSTS) Header Not Set

- **Severity:** Low 
- **Description:**  
  HSTS not enabled, allowing downgrade attacks.

- **Affected URLs:**  
  -  https://ihealth.iium.edu.my

- **Business Impact:**  
  Users can be tricked into using HTTP instead of HTTPS.

- **OWASP Reference:**  
  - [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

- **Recommendation:**  
  Enable HSTS by adding the appropriate header.

- **Prevention Strategy:**  
  - Add Strict-Transport-Security header with max-age and includeSubDomains.
  - Consider preloading.

> **Responsible Team:** DevOps Team    
> **Target Remediation Date:** 2025-06-15

---

### 9. X-Content-Type-Options Header Missing

- **Severity:** Low 
- **Description:**  
  This header prevents MIME-sniffing, which could lead to XSS.

- **Affected URLs:**  
  -  https://ihealth.iium.edu.my

- **Business Impact:**  
  Could lead to unintended execution of scripts or styles.

- **OWASP Reference:**  
  - [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

- **Recommendation:**  
  Add X-Content-Type-Options: nosniff to all responses.

- **Prevention Strategy:**  
  - Configure web server to include this header.
  - Ensure application includes it in responses.

> **Responsible Team:** DevOps Team    
> **Target Remediation Date:** 2025-06-15

---

### 10. Information Disclosure - Suspicious Comments

- **Severity:** Informational 
- **Description:**  
  Code comments in JavaScript files contain sensitive terms like USERNAME.

- **Affected URLs:**  
  -  [/public/js/plugins/jquery/jquery.min.js](https://ihealth.iium.edu.my/public/js/plugins/jquery/jquery.min.js)

- **Business Impact:**  
  Could help attackers understand application structure or identify weak points.

- **OWASP Reference:**  
  - [OWASP Info Leak](https://owasp.org/www-project-top-10-infrastructure-security-risks/docs/2023/INT08_2023-Information_Leakage)

- **Recommendation:**  
  Remove or sanitize comments before deploying code to production.

- **Prevention Strategy:**  
  - Minify JavaScript and remove comments.
  - Automate the removal process in your build pipeline.

> **Responsible Team:** Frontend Team    
> **Target Remediation Date:** 2025-06-15

---

### 11. Modern Web Application (Fingerprinting)

- **Severity:** Informational 
- **Description:**  
  The scanner identified characteristics typical of a modern web application. Often gathered through headers, response patterns, or observable behaviors.

- **Affected URLs:**  
  -  https://ihealth.iium.edu.my

- **Business Impact:**  
  May help attackers tailor their approach when attempting exploitation, especially if known vulnerabilities exist in the identified frameworks.

- **OWASP Reference:**  
  - [OWASP Info Gathering](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering)

- **Recommendation:**  
  Minimize response headers or client behaviors that reveal underlying technologies unless absolutely necessary.

- **Prevention Strategy:**  
  - Disable framework-specific headers.
  - Obfuscate URLs and API endpoints where practical.
  - Keep frameworks and dependencies up to date.

> **Responsible Team:** DevOps Team    
> **Target Remediation Date:** 2025-06-15

---

### 12. Session Management Response Identified

- **Severity:** Informational 
- **Description:**  
  The scan identified session-related responses such as session ID cookies or authentication tokens being issued. This indicates that session management is in place and potentially targetable.

- **Affected URLs:**  
  - https://ihealth.iium.edu.my/public/js/plugins/jquery/jquery.min.js)

- **Business Impact:**  
  This information could aid attackers in crafting session fixation or hijacking attacks if additional weaknesses exist.

- **OWASP Reference:**  
  - [OWASP Session Management Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/)

- **Recommendation:**  
  Ensure strong session management policies and headers (e.g., HttpOnly, Secure, SameSite) are consistently applied.

- **Prevention Strategy:**  
  - Use secure cookie attributes.
  - Rotate session IDs after login.
  - Set appropriate session timeouts and controls.

> **Responsible Team:** Backend Team    
> **Target Remediation Date:** 2025-06-15

---
### 13. User Agent Fuzzer

- **Severity:** Informational 
- **Description:**  
  The scanner used a variety of User-Agent headers to probe for differences in response behavior. The application responded consistently, but this check is noted as part of reconnaissance.

- **Affected URLs:**  
  -  (https://ihealth.iium.edu.my)

- **Business Impact:**  
  No direct vulnerability, but response differences could in some cases reveal business logic or security flaws.

- **OWASP Reference:**  
  - [OWASP Info Gathering](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering)

- **Recommendation:**  
  Validate consistent behavior across varied user agents and implement default response handling.

- **Prevention Strategy:**  
  - Normalize and sanitize user input headers.
  - Log and alert unusual user agent patterns.

> **Responsible Team:** DevOps Team    
> **Target Remediation Date:** 2025-06-15
---

## Recommendations & Next Steps
- Address all Medium risk issues within two weeks.
- Upgrade any outdated frontend libraries (e.g., Bootstrap).
- Enforce secure headers and cookies (e.g., HttpOnly, Secure, SameSite).
- Re-scan the application post-remediation.
- Adopt secure development lifecycle practices.
- Schedule monthly vulnerability assessments.

---

## Appendix (Optional)
- Scan configuration: All risk and confidence levels included.
- Total scanned site: https://ihealth.iium.edu.my
- Tool Version: OWASP ZAP 2.16.1
- Full technical findings available upon request.

---

**Prepared by:**  
Nur Atiqah Batrisyia  
atiqah.batrisyia@live.iium.edu.my  
25-5-2025
