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
The scan identified 3 medium-risk vulnerabilities that require immediate attention. No critical issues were found.  

---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability          |
|------------|------------------|--------------------------------|
| Critical   | 0                | -  |
| High       | 0                | -  |
| Medium     | 3                | Absence of Anti-CSRF Tokens |
|            |                  | Content Security Policy (CSP) Header Not Set |
|            |                  | Vulnerable JS Library |

---

## 3. Detailed Findings

### 1. Absence of Anti-CSRF Tokens

- **Severity:** Medium   
- **Description:** No CSRF tokens were detected in forms or headers. This leaves the application vulnerable to Cross-Site Request Forgery (CSRF) attacks, where attackers could perform unauthorized actions on behalf of authenticated users.   
- **Affected URLs:** https://ihealth.iium.edu.my   
- **Business Impact:** Could lead to unauthorized actions, such as modifying user profiles, changing passwords, or initiating transactions without user consent.  
- **OWASP Reference:** [OWASP A01 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control)  

**Recommendation and Prevention Strategy:** 
1. **Implement CSRF protection in the backend framework**
  - If using Laravel, ensure the `VerifyCsrfToken` middleware is enabled (default is on).
    - File to check:
```bash app/Http/Middleware/VerifyCsrfToken.php ```
    - Ensure routes are not unnecessarily excluded in the `$except` array.
  - In `routes/web.php`, CSRF is enforced automatically on POST, PUT, PATCH, DELETE.  

2. **Include CSRF tokens in all HTML forms**
  - In Blade templates, include:
```bash <form method="POST" action="/example">
    @csrf
    <!-- form fields -->
</form>```
  - This will insert a hidden <input> field with the token.

3. **For AJAX requests (if any), set the CSRF token in headers**
  - In your main JS (example in resources/js/app.js or public/js/custom.js):

javascript
Copy code
$.ajaxSetup({
    headers: {
        'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
    }
});
Ensure you have in your <head> section of layouts/app.blade.php:

html
Copy code
<meta name="csrf-token" content="{{ csrf_token() }}">

> **Responsible Team:** Backend    
> **Target Remediation Date:** 2025-06-15  

---

### 2. Content Security Policy (CSP) Header Not Set

- **Severity:** Medium 
- **Description:** No CSP header is set to restrict where resources can be loaded from.  
- **Affected URLs:**  
  -  https://ihealth.iium.edu.my  
- **Business Impact:** Increases risk of XSS and data injection attacks.  
- **OWASP Reference:**  
  - [OWASP A05 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)  
- **Recommendation:** Set a strict CSP header to control allowed sources.  
- **Prevention Strategy:**  
  - Define a strong CSP
  - Regularly audit headers and script sources

> **Responsible Team:** DevOps Team    
> **Target Remediation Date:** 2025-06-15  

---

### 3. Vulnerable JS Library (Bootstrap v3.3.0)

- **Severity:** Medium 
- **Description:** The version in use has known vulnerabilities (e.g., CVE-2018-14041, CVE-2019-8331).  
- **Affected URLs:**  
  -  /public/js/plugins/bootstrap/bootstrap.min.js  
- **Business Impact:** May lead to XSS or client-side logic bypass.  
- **OWASP Reference:**  
  - [OWASP A06 - Using Vulnerable Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)  
- **Recommendation:** Upgrade to the latest Bootstrap version.  
- **Prevention Strategy:**  
  - Monitor NVD (National Vulnerability Database)
  - Use dependency management tools

> **Responsible Team:** Frontend Team    
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

## Appendix
- Scan configuration: All risk and confidence levels included.
- Total scanned site: https://ihealth.iium.edu.my
- Tool Version: OWASP ZAP 2.16.1
- Full technical findings available upon request.

---

**Prepared by:**  
Nur Atiqah Batrisyia  
atiqah.batrisyia@live.iium.edu.my  
25-5-2025
