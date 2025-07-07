# Web Application Vulnerability Scan Report

**Tool Used:** OWASP ZAP  
**Date of Scan:** 2025-05-22  
**Scanned By:** The Jannah Seekers  
**Target Application:** https://ihealth.iium.edu.my  
**Scan Type:** Active  
**Scan Duration:** 3.30PM – 3.40PM  

---
- [1. Executive Summary](#1-executive-summary)
- [2. Summary of Findings](#2-summary-of-findings)
- [3. Detailed Findings](#3-detailed-findings)
  - [Absence of Anti-CSRF Tokens](#1-absence-of-anti-csrf-tokens)
  - [Content Security Policy](#2-content-security-policy-csp-header-not-set)
  - [Vulnerable JS Library](#3-vulnerable-js-library)
- [4. Result of The Report](#4-result-of-the-report)
- [5. Appendix](#5-appendix)
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

| Risk Level | Number of Issues | Example Vulnerability          | Why It Needs to Be Solved         |
|------------|------------------|--------------------------------|-----------------------------------|
| Critical   | 0                | -  | -  |
| High       | 0                | -  | -  |
| Medium     | 3                | Absence of Anti-CSRF Tokens | **CSRF tokens missing:** Could let attackers perform unauthorized actions by tricking logged-in users into submitting malicious requests (e.g., change password, make a booking)  |
|            |                  | Content Security Policy (CSP) Header Not Set | **CSP header missing:** Increases the risk of Cross-Site Scripting (XSS) because browsers have no restrictions on where scripts/styles load from. |
|            |                  | Vulnerable JS Library | Outdated Bootstrap has known security flaws that attackers can exploit to bypass client-side checks or inject malicious scripts.  |

### Why It Matters
Fixing these issues is critical to:
- Protect user data and actions, ensuring attackers can’t hijack sessions or perform unauthorized transactions.
- Prevent malicious script injections that could steal data or manipulate the page (XSS).
- Avoid known exploits in outdated third-party libraries that put the entire system at risk.

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
`app/Http/Middleware/VerifyCsrfToken.php`
    - Ensure routes are not unnecessarily excluded in the `$except` array.
  - In `routes/web.php`, CSRF is enforced automatically on POST, PUT, PATCH, DELETE.  

2. **Include CSRF tokens in all HTML forms**
    - In Blade templates, include:
```bash
<form method="POST" action="/example">
    @csrf
    <!-- form fields -->
</form>
```
    - This will insert a hidden `<input>` field with the token.  

3. **For AJAX requests (if any), set the CSRF token in headers**
    - In your main JS (example in `resources/js/app.js or public/js/custom.js`):

```bash
$.ajaxSetup({
    headers: {
        'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
    }
});
```

    - Ensure you have in your `<head>` section of `layouts/app.blade.php`:

```bash
<meta name="csrf-token" content="{{ csrf_token() }}">
```

> **Responsible Team:** Backend    
> **Target Remediation Date:** 2025-06-15  

---

### 2. Content Security Policy (CSP) Header Not Set

- **Severity:** Medium 
- **Description:** The application does not set a Content-Security-Policy (CSP) header. Without this, browsers do not restrict where scripts, styles, images, and other resources can be loaded from, increasing the risk of Cross-Site Scripting (XSS).  
- **Affected URLs:**  
  -  https://ihealth.iium.edu.my  
- **Business Impact:** Increases risk of XSS and data injection attacks.  
- **OWASP Reference:**  
  - [OWASP A05 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)  

**Recommendation and Prevention Strategy:** 
1. **Add CSP header globally in the HTTP response**
    - In Laravel, this can be done by creating a middleware. Example: `app/Http/Middleware/ContentSecurityPolicy.php`

```bash
namespace App\Http\Middleware;

use Closure;

class ContentSecurityPolicy
{
    public function handle($request, Closure $next)
    {
        $response = $next($request);
        $response->headers->set('Content-Security-Policy', 
            "default-src 'self'; script-src 'self'; style-src 'self' fonts.googleapis.com; font-src fonts.gstatic.com;"
        );
        return $response;
    }
}
```

2. **Register the middleware in `app/Http/Kernel.php`**
```bash
protected $middleware = [
    // existing middleware...
    \App\Http\Middleware\ContentSecurityPolicy::class,
];
```

3. **Regularly audit the policy**
   - Ensure allowed external resources are minimal (for example, if using Google Fonts, explicitly include them as shown above).
  
> **Target Remediation Date:** 2025-06-15  

---

### 3. Vulnerable JS Library (Bootstrap v3.3.0)

- **Severity:** Medium 
- **Description:** The application uses an outdated version of Bootstrap `(v3.3.0)` which has known security vulnerabilities, including **CVE-2018-14041** and **CVE-2019-8331**. 
- **Affected URLs:**  
  -  `/public/js/plugins/bootstrap/bootstrap.min.js`  
- **Business Impact:** May allow attackers to exploit XSS or bypass client-side security logic.  
- **OWASP Reference:**  
  - [OWASP A06 - Using Vulnerable Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)  

**Recommendation and Prevention Strategy:** 
1. **Upgrade Bootstrap to the latest stable version**
    - Replace old Bootstrap files in:

```bash
/public/js/plugins/bootstrap/
/public/css/plugins/bootstrap/
```

    - For example, download Bootstrap 5.3.x from [https://getbootstrap.com] and update these files.

2. **Update all references in your Blade templates**
    - In resources/views/layouts/app.blade.php or similar, change:

```bash
<link rel="stylesheet" href="/public/css/plugins/bootstrap/bootstrap.min.css">
<script src="/public/js/plugins/bootstrap/bootstrap.min.js"></script>
```

    - to point to the new version.

3. **Use dependency scanning tools**
    - Run `npm audit` (if using npm) or enable **GitHub Dependabot alerts** to automatically monitor outdated packages. 

> **Responsible Team:** Frontend Team    
> **Target Remediation Date:** 2025-06-15 
---

## 4. Result of The Report
- No critical or high-risk vulnerabilities were found, indicating the system does not have immediate severe security flaws such as remote code execution or direct unauthorized data access.
- However, three medium-level issues were identified, which could still be exploited by attackers to perform unauthorized actions, inject malicious scripts, or take advantage of known third-party library vulnerabilities.
- Need to implement CSRF protection by using framework-native CSRF middleware and tokens in all forms and AJAX requests. Validate these tokens server-side.
- Need to define and apply a strict Content-Security-Policy HTTP header to control which sources scripts, styles, and other resources can load from. Regularly audit these policies.
- Need to upgrade to the latest stable version of Bootstrap (or any vulnerable third-party library) and monitor dependencies using tools like npm audit or GitHub Dependabot.
- After implementing fixes, perform a follow-up OWASP ZAP scan to confirm that the vulnerabilities have been resolved.
- Plan for monthly automated vulnerability scans and quarterly manual code reviews to proactively catch future issues.

---

## 5. Appendix
- Scan configuration: All risk and confidence levels included.
- Total scanned site: https://ihealth.iium.edu.my
- Tool Version: OWASP ZAP 2.16.1
- Full technical findings available upon request.

---

**Prepared by:**  
Nur Atiqah Batrisyia  
atiqah.batrisyia@live.iium.edu.my  
25-5-2025
