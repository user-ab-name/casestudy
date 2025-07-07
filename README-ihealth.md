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
