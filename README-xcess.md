# Web Application Vulnerability Scan Report

**Tool Used:** OWASP ZAP  
**Date of Scan:** 2025-05-23  
**Scanned By:** The Jannah Seekers  
**Target Application:** [https://xcess.iium.edu.my](https://xcess.iium.edu.my)  
**Scan Type:** Active  
**Scan Duration:** 12.00AM – 12.09AM  

---

## 1. Executive Summary

| Metric                        | Value   |
| ----------------------------- | ------- |
| Total Issues Identified       | 5       |
| Critical Issues               | 0       |
| High-Risk Issues              | 1       |
| Medium-Risk Issues            | 4       |
| Remediation Status            | Pending |

**Key Takeaway:**
The scan identified 1 high-risk vulnerability (Medium confidence) and 4 medium-risk vulnerabilities (1 with High confidence, 3 with Medium confidence). These should be prioritized for remediation. No critical issues were found.

---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability               |
| ---------- | ---------------- | ----------------------------------- |
| High       | 1                | Vulnerable JS Library               |
| Medium     | 4                | CSP Header Not Set                  |
|            |                  | Cross-Domain Misconfigurationt      | 
|            |                  | Vulnerable JS Library               |  
|            |                  | Missing Anti-clickjacking Header    |

**Why These Findings are Important:**
The vulnerabilities identified could allow attackers to exploit outdated components, inject malicious code, bypass security policies, or perform clickjacking attacks. If left unaddressed, these security gaps can:

* Compromise sensitive user and system data.
* Enable unauthorized access or manipulation of application resources.
* Disrupt normal application functionality and availability.
* Damage the organization’s reputation and erode user trust.

**Why It’s Important to Address Them:**
Prompt remediation reduces the window of opportunity for attackers to exploit these weaknesses. Addressing the vulnerabilities strengthens the overall security posture, ensures compliance with security standards, and safeguards both the organization’s assets and the privacy of its users.

---

## 3. Detailed Findings

### 3.1 Vulnerable JS Library

* **Severity:** High (High Risk, Medium Confidence)
* **Description:**
  The scan identified the use of an outdated and vulnerable JavaScript library (`jquery.datatables`, version 1.10.12) with known security issues (CVE-2020-28458, CVE-2021-23445).
* **Affected URLs:**
  * [https://cdn.datatables.net](https://cdn.datatables.net)
  * GET: [https://cdn.datatables.net/1.10.12/js/jquery.dataTables.min.js](https://cdn.datatables.net/1.10.12/js/jquery.dataTables.min.js)
* **Business Impact:**
  Exploiting vulnerabilities in client-side libraries can allow attackers to compromise user sessions, deface websites, or steal sensitive data.
* **OWASP Reference:**
  [OWASP A06:2021 - Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
* **Recommendation:**
  Update to the latest secure version of all third-party libraries especially the affected library (DataTables).
* **How to Fix:**
  * Pure PHP: Replace old CDN references with links to the latest version from the official provider.
  Example:
  <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
  * Laravel: If DataTables is used via npm/yarn:
  npm install datatables.net@latest
  npm run build
    * If used via CDN, update Blade templates (.blade.php) to point to the latest secure version.
    * Use npm audit regularly to check for vulnerabilities.
* **Prevention Strategy:**
  * Regularly monitor for vulnerable libraries in dependencies.
  * Use trusted sources for updates.
  * Apply a patch management policy.
  * Automate dependency checks.
  * Update third-party libraries regularly. 


---

### 3.2 Content Security Policy (CSP) Header Not Set

* **Severity:** Medium (Medium Risk, High Confidence)
* **Description:**
  The application does not use the `Content-Security-Policy` HTTP header, increasing the risk of XSS attacks.
* **Affected URLs:**
  * [https://xcess.iium.edu.my](https://xcess.iium.edu.my)
  * GET: [https://xcess.iium.edu.my/robots.txt](https://xcess.iium.edu.my/robots.txt)
* **Business Impact:**
  Attackers may be able to inject malicious scripts, leading to session hijacking or data theft. Increases risk of script injection (XSS) attacks.
* **OWASP Reference:**
  [OWASP A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
* **Recommendation:**
  Implement a strong CSP header to restrict resource loading and script execution.
* **How to Fix (PHP & Laravel):**
  * Pure PHP:
    header("Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none'");
    Place it at the top of PHP scripts or in Apache/Nginx configuration.
  * Laravel: Create middleware:
    namespace App\Http\Middleware;
    use Closure;
    
    class ContentSecurityPolicy
    {
        public function handle($request, Closure $next)
        {
            $response = $next($request);
            $response->headers->set('Content-Security-Policy', "default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none'");
            return $response;
        }
    }
   * Register middleware in app/Http/Kernel.php.
* **Prevention Strategy:**
  * Apply and test CSP in staging; Ensure that web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.
  * Avoid use of `unsafe-inline` and `unsafe-eval`.


---

### 3.3 Cross-Domain Misconfiguration

* **Severity:** Medium (Medium Risk, Medium Confidence)
* **Description:**
  The site’s CORS (Cross-Origin Resource Sharing) policy is too permissive or not set, increasing risk of unauthorized cross-domain access.
* **Affected URLs:**
  * [https://maxcdn.bootstrapcdn.com](https://maxcdn.bootstrapcdn.com)
  * GET: [https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css](https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css)
* **Business Impact:**
  May allow attackers to load or manipulate resources, leading to data leakage or other attacks.
* **OWASP Reference:**
  [OWASP A08:2021 - Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
* **Recommendation:**
  Properly configure CORS to restrict cross-domain requests to only allow trusted origins.
* **Prevention Strategy:**
  * Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains or
  * Remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.
  * Avoid wildcard domains.
  * Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
* **How to Fix (PHP & Laravel):**
  * Pure PHP:
    header("Access-Control-Allow-Origin: https://trusteddomain.com");
    header("Access-Control-Allow-Methods: GET, POST");
    header("Access-Control-Allow-Headers: Content-Type, Authorization");
  * Laravel:
    In config/cors.php, set:
    'paths' => ['api/*'],
    'allowed_origins' => ['https://trusteddomain.com'],
    'allowed_methods' => ['GET', 'POST'],
    'allowed_headers' => ['Content-Type', 'Authorization'],
  * Clear config cache:
    php artisan config:cache

---

### 3.4 Vulnerable JS Library 

* **Severity:** Medium (Medium Risk, Medium Confidence)
* **Description:**
  The identified library bootstrap, version 3.3.6 (instance of a JavaScript library) with known vulnerabilities was detected.
* **Affected URLs:**
  * [https://maxcdn.bootstrapcdn.com](https://maxcdn.bootstrapcdn.com)
  * GET: [https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js](https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js)
* **Business Impact:**
  Similar to previous finding—possible client-side compromise.
* **OWASP Reference:**
  [A06:2021 - Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
* **Recommendation:**
  Update or remove vulnerable libraries.
* **How to Fix (PHP & Laravel):**
 * Pure PHP: Replace CDN link with the latest Bootstrap version:
   <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
 * Laravel:
  If using npm:
  npm install bootstrap@latest
  npm run build
  * If using CDN, update Blade templates with the latest secure version.
* **Prevention Strategy:**
  Conduct regular dependency audits.


---

### 3.5 Missing Anti-clickjacking Header

* **Severity:** Medium (Medium Risk, Medium Confidence)
* **Description:**
  The `X-Frame-Options` or equivalent header is not set, allowing the site to be embedded in iframes (expose clickjacking risk).
* **Affected URLs:**
  * [https://xcess.iium.edu.my](https://xcess.iium.edu.my)
  * GET: [https://xcess.iium.edu.my/robots.txt](https://xcess.iium.edu.my/robots.txt)
* **Business Impact:**
  Could allow attackers to trick users into clicking on hidden or disguised interface elements.
* **OWASP Reference:**
  [OWASP A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
* **Recommendation:**
  Add `X-Frame-Options: DENY` or use CSP frame-ancestors. Ensure one of them is set on all web pages returned by the site.
* **How to Fix (PHP & Laravel):**
  * Pure PHP:
  header('X-Frame-Options: DENY');
  * Laravel:
  Create middleware:
  namespace App\Http\Middleware;
  use Closure;
  
  class FrameOptions
  {
      public function handle($request, Closure $next)
      {
          $response = $next($request);
          $response->headers->set('X-Frame-Options', 'DENY');
          return $response;
      }
  }
  * Register in app/Http/Kernel.php.
  * Alternatively, set via web server config (Apache/Nginx).
* **Prevention Strategy:**
  * Implement security headers.
  * Test for framing vulnerabilities.


---

## 4. Recommendations & Next Steps

* Remediate **High** and **Medium** vulnerabilities immediately.
* Re-test the application in a staging environment after fixes before going live.
* Conduct a **follow-up vulnerability scan (rescan)** using OWASP ZAP after all fixes have been applied to confirm that issues are resolved.
* Compare results with the initial scan to verify that previously detected issues no longer appear.
* Document any remaining or newly discovered vulnerabilities and address them promptly.
* Schedule regular vulnerability scans.
* Regularly review and update third-party libraries and dependencies.
* Ensure all security headers are set according to best practices.
* Consider a third-party penetration test for comprehensive coverage.
* Apply secure coding practices and integrate security checks into the SDLC.

---

## Appendix

* **Scan configuration details:**
  * ZAP version: 2.16.1
  * No specific context; all sites included by default.
  
* **List of all scanned URLs:**
  * [https://xcess.iium.edu.my](https://xcess.iium.edu.my)
  * [https://cdn.datatables.net](https://cdn.datatables.net)
  * [https://cdnjs.cloudflare.com](https://cdnjs.cloudflare.com)
  * [https://maxcdn.bootstrapcdn.com](https://maxcdn.bootstrapcdn.com)
  * [https://use.fontawesome.com](https://use.fontawesome.com)
    
* **Full technical findings:**
  See attached ZAP HTML report for details.
  
---

**Prepared by:**  
Nur Fatihah Adawiyah binti Rusdi  
fatihahadawiyah@gmail.com   
28-5-2025
