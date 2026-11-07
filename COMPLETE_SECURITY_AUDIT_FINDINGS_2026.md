# Complete Master Security & Architecture Audit Report (2026)
**Target Project:** Unique Delta Force (`https://udfonline.in`, `admin.udfonline.in`, `employee.udfonline.in`)  
**Firebase Project ID:** `hr-portal-unique-delta`  
**Workspace Directory:** `Z:\UDF_SUBDOMAINS`  
**Date Generated:** November 7, 2026  
**Auditor:** Antigravity AI Security Audit  
**Total Findings Documented:** **31 Actionable Findings** (10 Live Web/Edge Findings + 21 Codebase Vulnerabilities) + **15 Verified Live Defenses**

---

## Table of Contents
1. [Executive Summary & Risk Matrix](#1-executive-summary--risk-matrix)
2. [Part 1: Live Web, CDN Edge & Public Infrastructure Findings (10 Pending Items)](#2-part-1-live-web-cdn-edge--public-infrastructure-findings)
3. [Live Infrastructure Checks: Verified Defenses (15 Items)](#3-live-infrastructure-checks-verified-defenses)
4. [Part 2: Codebase & Backend Vulnerability Register (SEC-01 to SEC-21)](#4-part-2-codebase--backend-vulnerability-register-sec-01-to-sec-21)
5. [In-Depth Code Vulnerability Analysis](#5-in-depth-code-vulnerability-analysis)
6. [Master Remediation Roadmap](#6-master-remediation-roadmap)

---

## 1. Executive Summary & Risk Matrix

This unified report combines the findings from two rigorous audit phases conducted on the Unique Delta Force workforce management platform:
1. **Phase 1: External Live Web & Infrastructure Scan:** Direct black-box / gray-box inspection of active production endpoints, HTTP headers, Cloudflare edge policies, DNS records, client-side JavaScript bundles, and Service Worker configurations.
2. **Phase 2: Full Codebase & Architecture Audit:** Comprehensive line-by-line inspection of backend security rules (`firestore.rules`, `storage.rules`), serverless backend (`functions/index.js`), 17 data service modules (`src/services/`), core authentication guards, and 81 presentation components across all 153 active codebase files (~75,000 lines).

### Overall Risk Breakdown
| Severity | Live Web & Edge Findings | Codebase Findings (SEC-xx) | Total Pending Issues |
| :--- | :---: | :---: | :---: |
| **CRITICAL** | 0 | 5 | **5** |
| **HIGH** | 2 | 6 | **8** |
| **MEDIUM** | 5 | 8 | **13** |
| **LOW / HYGIENE** | 3 | 2 | **5** |
| **TOTAL** | **10** | **21** | **31** |

---

## 2. Part 1: Live Web, CDN Edge & Public Infrastructure Findings

These 10 findings were identified by probing live public endpoints, HTTP response headers, DNS records, and deployed client-side bundles.

---

### Finding L-01: Internal Operational & Audit Map Publicly Accessible
* **Severity:** **HIGH**
* **Target Endpoint:** `https://udfonline.in/PORTAL_OPERATIONAL_MAP.html`
* **Live Observation:** Returns `HTTP 200 OK` anonymously to any browser or scraper on the internet.
* **Vulnerability & Impact:** The file renders complete interactive architecture diagrams (powered by Mermaid.js) and internal workflow audits, detailing exact database collections, admin approval workflows, and operational state transitions. This exposes sensitive architectural blueprints to competitors or potential attackers.
* **Remediation:** Remove `PORTAL_OPERATIONAL_MAP.html` from the `public/` directory (or exclude it in `firebase.json` hosting rewrites) and redeploy hosting.

---

### Finding L-02: Deprecated TLS 1.0 & TLS 1.1 Accepted at Edge
* **Severity:** **HIGH**
* **Target Endpoint:** Cloudflare Edge / `https://udfonline.in`
* **Live Observation:** Negotiates connections over TLS 1.0 and TLS 1.1 with `HTTP/1.1 200 OK`.
* **Vulnerability & Impact:** Legacy TLS versions rely on obsolete cryptographic ciphers (CBC-mode ciphers vulnerable to BEAST and POODLE attacks). This causes automated compliance failures under PCI-DSS 3.2.1 (Requirement 2.2.3), NIST SP 800-52r2, and ISO/IEC 27001.
* **Remediation:** In **Cloudflare Dashboard &rarr; SSL/TLS &rarr; Edge Certificates**, set **Minimum TLS Version** to **`TLS 1.2`**.

---

### Finding L-03: Low Entropy in Draft Submission Recovery Codes
* **Severity:** **MEDIUM**
* **Target File & Code:** `src/services/employeeService.ts` (`getNextSubmissionId`)
* **Live Observation:** Generates draft recovery IDs using `Math.random().toString(36).substring(2, 6)` (only 4 alphanumeric characters).
* **Vulnerability & Impact:** A 4-character base36 space yields only ~1,679,616 possible combinations. When paired with unauthenticated `allow get: if true` rules on `draft_submissions` (see SEC-05), an automated script can enumerate and download draft candidate profiles containing PAN, Aadhaar, and phone numbers in under an hour.
* **Remediation:** Use `crypto.getRandomValues()` to generate cryptographically random, high-entropy 10-character alphanumeric tokens (e.g., `nanoid` or CSPRNG).

---

### Finding L-04: Subdomain Email Spoofing Gap (Missing `sp=` & Wildcard SPF)
* **Severity:** **MEDIUM**
* **Target Domain:** DNS records for `udfonline.in`, `admin.udfonline.in`, `employee.udfonline.in`
* **Live Observation:** Root DMARC record enforces `p=reject`, but lacks an explicit `sp=reject;` directive. Subdomains lack individual SPF records.
* **Vulnerability & Impact:** Some enterprise mail servers will not apply the root rejection policy to subdomains if `sp=` is omitted, allowing attackers to send spoofed emails appearing from `security@admin.udfonline.in` or `hr@employee.udfonline.in`.
* **Remediation:** 
  1. Update root DMARC TXT record to: `v=DMARC1; p=reject; sp=reject; ...`
  2. Add a wildcard DNS TXT record for subdomains: `* IN TXT "v=spf1 -all"`

---

### Finding L-05: DNSSEC Disabled in DNS Root
* **Severity:** **MEDIUM**
* **Target Domain:** `udfonline.in`
* **Live Observation:** Google Public DNS (`8.8.8.8`) and Cloudflare DNS confirm that no Delegation Signer (DS) record is registered in the `.in` registry.
* **Vulnerability & Impact:** Without DNSSEC cryptographic signatures, users on untrusted networks (public Wi-Fi, malicious ISPs) can be targeted by DNS cache poisoning / spoofing attacks that redirect portal traffic to credential-harvesting phishing clones.
* **Remediation:** Enable **DNSSEC** in Cloudflare Dashboard and copy the generated DS records to your domain registrar's DNS management console.

---

### Finding L-06: HSTS Policy Missing `includeSubDomains` and `preload`
* **Severity:** **MEDIUM**
* **Target Header:** `strict-transport-security: max-age=31556926`
* **Live Observation:** The header sets a 1-year duration, but lacks `includeSubDomains` and `preload`.
* **Vulnerability & Impact:** First-time visitors navigating to subdomains (`admin.udfonline.in`, `employee.udfonline.in`) over plain HTTP remain vulnerable to SSL-stripping man-in-the-middle attacks before the initial 301 redirect completes.
* **Remediation:** In Cloudflare &rarr; **SSL/TLS** &rarr; **Edge Certificates** &rarr; **HTTP Strict Transport Security (HSTS)**, enable **"Apply HSTS to subdomains"** and **"Preload"**.

---

### Finding L-07: Open Redirect Guard on `?redirect=` Query Parameter
* **Severity:** **MEDIUM**
* **Target Bundle:** Client routing in `index-*.js` / `AppRoutes.tsx`
* **Live Observation:** Login handlers execute `navigate(target || "/dashboard")` where `target` is read directly from `new URLSearchParams(window.location.search).get('redirect')`.
* **Vulnerability & Impact:** Protocol-relative URLs (such as `?redirect=//attacker.com`) bypass simple leading-slash checks and force the browser to redirect off-site immediately upon successful authentication, enabling high-credibility credential harvesting.
* **Remediation:** Enforce strict internal routing validation:
  ```typescript
  const isValidRedirect = (url: string | null): boolean => {
    return Boolean(url && url.startsWith('/') && !url.startsWith('//') && !url.includes('\\'));
  };
  navigate(isValidRedirect(redirectParam) ? redirectParam! : '/dashboard');
  ```

---

### Finding L-08: High Cross-Continental API Latency (~455ms Round-Trip)
* **Severity:** **LOW / PERFORMANCE**
* **Target Service:** Cloud Functions in `us-central1` (Iowa, USA)
* **Live Observation:** ICMP and TCP ping benchmarks from Indian clients to the backend average **454.7 ms** (Min: 361.7 ms, Max: 584.2 ms).
* **Impact:** Every login, profile claim, or administrative submission experiences nearly half a second of unavoidable network transit time.
* **Remediation:** Co-deploy or migrate Firebase Cloud Functions to **`asia-south1` (Mumbai, India)** for sub-30ms latency across India and compliance with India's Digital Personal Data Protection (DPDP) Act.

---

### Finding L-09: Service Worker Precaching 30+ Admin Pages on Public Site
* **Severity:** **LOW / HYGIENE**
* **Target Asset:** `https://udfonline.in/sw.js`
* **Live Observation:** The public domain's Service Worker precaches 30 internal administrative chunks (`AdminWorkflowConfigPage`, `AdminStaffManagementPage`, `AdminAuditLogPage`, etc.).
* **Impact:** Bloats initial download cache for public mobile visitors and exposes internal administrative module names in browser storage.
* **Remediation:** In `vite.config.ts`, configure Workbox build options:
  ```typescript
  workbox: {
    globIgnores: ['**/Admin*.js', '**/admin/**']
  }
  ```

---

### Finding L-10: SPA `index.html` Caching (`Cache-Control: max-age=3600`)
* **Severity:** **LOW / OPERATIONAL**
* **Target Header:** HTML entry points (`/`, `/join`, `/contact`) serve `Cache-Control: max-age=3600`.
* **Impact:** Users who visit within 1 hour of a new production deployment continue executing stale cached `index.html` files requesting deleted or hashed Vite chunks, leading to runtime chunk load errors.
* **Remediation:** In `firebase.json`, configure explicit cache headers:
  ```json
  "headers": [
    {
      "source": "**/*.@(html|json)",
      "headers": [{ "key": "Cache-Control", "value": "no-cache, no-store, must-revalidate" }]
    },
    {
      "source": "/assets/**",
      "headers": [{ "key": "Cache-Control", "value": "public, max-age=31536000, immutable" }]
    }
  ]
  ```

---

## 3. Live Infrastructure Checks: Verified Defenses

During the live web inspection, the following 15 controls were actively probed and confirmed to be securely configured and operating correctly:

| # | Inspection Item | Scope / Test Method | Result / Security Status |
| :---: | :--- | :--- | :--- |
| **1** | **SheetJS CVE-2023-30533** | Examined `vendor-excel` bundle in production | **✅ FIXED:** Updated to `0.19.3`; prototype pollution blocked. |
| **2** | **Staff Claim Escalation** | Probed `setAdminClaims` callable function | **✅ FIXED:** Server validates caller UID/email against database before stamping claims. |
| **3** | **Storage Path Traversal** | Probed `getUploadUrl` with traversal payloads | **✅ FIXED:** Backend blocks `..`, null bytes, and caps file uploads to 10MB. |
| **4** | **Firestore Anonymous Scraping** | Probed all 13 Firestore REST collections anonymously | **✅ FIXED:** All collections return `HTTP 403 Forbidden`. |
| **5** | **Storage Bucket Scraping** | REST enumeration of `/onboarding/` and `/employees/` | **✅ FIXED:** Bucket root listing returns `HTTP 403 Permission Denied`. |
| **6** | **Service Worker 1-Year Cache** | Inspected `sw.js` and `registerSW.js` headers | **✅ FIXED:** Edge serves `no-cache, no-store` with Cloudflare `cf-cache-status: BYPASS`. |
| **7** | **Direct Origin Bypass** | Probed `hr-portal-unique-delta.web.app` | **✅ FIXED:** Immediate canonical `<head>` redirect bounces visitors to `udfonline.in`. |
| **8** | **Kiosk Key Storage Exposure** | Inspected `__fs_key` storage in client JavaScript | **✅ FIXED:** Encryption keys stored only in `sessionStorage` (cleared on tab close). |
| **9** | **CORS Origin Reflection** | Probed `employeeLogin` with `Origin: https://attacker.com` | **✅ FIXED:** Wildcard reflection eliminated; untrusted origins rejected. |
| **10** | **Cloudflare WAF Enforcement** | Direct API traffic routing check | **✅ FIXED:** API requests proxied through `/api/**` under Cloudflare WAF inspection. |
| **11** | **Google Cloud Web API Key** | Tested API key via external curl commands | **✅ FIXED:** Identity Toolkit API enforces HTTP Referrer whitelisting. |
| **12** | **Content Security Policy (CSP)** | Inspected live CSP header | **✅ FIXED:** Enforces `object-src 'none'`, `frame-ancestors 'self'`, and `base-uri 'self'`. |
| **13** | **DMARC Email Spoofing Defense** | Polled public DNS TXT record | **✅ FIXED:** Configured with `v=DMARC1; p=reject; ...`. |
| **14** | **DNS CAA Records** | Polled CAA records across global nameservers | **✅ FIXED:** Restricted to authorized CAs (`letsencrypt.org`, `pki.goog`, `digicert.com`). |
| **15** | **Google AdSense Artifacts** | Probed `https://udfonline.in/ads.txt` | **✅ FIXED:** Cleanly removed; safely falls back to SPA 404 handler. |

---

## 4. Part 2: Codebase & Backend Vulnerability Register (SEC-01 to SEC-21)

The following 21 vulnerabilities were uncovered during exhaustive line-by-line inspection of the backend rules, Cloud Functions, and client codebase.

| ID | Severity | Category | File & Location | Short Vulnerability Summary |
| :---: | :---: | :---: | :---: | :--- |
| **SEC-01** | **CRITICAL** | IDOR / Arbitrary File Theft | `functions/index.js`<br>L2144–L2198 | `moveStorageFolder` sets `isAdminOrStaff = true` if `targetId === uid`. Any employee can hijack & delete other employees' confidential files. |
| **SEC-02** | **CRITICAL** | Mass Data Loss / DoS | `functions/index.js`<br>L2230–L2320 | `deleteStoragePath` allows any staff user to pass `storagePath: 'employees'` with `isFolder: true` and wipe all bucket files. |
| **SEC-03** | **CRITICAL** | Privilege Escalation | `firestore.rules`<br>L190–L198, `employeeService.ts` | Rules permit `request.resource.data.profileStatus == 'approved'`. Employees can self-approve their own profiles directly via DevTools. |
| **SEC-04** | **CRITICAL** | Multi-Tenant / Branch Bypass | `firestore.rules`<br>L185, L215, L260, `requestService.ts` | All staff receive `isAdmin: true`. Rules lack site checks on list/update/delete. Client uses in-memory filtering; any supervisor can query all branches nationwide. |
| **SEC-05** | **CRITICAL** | Public PII Exposure | `firestore.rules`<br>L231–L256 | Unauthenticated `allow get: if true` on `draft_submissions` combined with short 4-char random codes enables bulk scraping of candidate PII. |
| **SEC-06** | **HIGH** | Workflow Tampering | `firestore.rules`<br>L413–L434, `bgvService.ts` | 3rd-party vendors have full update access to `bgv_records` without a status whitelist and can self-approve their own background checks. |
| **SEC-07** | **HIGH** | Privilege Escalation Trap | `firestore.rules`<br>L517, `recycleBinService.ts` | Any admin can plant a `STAFF` item with `role-super-admin` in `recycle_bin`. When SuperAdmin clicks restore, attacker is granted SuperAdmin status. |
| **SEC-08** | **HIGH** | Excessive Data Exposure | `functions/index.js`<br>L1767, L1999 | `getSecureDocumentURL` and `getBatchSignedViewUrls` issue signed URLs to any staff user for any employee across all sites without checking `sitesManaged`. |
| **SEC-09** | **HIGH** | Denial of Service | `firestore.rules`<br>L360–L367 | Dismissing or marking a broadcast notification read by a single employee deletes or updates the single document for all employees company-wide. |
| **SEC-10** | **MEDIUM** | Point Farming / Logic Bypass | `functions/index.js`<br>L5660–L5679, `firestore.rules` | `completeTrainingQuizServer` trusts client-supplied `quizDate`, allowing automated loops to mint unlimited gamification points. |
| **SEC-11** | **MEDIUM** | Information Disclosure | `functions/index.js`<br>L831, L3045, L3093 | Discrepant error messages in password reset and unauthenticated endpoints leak valid Employee IDs and staff emails. |
| **SEC-12** | **MEDIUM** | Audit Log Forgery | `functions/index.js`<br>L5612–L5652 | `logClientAuditEvent` callable by any authenticated user without role verification, enabling audit log spoofing. |
| **SEC-13** | **MEDIUM** | Resource Exhaustion | `functions/index.js`<br>L6247–L6287 | `syncEmployeeToGoogleDriveServer` and `syncSubmissionToSheetsServer` lack role checks, allowing quota exhaustion and cost spikes. |
| **SEC-14** | **MEDIUM** | Access Control Inconsistency | `functions/index.js`<br>L180, L251, L303, L343 | `createStaffUser`, `deleteStaffUser`, etc., check `roleId === 'role-super-admin'` but omit `isDisabled !== true`. |
| **SEC-15** | **CRITICAL** | Cleartext Verification Leak | `DataCorrectionPage.tsx`<br>L164–L250, `firestore.rules` L445 | `correction_requests` sends candidate DOB & phone to client browser in plaintext via `getDoc()`; verification runs entirely in client JS. |
| **SEC-16** | **HIGH** | Hardcoded Fallback Secret | `functions/index.js`<br>L4082 | `verifyCorrectionIdentity` contains hardcoded fallback HMAC key (`'UDF_CORRECTION_SESSION_KEY_2026_@DELTA'`). |
| **SEC-17** | **HIGH** | Client-Side Points Inflation | `EmployeeEngagementHub.tsx`<br>L106, `AttendanceCalendar.tsx` | Quiz and attendance points calculations bypass server functions and write directly to `user_engagement/{userId}`. |
| **SEC-18** | **MEDIUM** | Uncontrolled Ingestion / DoS | `ContactPage.tsx`<br>L52–L59, `firestore.rules` | `contact_messages` has no rate limiting or CAPTCHA, allowing infinite automated submissions to inflate billing. |
| **SEC-19** | **MEDIUM** | XSS / DOM Clobbering | `src/utils/sanitizeHtml.ts`<br>L13–L16 | `ALLOWED_ATTRS` permits unparsed `style` (CSS injection/clickjacking) and un-namespaced `id` (DOM clobbering). |
| **SEC-20** | **LOW** | Reverse Tabnabbing | `EmployeeFormPage.tsx`<br>L3071, L3080, L3103 | File preview links open via `window.open(url, '_blank')` without `'noopener,noreferrer'`. |
| **SEC-21** | **HIGH** | Accidental Production Wipe | `scripts/clear-employee-test-data.mjs`<br>L32 | Script hardcodes automatic recursive purge of all 20 live Firestore collections without environment guards. |

---

## 5. In-Depth Code Vulnerability Analysis

---

### SEC-01: Storage File Hijacking & Theft via `moveStorageFolder` IDOR
* **Location:** [`functions/index.js#L2144-L2198`](file:///Z:/UDF_SUBDOMAINS/functions/index.js#L2144-L2198)
* **Code Trace:**
  ```javascript
  const targetId = destinationPath.split('/')[1];
  let isAdminOrStaff = (context.auth.token.role === 'admin') || (context.auth.token.admin === true);
  if (!isAdminOrStaff && targetId === uid) {
    isAdminOrStaff = true; // Flaw: authorizes based on destination alone!
  }
  ```
* **Mechanics:** An authenticated employee with UID `emp_attacker` calls `moveStorageFolder({ sourcePath: 'employees/emp_victim', destinationPath: 'employees/emp_attacker/stolen' })`. Because `targetId` is extracted from `destinationPath` and matches `emp_attacker`, the server sets `isAdminOrStaff = true`. It proceeds to copy all files from the victim's folder into the attacker's folder and deletes the originals from the victim's folder.
* **Impact:** Any employee can steal and delete identity documents (Aadhaar, PAN, bank passes) of any other employee company-wide.

---

### SEC-02: Company-Wide Storage Wipeout via `deleteStoragePath`
* **Location:** [`functions/index.js#L2230-L2320`](file:///Z:/UDF_SUBDOMAINS/functions/index.js#L2230-L2320)
* **Code Trace:**
  ```javascript
  if (isFolder) {
    const [files] = await bucket.getFiles({ prefix: normalizedPath });
    await Promise.all(files.map(file => file.delete()));
  }
  ```
* **Mechanics:** The function verifies that the caller is staff, but does not validate permissions or block root directories. Any staff member (e.g., a junior site supervisor) can send `storagePath: 'employees'` with `isFolder: true`. The backend executes `bucket.deleteFiles({ prefix: 'employees/' })`, destroying all identity records for every employee in the company.
* **Impact:** Catastrophic, irreversible data loss across the entire corporate storage bucket.

---

### SEC-03: Employee Profile Self-Approval Bypass
* **Location:** [`firestore.rules#L190-L198`](file:///Z:/UDF_SUBDOMAINS/firestore.rules#L190-L198) & [`src/services/employeeService.ts#L95-L204`](file:///Z:/UDF_SUBDOMAINS/src/services/employeeService.ts#L95-L204)
* **Code Trace:**
  ```javascript
  allow update: if isEmployeeOwner(employeeId) && 
    request.resource.data.diff(resource.data).affectedKeys()
      .hasOnly(['personalInfo', 'profileStatus', ...]) &&
    request.resource.data.profileStatus in ['submitted', 'approved']; // Flaw!
  ```
* **Mechanics:** While the client UI only submits `profileStatus: 'submitted'`, the Firestore security rule explicitly includes `'approved'` in the permitted employee self-update values. Any employee can run `await updateDoc(doc(db, 'employees', uid), { profileStatus: 'approved' })` in the browser console.
* **Impact:** Employees bypass HR background screening and document validation, granting themselves active payroll and shift status.

---

### SEC-04: Multi-Tenant / Branch Isolation Bypass via In-Memory Filtering
* **Location:** [`firestore.rules#L185, L215, L260`](file:///Z:/UDF_SUBDOMAINS/firestore.rules#L185), [`src/services/requestService.ts#L40-L150`](file:///Z:/UDF_SUBDOMAINS/src/services/requestService.ts#L40-L150)
* **Mechanics:**
  1. In Cloud Functions, every staff member is minted a custom claim `{ admin: true }`.
  2. In `firestore.rules`, rules use `isAdmin()` to grant full collection access: `allow read, write: if isAdmin();`.
  3. The rule defines `canStaffViewSite(siteId)`, but never invokes it on collections such as `employees`, `leave_requests`, `onboarding_submissions`, or `resignations`.
  4. In `src/services/requestService.ts`, the frontend fetches **all records across all client sites nationwide**, and performs `records.filter(r => userSites.includes(r.siteId))` in client React memory.
* **Impact:** A supervisor assigned strictly to Site A can open DevTools, remove the client filter, or run direct queries to view, approve, modify, or delete employee records, leaves, and resignations for Site B, Site C, or corporate headquarters.

---

### SEC-05: Public Candidate PII Scraping via `draft_submissions`
* **Location:** [`firestore.rules#L231-L256`](file:///Z:/UDF_SUBDOMAINS/firestore.rules#L231-L256)
* **Code Trace:**
  ```javascript
  match /draft_submissions/{submissionId} {
    allow get: if true; // Flaw: Anonymous public read access!
    allow list: if isAdmin();
  }
  ```
* **Mechanics:** Candidates who save their onboarding draft receive a short 4-character ID (Finding L-03). Because `allow get: if true;` is open to the public internet without authentication, an attacker can loop through base36 combinations and download unencrypted Aadhaar numbers, PAN numbers, dates of birth, bank account details, and full home addresses.
* **Impact:** Massive regulatory breach under India's Digital Personal Data Protection Act (DPDPA 2023).

---

### SEC-06: 3rd-Party Vendor Self-Approval on BGV Records
* **Location:** [`firestore.rules#L413-L434`](file:///Z:/UDF_SUBDOMAINS/firestore.rules#L413-L434), [`src/services/bgvService.ts#L367-L382`](file:///Z:/UDF_SUBDOMAINS/src/services/bgvService.ts#L367-L382)
* **Code Trace:**
  ```javascript
  allow update: if isBgvVendor() && 
    request.resource.data.vendorId == request.auth.uid; // Missing status whitelist!
  ```
* **Mechanics:** External background verification vendors have update permissions on `bgv_records`. However, the rule does not restrict what fields or statuses they can write. A vendor can directly update `{ status: 'COMPLETED', internalStatus: 'APPROVED', result: 'CLEAR' }` without an internal HR officer verifying the attached reports.
* **Impact:** Unvetted personnel can be marked as fully verified without company oversight.

---

### SEC-07: SuperAdmin Privilege Escalation via Poisoned `recycle_bin` Restore
* **Location:** [`firestore.rules#L517`](file:///Z:/UDF_SUBDOMAINS/firestore.rules#L517), [`src/services/recycleBinService.ts#L120-L138`](file:///Z:/UDF_SUBDOMAINS/src/services/recycleBinService.ts#L120-L138)
* **Mechanics:**
  1. `firestore.rules` allows any staff user to create items in `recycle_bin`: `allow create: if isStaff();`.
  2. A compromised junior staff user writes a malicious item into `recycle_bin`:
     `{ originalCollection: 'staff', originalId: 'attacker_uid', data: { roleId: 'role-super-admin', email: 'attacker@udf.in' } }`.
  3. When an authentic SuperAdmin views the Recycle Bin in the Admin Console and clicks "Restore", `restoreFromRecycleBin` writes the document into `/staff/attacker_uid` using the SuperAdmin's authenticated session.
* **Impact:** Privilege escalation from regular staff to SuperAdmin.

---

### SEC-08: Global Storage Download URL Over-Privilege Without Site Scoping
* **Location:** [`functions/index.js#L1767, L1999`](file:///Z:/UDF_SUBDOMAINS/functions/index.js#L1767)
* **Mechanics:** Both `getSecureDocumentURL` and `getBatchSignedViewUrls` verify `context.auth.token.admin === true`. However, they fail to query the employee's `siteId` or verify if the caller is authorized to view that site via `callerDoc.data().sitesManaged`.
* **Impact:** A site supervisor can generate signed Google Cloud Storage read URLs for private identity documents of staff at any branch.

---

### SEC-09: Shared Broadcast Notification Deletion by Single Employee
* **Location:** [`firestore.rules#L360-L367`](file:///Z:/UDF_SUBDOMAINS/firestore.rules#L360-L367)
* **Mechanics:** When management issues a company-wide announcement, a single notification document is created with `targetUserId: 'ROLE:employee'`. The rule allows `allow update, delete: if isEmployee() && resource.data.targetUserId == 'ROLE:employee'`. When one employee clicks "Dismiss" or "Mark as Read", the client deletes or updates the single shared document.
* **Impact:** The first employee to dismiss the broadcast removes the notification for every other employee in the organization.

---

### SEC-10: Daily Quiz Point Farming via Client-Supplied `quizDate`
* **Location:** [`functions/index.js#L5660-L5679`](file:///Z:/UDF_SUBDOMAINS/functions/index.js#L5660-L5679), [`firestore.rules#L480`](file:///Z:/UDF_SUBDOMAINS/firestore.rules#L480)
* **Mechanics:** `completeTrainingQuizServer` receives `quizDate` from the client parameters to verify whether the user has already taken today's quiz:
  `const historyDoc = await db.collection('user_engagement').doc(uid).collection('quiz_history').doc(quizDate).get();`
* **Impact:** An attacker can invoke this function in a loop supplying arbitrary dates (`2026-01-01`, `2026-01-02`, etc.) to answer quizzes and mint infinite reward points.

---

### SEC-11: Information Disclosure / Employee ID & Staff Email Enumeration
* **Location:** [`functions/index.js#L831, L3045, L3093`](file:///Z:/UDF_SUBDOMAINS/functions/index.js#L831)
* **Mechanics:** 
  1. `verifyAndResetEmployeePassword` returns `'Employee ID not registered'` when an ID doesn't exist, but returns `'Verification details do not match'` when it does.
  2. `resolveUsernameToEmail` is callable anonymously without authentication or rate limiting and converts usernames into valid corporate email addresses.
* **Impact:** Enables external attackers to build targeted lists of valid employee IDs and staff email addresses for phishing campaigns.

---

### SEC-12: Client-Side Audit Log Forgery
* **Location:** [`functions/index.js#L5612-L5652`](file:///Z:/UDF_SUBDOMAINS/functions/index.js#L5612-L5652)
* **Mechanics:** `logClientAuditEvent` is an unconstrained callable that accepts arbitrary strings (`action`, `details`, `metadata`) from any authenticated user and writes directly into the immutable `audit_logs` collection.
* **Impact:** Malicious users can flood audit trails with fake actions, framing other administrators or polluting compliance records.

---

### SEC-13: Drive/Sheets Cloud Function Resource Exhaustion
* **Location:** [`functions/index.js#L6247-L6287`](file:///Z:/UDF_SUBDOMAINS/functions/index.js#L6247-L6287)
* **Mechanics:** Both `syncEmployeeToGoogleDriveServer` and `syncSubmissionToSheetsServer` allocate maximum memory (1 GiB) and a 300-second execution timeout. Neither endpoint checks user roles beyond basic authentication.
* **Impact:** A regular employee can repeatedly trigger hundreds of concurrent sync jobs, exhausting Google Workspace API quotas and generating excessive Cloud Functions billing.

---

### SEC-14: Disabled SuperAdmins Retaining User-Management Powers
* **Location:** [`functions/index.js#L180, L251, L303, L343`](file:///Z:/UDF_SUBDOMAINS/functions/index.js#L180)
* **Mechanics:** Functions such as `createStaffUser`, `deleteStaffUser`, and `toggleStaffStatus` check `if (callerDoc.data().roleId === 'role-super-admin')`. They fail to verify `callerDoc.data().isDisabled !== true`.
* **Impact:** A SuperAdmin account that has been formally disabled in the staff table can still invoke backend callables using an unexpired session token to create new admin accounts or delete other users.

---

### SEC-15: Plaintext Identity Challenge Leak in Data Correction
* **Location:** [`components/employee/DataCorrectionPage.tsx#L164-L250`](file:///Z:/UDF_SUBDOMAINS/components/employee/DataCorrectionPage.tsx#L164-L250), [`firestore.rules#L445`](file:///Z:/UDF_SUBDOMAINS/firestore.rules#L445)
* **Mechanics:**
  1. `firestore.rules` allows `get: if true` on `correction_requests/{id}`.
  2. When an applicant opens the correction link, the React component fetches the document via `getDoc()`.
  3. The returned document contains the correct `verificationDob` and `verificationPhone` in cleartext.
  4. The identity check (`userEnteredDob === doc.verificationDob`) is executed entirely in client JavaScript.
  5. The client attempts to write incremented `failedAttempts` directly to Firestore, but fails with `PERMISSION_DENIED` because the rules require admin rights.
* **Impact:** Any user in possession of a correction link can read the secret verification values in browser network tools, bypass identity checks completely, and never be locked out.

---

### SEC-16: Hardcoded Fallback HMAC Secret in Cloud Functions
* **Location:** [`functions/index.js#L4082`](file:///Z:/UDF_SUBDOMAINS/functions/index.js#L4082)
* **Code Trace:**
  ```javascript
  const hmacSecret = process.env.CORRECTION_HMAC_SECRET || 'UDF_CORRECTION_SESSION_KEY_2026_@DELTA';
  ```
* **Mechanics:** If the production environment variable `CORRECTION_HMAC_SECRET` is unset, the system falls back to a publicly known static key embedded in the repository.
* **Impact:** Attackers can mint valid session tokens to forge identity validations across the platform.

---

### SEC-17: Client-Side Points Inflation in Engagement Hub & Attendance
* **Location:** [`components/employee/EmployeeEngagementHub.tsx#L106-L114`](file:///Z:/UDF_SUBDOMAINS/components/employee/EmployeeEngagementHub.tsx#L106-L114), [`components/employee/AttendanceCalendar.tsx#L136-L142`](file:///Z:/UDF_SUBDOMAINS/components/employee/AttendanceCalendar.tsx#L136-L142)
* **Mechanics:** Rather than invoking the secure server function `completeTrainingQuizServer`, both components execute direct client-side mutations:
  ```typescript
  await setDoc(docRef, { points: currentPoints + pointsToAdd }, { merge: true });
  ```
* **Impact:** Employees can execute client-side scripts to award themselves maximum reward points repeatedly.

---

### SEC-18: Uncontrolled Database Ingestion on Contact Inquiries
* **Location:** [`components/ContactPage.tsx#L52-L59`](file:///Z:/UDF_SUBDOMAINS/components/ContactPage.tsx#L52-L59), [`firestore.rules#L155-L158`](file:///Z:/UDF_SUBDOMAINS/firestore.rules#L155-L158)
* **Mechanics:** The `contact_messages` collection allows unauthenticated `create` operations with only a check that `name.size() > 0`. There is no reCAPTCHA verification or rate limiting on this endpoint.
* **Impact:** Spambots can flood the database with millions of fake inquiries, causing database denial of service and inflated Cloud billing.

---

### SEC-19: Unsanitized Style & ID Attributes in HTML Sanitizer
* **Location:** [`src/utils/sanitizeHtml.ts#L13-L16`](file:///Z:/UDF_SUBDOMAINS/src/utils/sanitizeHtml.ts#L13-L16)
* **Mechanics:** `ALLOWED_ATTRS` permits arbitrary `style` attributes and raw `id` tags without sanitation or namespacing.
* **Impact:** Enables CSS injection, UI redressing (overlaying invisible clickjacking elements), and DOM clobbering attacks against internal variables.

---

### SEC-20: Reverse Tabnabbing via `window.open`
* **Location:** [`components/EmployeeFormPage.tsx#L3071, L3080, L3103`](file:///Z:/UDF_SUBDOMAINS/components/EmployeeFormPage.tsx#L3071)
* **Mechanics:** File preview links execute `window.open(url, '_blank')` without specifying `noopener,noreferrer`.
* **Impact:** Maliciously uploaded HTML/SVG documents can access `window.opener.location` and redirect the staff member's active portal session to a credential phishing page.

---

### SEC-21: Destructive Production Wipe Script Lacks Environment Guards
* **Location:** [`scripts/clear-employee-test-data.mjs#L32`](file:///Z:/UDF_SUBDOMAINS/scripts/clear-employee-test-data.mjs#L32)
* **Mechanics:** The maintenance script triggers automated recursive CLI deletions across all 20 live Firestore collections without checking `process.env.NODE_ENV` or prompting for interactive confirmation.
* **Impact:** Accidental execution by a developer against the production project irreversibly wipes the entire corporate database.

---

## 6. Master Remediation Roadmap

The 31 findings should be implemented across 4 structured remediation batches:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        REMEDIATION BATCHES                             │
├──────────────────────────┬─────────────────────────────────────────────┤
│ Batch 1: Backend Rules   │ Harden firestore.rules & functions/index.js │
│ & Cloud Functions        │ (Closes SEC-01 through SEC-14)              │
├──────────────────────────┼─────────────────────────────────────────────┤
│ Batch 2: Client Web Apps │ Patch components & sanitizers               │
│ & UI Security            │ (Closes SEC-15 through SEC-20, L-03, L-07)  │
├──────────────────────────┼─────────────────────────────────────────────┤
│ Batch 3: Scripts & Build │ Safe maintenance & cache configs            │
│ Hygiene                  │ (Closes SEC-21, L-01, L-09, L-10)           │
├──────────────────────────┼─────────────────────────────────────────────┤
│ Batch 4: Cloudflare &    │ Minimum TLS 1.2, HSTS preload, DNSSEC, DMARC│
│ Edge Security            │ (Closes L-02, L-04, L-05, L-06, L-08)       │
└──────────────────────────┴─────────────────────────────────────────────┘
```

### Action Items Per Batch

#### Batch 1: Backend Rules & Cloud Functions (`firestore.rules`, `functions/index.js`)
1. **Fix `moveStorageFolder`:** Validate that `sourcePath` belongs to `context.auth.uid` or require staff role before file operations.
2. **Harden `deleteStoragePath`:** Explicitly forbid top-level directory deletions (`employees`, `onboarding`, etc.) and require admin claims.
3. **Close Employee Self-Approval:** Remove `'approved'` from permitted values in `firestore.rules` employee self-update rules.
4. **Enforce Branch/Site Scoping in Database:** Update rules for `employees`, `leave_requests`, and `onboarding_submissions` to evaluate `canStaffViewSite(resource.data.siteId)`.
5. **Protect `draft_submissions`:** Remove unauthenticated `allow get: if true` and route draft retrieval through a rate-limited Cloud Function.
6. **Restrict BGV Vendor Updates:** Add explicit field-level whitelisting preventing vendors from changing overall completion or approval statuses.
7. **Lock `recycle_bin`:** Restrict creation to verified administrators; strip sensitive role escalations during restore operations.
8. **Enforce Server Timestamp on Gamification:** Deprecate client-supplied `quizDate` in `completeTrainingQuizServer` and derive date strictly on the server.
9. **Eliminate Fallback HMAC Key:** Throw a fatal error on server startup if `CORRECTION_HMAC_SECRET` is missing.
10. **Add Account Status Verification:** Append `&& callerDoc.data().isDisabled !== true` across all staff management callables.

#### Batch 2: Client Web Applications & Presentation Layer
1. **Fix `DataCorrectionPage.tsx`:** Remove plaintext verification comparisons from client React code; gate the flow entirely behind server callable `verifyCorrectionIdentityClient`.
2. **Centralize Gamification Points:** Remove direct `setDoc` calls in `EmployeeEngagementHub.tsx` and `AttendanceCalendar.tsx`, routing all awards through backend functions.
3. **Harden `src/utils/sanitizeHtml.ts`:** Strip `style` from allowed attributes and prefix all user-supplied `id` attributes.
4. **Remediate Reverse Tabnabbing:** Append `noopener,noreferrer` to all `window.open` calls across `EmployeeFormPage.tsx` and document viewers.
5. **Sanitize Redirect Query Parameters:** Enforce leading slash validation (`/`) and block protocol-relative redirects (`//`) in login components.

#### Batch 3: Scripts & Hosting Configuration
1. **Protect Maintenance Script:** Add confirmation prompts and environment assertions (`process.env.ALLOW_PURGE === 'CONFIRM_DELETE_ALL_TEST_DATA'`) in `scripts/clear-employee-test-data.mjs`.
2. **Remove Operational Blueprint:** Delete `public/PORTAL_OPERATIONAL_MAP.html`.
3. **Exclude Admin Chunks in Public Service Worker:** Add `workbox: { globIgnores: ['**/Admin*.js'] }` in `vite.config.ts`.
4. **Fix HTML Caching:** Update `firebase.json` headers to serve `no-cache, no-store, must-revalidate` for `**/*.html`.

#### Batch 4: Cloudflare & Edge Configuration
1. **Set Minimum TLS 1.2:** In Cloudflare Edge Certificates, disable TLS 1.0 and 1.1.
2. **Harden HSTS:** Enable **"Apply HSTS to subdomains"** and **"Preload"**.
3. **Activate DNSSEC:** Enable DNSSEC in Cloudflare and register DS records with the registrar.
4. **Harden Subdomain Email Security:** Update DMARC with `sp=reject;` and add wildcard SPF record `* IN TXT "v=spf1 -all"`.
5. **Evaluate Regional Deployment:** Co-deploy Cloud Functions to `asia-south1` (Mumbai) to reduce network latency.

---
*End of Complete Security Audit Report — Unique Delta Force 2026*

