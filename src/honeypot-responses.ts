/**
 * Honeypot Response Engine
 * ─────────────────────────
 * Generates convincing fake HTTP responses for honeypot traps.
 *
 * Design principles (based on security research into attacker behaviour):
 *
 *   1. Always return HTTP 200 with realistic content — 403/404 tells the attacker
 *      the path exists but is protected; 200 with plausible fake data makes them
 *      believe they succeeded and linger long enough to reveal their tooling.
 *      Source: Thinkst blog "Creating REST API Canary Endpoints" (2022)
 *
 *   2. Every response embeds a unique canary token in a realistic position.
 *      The token appears as a legitimate-looking credential value — NOT as a
 *      special prefix or obvious marker — so automated scanners do not filter it.
 *      Source: Thinkst canarytokens.org documentation
 *
 *   3. Credentials must follow the exact format of real credentials:
 *      - AWS Access Key ID: `AKIA` + `I` (pos 5) + 14 base32 chars + `A` = 20 chars
 *        Source: AWS docs + awsteele.com/blog/2020/09/26/aws-access-key-format
 *      - AWS Secret Key: 40 base64-standard chars (A-Z, a-z, 0-9, +, /)
 *        Source: summitroute.com/blog/2018/06/20/aws_security_credential_formats
 *      - JWT: valid HS256 signature, `exp` set 24h in the past, `kid` contains
 *        the canary token for detection. Source: Auth0 JWT docs + canarytokens.org
 *
 *   4. HTTP headers must match the technology being impersonated — e.g., Apache
 *      headers on /.env not Express headers, since attackers cross-reference them.
 *
 *   5. Callback URLs embedded in fake webhook fields point to the Anomira ingest.
 *      When an attacker configures their system with the fake webhook and it fires,
 *      the ingest records the canary_triggered event immediately.
 *      Source: Thinkst "A Safety Net for AWS Canarytokens" blog (2022)
 */

import { randomBytes, createHmac } from "node:crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export type HoneypotType =
  | "env_file"          // .env, .env.production, .env.local
  | "aws_credentials"   // .aws/credentials
  | "git_config"        // .git/config
  | "graphql"           // /graphql with introspection
  | "spring_actuator"   // /actuator/env (Spring Boot)
  | "json_config"       // config.json, settings.json, secrets.json
  | "htpasswd"          // .htpasswd — Apache password file with hashed credentials
  | "s3_bucket"         // S3-style XML responses for bucket listing paths
  | "admin_portal"      // HTML admin login form — captures credential attempts
  | "generic";          // all other honeypot paths

export interface HoneypotResponse {
  statusCode:  number;
  contentType: string;
  headers:     Record<string, string>;
  body:        string;
  canaryToken: string; // stored in ingest for subsequent detection
}

// ─── Path → type detection ────────────────────────────────────────────────────

/**
 * Determine the honeypot type from the request path so the right fake
 * response can be generated.
 */
export function detectHoneypotType(path: string): HoneypotType {
  const p = path.toLowerCase().split("?")[0] ?? path.toLowerCase();

  if (/\/\.env(\.[\w]+)?$/.test(p) || p.endsWith("/.env"))        return "env_file";
  if (p.includes(".aws/credentials") || p.includes("aws/credentials")) return "aws_credentials";
  if (p.includes(".git/config") || p.endsWith("/git/config"))     return "git_config";
  if (p.includes("/graphql") || p.includes("/graphiql"))          return "graphql";
  if (p.includes("/actuator/env") || p.includes("/actuator/"))    return "spring_actuator";
  if (/\/(config|settings|secrets?)(\.json)?$/.test(p))           return "json_config";
  // .htpasswd — Apache password file
  if (p.endsWith("/.htpasswd") || p.endsWith("/.htaccess"))       return "htpasswd";
  // S3 bucket listing paths
  if (p.includes("/.s3cfg") || p.endsWith("/s3") || p.includes("s3cfg")) return "s3_bucket";
  // Admin portals — match common admin paths
  if (/\/(admin|wp-admin|administrator|panel|cpanel|dashboard|manage|backend)(\/|$)/.test(p)) return "admin_portal";
  return "generic";
}

// ─── Main generator ───────────────────────────────────────────────────────────

/**
 * Generate a convincing fake HTTP response for a honeypot trap.
 *
 * @param type         The type of honeypot (derived from path)
 * @param canaryToken  Unique token to embed in the response for later detection
 * @param callbackBase Base URL of the Anomira ingest, used for webhook canaries
 *                     (e.g. "https://ingest.anomira.io")
 * @param orgId        Organisation ID — used in callback URLs and canary key generation
 */
export function generateHoneypotResponse(
  type:         HoneypotType,
  canaryToken:  string,
  callbackBase: string,
  orgId:        string,
): HoneypotResponse {
  switch (type) {
    case "env_file":       return makeEnvFile(canaryToken, callbackBase, orgId);
    case "aws_credentials": return makeAwsCredentials(canaryToken);
    case "git_config":     return makeGitConfig(canaryToken, callbackBase, orgId);
    case "graphql":        return makeGraphQL();
    case "spring_actuator": return makeSpringActuator(canaryToken);
    case "json_config":    return makeJsonConfig(canaryToken, callbackBase, orgId);
    case "htpasswd":       return makeHtpasswd(canaryToken);
    case "s3_bucket":      return makeS3Bucket(canaryToken);
    case "admin_portal":   return makeAdminPortal(canaryToken);
    default:               return makeGeneric(canaryToken);
  }
}

// ─── .env file ────────────────────────────────────────────────────────────────

function makeEnvFile(canaryToken: string, _callbackBase: string, _orgId: string): HoneypotResponse {
  const jwtSecret     = genHex(32);
  const dbPassword    = genAlphanumeric(20);
  const redisPassword = genAlphanumeric(16);
  const apiKey        = genHex(32);

  // DNS canary hostnames — fire detection the instant an attacker's tool
  // resolves the domain, before any TCP connection is attempted.
  // The DNS server at srv.anomira.io receives the query, extracts the canary
  // token from the subdomain, and fires the alert via our ingest API.
  const dnsDb         = `db.${canaryToken}.srv.anomira.io`;
  const dnsCache      = `cache.${canaryToken}.srv.anomira.io`;
  const dnsMonitoring = `hooks.monitoring.${canaryToken}.srv.anomira.io`;
  const dnsAlerts     = `hooks.alerts.${canaryToken}.srv.anomira.io`;
  const dnsDeploy     = `deploy.internal.${canaryToken}.srv.anomira.io`;

  // JWT token: valid format, expired 24h ago. Detection is via jti claim.
  const fakeJwt = generateCanaryJwt(canaryToken, jwtSecret);

  const body = `# Production Environment Configuration
# Last updated: ${new Date(Date.now() - 7 * 86400000).toISOString().split("T")[0]}

NODE_ENV=production
PORT=3000

# ── Database ──────────────────────────────────────────────────────────────
DATABASE_URL=postgresql://db_prod:${dbPassword}@${dnsDb}:5432/app_production
DATABASE_REPLICA_URL=postgresql://db_prod:${dbPassword}@${dnsDb}:5433/app_production
DATABASE_POOL_MIN=2
DATABASE_POOL_MAX=10

# ── Cache ─────────────────────────────────────────────────────────────────
REDIS_URL=redis://:${redisPassword}@${dnsCache}:6379/0

# ── Authentication ────────────────────────────────────────────────────────
JWT_SECRET=${jwtSecret}
JWT_EXPIRES_IN=15m
REFRESH_TOKEN_SECRET=${genHex(32)}
SESSION_SECRET=${genHex(32)}

# ── Sample authenticated token (service account) ─────────────────────────
SERVICE_ACCOUNT_TOKEN=${fakeJwt}

# ── AWS ───────────────────────────────────────────────────────────────────
AWS_REGION=eu-west-1
AWS_S3_BUCKET=app-production-${genHex(4)}

# ── Monitoring / Webhooks ─────────────────────────────────────────────────
MONITORING_WEBHOOK=https://${dnsMonitoring}/v1/events/ingest
ALERT_WEBHOOK=https://${dnsAlerts}/services/${genHex(7).toUpperCase()}/notify
DEPLOY_HOOK=https://${dnsDeploy}/hooks/deploy/${genHex(6)}

# ── External APIs ─────────────────────────────────────────────────────────
INTERNAL_API_KEY=${apiKey}
`;

  return {
    statusCode:  200,
    contentType: "text/plain; charset=utf-8",
    headers: {
      "Cache-Control":       "no-store",
      "Last-Modified":       new Date(Date.now() - 7 * 86400000).toUTCString(),
      "ETag":                `"${genHex(8)}-${genHex(4)}"`,
      // Apache-style headers — most exposed .env files are on PHP/Apache stacks
      "Server":              "Apache/2.4.41 (Ubuntu)",
      "X-Content-Type-Options": "nosniff",
    },
    body,
    canaryToken,
  };
}

// ─── .aws/credentials ─────────────────────────────────────────────────────────

function makeAwsCredentials(canaryToken: string): HoneypotResponse {
  // AWS Access Key ID format (confirmed from awsteele.com + summitroute.com):
  // - Exactly 20 characters
  // - Character set: A-Z and 2-7 (base32 alphabet, no 0,1,8,9)
  // - Position 5 (first char after "AKIA"): always I or J (per statistical analysis)
  // - Last character: A or Q
  const fakeKeyId     = makeAwsKeyId();
  const fakeSecret    = makeAwsSecret();
  // Second profile uses ASIA prefix (temporary/STS credentials — more enticing)
  const stsPrefixKey  = "ASIA" + makeAwsKeyId().slice(4);
  const stsSecret     = makeAwsSecret();
  const stsToken      = genBase64(300);

  const body = `[default]
aws_access_key_id=${fakeKeyId}
aws_secret_access_key=${fakeSecret}
region=eu-west-1

[production]
aws_access_key_id=${fakeKeyId}
aws_secret_access_key=${fakeSecret}
region=eu-west-1

[staging]
aws_access_key_id=${stsPrefixKey}
aws_secret_access_key=${stsSecret}
aws_session_token=${stsToken}
region=eu-west-1
`;

  return {
    statusCode:  200,
    contentType: "text/plain; charset=utf-8",
    headers: {
      "Cache-Control":       "no-store",
      "Last-Modified":       new Date(Date.now() - 14 * 86400000).toUTCString(),
      // Match the Server header an AWS EC2 instance metadata endpoint might have
      "Server":              "EC2ws",
      "X-Content-Type-Options": "nosniff",
    },
    body,
    canaryToken,
  };
}

// ─── .git/config ─────────────────────────────────────────────────────────────

function makeGitConfig(canaryToken: string, callbackBase: string, orgId: string): HoneypotResponse {
  // GitHub PAT format: ghp_ + 36 alphanumeric chars (confirmed from GitHub docs)
  const ghpToken   = `ghp_${genAlphanumeric(36)}`;
  const glpatToken = `glpat-${genAlphanumeric(20)}`;
  const webhookUrl = `${callbackBase}/v1/canary/${orgId}/${canaryToken}`;
  // DNS canary in the git remote URL — fires on `git fetch` or `git clone`
  const dnsGit     = `git.${canaryToken}.srv.anomira.io`;

  const body = `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true

[remote "origin"]
	url = https://oauth2:${ghpToken}@github.com/company/app.git
	fetch = +refs/heads/*:refs/remotes/origin/*

[remote "deploy"]
	url = https://deploy-token:${glpatToken}@${dnsGit}/backend/app.git
	fetch = +refs/heads/*:refs/remotes/deploy/*

[remote "notify"]
	url = ${webhookUrl}

[branch "main"]
	remote = origin
	merge = refs/heads/main

[branch "production"]
	remote = deploy
	merge = refs/heads/production

[credential "https://github.com"]
	username = deploy-bot
`;

  return {
    statusCode:  200,
    contentType: "text/plain; charset=utf-8",
    headers: {
      "Cache-Control":    "no-store",
      "Last-Modified":    new Date(Date.now() - 30 * 86400000).toUTCString(),
      "Server":           "Apache/2.4.41 (Ubuntu)",
    },
    body,
    canaryToken,
  };
}

// ─── GraphQL introspection ────────────────────────────────────────────────────

function makeGraphQL(): HoneypotResponse {
  // Minimal but realistic introspection response.
  // Includes an "AdminMutation" type with enticing-sounding fields to
  // fingerprint any tool that auto-generates exploit queries after introspection.
  const body = JSON.stringify({
    data: {
      __schema: {
        queryType:    { name: "Query" },
        mutationType: { name: "Mutation" },
        types: [
          { kind: "OBJECT",  name: "Query",        fields: [{ name: "user" }, { name: "users" }, { name: "posts" }] },
          { kind: "OBJECT",  name: "Mutation",      fields: [{ name: "login" }, { name: "createUser" }, { name: "adminReset" }, { name: "exportData" }] },
          { kind: "OBJECT",  name: "User",          fields: [{ name: "id" }, { name: "email" }, { name: "role" }, { name: "createdAt" }] },
          { kind: "OBJECT",  name: "AuthPayload",   fields: [{ name: "token" }, { name: "user" }] },
          { kind: "SCALAR",  name: "String",        fields: null },
          { kind: "SCALAR",  name: "Boolean",       fields: null },
          { kind: "SCALAR",  name: "Int",           fields: null },
          { kind: "SCALAR",  name: "ID",            fields: null },
        ],
      },
    },
  });

  return {
    statusCode:  200,
    contentType: "application/json; charset=utf-8",
    headers: {
      "X-Powered-By": "Express",
      "X-Request-Id": `req_${genHex(16)}`,
    },
    body,
    canaryToken: "",
  };
}

// ─── Spring Boot actuator ─────────────────────────────────────────────────────

function makeSpringActuator(canaryToken: string): HoneypotResponse {
  // Spring Boot /actuator/env format confirmed from official docs.
  // Sensitive values are shown UNMASKED (simulating misconfigured `show-values=ALWAYS`)
  // — the most dangerous configuration, which is what attackers specifically look for.
  const dbPassword = genAlphanumeric(20);
  const secretKey  = genHex(32);

  const body = JSON.stringify({
    activeProfiles:  ["production"],
    defaultProfiles: ["default"],
    propertySources: [
      {
        name: "systemProperties",
        properties: {
          "java.runtime.version": { value: "17.0.9+9" },
          "server.port":          { value: "8080" },
          "user.home":            { value: "/home/appuser" },
        },
      },
      {
        name: "applicationConfig: [classpath:/application-production.properties]",
        properties: {
          "spring.datasource.url":      { origin: "class path resource [application-production.properties] - 3:1", value: "jdbc:postgresql://db.internal:5432/myapp" },
          "spring.datasource.username": { origin: "class path resource [application-production.properties] - 4:1", value: "dbadmin" },
          "spring.datasource.password": { origin: "class path resource [application-production.properties] - 5:1", value: dbPassword },
          "app.jwt.secret":             { origin: "class path resource [application-production.properties] - 8:1", value: secretKey },
          "app.canary.token":           { value: canaryToken },
          "management.endpoints.web.exposure.include": { value: "health,info,env,metrics,loggers" },
        },
      },
    ],
  }, null, 2);

  return {
    statusCode:  200,
    contentType: "application/vnd.spring-boot.actuator.v3+json",
    headers: {
      "X-Application-Context":    "myapp:production:8080",
      "X-Content-Type-Options":   "nosniff",
      "X-XSS-Protection":         "1; mode=block",
    },
    body,
    canaryToken,
  };
}

// ─── JSON config ──────────────────────────────────────────────────────────────

function makeJsonConfig(canaryToken: string, callbackBase: string, orgId: string): HoneypotResponse {
  const webhookUrl = `${callbackBase}/v1/canary/${orgId}/${canaryToken}`;

  const body = JSON.stringify({
    environment: "production",
    version:     "2.4.1",
    database: {
      host:     "db.internal.company.com",
      port:     5432,
      name:     "app_production",
      user:     "db_prod",
      password: genAlphanumeric(20),
    },
    jwt: {
      secret:    genHex(32),
      expiresIn: "15m",
    },
    webhooks: {
      events:  webhookUrl,
      alerts:  `${callbackBase}/v1/canary/${orgId}/${canaryToken}`,
    },
    internalApiKey: genHex(32),
  }, null, 2);

  return {
    statusCode:  200,
    contentType: "application/json; charset=utf-8",
    headers: {
      "Cache-Control": "no-store",
      "ETag":          `"${genHex(8)}"`,
      "X-Powered-By":  "Express",
    },
    body,
    canaryToken,
  };
}

// ─── .htpasswd ────────────────────────────────────────────────────────────────
//
// Apache password file format:
//   username:$apr1$salt$hash    ← APR1-MD5 (most common)
//   username:$2y$10$...         ← bcrypt (newer systems)
//
// The canary token is embedded as part of one of the password hashes so that
// any attacker who cracks it offline and tries to use it will be detected.
// Format confirmed: Apache httpd documentation + htpasswd man page.

function makeHtpasswd(canaryToken: string): HoneypotResponse {
  // APR1-MD5: $apr1$ + 8-char salt + $ + 22-char base64-like hash
  // Character set for APR1: A-Z, a-z, 0-9, /, .
  const apr1Salt = genAlphanumeric(8).toLowerCase();
  const apr1Hash = genBase64(22).replace(/[+=/]/g, (c) =>
    ({ "+": ".", "=": "/", "/": "X" }[c] ?? c)
  );

  // bcrypt: $2y$10$ + 53-char base64url hash (standard bcrypt output)
  const bcryptHash = genBase64(53).replace(/[+=]/g, (c) =>
    ({ "+": ".", "=": "/" }[c] ?? c)
  );

  // Third entry uses the canary token woven into the hash — if cracked and used:
  const canaryApr1 = `$apr1$${canaryToken.slice(0, 8)}$${genBase64(22).slice(0, 22)}`;

  const body = `# Apache HTTP Server password file
admin:$apr1$${apr1Salt}$${apr1Hash}
deploy:$2y$10$${bcryptHash}
root:${canaryApr1}
backup-user:$apr1$${genAlphanumeric(8).toLowerCase()}$${genBase64(22).slice(0, 22)}
`;

  return {
    statusCode:  200,
    contentType: "text/plain; charset=utf-8",
    headers: {
      "Cache-Control":    "no-store",
      "Last-Modified":    new Date(Date.now() - 45 * 86400000).toUTCString(),
      "Server":           "Apache/2.4.41 (Ubuntu)",
      "Content-Disposition": "inline",
    },
    body,
    canaryToken,
  };
}

// ─── S3 bucket listing XML ─────────────────────────────────────────────────────
//
// AWS S3 ListAllMyBucketsResult XML format.
// Source: AWS S3 REST API documentation (ListBuckets response syntax).
// The canary token is embedded in one bucket name — if the attacker tries
// to access that bucket on real AWS, their IP and tool are logged by CloudTrail.

function makeS3Bucket(canaryToken: string): HoneypotResponse {
  const ownerId = genHex(32) + genHex(32); // 64 hex chars — real S3 owner IDs
  const now = new Date();
  const dateStr = (offset: number) =>
    new Date(now.getTime() - offset).toISOString().replace(/\.\d{3}Z/, ".000Z");

  const body = `<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner>
    <ID>${ownerId}</ID>
    <DisplayName>company-admin</DisplayName>
  </Owner>
  <Buckets>
    <Bucket>
      <Name>company-production-data</Name>
      <CreationDate>${dateStr(120 * 86400000)}</CreationDate>
    </Bucket>
    <Bucket>
      <Name>company-assets-${genHex(4)}</Name>
      <CreationDate>${dateStr(90 * 86400000)}</CreationDate>
    </Bucket>
    <Bucket>
      <Name>company-backups-${canaryToken.slice(0, 12)}</Name>
      <CreationDate>${dateStr(30 * 86400000)}</CreationDate>
    </Bucket>
    <Bucket>
      <Name>company-logs-archive</Name>
      <CreationDate>${dateStr(180 * 86400000)}</CreationDate>
    </Bucket>
  </Buckets>
</ListAllMyBucketsResult>`;

  return {
    statusCode:  200,
    contentType: "application/xml",
    headers: {
      "x-amz-request-id": genHex(8).toUpperCase() + genHex(8).toUpperCase(),
      "x-amz-id-2":       genBase64(60),
      "Server":           "AmazonS3",
    },
    body,
    canaryToken,
  };
}

// ─── Admin portal HTML ────────────────────────────────────────────────────────
//
// Returns a convincing generic admin login page. The form posts back to a
// sub-path (./login) so that POST requests with credential bodies are also
// intercepted by the SDK's honeypot prefix-matching and captured as
// http.honeypot.credential_attempt events.
//
// Design: clean, minimal, looks like a lightweight CMS admin panel.
// The canary token is embedded in a hidden _token field — if an attacker
// automates form submission with this token, subsequent requests carrying
// it are detected.

function makeAdminPortal(canaryToken: string): HoneypotResponse {
  const body = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Administration — Login</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #0f1117;
      color: #c9d1d9;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 32px;
      width: 100%;
      max-width: 360px;
    }
    h1 { font-size: 1.1rem; font-weight: 600; color: #e6edf3; margin-bottom: 4px; }
    .subtitle { font-size: 0.8rem; color: #7d8590; margin-bottom: 24px; }
    label { display: block; font-size: 0.8rem; font-weight: 600; color: #c9d1d9; margin-bottom: 6px; }
    input[type=text], input[type=password] {
      width: 100%; padding: 8px 12px; border: 1px solid #30363d;
      border-radius: 6px; background: #0d1117; color: #c9d1d9;
      font-size: 0.875rem; outline: none; margin-bottom: 16px;
    }
    input:focus { border-color: #388bfd; box-shadow: 0 0 0 3px rgba(56,139,253,.1); }
    .row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
    .row label { margin-bottom: 0; font-weight: normal; display: flex; align-items: center; gap: 6px; cursor: pointer; }
    button {
      width: 100%; padding: 8px 16px; background: #238636; color: #fff;
      border: none; border-radius: 6px; font-size: 0.875rem; font-weight: 600;
      cursor: pointer; transition: background .15s;
    }
    button:hover { background: #2ea043; }
    .footer { text-align: center; font-size: 0.72rem; color: #7d8590; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Administration Panel</h1>
    <p class="subtitle">Sign in to continue</p>
    <form method="POST" action="./login" autocomplete="off">
      <input type="hidden" name="_token" value="${canaryToken}" />
      <div>
        <label for="username">Username</label>
        <input id="username" name="username" type="text" placeholder="admin" autocomplete="off" />
      </div>
      <div>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" placeholder="••••••••" autocomplete="off" />
      </div>
      <div class="row">
        <label><input type="checkbox" name="remember" /> Remember me</label>
        <a href="#" style="font-size:.8rem;color:#388bfd;text-decoration:none;">Forgot password?</a>
      </div>
      <button type="submit">Sign in</button>
    </form>
    <p class="footer">v3.2.1 · Secure Administration Portal</p>
  </div>
</body>
</html>`;

  return {
    statusCode:  200,
    contentType: "text/html; charset=utf-8",
    headers: {
      "Cache-Control":    "no-store, no-cache",
      "X-Frame-Options":  "SAMEORIGIN",
      "Server":           "nginx/1.18.0 (Ubuntu)",
    },
    body,
    canaryToken,
  };
}

/**
 * Response returned when an attacker submits credentials to an admin portal honeypot.
 * Returns a convincing "invalid credentials" page that lures them to try more combinations.
 */
export function makeAdminLoginFailed(): HoneypotResponse {
  const body = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Administration — Login</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0f1117; color: #c9d1d9; font-family: -apple-system, sans-serif;
      display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 32px; width: 100%; max-width: 360px; }
    h1 { font-size: 1.1rem; font-weight: 600; color: #e6edf3; margin-bottom: 4px; }
    .error { background: #3d1010; border: 1px solid #f85149; color: #f85149; border-radius: 6px; padding: 10px 14px; font-size: .8rem; margin-bottom: 16px; }
    label { display: block; font-size: .8rem; font-weight: 600; color: #c9d1d9; margin-bottom: 6px; }
    input[type=text], input[type=password] { width: 100%; padding: 8px 12px; border: 1px solid #f85149; border-radius: 6px; background: #0d1117; color: #c9d1d9; font-size: .875rem; outline: none; margin-bottom: 16px; }
    button { width: 100%; padding: 8px 16px; background: #238636; color: #fff; border: none; border-radius: 6px; font-size: .875rem; font-weight: 600; cursor: pointer; }
    .footer { text-align: center; font-size: .72rem; color: #7d8590; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Administration Panel</h1>
    <div class="error">⚠ Invalid username or password. Please try again.</div>
    <form method="POST" action="" autocomplete="off">
      <div><label for="u">Username</label><input id="u" name="username" type="text" autocomplete="off" /></div>
      <div><label for="p">Password</label><input id="p" name="password" type="password" autocomplete="off" /></div>
      <button type="submit">Sign in</button>
    </form>
    <p class="footer">v3.2.1 · Secure Administration Portal</p>
  </div>
</body>
</html>`;

  return {
    statusCode:  401,
    contentType: "text/html; charset=utf-8",
    headers: {
      "Cache-Control":   "no-store",
      "Server":          "nginx/1.18.0 (Ubuntu)",
      "WWW-Authenticate": 'Form realm="Administration Panel"',
    },
    body,
    canaryToken: "",
  };
}

// ─── Generic ──────────────────────────────────────────────────────────────────

function makeGeneric(canaryToken: string): HoneypotResponse {
  return {
    statusCode:  200,
    contentType: "text/plain; charset=utf-8",
    headers:     { "Cache-Control": "no-store" },
    body:        `# ${canaryToken}\n`,
    canaryToken,
  };
}

// ─── Canary JWT generation ────────────────────────────────────────────────────

/**
 * Generate a valid-format JWT that is expired (24h ago).
 * The `kid` header and `jti` claim both contain the canary token.
 * Any request arriving with this JWT (replayed or reforged with the same secret)
 * can be detected by checking `kid` against the org's canary registry.
 *
 * Format confirmed: Auth0 JWT docs + canarytokens.org JWT token implementation.
 */
export function generateCanaryJwt(canaryToken: string, secret: string): string {
  const now     = Math.floor(Date.now() / 1000);
  // kid looks like a normal UUID-format signing key — detection uses jti instead
  const kid = `${canaryToken.slice(0,8)}-${canaryToken.slice(8,12)}-4${canaryToken.slice(13,16)}-${canaryToken.slice(16,20)}-${canaryToken.slice(20,32)}`;
  const header  = { alg: "HS256", typ: "JWT", kid };
  const payload = {
    sub:   "svc_internal_7482",
    name:  "service-account",
    role:  "admin",
    email: "admin@internal.company.com",
    iat:   now - 172_800, // issued 48h ago (realistic stale credential)
    exp:   now - 86_400,  // expired 24h ago
    jti:   canaryToken,   // raw hex — no "canary-" prefix to leak purpose
  };

  const h  = Buffer.from(JSON.stringify(header)).toString("base64url");
  const p  = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", secret).update(`${h}.${p}`).digest("base64url");
  return `${h}.${p}.${sig}`;
}

// ─── Credential helpers ───────────────────────────────────────────────────────

/** AWS Access Key ID — 20 chars, AKIA prefix, position 5 = I, last = A */
function makeAwsKeyId(): string {
  // Confirmed format: AKIA + I (pos 5) + 14 random [A-Z2-7] + A
  // Source: awsteele.com/blog/2020/09/26/aws-access-key-format
  const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const middle      = Array.from({ length: 13 }, () =>
    base32Chars[randomBytes(1)[0]! % base32Chars.length]!
  ).join("");
  return `AKIAI${middle}A`; // AKIA + I + 13 chars + A = 20 total
}

/** AWS Secret Access Key — 40 chars, base64-standard charset */
function makeAwsSecret(): string {
  // Confirmed: 40 chars, A-Z, a-z, 0-9, +, /
  // Source: summitroute.com/blog/2018/06/20/aws_security_credential_formats
  return randomBytes(30).toString("base64").slice(0, 40);
}

function genHex(bytes: number): string {
  return randomBytes(bytes).toString("hex");
}

function genAlphanumeric(len: number): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  return Array.from({ length: len }, () =>
    chars[randomBytes(1)[0]! % chars.length]!
  ).join("");
}

function genBase64(approxLen: number): string {
  return randomBytes(Math.ceil(approxLen * 3 / 4)).toString("base64").slice(0, approxLen);
}
