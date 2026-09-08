// ─── Credential / PII leak scanner ───────────────────────────────────────────
// Scans log messages and source files for sensitive data patterns.
// Nigeria-aware: includes BVN/NIN (11-digit), Nigerian phone numbers, and
// fintech credential patterns alongside universal secret formats.

export interface LeakMatch {
  type:  string;
  label: string;
}

interface Pattern {
  type:  string;
  label: string;
  regex: RegExp;
}

const PATTERNS: Pattern[] = [

  // ── Cryptographic private keys ────────────────────────────────────────────
  // NOTE: -----BEGIN CERTIFICATE----- is intentionally excluded — public
  // certificates are designed to be public and committing them is correct.
  // Only PRIVATE keys are dangerous.
  {
    type:  "private_key",
    label: "Private Key",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
  },

  // ── Cloud provider credentials ────────────────────────────────────────────
  {
    // AWS access key ID — highly specific, almost no false positives
    type:  "aws_key",
    label: "AWS Access Key",
    regex: /\bAKIA[0-9A-Z]{16}\b/,
  },
  {
    // AWS secret access key — 40-char base64 string after keyword
    type:  "aws_secret",
    label: "AWS Secret Key",
    regex: /\b(?:aws[_-]?secret|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*[A-Za-z0-9+/]{40}\b/i,
  },
  {
    // Google API key
    type:  "google_key",
    label: "Google API Key",
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/,
  },
  {
    // Google OAuth client secret
    type:  "google_oauth",
    label: "Google OAuth Secret",
    regex: /\bGOCSP[A-Za-z0-9\-_]{28}\b/,
  },
  {
    // Firebase server key
    type:  "firebase_key",
    label: "Firebase Server Key",
    regex: /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b/,
  },
  {
    // Azure storage/connection string
    type:  "azure_key",
    label: "Azure Key",
    regex: /\bDefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}/,
  },

  // ── Source control & CI tokens ────────────────────────────────────────────
  {
    // GitHub personal access tokens (classic and fine-grained)
    type:  "github_token",
    label: "GitHub Token",
    regex: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,255}\b/,
  },
  {
    // GitLab personal/project/group tokens
    type:  "gitlab_token",
    label: "GitLab Token",
    regex: /\bglpat-[A-Za-z0-9\-_]{20}\b/,
  },
  {
    // NPM access tokens
    type:  "npm_token",
    label: "NPM Token",
    regex: /\bnpm_[A-Za-z0-9]{36}\b/,
  },

  // ── Payment providers ─────────────────────────────────────────────────────
  {
    // Stripe — secret, restricted, webhook keys
    type:  "stripe_key",
    label: "Stripe Key",
    regex: /\b(?:sk|rk|whsec)_(?:live|test)_[A-Za-z0-9]{24,}\b/,
  },
  {
    // Paystack secret/public keys
    type:  "paystack_key",
    label: "Paystack Key",
    regex: /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{40,}\b/,
  },
  {
    // Card PANs: Visa (4), Mastercard (51-55), Amex (34/37), Discover (6011/65)
    type:  "card_pan",
    label: "Card PAN",
    regex: /\b(?:4[0-9]{15}|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/,
  },

  // ── Communication & messaging ─────────────────────────────────────────────
  {
    // Slack bot/user/app tokens
    type:  "slack_token",
    label: "Slack Token",
    regex: /\bxox[baprs]-[0-9A-Za-z]{10,48}\b/,
  },
  {
    // Slack webhook URL
    type:  "slack_webhook",
    label: "Slack Webhook URL",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/,
  },
  {
    // Twilio account SID and auth token
    type:  "twilio",
    label: "Twilio Credential",
    regex: /\bAC[a-z0-9]{32}\b|\bSK[a-z0-9]{32}\b/,
  },
  {
    // SendGrid / Brevo / Mailgun API keys
    type:  "email_provider_key",
    label: "Email Provider API Key",
    regex: /\bSG\.[A-Za-z0-9._-]{66}\b|\bkey-[0-9a-zA-Z]{32}\b/,
  },

  // ── Database connection strings with embedded credentials ─────────────────
  {
    type:  "db_connection",
    label: "Database Connection String",
    regex: /(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|amqp(?:s)?):\/\/[^:]+:[^@\s]{3,}@/i,
  },

  // ── Auth tokens ───────────────────────────────────────────────────────────
  {
    // JWT — three base64url segments separated by dots
    type:  "jwt",
    label: "JWT Token",
    regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
  },
  {
    // Generic API key / token — only flag QUOTED literals, not variable/env references.
    // Skips: api_key = process.env.KEY, token = myVar
    // Matches: api_key = "sk-abc123...", bearer: "eyJhb..."
    type:  "api_key",
    label: "API Key / Token",
    regex: /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer|client[_-]?secret)\s*[:=]\s*["'][A-Za-z0-9_.\/+\-]{20,}["']/i,
  },

  // ── Password fields ───────────────────────────────────────────────────────
  {
    // Only flag QUOTED string literals after a password/secret keyword.
    // Skips: process.env.*, variable references, undefined/null, template literals.
    // Matches: password: "hunter2", secret: 'abc123def', pass="hardcoded!"
    type:  "password",
    label: "Hardcoded Password",
    regex: /\b(?:password|passwd|pwd|pass|secret|credentials?)\s*[:=]\s*["'][^"'$\s]{6,}["']/i,
  },

  // ── Nigeria-specific PII ──────────────────────────────────────────────────
  {
    // BVN / NIN: 11 digits, first digit 1-9 (not a phone number starting with 0)
    // Exclude: inside URLs (preceded by / : @ - %), hex strings (followed by a-f),
    // and UUIDs/hashes (surrounded by alphanumeric chars)
    type:  "bvn",
    label: "BVN / NIN (11-digit identifier)",
    regex: /(?<![/\-:@%=a-fA-F\w])[1-9]\d{10}(?![a-fA-F\d])/,
  },
  {
    // Nigerian phone numbers: 080x, 081x, 070x, 090x, 091x — or with +234 prefix
    type:  "ng_phone",
    label: "Nigerian Phone Number",
    regex: /\b(?:\+?234|0)(?:7[0-9]|8[0-1]|9[0-1])\d{8}\b/,
  },

  // ── PII in credential context ─────────────────────────────────────────────
  {
    // Email only flagged when adjacent to a password/credential keyword
    // Prevents false positives on normal email references in code
    type:  "email_credential",
    label: "Email + Password Combo",
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\s+(?:password|passwd|pwd|secret|pass)\s*[:=]?\s*\S+/i,
  },
];

// Returns which sensitive patterns matched, deduplicated by type.
export function scanForLeaks(message: string): LeakMatch[] {
  const seen  = new Set<string>();
  const found: LeakMatch[] = [];
  for (const p of PATTERNS) {
    p.regex.lastIndex = 0;
    if (p.regex.test(message) && !seen.has(p.type)) {
      seen.add(p.type);
      found.push({ type: p.type, label: p.label });
    }
  }
  return found;
}

// Returns a copy of the message with sensitive values partially masked.
export function redactMessage(message: string): string {
  return message
    // Private keys
    .replace(/-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z ]+ )?PRIVATE KEY-----/g,
      "[PRIVATE KEY REDACTED]")
    // AWS access key
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "AKIA••••••••••••••••")
    // Google API key
    .replace(/\bAIza[0-9A-Za-z\-_]{35}\b/g, "AIza••••••••••••••••••••••••••••••••")
    // GitHub tokens
    .replace(/\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{4}[A-Za-z0-9_]{32,251}\b/g,
      (_, prefix) => `${prefix}_••••[REDACTED]`)
    // Stripe keys
    .replace(/\b((?:sk|rk|whsec)_(?:live|test)_)[A-Za-z0-9]{4}[A-Za-z0-9]{20,}/g,
      (_, prefix) => `${prefix}••••[REDACTED]`)
    // JWT tokens
    .replace(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, "[JWT REDACTED]")
    // Database URLs — redact password part
    .replace(/((?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis):\/\/[^:]+:)[^@\s]{3,}(@)/gi,
      "$1••••••••$2")
    // API keys after keyword
    .replace(/(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer|client[_-]?secret)\s*[:=]\s*["']?)([A-Za-z0-9_.\/+\-]{4})([A-Za-z0-9_.\/+\-]{16,})["']?/gi,
      (_, prefix, first4) => `${prefix}${first4}••••[REDACTED]`)
    // Passwords after keyword
    .replace(/(\b(?:passwd|pwd|pass|secret|credentials?|password)\s*[:=]\s*["']?)(\S{2})(\S{4,})/gi,
      (_, prefix, first2) => `${prefix}${first2}••••••`)
    // Card PANs — show first 6 + last 4
    .replace(/\b(4[0-9]{5}|5[1-5][0-9]{4}|3[47][0-9]{4}|6(?:011|5[0-9]{2})[0-9]{1})[0-9]{6,9}([0-9]{4})\b/g,
      (_, first6, last4) => `${first6}••••••${last4}`)
    // BVN/NIN — show first 2 + last 2
    .replace(/(?<!\d)([1-9]\d)(\d{7})(\d{2})(?!\d)/g, (_, f2, _mid, l2) => `${f2}•••••••${l2}`)
    // Nigerian phone numbers
    .replace(/\b((?:\+?234|0)(?:7[0-9]|8[0-1]|9[0-1])\d{2})\d{6}\b/g, "$1••••••");
}
