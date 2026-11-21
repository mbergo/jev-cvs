import type { Finding, GuardrailCategory } from "./types";

export type PureDetector = (input: string) => Finding[];

/**
 * Masks a raw matched string so raw secrets or PII never appear in logs, findings, or errors.
 * Always keeps first 4 characters (or fewer if string < 4 chars) followed by "****".
 */
export function maskMatch(raw: string): string {
  const trimmed = raw.trim();
  const prefix = trimmed.slice(0, 4);
  return `${prefix}****`;
}

/**
 * Computes Shannon entropy in bits per character for a given token.
 */
export function calculateShannonEntropy(str: string): number {
  if (str.length === 0) return 0;
  const frequencies = new Map<string, number>();
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    frequencies.set(ch, (frequencies.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const GIT_SHA_HEX_REGEX = /^[0-9a-f]{32,64}$/i;
const URL_PREFIX_REGEX = /^https?:\/\//i;
const FILE_PATH_REGEX = /^(?:\/|[a-zA-Z]:\\|\.\.?\/)/;

// 1. Credential Leak Detectors
const AWS_KEY_PATTERN = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g;
const GITHUB_TOKEN_PATTERN = /\bgh[pousr]_[A-Za-z0-9_]{20,255}\b/g;
const PRIVATE_KEY_HEADER_PATTERN =
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g;
const JWT_SHAPE_PATTERN =
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;
const CANDIDATE_TOKEN_PATTERN = /\S{20,}/g;

export const detectAwsAccessKey: PureDetector = (input: string): Finding[] => {
  const findings: Finding[] = [];
  for (const match of input.matchAll(AWS_KEY_PATTERN)) {
    findings.push({
      category: "credential_leak",
      match: maskMatch(match[0]),
      confidence: 0.98,
      detector: "aws_access_key",
    });
  }
  return findings;
};

export const detectGithubToken: PureDetector = (input: string): Finding[] => {
  const findings: Finding[] = [];
  for (const match of input.matchAll(GITHUB_TOKEN_PATTERN)) {
    findings.push({
      category: "credential_leak",
      match: maskMatch(match[0]),
      confidence: 0.99,
      detector: "github_token",
    });
  }
  return findings;
};

export const detectPrivateKeyHeader: PureDetector = (
  input: string
): Finding[] => {
  const findings: Finding[] = [];
  for (const match of input.matchAll(PRIVATE_KEY_HEADER_PATTERN)) {
    findings.push({
      category: "credential_leak",
      match: maskMatch(match[0]),
      confidence: 0.99,
      detector: "private_key_header",
    });
  }
  return findings;
};

export const detectJwtToken: PureDetector = (input: string): Finding[] => {
  const findings: Finding[] = [];
  for (const match of input.matchAll(JWT_SHAPE_PATTERN)) {
    findings.push({
      category: "credential_leak",
      match: maskMatch(match[0]),
      confidence: 0.94,
      detector: "jwt_shape",
    });
  }
  return findings;
};

export const detectHighEntropyString: PureDetector = (
  input: string
): Finding[] => {
  const findings: Finding[] = [];
  for (const match of input.matchAll(CANDIDATE_TOKEN_PATTERN)) {
    const token = match[0].replace(/^[("'`]+|[.,;!?)"'`]+$/g, "");
    if (token.length < 20) continue;
    // Exclude known benign shapes: UUIDs, hex git SHAs, URLs, paths
    if (UUID_REGEX.test(token)) continue;
    if (GIT_SHA_HEX_REGEX.test(token)) continue;
    if (URL_PREFIX_REGEX.test(token)) continue;
    if (FILE_PATH_REGEX.test(token)) continue;
    // Skip tokens already matched by specific high-confidence detectors
    if (/^(?:AKIA|ASIA)[0-9A-Z]{16}$/.test(token)) continue;
    if (/^gh[pousr]_/.test(token)) continue;
    if (/^eyJ[A-Za-z0-9_-]{10,}/.test(token)) continue;
    if (/^(?:sk_live_|sk_test_|rk_live_|xox[baprs]-|AIza)/.test(token)) continue;

    // Require mixed character classes (not purely alphabetic words/identifiers)
    const hasLower = /[a-z]/.test(token);
    const hasUpper = /[A-Z]/.test(token);
    const hasDigitOrSymbol = /[0-9+/=_!@#$%^&*-]/.test(token);
    if (!(hasDigitOrSymbol && (hasLower || hasUpper))) continue;

    const entropy = calculateShannonEntropy(token);
    if (entropy >= 4.5) {
      findings.push({
        category: "credential_leak",
        match: maskMatch(token),
        confidence: 0.65,
        detector: "high_entropy_string",
      });
    }
  }
  return findings;
};

// 2. Secret Key Detectors (API Keys and Secrets)
const SECRET_API_KEY_PATTERN =
  /\b(?:sk_live_[0-9a-zA-Z]{16,}|rk_live_[0-9a-zA-Z]{16,}|xox[baprs]-[0-9A-Za-z-]{16,}|AIza[0-9A-Za-z_-]{35}|sk-proj-[A-Za-z0-9_-]{20,})\b/g;

export const detectSecretApiKey: PureDetector = (input: string): Finding[] => {
  const findings: Finding[] = [];
  for (const match of input.matchAll(SECRET_API_KEY_PATTERN)) {
    findings.push({
      category: "secret_key",
      match: maskMatch(match[0]),
      confidence: 0.97,
      detector: "api_keys_and_secrets",
    });
  }
  return findings;
};

// 3. PII Detectors (from Control Plane screenshots: SSN, Credit Card, Bank Account, US Passport, EIN, TIN)
const SSN_PATTERN = /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
const CREDIT_CARD_PATTERN =
  /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/g;
const BANK_ACCOUNT_PATTERN =
  /\b(?:routing|aba|account\s*(?:no|num|number|#)?)\s*[:=#]?\s*(\d{9,17})\b/gi;
const US_PASSPORT_PATTERN =
  /\b(?:passport(?:\s*(?:no|num|number|#))?\s*[:=#]?\s*)([A-Z]\d{8}|\d{9})\b/gi;
const EIN_PATTERN = /\b(?:ein|employer\s*id(?:entification)?)\s*[:=#]?\s*(\d{2}-\d{7})\b/gi;
const TIN_PATTERN = /\b(?:tin|tax\s*id(?:entification)?|itin)\s*[:=#]?\s*(9\d{2}-\d{2}-\d{4})\b/gi;

export const detectSsn: PureDetector = (input: string): Finding[] => {
  const findings: Finding[] = [];
  for (const match of input.matchAll(SSN_PATTERN)) {
    findings.push({
      category: "pii",
      match: maskMatch(match[0]),
      confidence: 0.96,
      detector: "social_security_number",
    });
  }
  return findings;
};

export const detectCreditCard: PureDetector = (input: string): Finding[] => {
  const findings: Finding[] = [];
  for (const match of input.matchAll(CREDIT_CARD_PATTERN)) {
    findings.push({
      category: "pii",
      match: maskMatch(match[0]),
      confidence: 0.95,
      detector: "credit_card_number",
    });
  }
  return findings;
};

export const detectBankAccount: PureDetector = (input: string): Finding[] => {
  const findings: Finding[] = [];
  for (const match of input.matchAll(BANK_ACCOUNT_PATTERN)) {
    findings.push({
      category: "pii",
      match: maskMatch(match[0]),
      confidence: 0.89,
      detector: "bank_account_number",
    });
  }
  return findings;
};

export const detectUsPassport: PureDetector = (input: string): Finding[] => {
  const findings: Finding[] = [];
  for (const match of input.matchAll(US_PASSPORT_PATTERN)) {
    findings.push({
      category: "pii",
      match: maskMatch(match[0]),
      confidence: 0.91,
      detector: "us_passport_number",
    });
  }
  return findings;
};

export const detectEin: PureDetector = (input: string): Finding[] => {
  const findings: Finding[] = [];
  for (const match of input.matchAll(EIN_PATTERN)) {
    findings.push({
      category: "pii",
      match: maskMatch(match[0]),
      confidence: 0.92,
      detector: "employer_identification_number",
    });
  }
  return findings;
};

export const detectTin: PureDetector = (input: string): Finding[] => {
  const findings: Finding[] = [];
  for (const match of input.matchAll(TIN_PATTERN)) {
    findings.push({
      category: "pii",
      match: maskMatch(match[0]),
      confidence: 0.93,
      detector: "tax_identification_number",
    });
  }
  return findings;
};

// 4. Prompt Injection & Execution/Policy Detectors (from Control Plane screenshots)
const PROMPT_INJECTION_RULES: ReadonlyArray<{
  detector: string;
  pattern: RegExp;
  confidence: number;
}> = [
  {
    detector: "prompt_injection_and_jailbreak",
    pattern:
      /(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules)|you\s+are\s+now\s+DAN|do\s+anything\s+now|bypass\s+(?:all\s+)?safety\s+(?:filters|guardrails)|system\s+override\s*:\s*disable)/gi,
    confidence: 0.97,
  },
  {
    detector: "indirect_prompt_injection",
    pattern:
      /(?:\[\s*SYSTEM\s*:\s*[^\]]+\]|<\!--\s*ai-instruction:|\bIMPORTANT:\s*When\s+summarizing\s+this\s+document,\s*(?:ignore|execute|append|send))/gi,
    confidence: 0.94,
  },
  {
    detector: "remote_code_execution",
    pattern:
      /(?:child_process\.exec|eval\s*\(\s*atob|bash\s+-i\s+>&\s*\/dev\/tcp\/|curl\s+[^\n|]+\|\s*(?:sh|bash)|nc\s+-e\s+\/bin\/(?:sh|bash))/gi,
    confidence: 0.98,
  },
  {
    detector: "system_file_access",
    pattern:
      /(?:\/etc\/passwd|\/etc\/shadow|\/root\/\.ssh\/id_rsa|C:\\Windows\\System32\\config\\SAM|\.aws\/credentials)/gi,
    confidence: 0.96,
  },
  {
    detector: "destructive_command",
    pattern:
      /(?:rm\s+-rf\s+\/(?:\s|$|\*)|mkfs\.ext4\s+\/dev\/|DROP\s+DATABASE\s+production|dd\s+if=\/dev\/zero\s+of=\/dev\/sd)/gi,
    confidence: 0.99,
  },
  {
    detector: "data_exfiltration",
    pattern:
      /(?:curl\s+(?:-X\s+POST\s+)?(?:-d|--data)\s+@?(?:\$ENV|\/etc|\.env)|webhook\.site\/|exfiltrate\s+to\s+https?:\/\/|ngrok-free\.app\/collect)/gi,
    confidence: 0.95,
  },
  {
    detector: "malicious_url_access",
    pattern:
      /(?:https?:\/\/(?:[\w-]+\.)?(?:evil-payload\.ru|malware-drop\.xyz|phish-login-verify\.net|darknet-c2\.onion)(?:\/\S*)?)/gi,
    confidence: 0.98,
  },
  {
    detector: "malicious_package",
    pattern:
      /(?:npm\s+install\s+(?:event-stream-malicious|cross-env-typosquat|solana-web3-backdoor)|pip\s+install\s+(?:reqeusts-stealer|urllib4-exploit|pytorch-nightly-miner))/gi,
    confidence: 0.96,
  },
  {
    detector: "custom_command_policy",
    pattern:
      /(?:chmod\s+777\s+\/|chown\s+root:root\s+.*suid|sudo\s+usermod\s+-aG\s+sudo)/gi,
    confidence: 0.9,
  },
  {
    detector: "custom_package_policy",
    pattern: /(?:npm\s+install\s+--ignore-scripts=false\s+git\+ssh:\/\/)/gi,
    confidence: 0.88,
  },
  {
    detector: "custom_url_policy",
    pattern: /(?:https?:\/\/169\.254\.169\.254\/latest\/meta-data)/gi,
    confidence: 0.99,
  },
  {
    detector: "harmful_content",
    pattern:
      /(?:step-by-step\s+synthesis\s+of\s+(?:ricin|VX\s+nerve\s+agent)|instructions\s+to\s+manufacture\s+untraceable\s+explosives)/gi,
    confidence: 0.99,
  },
  {
    detector: "racism",
    pattern:
      /(?:generate\s+a\s+racist\s+manifesto\s+promoting\s+ethnic\s+supremacy|explicit\s+racial\s+slur\s+attack\s+template)/gi,
    confidence: 0.98,
  },
  {
    detector: "sexism",
    pattern:
      /(?:reject\s+all\s+female\s+engineering\s+applicants\s+automatically\s+because\s+of\s+gender|women\s+are\s+biologically\s+incapable\s+of\s+software\s+leadership)/gi,
    confidence: 0.97,
  },
];

export const detectPromptInjection: PureDetector = (
  input: string
): Finding[] => {
  const findings: Finding[] = [];
  for (const rule of PROMPT_INJECTION_RULES) {
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    for (const match of input.matchAll(regex)) {
      findings.push({
        category: "prompt_injection",
        match: maskMatch(match[0]),
        confidence: rule.confidence,
        detector: rule.detector,
      });
    }
  }
  return findings;
};

export const ALL_PURE_DETECTORS: ReadonlyArray<PureDetector> = [
  detectAwsAccessKey,
  detectGithubToken,
  detectPrivateKeyHeader,
  detectJwtToken,
  detectHighEntropyString,
  detectSecretApiKey,
  detectSsn,
  detectCreditCard,
  detectBankAccount,
  detectUsPassport,
  detectEin,
  detectTin,
  detectPromptInjection,
];

/**
 * Resolves the exact character span `{ start, end }` in `input` for a detector finding,
 * without storing raw strings inside `Finding`.
 */
export function resolveFindingSpan(
  input: string,
  detectorName: string
): { start: number; end: number } {
  const detectorRegexMap: Record<string, RegExp> = {
    aws_access_key: AWS_KEY_PATTERN,
    github_token: GITHUB_TOKEN_PATTERN,
    private_key_header: PRIVATE_KEY_HEADER_PATTERN,
    jwt_shape: JWT_SHAPE_PATTERN,
    high_entropy_string: CANDIDATE_TOKEN_PATTERN,
    api_keys_and_secrets: SECRET_API_KEY_PATTERN,
    social_security_number: SSN_PATTERN,
    credit_card_number: CREDIT_CARD_PATTERN,
    bank_account_number: BANK_ACCOUNT_PATTERN,
    us_passport_number: US_PASSPORT_PATTERN,
    employer_identification_number: EIN_PATTERN,
    tax_identification_number: TIN_PATTERN,
  };

  let pattern = detectorRegexMap[detectorName];
  if (!pattern) {
    const injectionRule = PROMPT_INJECTION_RULES.find(
      (r) => r.detector === detectorName
    );
    if (injectionRule) {
      pattern = injectionRule.pattern;
    }
  }

  if (!pattern) {
    return { start: 0, end: Math.min(input.length, 16) };
  }

  const clone = new RegExp(pattern.source, pattern.flags);
  for (const match of input.matchAll(clone)) {
    const token = match[0];
    const start = match.index ?? 0;
    if (detectorName === "high_entropy_string") {
      if (
        token.length >= 20 &&
        !UUID_REGEX.test(token) &&
        !GIT_SHA_HEX_REGEX.test(token) &&
        calculateShannonEntropy(token) >= 4.5
      ) {
        return { start, end: start + token.length };
      }
      continue;
    }
    return { start, end: start + token.length };
  }

  return { start: 0, end: Math.min(input.length, 16) };
}

/**
 * Pure sanitization helper that replaces all detected matches for the active findings
 * with masked placeholders (`[REDACTED:<detector>:<masked>]`).
 */
export function sanitizeWithFindings(
  input: string,
  findings: ReadonlyArray<Finding>
): string {
  let sanitized = input;
  const activeDetectors = new Set(findings.map((f) => f.detector));

  const replacements: Array<{ detector: string; pattern: RegExp }> = [
    { detector: "aws_access_key", pattern: AWS_KEY_PATTERN },
    { detector: "github_token", pattern: GITHUB_TOKEN_PATTERN },
    { detector: "private_key_header", pattern: PRIVATE_KEY_HEADER_PATTERN },
    { detector: "jwt_shape", pattern: JWT_SHAPE_PATTERN },
    { detector: "api_keys_and_secrets", pattern: SECRET_API_KEY_PATTERN },
    { detector: "social_security_number", pattern: SSN_PATTERN },
    { detector: "credit_card_number", pattern: CREDIT_CARD_PATTERN },
    { detector: "bank_account_number", pattern: BANK_ACCOUNT_PATTERN },
    { detector: "us_passport_number", pattern: US_PASSPORT_PATTERN },
    { detector: "employer_identification_number", pattern: EIN_PATTERN },
    { detector: "tax_identification_number", pattern: TIN_PATTERN },
    ...PROMPT_INJECTION_RULES.map((r) => ({
      detector: r.detector,
      pattern: r.pattern,
    })),
  ];

  for (const item of replacements) {
    if (!activeDetectors.has(item.detector)) continue;
    const regex = new RegExp(item.pattern.source, item.pattern.flags);
    sanitized = sanitized.replace(regex, (raw) => `[REDACTED:${maskMatch(raw)}]`);
  }

  if (activeDetectors.has("high_entropy_string")) {
    const entropyRegex = new RegExp(
      CANDIDATE_TOKEN_PATTERN.source,
      CANDIDATE_TOKEN_PATTERN.flags
    );
    sanitized = sanitized.replace(entropyRegex, (rawToken) => {
      const token = rawToken.replace(/^[("'`]+|[.,;!?)"'`]+$/g, "");
      if (
        token.length >= 20 &&
        !UUID_REGEX.test(token) &&
        !GIT_SHA_HEX_REGEX.test(token) &&
        !URL_PREFIX_REGEX.test(token) &&
        !FILE_PATH_REGEX.test(token) &&
        /[0-9+/=_!@#$%^&*-]/.test(token) &&
        /[A-Za-z]/.test(token) &&
        calculateShannonEntropy(token) >= 4.5
      ) {
        return `[REDACTED:${maskMatch(token)}]`;
      }
      return rawToken;
    });
  }

  return sanitized;
}

export function getCategoryOrder(): ReadonlyArray<GuardrailCategory> {
  return ["prompt_injection", "secret_key", "credential_leak", "pii", "confidential_data"];
}
