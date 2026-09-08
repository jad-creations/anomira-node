/**
 * AI Agent & MCP Traffic Detection
 *
 * Identifies requests originating from AI agents, LLM tool-callers, and
 * Model Context Protocol (MCP) clients using only confirmed, primary-source
 * verified signals.
 *
 * Signal sources:
 *   - MCP Streamable HTTP spec (2025-03-26):
 *       https://modelcontextprotocol.io/specification/2025-03-26/basic/transports
 *   - OpenAI bot documentation:
 *       https://developers.openai.com/api/docs/bots
 *   - Anthropic crawler documentation:
 *       https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data
 *   - Perplexity bot documentation:
 *       https://docs.perplexity.ai/guides/bots
 *   - RFC 9421 HTTP Message Signatures (ChatGPT Agent + Google Agent):
 *       https://blog.castle.io/how-to-authenticate-openai-operator-requests-using-http-message-signatures/
 */

export type AgentType =
  | "openai"       // GPTBot, ChatGPT-User, OAI-SearchBot, ChatGPT Agent
  | "anthropic"    // ClaudeBot, Claude-User, Claude-SearchBot
  | "perplexity"   // PerplexityBot, Perplexity-User
  | "mcp_client"   // Generic MCP client (no provider-specific UA)
  | "rfc9421_agent" // Signed agent via RFC 9421 HTTP Message Signatures
  | "unknown_agent"; // Has agent signals but no provider identified

export type AgentConfidence = "high" | "medium";

export interface AgentDetectionResult {
  isAgent:    boolean;
  confidence: AgentConfidence;
  agentType:  AgentType | null;
  /** The matched UA token, e.g. "GPTBot/1.3" or "ClaudeBot/1.0" */
  agentName:  string | null;
  /** Mcp-Session-Id header value when MCP protocol is confirmed */
  sessionId:  string | null;
  /** True when Mcp-Session-Id or MCP Accept header is confirmed present */
  isMcp:      boolean;
  /** Which specific signals fired — for observability and tuning */
  signals:    string[];
}

// ─── Confirmed user-agent substrings (official documentation only) ─────────────
//
// Each entry: [substring_to_match (case-insensitive), agentType, display_name]
// Only UA patterns confirmed from first-party sources are listed here.
// Do NOT add patterns based on community aggregators or unverified reports.
const CONFIRMED_UA_PATTERNS: [RegExp, AgentType, string][] = [
  // OpenAI — https://developers.openai.com/api/docs/bots
  [/GPTBot\//i,         "openai",     "GPTBot"],
  [/ChatGPT-User\//i,   "openai",     "ChatGPT-User"],
  [/OAI-SearchBot\//i,  "openai",     "OAI-SearchBot"],
  [/OAI-AdsBot\//i,     "openai",     "OAI-AdsBot"],

  // Anthropic — https://support.claude.com/en/articles/8896518
  [/ClaudeBot\//i,        "anthropic",  "ClaudeBot"],
  [/Claude-User\//i,      "anthropic",  "Claude-User"],
  [/Claude-SearchBot\//i, "anthropic",  "Claude-SearchBot"],

  // Perplexity — https://docs.perplexity.ai/guides/bots
  [/PerplexityBot\//i,    "perplexity", "PerplexityBot"],
  [/Perplexity-User\//i,  "perplexity", "Perplexity-User"],
];

// ─── MCP Protocol headers (confirmed from MCP spec 2025-03-26) ─────────────────
//
// Node.js normalises all incoming HTTP header names to lowercase, so we
// match the lowercase form here.
const MCP_SESSION_HEADER   = "mcp-session-id";   // Mcp-Session-Id (normalised)
const RFC9421_SIG_HEADER   = "signature-agent";   // Signature-Agent (RFC 9421)

// The MCP spec mandates clients send EXACTLY this Accept header value.
// Source: spec + confirmed via multiple bug reports about HTTP 406 errors
// when this exact value is missing.
const MCP_ACCEPT_EXACT = "application/json, text/event-stream";

// ─── Detection function ─────────────────────────────────────────────────────────

/**
 * Analyse request headers and identify AI agent / MCP client traffic.
 * Accepts a plain header map (as returned by Node.js `req.headers` — all
 * keys lowercase, values are string or string[]).
 */
export function detectAgent(
  headers: Record<string, string | string[] | undefined>,
): AgentDetectionResult {
  const signals: string[] = [];
  let agentType:  AgentType | null  = null;
  let agentName:  string    | null  = null;
  let sessionId:  string    | null  = null;
  let isMcp                         = false;
  let confidence: AgentConfidence | null = null;

  // ── 1. RFC 9421 Signature-Agent (HIGH confidence) ──────────────────────────
  // Confirmed: OpenAI ChatGPT Agent and Google Agent (Mariner) both send this.
  // Source: https://blog.castle.io/how-to-authenticate-openai-operator-requests
  const sigAgent = headerStr(headers[RFC9421_SIG_HEADER]);
  if (sigAgent) {
    signals.push("rfc9421_signature_agent");
    confidence = "high";
    agentType  = sigAgent.includes("chatgpt.com") ? "openai" : "rfc9421_agent";
    agentName  = `rfc9421:${sigAgent.slice(0, 60)}`;
  }

  // ── 2. MCP Session ID header (HIGH confidence) ─────────────────────────────
  const mcpSession = headerStr(headers[MCP_SESSION_HEADER]);
  if (mcpSession) {
    signals.push("mcp_session_id");
    isMcp      = true;
    sessionId  = mcpSession;
    confidence = "high";
    if (!agentType) agentType = "mcp_client";
  }

  // ── 3. MCP mandatory Accept header (HIGH confidence when alone) ────────────
  // The exact value "application/json, text/event-stream" is mandated by the
  // MCP Streamable HTTP spec. No standard browser sends this exact combination.
  const accept = headerStr(headers["accept"]);
  if (accept === MCP_ACCEPT_EXACT) {
    signals.push("mcp_accept_header");
    isMcp = true;
    if (!confidence) confidence = "high";
    if (!agentType)  agentType  = "mcp_client";
  }

  // ── 4. Known AI agent User-Agent strings (HIGH confidence) ─────────────────
  const ua = headerStr(headers["user-agent"]) ?? "";
  for (const [pattern, type, name] of CONFIRMED_UA_PATTERNS) {
    const match = ua.match(pattern);
    if (match) {
      signals.push(`ua_${name.toLowerCase().replace(/[^a-z0-9]/g, "_")}`);
      confidence = "high";
      // Extract the full token with version e.g. "GPTBot/1.3"
      const tokenStart = ua.indexOf(match[0]);
      const tokenEnd   = ua.indexOf(" ", tokenStart);
      agentName  = tokenEnd > -1 ? ua.slice(tokenStart, tokenEnd) : match[0];
      agentType  = type;
      break; // First match wins — patterns are mutually exclusive
    }
  }

  // ── 5. python-httpx User-Agent (MEDIUM confidence) ─────────────────────────
  // The MCP Python SDK (modelcontextprotocol/python-sdk) uses httpx as its
  // HTTP client and sets no custom User-Agent, resulting in "python-httpx/<v>".
  // Source: https://github.com/modelcontextprotocol/python-sdk/issues/1641
  // NOTE: Any Python service using httpx will produce this UA, so we only
  // treat it as a signal when combined with MCP-specific headers above.
  if (!agentType && /^python-httpx\//i.test(ua) && isMcp) {
    signals.push("ua_python_httpx_with_mcp");
    confidence = "medium";
    agentType  = "mcp_client";
    agentName  = ua.split(" ")[0] ?? "python-httpx";
  }

  const isAgent = confidence !== null;

  return {
    isAgent,
    confidence:  confidence ?? "medium",
    agentType:   isAgent ? (agentType ?? "unknown_agent") : null,
    agentName:   isAgent ? agentName : null,
    sessionId,
    isMcp,
    signals,
  };
}

// ─── Helper ─────────────────────────────────────────────────────────────────────

function headerStr(v: string | string[] | undefined): string | undefined {
  if (v === undefined) return undefined;
  return Array.isArray(v) ? v[0] : v;
}
