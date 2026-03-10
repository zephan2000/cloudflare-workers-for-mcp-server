/**
 * Minimal OAuth 2.1 proxy for n8n MCP server
 * Handles the Claude web OAuth flow, then proxies /mcp requests to n8n
 * 
 * No per-user auth needed — anyone who clicks "Connect" gets access.
 */

const N8N_MCP_URL = "https://webhook.zephan.space/mcp/create-client-page";
const WORKER_BASE_URL = "https://mcp-oauth-proxy.zephanw0ng23.workers.dev"; // ← change to your Worker's domain
const PRODUCT_NAME = "Zephan MCP"; // ← change to your product name

interface Env {
  KV: KVNamespace;
  CF_ACCESS_CLIENT_ID: string;
  CF_ACCESS_CLIENT_SECRET: string;
}

function generateRandom(length = 32): string {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function verifyPKCE(verifier: string, challenge: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const base64url = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  return base64url === challenge;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // ── OAuth metadata discovery ──────────────────────────────────────────────
    if (path === "/.well-known/oauth-authorization-server") {
      return Response.json({
        issuer: WORKER_BASE_URL,
        authorization_endpoint: `${WORKER_BASE_URL}/authorize`,
        token_endpoint: `${WORKER_BASE_URL}/token`,
        registration_endpoint: `${WORKER_BASE_URL}/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
      });
    }

    if (path === "/.well-known/oauth-protected-resource") {
      return Response.json({
        resource: `${WORKER_BASE_URL}/mcp`,
        authorization_servers: [WORKER_BASE_URL],
        bearer_methods_supported: ["header"],
      });
    }

    // ── Dynamic Client Registration (Claude requires this) ────────────────────
    if (path === "/register" && request.method === "POST") {
      const body = await request.json() as any;
      // Accept any client — we don't restrict access at this layer
      return Response.json({
        client_id: generateRandom(16),
        client_name: body.client_name ?? "MCP Client",
        redirect_uris: body.redirect_uris ?? [],
        grant_types: ["authorization_code"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      }, { status: 201 });
    }

    // ── Authorization endpoint — show consent page ────────────────────────────
    if (path === "/authorize" && request.method === "GET") {
      const responseType = url.searchParams.get("response_type");
      const clientId = url.searchParams.get("client_id");
      const redirectUri = url.searchParams.get("redirect_uri");
      const codeChallenge = url.searchParams.get("code_challenge");
      const state = url.searchParams.get("state");

      if (!clientId || !redirectUri || !codeChallenge) {
        return new Response("Missing required parameters", { status: 400 });
      }

      // Store params temporarily, keyed by a session ID in a hidden form field
      const sessionId = generateRandom(16);
      await env.KV.put(`session:${sessionId}`, JSON.stringify({ redirectUri, codeChallenge, clientId }), { expirationTtl: 300 });

      

      return new Response(consentPage(sessionId, state ?? "", PRODUCT_NAME), {
        headers: { "Content-Type": "text/html" },
      });
    }

    // ── Handle consent form submission ────────────────────────────────────────
    if (path === "/authorize" && request.method === "POST") {
      const body = await request.formData();
      const sessionId = body.get("session_id") as string;
      const state = body.get("state") as string;
      const approved = body.get("action") === "approve";

      const session = JSON.parse(await env.KV.get(`session:${sessionId}`) ?? "null");
      if (!session) return new Response("Session expired", { status: 400 });
      await env.KV.delete(`session:${sessionId}`);

      if (!approved) {
        const redirectUrl = new URL(session.redirectUri);
        redirectUrl.searchParams.set("error", "access_denied");
        if (state) redirectUrl.searchParams.set("state", state);
        return Response.redirect(redirectUrl.toString(), 302);
      }

      const code = generateRandom(24);
      await env.KV.put(`code:${code}`, JSON.stringify(session), { expirationTtl: 300 });

      const redirectUrl = new URL(session.redirectUri);
      redirectUrl.searchParams.set("code", code);
      if (state) redirectUrl.searchParams.set("state", state);
      return Response.redirect(redirectUrl.toString(), 302);
    }

    // ── Token exchange ─────────────────────────────────────────────────────────
    if (path === "/token" && request.method === "POST") {
      const body = await request.formData();
      const grantType = body.get("grant_type");
      const code = body.get("code") as string;
      const codeVerifier = body.get("code_verifier") as string;

      if (grantType !== "authorization_code") {
        return Response.json({ error: "unsupported_grant_type" }, { status: 400 });
      }

      const session = JSON.parse(await env.KV.get(`code:${code}`) ?? "null");
      if (!session) {
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }

      const valid = await verifyPKCE(codeVerifier, session.codeChallenge);
      if (!valid) {
        return Response.json({ error: "invalid_grant", error_description: "PKCE verification failed" }, { status: 400 });
      }

      await env.KV.delete(`code:${code}`);

      const accessToken = generateRandom(32);
      await env.KV.put(`token:${accessToken}`, "1", { expirationTtl: 86400 });

      return Response.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 86400,
      });
    }

    // ── MCP proxy — forward authenticated requests to n8n ─────────────────────
    if (path.startsWith("/mcp")) {
      const authHeader = request.headers.get("Authorization");
      const token = authHeader?.replace("Bearer ", "");

      if (!token || !await env.KV.get(`token:${token}`)) {
        return new Response(JSON.stringify({ error: "unauthorized" }), {
          status: 401,
          headers: {
            "Content-Type": "application/json",
            "WWW-Authenticate": `Bearer realm="${WORKER_BASE_URL}"`,
          },
        });
      }

      // Forward to n8n MCP webhook (strip our auth token — n8n doesn't know it)
      const proxyUrl = N8N_MCP_URL + (path.replace("/mcp", "") || "");
      const proxyHeaders = new Headers(request.headers);
      proxyHeaders.delete("Authorization");
      proxyHeaders.set("CF-Access-Client-Id", env.CF_ACCESS_CLIENT_ID);
      proxyHeaders.set("CF-Access-Client-Secret", env.CF_ACCESS_CLIENT_SECRET);
      const proxyRequest = new Request(proxyUrl, {
        method: request.method,
        headers: proxyHeaders,
        body: request.body,
      });

      const proxyResponse = await fetch(proxyRequest);
      console.log(`n8n response: ${proxyResponse.status} ${proxyResponse.statusText}`);
      return proxyResponse;
    }

    return new Response("Not found", { status: 404 });
  },
};

// ── Consent page HTML ──────────────────────────────────────────────────────────
function consentPage(sessionId: string, state: string, productName: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Connect to ${productName}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: #f5f5f5;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 1rem;
    }
    .card {
      background: white;
      border-radius: 12px;
      padding: 2rem;
      max-width: 400px;
      width: 100%;
      box-shadow: 0 4px 24px rgba(0,0,0,0.08);
      text-align: center;
    }
    .icon { font-size: 2.5rem; margin-bottom: 1rem; }
    h1 { font-size: 1.25rem; font-weight: 600; color: #111; margin-bottom: 0.5rem; }
    p { color: #666; font-size: 0.9rem; line-height: 1.5; margin-bottom: 1.5rem; }
    .btn {
      display: block;
      width: 100%;
      padding: 0.75rem;
      border-radius: 8px;
      border: none;
      font-size: 0.95rem;
      font-weight: 500;
      cursor: pointer;
      margin-bottom: 0.75rem;
    }
    .btn-primary { background: #2563eb; color: white; }
    .btn-primary:hover { background: #1d4ed8; }
    .btn-secondary { background: #f3f4f6; color: #374151; }
    .btn-secondary:hover { background: #e5e7eb; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">🔗</div>
    <h1>Connect Claude to ${productName}</h1>
    <p>Claude is requesting access to use your ${productName} tools. This will allow Claude to trigger your workflows.</p>
    <form method="POST" action="/authorize">
      <input type="hidden" name="session_id" value="${sessionId}">
      <input type="hidden" name="state" value="${state}">
      <button type="submit" name="action" value="approve" class="btn btn-primary">
        Allow access
      </button>
      <button type="submit" name="action" value="deny" class="btn btn-secondary">
        Cancel
      </button>
    </form>
  </div>
</body>
</html>`;
}
