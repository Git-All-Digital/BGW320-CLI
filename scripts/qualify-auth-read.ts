import { BGW320Client, RouterAuthError, RouterResponseError } from "../src/client.js";
import { parsePage } from "../src/parser.js";
import { withRouterSession } from "../src/session.js";

// A deliberately narrow qualification entrypoint, not a general command runner.
export async function qualifyAuthenticatedRead(host: string, accessCode: string) {
  const origin = new URL(host).origin;
  if (!accessCode) throw new Error("Access code required on stdin.");
  const client = new BGW320Client({ host: origin, accessCode, boundedLogin: true,
    waitForSession: false, timeoutMs: 10000, insecureTls: false,
    userAgent: "bgw-bounded-read/1" });
  const originalFetch = globalThis.fetch;
  const counts = new Map<string, number>();
  const limits = new Map([
    ["GET /cgi-bin/login.ha", 1], ["POST /cgi-bin/login.ha", 1],
    ["GET /cgi-bin/remoteaccess.ha", 1], ["GET /cgi-bin/syslog.ha", 1],
  ]);
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const method = init?.method ?? (input instanceof Request ? input.method : "GET");
    const key = `${method} ${url.pathname}`;
    const limit = limits.get(key);
    if (url.origin !== origin || url.search || url.username || url.password || !limit) {
      throw new RouterResponseError("Qualification request outside exact allowlist.");
    }
    const count = (counts.get(key) ?? 0) + 1;
    if (count > limit) throw new RouterResponseError("Qualification request budget exhausted.");
    counts.set(key, count);
    const response = await originalFetch(input, { ...init, redirect: "manual" });
    if (method === "GET" && response.status !== 200) {
      await response.body?.cancel();
      throw new RouterResponseError("Qualification GET status unexpected; redirect not followed.");
    }
    return response;
  }) as typeof fetch;
  try {
    return await withRouterSession(client, { cacheTtlMs: 0, poolCooldownMs: 300000,
      lockTimeoutMs: 1000, waitForSession: false }, async () => {
      await client.login();
      const pages = [];
      for (const page of ["remoteaccess", "syslog"]) {
        const response = await client.getCgiPage(page);
        const parsed = parsePage(page, response.body);
        const expected = page === "remoteaccess" ? /^Remote Access$/i : /^Syslog$/i;
        if (!expected.test(parsed.heading) && !expected.test(parsed.title)) {
          throw new RouterResponseError("Qualification page identity unexpected.");
        }
        pages.push({ page, statusCode: response.statusCode,
          fields: parsed.fields.length, forms: parsed.forms.length });
      }
      return { status: "READ_QUALIFIED", pages,
        loginPosts: counts.get("POST /cgi-bin/login.ha") ?? 0,
        configurationPosts: 0, requestCounts: Object.fromEntries(counts) };
    });
  } finally {
    client.clearSession();
    globalThis.fetch = originalFetch;
  }
}

if (import.meta.main) {
  try {
    const code = (await Bun.stdin.text()).trimEnd();
    console.log(JSON.stringify(await qualifyAuthenticatedRead(
      process.env.BGW_HOST ?? "http://192.168.1.254", code,
    )));
  } catch (error) {
    // Never emit transport messages, page bodies, cookies, or credential values.
    console.log(JSON.stringify({ status: "STOPPED",
      category: error instanceof RouterAuthError ? "authentication" : "qualification",
      configurationPosts: 0 }));
    process.exitCode = 2;
  }
}
