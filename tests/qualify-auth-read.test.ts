import { expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { qualifyAuthenticatedRead, QualificationStopped } from "../scripts/qualify-auth-read.js";

async function runFixture(firstPage: () => Response | Promise<Response>) {
  const originalFetch = globalThis.fetch;
  const originalDir = process.env.BGW_SESSION_CACHE_DIR;
  const dir = await mkdtemp(join(tmpdir(), "bgw-qualify-"));
  process.env.BGW_SESSION_CACHE_DIR = dir;
  const calls: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    calls.push(`${init?.method ?? "GET"} ${url.pathname}`);
    if (init?.method === "POST") return new Response("", {
      status: 302, headers: { location: "/cgi-bin/home.ha", "set-cookie": "sid=synthetic; Path=/" },
    });
    if (url.pathname.endsWith("login.ha")) return new Response('<title>Login</title><input name="nonce" value="abc123">');
    if (url.pathname.endsWith("remoteaccess.ha")) return firstPage();
    return new Response("<title>Syslog</title><form></form>");
  }) as typeof fetch;
  try {
    try {
      const result = await qualifyAuthenticatedRead("http://router.local", "synthetic");
      return { calls, result, failed: false };
    } catch (error) {
      return { calls, failed: true, result: undefined,
        diagnostic: error instanceof QualificationStopped ? error.summary : undefined };
    }
  } finally {
    globalThis.fetch = originalFetch;
    if (originalDir === undefined) delete process.env.BGW_SESSION_CACHE_DIR;
    else process.env.BGW_SESSION_CACHE_DIR = originalDir;
    await rm(dir, { recursive: true, force: true });
  }
}

test("qualification reads exactly two pages with one login POST", async () => {
  const run = await runFixture(() => new Response("<title>Remote Access</title><form></form>"));
  expect(run.failed).toBe(false);
  expect(run.result?.loginPosts).toBe(1);
  expect(run.calls).toEqual(["GET /cgi-bin/login.ha", "POST /cgi-bin/login.ha",
    "GET /cgi-bin/remoteaccess.ha", "GET /cgi-bin/syslog.ha"]);
});

test("qualification stops before second page on redirect", async () => {
  const run = await runFixture(() => new Response("", { status: 302, headers: { location: "/cgi-bin/home.ha" } }));
  expect(run.failed).toBe(true);
  expect(run.calls).toHaveLength(3);
});

test("qualification stops before second page on unexpected page", async () => {
  const run = await runFixture(() => new Response("<title>Page not found</title>"));
  expect(run.failed).toBe(true);
  expect(run.calls).toHaveLength(3);
});

test("qualification stops before second page on timeout", async () => {
  const run = await runFixture(() => { throw new DOMException("Timed out", "AbortError"); });
  expect(run.failed).toBe(true);
  expect(run.calls).toHaveLength(3);
  expect(run.diagnostic).toEqual({ status: "STOPPED", category: "qualification",
    phase: "GET /cgi-bin/remoteaccess.ha", loginPostAttempts: 1,
    configurationPosts: 0, lastResponseStatus: null });
});

test("qualification diagnostics omit response content and exception messages", async () => {
  const run = await runFixture(() => { throw new Error("secret-synthetic-value"); });
  expect(JSON.stringify(run.diagnostic)).not.toContain("secret-synthetic-value");
  expect(run.diagnostic?.loginPostAttempts).toBe(1);
});
