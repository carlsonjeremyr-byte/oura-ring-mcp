import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const tokenUrl = "https://api.ouraring.com/oauth/token";

describe("OuraTokenManager", () => {
  let dir: string;
  const originalEnv = process.env;
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.resetModules();
    dir = mkdtempSync(join(tmpdir(), "oura-tm-"));
    process.env = {
      ...originalEnv,
      OURA_CREDENTIALS_PATH: join(dir, "creds.json"),
      OURA_CLIENT_ID: "cid",
      OURA_CLIENT_SECRET: "csecret",
    };
    delete process.env.OURA_ACCESS_TOKEN;
  });

  afterEach(() => {
    process.env = originalEnv;
    global.fetch = originalFetch;
    rmSync(dir, { recursive: true, force: true });
  });

  it("reports none when there are no credentials", async () => {
    const { OuraTokenManager } = await import("./token-manager.js");
    const tm = new OuraTokenManager();
    await tm.load();
    expect(tm.hasCredentials()).toBe(false);
    expect(tm.status().mode).toBe("none");
    await expect(tm.getAccessToken()).rejects.toThrow(/oauth\/start/);
  });

  it("falls back to a static token", async () => {
    const { OuraTokenManager } = await import("./token-manager.js");
    const tm = new OuraTokenManager({ staticToken: "pat" });
    await tm.load();
    expect(tm.status().mode).toBe("static");
    expect(await tm.getAccessToken()).toBe("pat");
  });

  it("persists credentials and prefers them over the static token", async () => {
    const { OuraTokenManager } = await import("./token-manager.js");
    const tm = new OuraTokenManager({ staticToken: "pat" });
    await tm.setCredentials({
      access_token: "at",
      refresh_token: "rt",
      token_type: "bearer",
      expires_at: Date.now() + 3600_000,
    });
    expect(await tm.getAccessToken()).toBe("at");
    expect(existsSync(process.env.OURA_CREDENTIALS_PATH!)).toBe(true);

    // A fresh manager loads them from disk
    const tm2 = new OuraTokenManager();
    await tm2.load();
    expect(tm2.status().mode).toBe("oauth");
    expect(await tm2.getAccessToken()).toBe("at");
  });

  it("refreshes an expired token once and saves the rotated refresh token", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        access_token: "new-at",
        refresh_token: "new-rt",
        token_type: "bearer",
        expires_in: 86400,
      }),
    });
    global.fetch = fetchMock as unknown as typeof fetch;

    const { OuraTokenManager } = await import("./token-manager.js");
    const tm = new OuraTokenManager();
    await tm.setCredentials({
      access_token: "old-at",
      refresh_token: "old-rt",
      token_type: "bearer",
      expires_at: Date.now() - 1,
    });

    // Concurrent callers share one refresh (refresh tokens are single-use)
    const [a, b] = await Promise.all([tm.getAccessToken(), tm.getAccessToken()]);
    expect(a).toBe("new-at");
    expect(b).toBe("new-at");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe(tokenUrl);
    const body = fetchMock.mock.calls[0][1].body as URLSearchParams;
    expect(body.get("grant_type")).toBe("refresh_token");
    expect(body.get("refresh_token")).toBe("old-rt");

    const saved = JSON.parse(readFileSync(process.env.OURA_CREDENTIALS_PATH!, "utf-8"));
    expect(saved.refresh_token).toBe("new-rt");
  });

  it("forceRefresh returns null when refresh is impossible", async () => {
    delete process.env.OURA_CLIENT_ID;
    const { OuraTokenManager } = await import("./token-manager.js");
    const tm = new OuraTokenManager({ staticToken: "pat" });
    expect(await tm.forceRefresh()).toBeNull();
  });
});
