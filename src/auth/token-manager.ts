/**
 * Oura token manager
 *
 * Owns the Oura OAuth credentials for this server and keeps them fresh:
 *   - loads persisted credentials at startup (OURA_CREDENTIALS_PATH or ~/.oura-mcp)
 *   - refreshes the access token before it expires (Oura refresh tokens are
 *     single-use, so every refresh is persisted immediately)
 *   - falls back to a static OURA_ACCESS_TOKEN (legacy PAT) when no OAuth
 *     credentials exist
 *
 * Personal Access Tokens are deprecated by Oura and can no longer be created,
 * so the OAuth path is the supported one; the PAT fallback only exists so
 * old deployments keep working until their token is shut off.
 */
import {
  loadCredentials,
  saveCredentials,
  isExpired,
  type OuraCredentials,
} from "./store.js";
import { refreshAccessToken, getOAuthConfigFromEnv, type OAuthConfig } from "./oauth.js";

export interface TokenManagerOptions {
  /** OAuth client config (needed to refresh). Defaults to env-derived config. */
  oauthConfig?: OAuthConfig | null;
  /** Static fallback token (legacy PAT). */
  staticToken?: string;
}

export class OuraTokenManager {
  private credentials: OuraCredentials | null = null;
  private oauthConfig: OAuthConfig | null;
  private staticToken: string | undefined;
  private refreshing: Promise<OuraCredentials> | null = null;

  constructor(options: TokenManagerOptions = {}) {
    this.oauthConfig =
      options.oauthConfig === undefined ? getOAuthConfigFromEnv() : options.oauthConfig;
    this.staticToken = options.staticToken;
  }

  /** Load persisted credentials from disk (no-op if none). */
  async load(): Promise<void> {
    this.credentials = await loadCredentials();
  }

  /** True when we have some way of authenticating to Oura. */
  hasCredentials(): boolean {
    return !!(this.credentials || this.staticToken);
  }

  /** True when OAuth credentials (refreshable) are present. */
  hasOAuthCredentials(): boolean {
    return !!this.credentials;
  }

  /** Human-readable status for /health and logs. */
  status(): { mode: "oauth" | "static" | "none"; expiresAt?: number; canRefresh: boolean } {
    if (this.credentials) {
      return {
        mode: "oauth",
        expiresAt: this.credentials.expires_at,
        canRefresh: !!this.oauthConfig,
      };
    }
    if (this.staticToken) return { mode: "static", canRefresh: false };
    return { mode: "none", canRefresh: false };
  }

  /**
   * Replace credentials (after an OAuth authorization) and persist them.
   */
  async setCredentials(credentials: OuraCredentials): Promise<void> {
    this.credentials = credentials;
    await saveCredentials(credentials);
  }

  /**
   * Return a valid access token, refreshing first if it is (about to be) expired.
   * Throws if there are no credentials at all.
   */
  async getAccessToken(): Promise<string> {
    if (this.credentials) {
      if (isExpired(this.credentials)) {
        await this.refresh();
      }
      return this.credentials!.access_token;
    }
    if (this.staticToken) return this.staticToken;
    throw new Error(
      "No Oura credentials. Visit /oauth/start on the server to authorize it with Oura."
    );
  }

  /**
   * Force a refresh (e.g. after a 401). Returns the new access token, or null
   * if refresh isn't possible.
   */
  async forceRefresh(): Promise<string | null> {
    if (!this.credentials || !this.oauthConfig) return null;
    try {
      await this.refresh();
      return this.credentials.access_token;
    } catch (err) {
      console.error(`Oura token refresh failed: ${err instanceof Error ? err.message : err}`);
      return null;
    }
  }

  private async refresh(): Promise<void> {
    if (!this.credentials) throw new Error("No credentials to refresh");
    if (!this.oauthConfig) {
      throw new Error(
        "Oura access token expired and OURA_CLIENT_ID/OURA_CLIENT_SECRET are not set, so it cannot be refreshed."
      );
    }
    // Coalesce concurrent refreshes — the refresh token is single-use, so two
    // parallel refreshes would invalidate each other.
    if (!this.refreshing) {
      const refreshToken = this.credentials.refresh_token;
      this.refreshing = refreshAccessToken(refreshToken, this.oauthConfig).finally(() => {
        this.refreshing = null;
      });
    }
    this.credentials = await this.refreshing;
    console.error("Oura access token refreshed");
  }
}
