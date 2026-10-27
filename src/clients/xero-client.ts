import axios, { AxiosError } from "axios";
import dotenv from "dotenv";
import fs from "fs";
import {
  IXeroClientConfig,
  Organisation,
  TokenSet,
  XeroClient,
} from "xero-node";

import { ensureError } from "../helpers/ensure-error.js";

dotenv.config();

const client_id = process.env.XERO_CLIENT_ID;
const client_secret = process.env.XERO_CLIENT_SECRET;
const bearer_token = process.env.XERO_CLIENT_BEARER_TOKEN;
const token_file = process.env.XERO_TOKEN_FILE;
const grant_type = "client_credentials";

if (!bearer_token && (!client_id || !client_secret)) {
  throw Error("Environment Variables not set - please check your .env file");
}

abstract class MCPXeroClient extends XeroClient {
  public tenantId: string;
  private shortCode: string;

  protected constructor(config?: IXeroClientConfig) {
    super(config);
    this.tenantId = "";
    this.shortCode = "";
  }

  public abstract authenticate(): Promise<void>;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  override async updateTenants(fullOrgDetails?: boolean): Promise<any[]> {
    await super.updateTenants(fullOrgDetails);
    if (this.tenants && this.tenants.length > 0) {
      this.tenantId = this.tenants[0].tenantId;
    }
    return this.tenants;
  }

  private async getOrganisation(): Promise<Organisation> {
    await this.authenticate();

    const organisationResponse = await this.accountingApi.getOrganisations(
      this.tenantId || "",
    );

    const organisation = organisationResponse.body.organisations?.[0];

    if (!organisation) {
      throw new Error("Failed to retrieve organisation");
    }

    return organisation;
  }

  public async getShortCode(): Promise<string | undefined> {
    if (!this.shortCode) {
      try {
        const organisation = await this.getOrganisation();
        this.shortCode = organisation.shortCode ?? "";
      } catch (error: unknown) {
        const err = ensureError(error);

        throw new Error(
          `Failed to get Organisation short code: ${err.message}`,
        );
      }
    }
    return this.shortCode;
  }
}

class CustomConnectionsXeroClient extends MCPXeroClient {
  private readonly clientId: string;
  private readonly clientSecret: string;

  // Legacy scopes (deprecated but still supported for existing apps)
  private readonly XERO_DEFAULT_AUTH_SCOPES_V1 = [
    "accounting.transactions",
    "accounting.contacts",
    "accounting.settings",
    "accounting.reports.read",
    "payroll.settings",
    "payroll.employees",
    "payroll.timesheets",
  ].join(" ");

  // Granular scopes (required for new apps)
  private readonly XERO_DEFAULT_AUTH_SCOPES_V2 = [
    "accounting.invoices",
    "accounting.payments",
    "accounting.banktransactions",
    "accounting.manualjournals",
    "accounting.reports.aged.read",
    "accounting.reports.balancesheet.read",
    "accounting.reports.profitandloss.read",
    "accounting.reports.trialbalance.read",
    "accounting.contacts",
    "accounting.settings",
    "payroll.settings",
    "payroll.employees",
    "payroll.timesheets",
  ].join(" ");

  constructor(config: {
    clientId: string;
    clientSecret: string;
    grantType: string;
  }) {
    super(config);
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
  }

  private formatTokenError(error: unknown, context: string): Error {
    const axiosError = error as AxiosError;
    const data = axiosError.response?.data;
    const message =
      typeof data === "object" ? JSON.stringify(data) : data || axiosError.message;
    return new Error(`Failed to get Xero token${context}: ${message}`);
  }

  public async getClientCredentialsToken(): Promise<TokenSet> {
    // If XERO_SCOPES is set, use that
    if (process.env.XERO_SCOPES) {                                                                                                                                                     
      try {
        return await this.requestToken(process.env.XERO_SCOPES);
      } catch (envError) {
        throw this.formatTokenError(envError, " with XERO_SCOPES");
      }
    }

    // Else if XERO_SCOPES is not set, try V1 scopes first (for existing apps), fallback to V2 scopes (for new apps) only on invalid_scope error
    try {
      return await this.requestToken(this.XERO_DEFAULT_AUTH_SCOPES_V1);
    } catch (error) {
      const axiosError = error as AxiosError;
      const isInvalidScope =
        axiosError.response?.status === 400 &&
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (axiosError.response?.data as any)?.error === "invalid_scope";

      if (!isInvalidScope) {
        throw this.formatTokenError(error, " with V1 scopes");
      }

      try {
        return await this.requestToken(this.XERO_DEFAULT_AUTH_SCOPES_V2);
      } catch (v2Error) {
        throw this.formatTokenError(v2Error, " with V2 scopes");
      }
    }
  }

  private async requestToken(scope: string): Promise<TokenSet> {
    const credentials = Buffer.from(
      `${this.clientId}:${this.clientSecret}`,
    ).toString("base64");

    const response = await axios.post(
      "https://identity.xero.com/connect/token",
      `grant_type=client_credentials&scope=${encodeURIComponent(scope)}`,
      {
        headers: {
          Authorization: `Basic ${credentials}`,
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
      },
    );

    // Get the tenant ID from the connections endpoint
    const token = response.data.access_token;
    const connectionsResponse = await axios.get(
      "https://api.xero.com/connections",
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
        },
      },
    );

    if (connectionsResponse.data && connectionsResponse.data.length > 0) {
      this.tenantId = connectionsResponse.data[0].tenantId;
    }

    return response.data;
  }

  public async authenticate() {
    const tokenResponse = await this.getClientCredentialsToken();

    this.setTokenSet({
      access_token: tokenResponse.access_token,
      expires_in: tokenResponse.expires_in,
      token_type: tokenResponse.token_type,
    });
  }
}

class BearerTokenXeroClient extends MCPXeroClient {
  private readonly bearerToken: string;

  constructor(config: { bearerToken: string }) {
    super();
    this.bearerToken = config.bearerToken;
  }

  async authenticate(): Promise<void> {
    this.setTokenSet({
      access_token: this.bearerToken,
    });

    await this.updateTenants();
  }
}

class RefreshTokenXeroClient extends MCPXeroClient {
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly tokenFile: string;
  // Refresh a minute early so a token doesn't expire mid-request
  private readonly EXPIRY_MARGIN_SECONDS = 60;
  private refreshInFlight: Promise<TokenSet> | null = null;

  constructor(config: {
    clientId: string;
    clientSecret: string;
    tokenFile: string;
  }) {
    super();
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.tokenFile = config.tokenFile;
  }

  private readTokens(): TokenSet {
    try {
      return JSON.parse(fs.readFileSync(this.tokenFile, "utf8"));
    } catch (error: unknown) {
      const err = ensureError(error);
      throw new Error(
        `Failed to read Xero token file ${this.tokenFile}: ${err.message}`,
      );
    }
  }

  private writeTokens(tokens: TokenSet): void {
    // Write to a temp file then rename so a crash can't leave a half-written file
    const tempFile = `${this.tokenFile}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(tokens, null, 2), {
      mode: 0o600,
    });
    fs.renameSync(tempFile, this.tokenFile);
  }

  private isExpired(tokens: TokenSet): boolean {
    if (!tokens.expires_at) return true;
    const now = Math.floor(Date.now() / 1000);
    return tokens.expires_at - this.EXPIRY_MARGIN_SECONDS <= now;
  }

  private async refreshTokens(refreshToken: string): Promise<TokenSet> {
    const credentials = Buffer.from(
      `${this.clientId}:${this.clientSecret}`,
    ).toString("base64");

    try {
      const response = await axios.post(
        "https://identity.xero.com/connect/token",
        `grant_type=refresh_token&refresh_token=${encodeURIComponent(refreshToken)}`,
        {
          headers: {
            Authorization: `Basic ${credentials}`,
            "Content-Type": "application/x-www-form-urlencoded",
            Accept: "application/json",
          },
        },
      );

      const tokens: TokenSet = {
        ...response.data,
        expires_at:
          Math.floor(Date.now() / 1000) + Number(response.data.expires_in),
      };
      // Xero rotates the refresh token, so the new one must be saved
      this.writeTokens(tokens);
      return tokens;
    } catch (error) {
      const axiosError = error as AxiosError;
      const data = axiosError.response?.data;
      const message =
        typeof data === "object" ? JSON.stringify(data) : data || axiosError.message;
      throw new Error(
        `Failed to refresh Xero token (you may need to re-authorise): ${message}`,
      );
    }
  }

  async authenticate(): Promise<void> {
    // Re-read each time so tokens refreshed by another process are picked up
    let tokens = this.readTokens();

    if (this.isExpired(tokens)) {
      if (!tokens.refresh_token) {
        throw new Error(
          `Xero token in ${this.tokenFile} has expired and has no refresh_token`,
        );
      }
      // Share one refresh between concurrent tool calls, since each refresh
      // rotates the refresh token
      this.refreshInFlight ??= this.refreshTokens(tokens.refresh_token).finally(
        () => {
          this.refreshInFlight = null;
        },
      );
      tokens = await this.refreshInFlight;
    }

    this.setTokenSet({
      access_token: tokens.access_token,
      token_type: tokens.token_type,
    });

    if (!this.tenantId) {
      await this.updateTenants();
    }
  }
}

export const xeroClient = bearer_token
  ? new BearerTokenXeroClient({
      bearerToken: bearer_token,
    })
  : token_file
    ? new RefreshTokenXeroClient({
        clientId: client_id!,
        clientSecret: client_secret!,
        tokenFile: token_file,
      })
    : new CustomConnectionsXeroClient({
        clientId: client_id!,
        clientSecret: client_secret!,
        grantType: grant_type,
      });
