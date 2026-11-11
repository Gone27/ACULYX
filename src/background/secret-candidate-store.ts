import type { CredentialProvider } from '../leads/types';

export interface SecretCandidate {
  leadId: string;
  provider: CredentialProvider;
  tokenFamily: string;
  rawToken: string;
  expiresAt: number;
  attempted: boolean;
}

const CANDIDATE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const MAX_CANDIDATES = 100;

/**
 * Ephemeral, in-memory store for candidate credentials.
 * Kept exclusively in background memory. Never persisted to chrome.storage,
 * IndexedDB, localStorage, sessionStorage, or exported artifacts.
 */
export class SecretCandidateStore {
  private candidates = new Map<string, SecretCandidate>();

  public addCandidate(
    leadId: string,
    provider: CredentialProvider,
    tokenFamily: string,
    rawToken: string
  ): void {
    if (!leadId || !rawToken) return;

    // Clean up expired entries first
    this.purgeExpired();

    // Enforce capacity bound by evicting oldest insertion
    if (this.candidates.size >= MAX_CANDIDATES) {
      const oldestKey = this.candidates.keys().next().value;
      if (oldestKey !== undefined) {
        this.candidates.delete(oldestKey);
      }
    }

    const candidate: SecretCandidate = {
      leadId,
      provider,
      tokenFamily,
      rawToken,
      expiresAt: Date.now() + CANDIDATE_TTL_MS,
      attempted: false,
    };

    this.candidates.set(leadId, candidate);
  }

  public getCandidate(leadId: string): SecretCandidate | undefined {
    const candidate = this.candidates.get(leadId);
    if (!candidate) return undefined;

    if (Date.now() > candidate.expiresAt || candidate.attempted) {
      this.candidates.delete(leadId);
      return undefined;
    }

    return candidate;
  }

  /**
   * Consumes a candidate for a single probe attempt.
   * Immediately removes from store to enforce one-attempt-per-candidate policy.
   */
  public consumeCandidate(leadId: string): SecretCandidate | undefined {
    const candidate = this.getCandidate(leadId);
    if (!candidate) return undefined;

    this.candidates.delete(leadId);
    candidate.attempted = true;
    return candidate;
  }

  public removeCandidate(leadId: string): void {
    this.candidates.delete(leadId);
  }

  public clear(): void {
    this.candidates.clear();
  }

  public count(): number {
    this.purgeExpired();
    return this.candidates.size;
  }

  private purgeExpired(): void {
    const now = Date.now();
    for (const [key, candidate] of this.candidates.entries()) {
      if (now > candidate.expiresAt || candidate.attempted) {
        this.candidates.delete(key);
      }
    }
  }
}

export const globalSecretCandidateStore = new SecretCandidateStore();
