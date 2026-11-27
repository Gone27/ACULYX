export type VerificationTarget = 'source' | 'chrome' | 'firefox' | 'full';

export interface ZipEntry {
  name: string;
  compressionMethod: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
}

export interface VerificationResult {
  success: boolean;
  errors: string[];
  entries: string[];
}

export interface AggregateVerificationResult {
  success: boolean;
  errors: string[];
  results: Record<string, VerificationResult>;
}

export function readRepoPackageVersion(): string;
export function validateNoticeContent(noticeText: string, locationLabel: string, errors: string[]): void;
export function parseZipEntries(buf: Buffer): ZipEntry[];
export function extractZipEntry(buf: Buffer, entry: ZipEntry): Buffer;
export function verifyZipArchive(
  zipPath: string,
  target: VerificationTarget,
  options?: { smokeExtract?: boolean; quiet?: boolean; expectedVersion?: string }
): VerificationResult;

export function verifyAllArchives(
  dir: string,
  options?: { smokeExtract?: boolean; quiet?: boolean; expectedVersion?: string }
): AggregateVerificationResult;
