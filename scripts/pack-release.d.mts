export interface CollectedFile {
  fullPath: string;
  relPath: string;
}

export interface PackResult {
  path: string;
  fileCount: number;
  sizeBytes: number;
}

export function isExcludedFile(relPath: string, target?: string): boolean;
export function collectFiles(sourceDir: string, target: string): CollectedFile[];
export function writeZipArchive(
  files: CollectedFile[],
  destZipPath: string,
  options?: { overwrite?: boolean }
): PackResult;
export function packTarget(
  target: string,
  outputDir: string,
  options?: { overwrite?: boolean }
): PackResult;
export function generateChecksumManifest(
  outputDir: string
): { manifestPath: string; lines: string[] } | null;
