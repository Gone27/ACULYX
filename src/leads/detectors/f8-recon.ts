import type { Lead } from '../types';
import { maskSecret, maskLocation } from '../sieve/mask';

let leadCounter = 0;
function nextLeadId(prefix: string): string {
  leadCounter++;
  return `LD-${prefix}-${Date.now().toString(36)}-${leadCounter}`;
}

export function detectReconLeads(
  content: string,
  url: string,
  scopeStatus: Lead['scopeStatus'] = 'unknown'
): Lead[] {
  const leads: Lead[] = [];
  if (!content || typeof content !== 'string') return leads;

  const origin = (() => {
    try {
      return new URL(url).origin;
    } catch {
      return 'https://unknown';
    }
  })();

  // 1. CLD-001: Cloud Bucket Extraction (AWS S3, GCP, Azure, DigitalOcean)
  const bucketPatterns = [
    { provider: 'aws', regex: /https?:\/\/([a-z0-9.\-_]+)\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com/gi },
    { provider: 'aws', regex: /s3:\/\/([a-z0-9.\-_]+)/gi },
    { provider: 'gcp', regex: /https?:\/\/storage\.googleapis\.com\/([a-z0-9.\-_]+)/gi },
    { provider: 'gcp', regex: /https?:\/\/([a-z0-9.\-_]+)\.storage\.googleapis\.com/gi },
    { provider: 'azure', regex: /https?:\/\/([a-z0-9.\-_]+)\.blob\.core\.windows\.net/gi },
    { provider: 'digitalocean', regex: /https?:\/\/([a-z0-9.\-_]+)\.[a-z0-9\-]+\.digitaloceanspaces\.com/gi },
  ];

  const seenBuckets = new Set<string>();

  for (const { provider, regex } of bucketPatterns) {
    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      const bucketName = match[1];
      if (bucketName && !seenBuckets.has(bucketName)) {
        seenBuckets.add(bucketName);
        leads.push({
          id: nextLeadId('CLD-BUCKET'),
          ruleId: 'CLD-001',
          family: 'F8',
          tier: 'observed',
          potential: 'low',
          confidence: 0.95,
          title: `Cloud Storage Bucket Reference Disclosed (${provider.toUpperCase()}: ${bucketName})`,
          needs: ['verify bucket ACLs and public listing/reading permissions'],
          doesNotProve: ['publicly readable or writable cloud bucket'],
          evidence: {
            preview: maskSecret(bucketName),
            location: maskLocation(url),
            extractedNames: [bucketName],
            context: `${provider.toUpperCase()} Bucket Reference: ${match[0]}`,
          },
          tags: ['cloud-bucket', 'cloud', 'recon', provider],
          scopeStatus,
          timestamp: Date.now(),
          origin,
          url,
          sourceSensor: 'S3',
          remediation: 'Ensure bucket permissions block public listing and unauthorized reads.',
        });
      }
    }
  }

  // 2. IFR-001: Insecure Iframes, target=_blank, and postMessage
  if (/<iframe[^>]*>/i.test(content)) {
    const iframeMatches = content.match(/<iframe\s+[^>]*>/gi) || [];
    for (const iframe of iframeMatches) {
      if (!iframe.includes('sandbox')) {
        leads.push({
          id: nextLeadId('IFR-NOSANDBOX'),
          ruleId: 'IFR-001',
          family: 'F8',
          tier: 'observed',
          potential: 'low',
          confidence: 0.85,
          title: 'Iframe Embedded Without Sandbox Attribute',
          needs: ['check cross-domain iframe context'],
          doesNotProve: ['framing attack or clickjacking'],
          evidence: {
            preview: maskSecret(iframe.slice(0, 60)),
            location: maskLocation(url),
          },
          tags: ['iframe', 'sandbox-missing'],
          scopeStatus,
          timestamp: Date.now(),
          origin,
          url,
          sourceSensor: 'S3',
        });
        break; // one per document
      }
    }
  }

  if (content.includes('postMessage(') && content.includes("'*'")) {
    leads.push({
      id: nextLeadId('IFR-POSTMSG'),
      ruleId: 'IFR-001',
      family: 'F8',
      tier: 'strong',
      potential: 'medium',
      confidence: 0.8,
      title: 'postMessage Invoked with Wildcard Target Origin (*)',
      needs: ['inspect message payload and recipient listener'],
      doesNotProve: ['data leakage without malicious recipient window'],
      evidence: {
        preview: maskSecret("postMessage(..., '*')"),
        location: maskLocation(url),
      },
      tags: ['postmessage', 'wildcard-origin'],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url,
      sourceSensor: 'S2',
    });
  }

  // 3. TECH-002: Tech Fingerprints (generator meta, wp-content)
  if (content.includes('wp-content') || content.includes('wp-includes')) {
    leads.push({
      id: nextLeadId('TECH-WP'),
      ruleId: 'TECH-002',
      family: 'F8',
      tier: 'observed',
      potential: 'info',
      confidence: 1.0,
      title: 'WordPress Technology Fingerprint Observed',
      needs: ['reconnaissance only'],
      doesNotProve: ['vulnerability'],
      evidence: {
        preview: maskSecret('WordPress asset path wp-content'),
        location: maskLocation(url),
      },
      tags: ['tech-fingerprint', 'wordpress'],
      scopeStatus,
      timestamp: Date.now(),
      origin,
      url,
      sourceSensor: 'S3',
    });
  }

  return leads;
}
