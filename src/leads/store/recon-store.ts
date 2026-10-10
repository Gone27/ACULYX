import type { ReconMemory, ReconHost, ReconParam, ReconEndpoint, ReconBucket } from '../types';
import { maskLocation } from '../sieve/mask';

const STORAGE_KEY = 'aculyx_recon_memory';

const LIMITS = {
  maxHosts: 500,
  maxParams: 1000,
  maxEndpoints: 500,
  maxBuckets: 200,
};

let inMemoryCache: ReconMemory = {
  hosts: [],
  params: [],
  endpoints: [],
  buckets: [],
};

function hasChromeStorage(): boolean {
  return typeof chrome !== 'undefined' && Boolean(chrome?.storage?.local);
}

interface SerializedReconMemory {
  hosts?: ReconHost[];
  params?: ReconParam[];
  endpoints?: ReconEndpoint[];
  buckets?: ReconBucket[];
}

export async function getReconMemory(): Promise<ReconMemory> {
  if (hasChromeStorage()) {
    try {
      const result = await chrome.storage.local.get([STORAGE_KEY]);
      const data = result[STORAGE_KEY] as SerializedReconMemory | undefined;
      if (typeof data === 'object' && data !== null) {
        inMemoryCache = {
          hosts: Array.isArray(data.hosts) ? data.hosts : [],
          params: Array.isArray(data.params) ? data.params : [],
          endpoints: Array.isArray(data.endpoints) ? data.endpoints : [],
          buckets: Array.isArray(data.buckets) ? data.buckets : [],
        };
      }
    } catch {
      // Ignore and use inMemoryCache
    }
  }
  return {
    hosts: [...inMemoryCache.hosts],
    params: [...inMemoryCache.params],
    endpoints: [...inMemoryCache.endpoints],
    buckets: [...inMemoryCache.buckets],
  };
}

async function persistReconMemory(mem: ReconMemory): Promise<void> {
  inMemoryCache = mem;
  if (hasChromeStorage()) {
    try {
      await chrome.storage.local.set({ [STORAGE_KEY]: mem });
    } catch {
      // Fallback
    }
  }
}

export async function recordHost(host: ReconHost): Promise<void> {
  const mem = await getReconMemory();
  const existingIdx = mem.hosts.findIndex(h => h.hostname === host.hostname);
  const existing = existingIdx !== -1 ? mem.hosts[existingIdx] : undefined;

  if (existing !== undefined) {
    existing.lastSeen = Math.max(existing.lastSeen, host.lastSeen);
    if (host.scopeStatus !== 'unknown') {
      existing.scopeStatus = host.scopeStatus;
    }
    // Move to back to refresh LRU
    mem.hosts.splice(existingIdx, 1);
    mem.hosts.push(existing);
  } else {
    mem.hosts.push(host);
    if (mem.hosts.length > LIMITS.maxHosts) {
      mem.hosts.shift();
    }
  }

  await persistReconMemory(mem);
}

export async function recordParam(param: ReconParam): Promise<void> {
  const mem = await getReconMemory();
  const existingIdx = mem.params.findIndex(
    p => p.name === param.name && p.origin === param.origin
  );
  const existing = existingIdx !== -1 ? mem.params[existingIdx] : undefined;

  if (existing !== undefined) {
    const mergedContexts = Array.from(new Set([...existing.contexts, ...param.contexts]));
    existing.contexts = mergedContexts;
    if (typeof param.category === 'string' && param.category.length > 0 && (existing.category === undefined || existing.category === 'general')) {
      existing.category = param.category;
    }
    mem.params.splice(existingIdx, 1);
    mem.params.push(existing);
  } else {
    mem.params.push({
      ...param,
      contexts: [...(param.contexts !== undefined ? param.contexts : [])],
    });
    if (mem.params.length > LIMITS.maxParams) {
      mem.params.shift();
    }
  }

  await persistReconMemory(mem);
}

export async function recordEndpoint(ep: ReconEndpoint): Promise<void> {
  const mem = await getReconMemory();
  const method = typeof ep.method === 'string' && ep.method.length > 0 ? ep.method : 'GET';
  const rawPath = ep.path;
  const maskedPath = maskLocation(typeof rawPath === 'string' && rawPath.length > 0 ? rawPath : '');
  const sanitizedPath = maskedPath.length > 0 ? maskedPath : ep.path;
  const existingIdx = mem.endpoints.findIndex(
    e => e.origin === ep.origin && e.path === sanitizedPath && (typeof e.method === 'string' && e.method.length > 0 ? e.method : 'GET') === method
  );
  const existing = existingIdx !== -1 ? mem.endpoints[existingIdx] : undefined;

  if (existing !== undefined) {
    const mergedTags = Array.from(new Set([...existing.tags, ...ep.tags]));
    existing.tags = mergedTags;
    if (ep.status !== undefined) {
      existing.status = ep.status;
    }
    mem.endpoints.splice(existingIdx, 1);
    mem.endpoints.push(existing);
  } else {
    mem.endpoints.push({
      ...ep,
      path: sanitizedPath,
      tags: [...(ep.tags !== undefined ? ep.tags : [])],
    });
    if (mem.endpoints.length > LIMITS.maxEndpoints) {
      mem.endpoints.shift();
    }
  }

  await persistReconMemory(mem);
}

export async function recordBucket(bucket: ReconBucket): Promise<void> {
  const mem = await getReconMemory();
  const existingIdx = mem.buckets.findIndex(
    b => b.bucket === bucket.bucket && b.provider === bucket.provider && b.origin === bucket.origin
  );
  const existing = existingIdx !== -1 ? mem.buckets[existingIdx] : undefined;

  if (existing !== undefined) {
    mem.buckets.splice(existingIdx, 1);
    mem.buckets.push(existing);
  } else {
    mem.buckets.push(bucket);
    if (mem.buckets.length > LIMITS.maxBuckets) {
      mem.buckets.shift();
    }
  }

  await persistReconMemory(mem);
}

export async function clearRecon(): Promise<void> {
  inMemoryCache = {
    hosts: [],
    params: [],
    endpoints: [],
    buckets: [],
  };
  if (hasChromeStorage()) {
    try {
      await chrome.storage.local.remove([STORAGE_KEY]);
    } catch {
      // Fallback
    }
  }
}

export const clearReconMemory = clearRecon;
