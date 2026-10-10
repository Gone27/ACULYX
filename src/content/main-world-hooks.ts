/**
 * main-world-hooks.ts - Sensor 3 (S3)
 *
 * Runs in the MAIN execution world (opt-in Deep Mode).
 * Hooks DOM sinks (innerHTML, outerHTML, insertAdjacentHTML, document.write, eval, setTimeout(string), location=),
 * window.postMessage calls & listeners, and Storage.prototype.setItem in-memory.
 *
 * Relays detected events via CustomEvent ('__ACULYX_MAIN_WORLD_EVENT__') to isolated content script.
 */

export interface MainWorldLeadEventDetail {
  eventType: 'sink' | 'postmessage_call' | 'postmessage_listener' | 'storage_write';
  nonce?: string;
  sinkName?: string;
  sourceValue?: string;
  targetOrigin?: string;
  hasOriginCheck?: boolean;
  storageKey?: string;
  tokenShape?: string;
  location?: string;
  details?: string;
}

let hooksInstalledInClosure = false;
const HOOKS_SYMBOL = Symbol.for('__aculyx_main_world_hooks_installed__');
const s3PerLoadNonce = `aculyx_s3_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`;

export function installMainWorldHooks(): void {
  if (hooksInstalledInClosure) return;
  const global = globalThis as any;
  if (global[HOOKS_SYMBOL]) return;
  hooksInstalledInClosure = true;
  try {
    Object.defineProperty(global, HOOKS_SYMBOL, {
      value: true,
      writable: false,
      configurable: false,
      enumerable: false,
    });
  } catch {
    // Protected by closure boolean
  }

  const dispatchedEventHashes = new Set<string>();
  const recentPostMessages: string[] = [];

  function emitEvent(detail: MainWorldLeadEventDetail): void {
    const hash = `${detail.eventType}|${detail.sinkName || ''}|${detail.storageKey || ''}|${detail.targetOrigin || ''}|${detail.details || ''}`;
    if (dispatchedEventHashes.has(hash)) return;
    if (dispatchedEventHashes.size > 200) {
      dispatchedEventHashes.clear();
    }
    dispatchedEventHashes.add(hash);

    try {
      const event = new CustomEvent('__ACULYX_MAIN_WORLD_EVENT__', {
        detail: {
          ...detail,
          nonce: s3PerLoadNonce,
          location: window.location.href,
        },
      });
      window.dispatchEvent(event);
    } catch {
      // Ignore dispatch failures
    }
  }

  // ── Source Extraction Helper ─────────────────────────────────────────────
  function getTaintSources(): Array<{ name: string; value: string }> {
    const sources: Array<{ name: string; value: string }> = [];

    // 1. location.hash
    if (window.location.hash && window.location.hash.length > 2) {
      sources.push({ name: 'location.hash', value: window.location.hash.slice(1) });
    }

    // 2. location.search & individual query params
    if (window.location.search && window.location.search.length > 2) {
      sources.push({ name: 'location.search', value: window.location.search.slice(1) });
      try {
        const sp = new URLSearchParams(window.location.search);
        sp.forEach((v, k) => {
          if (v && v.length >= 3) {
            sources.push({ name: `query_param:${k}`, value: v });
          }
        });
      } catch {
        // Ignore parsing errors
      }
    }

    // 3. document.referrer
    if (document.referrer && document.referrer.length > 5) {
      sources.push({ name: 'document.referrer', value: document.referrer });
    }

    // 4. window.name
    if (window.name && window.name.length >= 3) {
      sources.push({ name: 'window.name', value: window.name });
    }

    // 5. Recent postMessage strings
    for (let i = 0; i < recentPostMessages.length; i++) {
      const msg = recentPostMessages[i];
      if (msg && msg.length >= 4) {
        sources.push({ name: 'postMessage_data', value: msg });
      }
    }

    return sources;
  }

  function checkTaint(assignedValue: unknown, sinkName: string): void {
    if (typeof assignedValue !== 'string' || assignedValue.length < 3) return;

    const sources = getTaintSources();
    for (const src of sources) {
      if (assignedValue.includes(src.value)) {
        emitEvent({
          eventType: 'sink',
          sinkName,
          sourceValue: src.value.slice(0, 80),
          details: `Sink ${sinkName} received string containing data from ${src.name}`,
        });
        break;
      }
    }
  }

  // ── 1. DOM Sinks Hooking ──────────────────────────────────────────────────
  try {
    // innerHTML
    const innerHtmlDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (innerHtmlDescriptor?.set) {
      const origInnerHtmlSet = innerHtmlDescriptor.set;
      Object.defineProperty(Element.prototype, 'innerHTML', {
        set(value: unknown) {
          checkTaint(value, 'Element.innerHTML');
          return origInnerHtmlSet.call(this, value);
        },
        configurable: true,
        enumerable: innerHtmlDescriptor.enumerable,
        get: innerHtmlDescriptor.get,
      });
    }

    // outerHTML
    const outerHtmlDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (outerHtmlDescriptor?.set) {
      const origOuterHtmlSet = outerHtmlDescriptor.set;
      Object.defineProperty(Element.prototype, 'outerHTML', {
        set(value: unknown) {
          checkTaint(value, 'Element.outerHTML');
          return origOuterHtmlSet.call(this, value);
        },
        configurable: true,
        enumerable: outerHtmlDescriptor.enumerable,
        get: outerHtmlDescriptor.get,
      });
    }

    // insertAdjacentHTML
    const origInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function (where: InsertPosition, html: string) {
      checkTaint(html, 'Element.insertAdjacentHTML');
      return origInsertAdjacentHTML.call(this, where, html);
    };

    // document.write & writeln
    const origDocWrite = document.write;
    document.write = function (...args: string[]) {
      for (const arg of args) {
        checkTaint(arg, 'document.write');
      }
      return origDocWrite.apply(this, args);
    };

    const origDocWriteln = document.writeln;
    document.writeln = function (...args: string[]) {
      for (const arg of args) {
        checkTaint(arg, 'document.writeln');
      }
      return origDocWriteln.apply(this, args);
    };

    // window.eval
    const origEval = window.eval;
    window.eval = function (code: string) {
      checkTaint(code, 'window.eval');
      return origEval.call(this, code);
    };

    // setTimeout with string handler
    const origSetTimeout = window.setTimeout;
    window.setTimeout = function (handler: TimerHandler, timeout?: number, ...args: unknown[]) {
      if (typeof handler === 'string') {
        checkTaint(handler, 'setTimeout(string)');
      }
      return origSetTimeout.call(this, handler, timeout, ...args);
    } as typeof window.setTimeout;

    // location.assign & location.replace
    if (window.location) {
      const origAssign = window.location.assign;
      if (typeof origAssign === 'function') {
        window.location.assign = function (url: string) {
          checkTaint(url, 'location.assign');
          return origAssign.call(this, url);
        };
      }

      const origReplace = window.location.replace;
      if (typeof origReplace === 'function') {
        window.location.replace = function (url: string) {
          checkTaint(url, 'location.replace');
          return origReplace.call(this, url);
        };
      }
    }
  } catch {
    // Sink hooking error swallowed to prevent application degradation
  }

  // ── 2. window.postMessage Calls & Listeners ───────────────────────────────
  try {
    const origPostMessage = window.postMessage;
    window.postMessage = function (message: unknown, targetOriginOrOptions: unknown, ...rest: unknown[]) {
      const targetOrigin = typeof targetOriginOrOptions === 'string'
        ? targetOriginOrOptions
        : (targetOriginOrOptions as WindowPostMessageOptions | undefined)?.targetOrigin ?? '*';

      if (targetOrigin === '*') {
        const msgStr = typeof message === 'string' ? message : JSON.stringify(message);
        const containsSensitive = /token|auth|secret|key|jwt|password|session/i.test(msgStr);
        emitEvent({
          eventType: 'postmessage_call',
          targetOrigin: '*',
          details: containsSensitive
            ? 'window.postMessage sent sensitive token/auth data to wildcard target origin "*"'
            : 'window.postMessage sent message to wildcard target origin "*"',
        });
      }
      return origPostMessage.call(this, message, targetOriginOrOptions as string, ...(rest as any));
    };

    const origAddEventListener = window.addEventListener;
    window.addEventListener = function (
      type: string,
      listener: EventListenerOrEventListenerObject | null,
      options?: boolean | AddEventListenerOptions
    ) {
      if (type === 'message' && typeof listener === 'function') {
        const originalFn = listener as (evt: MessageEvent) => void;
        const fnSource = originalFn.toString();
        const hasOriginCheckInSource = /\.origin\b/.test(fnSource);

        const wrapped = function (event: MessageEvent) {
          // Track postMessage data in recent list for source-to-sink correlation
          try {
            if (typeof event.data === 'string') {
              recentPostMessages.push(event.data);
              if (recentPostMessages.length > 20) recentPostMessages.shift();
            } else if (typeof event.data === 'object' && event.data !== null) {
              const str = JSON.stringify(event.data);
              recentPostMessages.push(str);
              if (recentPostMessages.length > 20) recentPostMessages.shift();
            }
          } catch {
            // Ignore serialization error
          }

          if (!hasOriginCheckInSource) {
            emitEvent({
              eventType: 'postmessage_listener',
              hasOriginCheck: false,
              details: 'Message listener registered without origin validation check',
            });
          }

          return originalFn.call(this, event);
        };

        return origAddEventListener.call(this, type, wrapped, options);
      }

      return origAddEventListener.call(this, type, listener, options);
    };
  } catch {
    // PostMessage hooking error swallowed
  }

  // ── 3. Storage Writes Inspection ──────────────────────────────────────────
  try {
    const origSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key: string, value: string) {
      if (typeof key === 'string') {
        const lowerKey = key.toLowerCase();
        const isSensitiveKey =
          lowerKey.includes('token') ||
          lowerKey.includes('jwt') ||
          lowerKey.includes('auth') ||
          lowerKey.includes('secret') ||
          lowerKey.includes('api_key') ||
          lowerKey.includes('apikey') ||
          lowerKey.includes('session');

        let tokenShape: string | undefined;
        if (typeof value === 'string') {
          // JWT shape check
          if (/^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/.test(value)) {
            tokenShape = 'JWT (JSON Web Token)';
          } else if (/^Bearer\s+[A-Za-z0-9._~+/-]+=*$/i.test(value)) {
            tokenShape = 'Bearer Token';
          } else if (value.length >= 32 && /^[a-f0-9]{32,64}$/i.test(value)) {
            tokenShape = 'High-Entropy Hex Token';
          }
        }

        if (isSensitiveKey || tokenShape) {
          emitEvent({
            eventType: 'storage_write',
            storageKey: key,
            tokenShape,
            details: tokenShape
              ? `Storage write to key "${key}" contains ${tokenShape} shape in memory`
              : `Storage write to sensitive key "${key}" observed`,
          });
        }
      }
      return origSetItem.call(this, key, value);
    };
  } catch {
    // Storage hook error swallowed
  }
}

// Auto-run if running in main world directly
if (typeof window !== 'undefined') {
  installMainWorldHooks();
}
