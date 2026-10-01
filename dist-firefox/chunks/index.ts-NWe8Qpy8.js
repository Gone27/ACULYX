import { a as DEFAULT_SETTINGS, d as SCORE_VERSION, i as BADGE_COLORS, l as POPUP_PORT_NAME, n as portSend, o as GRADE_THRESHOLDS, p as SIDEPANEL_PORT_NAME, t as PortRegistry, u as RESTRICTED_SCHEMES } from "./messaging-BCRf7spF.js";
import { n as SessionStorage, r as SettingsService, t as LocalStorage } from "./storage-DkrZ3D78.js";
import { a as registerCaptureListeners, c as originAuthBaselines, i as captureMap, l as tabStates, n as reconcilePermissionsOnRemoved, o as hydrateFromSession, r as reconcilePermissionsOnStartup, s as initLifecycle, t as PermissionsService } from "./permissions-C601rqBC.js";
import { a as isSensitiveCookie, c as parseCspDirectives, f as sanitizeEvidence, n as extractSetCookieHeaders, r as hasCspBypassProtection, s as originFromUrl, t as checkDuplicateHeaders } from "./utils-DgBLspgH.js";
import { n as registrableDomain, t as checkSubdomainTrust } from "./subdomain-trust-B3Jbs8TC.js";
//#region \0rolldown/runtime.js
var __commonJSMin = (cb, mod) => () => (mod || (cb((mod = { exports: {} }).exports, mod), cb = null), mod.exports);
//#endregion
//#region src/background/correlate.ts
/**
* Extract the cookie name from a raw Set-Cookie header value.
* The name is everything before the first '=' character.
* If no '=' is found the entire token is treated as the name.
*/
function parseCookieName(setCookieHeader) {
	const eqIdx = setCookieHeader.indexOf("=");
	if (eqIdx === -1) return setCookieHeader.trim();
	return setCookieHeader.slice(0, eqIdx).trim();
}
function parseCookieHeaderMetadata(setCookieHeader) {
	const parts = setCookieHeader.split(";").map((part) => part.trim());
	const name = parseCookieName(setCookieHeader);
	let path = null;
	let domainAttributePresent = false;
	let domain = null;
	let sameSiteNone = false;
	let secure = false;
	for (const attribute of parts.slice(1)) {
		const separator = attribute.indexOf("=");
		const attributeName = (separator === -1 ? attribute : attribute.slice(0, separator)).trim().toLowerCase();
		if (attributeName === "path" && separator !== -1) path = attribute.slice(separator + 1).trim();
		if (attributeName === "domain") {
			domainAttributePresent = true;
			domain = separator === -1 ? "" : attribute.slice(separator + 1).trim().replace(/^\./, "").toLowerCase();
		}
		if (attributeName === "samesite" && separator !== -1) sameSiteNone = attribute.slice(separator + 1).trim().toLowerCase() === "none";
		if (attributeName === "secure" && separator === -1) secure = true;
	}
	return {
		name,
		path,
		domainAttributePresent,
		domain,
		sameSiteNone,
		secure
	};
}
function findUnobservedCookieFindings(setCookieHeaders, cookies, tabUrl) {
	const metadata = setCookieHeaders.map(parseCookieHeaderMetadata);
	const url = (() => {
		try {
			return new URL(tabUrl);
		} catch {
			return null;
		}
	})();
	if (url === null) return [];
	const visibleNames = new Set(cookies.map((cookie) => cookie.name));
	return metadata.filter((cookie) => cookie.name.length > 0 && !visibleNames.has(cookie.name)).flatMap((cookie) => {
		const reasons = [];
		let likelyRejected = false;
		if (cookie.sameSiteNone && !cookie.secure) {
			reasons.push("SameSite=None requires Secure in modern browsers");
			likelyRejected = true;
		}
		if (cookie.domain !== null && cookie.domain.length > 0 && url.hostname !== cookie.domain && !url.hostname.endsWith(`.${cookie.domain}`)) {
			reasons.push("the Domain attribute does not match the response host");
			likelyRejected = true;
		}
		if (cookie.domainAttributePresent && cookie.domain === "") {
			reasons.push("the Domain attribute is empty or malformed");
			likelyRejected = true;
		}
		if (cookie.path !== null && cookie.path.startsWith("/") && !cookiePathMatches(url.pathname, cookie.path)) {
			reasons.push(`the cookie Path (${cookie.path}) does not include the current page path`);
			if (!likelyRejected) return [];
		}
		if (reasons.length === 0) reasons.push("browser privacy policy, third-party cookie blocking, expiry, or another cookie validation rule may apply");
		return [{
			ruleId: "COOKIE-REJECTED",
			category: "cookie",
			severity: "info",
			title: `Set-Cookie named "${sanitizeEvidence(cookie.name)}" was not observed in the accessible cookie jar`,
			impact: "The cookie may not persist in this browser context, which can break a login or other stateful flow.",
			evidence: sanitizeEvidence(`Cookie name: ${cookie.name}; sent attributes: ${[
				cookie.sameSiteNone ? "SameSite=None" : "",
				cookie.secure ? "Secure" : "",
				cookie.domainAttributePresent ? "Domain attribute" : "host-only"
			].filter((part) => part.length > 0).join(", ")}`),
			recommendation: `Check whether ${reasons.join("; ")}. A name-only jar comparison cannot prove rejection if a same-name cookie existed before this response.`,
			reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
			sourceUrl: url.href
		}];
	});
}
function cookiePathMatches(requestPath, cookiePath) {
	if (requestPath === cookiePath) return true;
	if (!requestPath.startsWith(cookiePath)) return false;
	if (cookiePath.endsWith("/")) return true;
	return requestPath[cookiePath.length] === "/";
}
/**
* Map Chrome's SameSiteStatus enum to the project's union type.
*
* Chrome reports:
*   'strict'        → 'strict'
*   'lax'           → 'lax'
*   'no_restriction'→ 'none'
*   'unspecified'   → ''
*/
function mapSameSite(chromeSameSite) {
	switch (chromeSameSite) {
		case "strict": return "strict";
		case "lax": return "lax";
		case "no_restriction": return "none";
		default: return "";
	}
}
/**
* Determine whether a cookie belongs to a third-party relative to the current
* page.
*
* A cookie is considered first-party when the page's hostname ends with the
* cookie's domain (accounting for the leading dot that Chrome adds for
* host-level cookies).
*/
function isThirdPartyCookie(pageHostname, cookieDomain) {
	const normalised = (cookieDomain.startsWith(".") ? cookieDomain.slice(1) : cookieDomain).toLowerCase();
	const pageDomain = registrableDomain(pageHostname);
	const cookieRegistrableDomain = registrableDomain(normalised);
	if (pageDomain !== null && cookieRegistrableDomain !== null) return pageDomain !== cookieRegistrableDomain;
	const normalisedPage = pageHostname.toLowerCase();
	return normalisedPage !== normalised && !normalisedPage.endsWith(`.${normalised}`);
}
/**
* Fetches all cookies accessible for `tabUrl` from the live cookie store and
* correlates them with the Set-Cookie headers emitted by the most recent
* response so we can tell whether each cookie was set by the server (via
* headers) or by JavaScript.
*
* Cookie *values* are intentionally never accessed or stored.
*
* @param tabId          - The tab being analysed (unused directly but kept for
*                         potential future use, e.g. per-tab JS-cookie heuristics).
* @param tabUrl         - The full URL of the page (used to scope the query).
* @param setCookieHeaders - Raw `Set-Cookie` header strings from the response.
* @returns              Array of {@link CookieRecord} metadata objects.
*/
async function correlateCookies(_tabId, tabUrl, setCookieHeaders) {
	const headerMetadata = setCookieHeaders.map(parseCookieHeaderMetadata);
	const headerSetNames = new Set(headerMetadata.map((item) => item.name));
	let urlScopedCookies;
	try {
		urlScopedCookies = await chrome.cookies.getAll({ url: tabUrl });
	} catch {
		return {
			records: [],
			findings: []
		};
	}
	let pageHostname;
	try {
		pageHostname = new URL(tabUrl).hostname;
	} catch {
		pageHostname = "";
	}
	return {
		records: urlScopedCookies.map((cookie) => {
			const setByJs = headerSetNames.has(cookie.name) ? false : null;
			const matchingHeaders = headerMetadata.filter((item) => item.name === cookie.name);
			const headerMatch = matchingHeaders.find((item) => item.path === cookie.path) ?? (matchingHeaders.length === 1 ? matchingHeaders[0] : void 0);
			const thirdParty = isThirdPartyCookie(pageHostname, cookie.domain);
			const partitioned = cookie.partitionKey != null;
			const expiresAt = cookie.session ? null : Math.round(cookie.expirationDate ?? 0) * 1e3;
			return {
				name: cookie.name,
				domain: cookie.domain,
				domainAttributePresent: setByJs === null ? null : headerMatch?.domainAttributePresent ?? false,
				path: cookie.path,
				secure: cookie.secure,
				httpOnly: cookie.httpOnly,
				sameSite: mapSameSite(cookie.sameSite),
				session: cookie.session,
				expiresAt,
				partitioned,
				setByJs,
				isThirdParty: thirdParty
			};
		}),
		findings: findUnobservedCookieFindings(setCookieHeaders, urlScopedCookies, tabUrl)
	};
}
//#endregion
//#region src/content/service-worker-detection.ts
/** Runs in the page's isolated world only after host permission is granted. */
function reportPageSignals() {
	const isolatedWorld = globalThis;
	if (isolatedWorld.__seccheckPageSignalsInstalled === true) return;
	isolatedWorld.__seccheckPageSignalsInstalled = true;
	const controller = navigator.serviceWorker?.controller;
	chrome.runtime.sendMessage({
		type: "SERVICE_WORKER_STATUS",
		status: controller == null ? "not-controlled" : "controlled",
		serviceWorkerUrl: controller?.scriptURL ?? null
	}).catch(() => void 0);
	function getMetaCspPolicies() {
		const policies = [];
		for (const meta of Array.from(document.querySelectorAll("meta[http-equiv]"))) if (meta.getAttribute("http-equiv")?.trim().toLowerCase() === "content-security-policy") {
			const content = meta.getAttribute("content")?.trim();
			if (content !== void 0 && content.length > 0) {
				policies.push(content.slice(0, 2048));
				if (policies.length >= 5) break;
			}
		}
		return policies;
	}
	function reportMetaCsp() {
		const policies = getMetaCspPolicies();
		if (policies.length === 0) return;
		chrome.runtime.sendMessage({
			type: "META_CSP_FOUND",
			policies
		}).catch(() => void 0);
	}
	if (getMetaCspPolicies().length > 0) reportMetaCsp();
	else {
		const observer = new MutationObserver(() => {
			if (getMetaCspPolicies().length > 0) {
				reportMetaCsp();
				observer.disconnect();
			}
		});
		observer.observe(document, {
			childList: true,
			subtree: true,
			attributes: true,
			attributeFilter: ["http-equiv", "content"]
		});
	}
	function reportSri() {
		const externalScripts = Array.from(document.querySelectorAll("script[src]")).filter((script) => {
			try {
				return new URL(script.src, location.href).origin !== location.origin;
			} catch {
				return false;
			}
		});
		const externalStylesheets = Array.from(document.querySelectorAll("link[rel~=\"stylesheet\"][href]")).filter((link) => {
			try {
				return new URL(link.href, location.href).origin !== location.origin;
			} catch {
				return false;
			}
		});
		const missingScriptIntegrity = externalScripts.filter((s) => !s.integrity.trim()).length;
		const missingStyleIntegrity = externalStylesheets.filter((l) => !l.integrity.trim()).length;
		chrome.runtime.sendMessage({
			type: "SRI_SCAN",
			externalScripts: externalScripts.length,
			missingIntegrity: missingScriptIntegrity,
			externalStylesheets: externalStylesheets.length,
			missingStyleIntegrity
		}).catch(() => void 0);
	}
	reportSri();
	new MutationObserver(reportSri).observe(document.documentElement, {
		childList: true,
		subtree: true,
		attributes: true,
		attributeFilter: [
			"src",
			"integrity",
			"href",
			"rel"
		]
	});
}
//#endregion
//#region src/background/page-signals.ts
function injectPageSignals(tabId, url) {
	const origin = originFromUrl(url);
	if (origin === null || origin.length === 0) return;
	chrome.permissions.contains({ origins: [`${origin}/*`] }, (permitted) => {
		if (!permitted) return;
		chrome.scripting.executeScript({
			target: {
				tabId,
				frameIds: [0]
			},
			func: reportPageSignals
		}).catch(() => void 0);
	});
}
function registerPageSignalInjection() {
	chrome.webNavigation.onCommitted.addListener((details) => {
		if (details.frameId !== 0 || details.tabId < 0) return;
		injectPageSignals(details.tabId, details.url);
	});
	chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
		if (details.frameId !== 0 || details.tabId < 0) return;
		injectPageSignals(details.tabId, details.url);
	});
}
//#endregion
//#region src/rules/headers/hsts.ts
var REFERENCE$7 = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security";
var HSTS_HEADER = "strict-transport-security";
var HSTS_MIN_MAX_AGE = 31536e3;
var HSTS_PRELOAD_MAX_AGE = 31536e3;
/**
* Evaluate HSTS posture for the final response hop.
* This function is pure — no browser APIs are used.
*
* @param finalHop - The last hop in the redirect chain.
* @returns An array of zero or more findings.
*/
function checkHsts(finalHop) {
	if (!finalHop.url.startsWith("https://")) return [];
	const findings = [];
	const headerValue = finalHop.headers[HSTS_HEADER];
	if (headerValue === void 0) {
		findings.push({
			ruleId: "HSTS-001",
			category: "transport",
			severity: "high",
			title: "Strict-Transport-Security header is missing",
			impact: "An attacker on the same network (e.g. public Wi-Fi) can downgrade the connection to unencrypted HTTP and intercept passwords or session cookies (SSL Stripping).",
			evidence: sanitizeEvidence("(header absent)"),
			recommendation: "Add \"Strict-Transport-Security: max-age=31536000; includeSubDomains\" to all HTTPS responses.",
			reference: REFERENCE$7
		});
		return findings;
	}
	const maxAgeMatch = /max-age\s*=\s*(\d+)/i.exec(headerValue);
	const maxAge = maxAgeMatch !== null ? parseInt(maxAgeMatch[1] ?? "0", 10) : 0;
	if (maxAge < HSTS_MIN_MAX_AGE) findings.push({
		ruleId: "HSTS-002",
		category: "transport",
		severity: "medium",
		title: "Strict-Transport-Security max-age is below the recommended minimum (1 year)",
		impact: "A short expiration allows browsers to silently revert to unencrypted HTTP if a user revisits after the window expires.",
		evidence: sanitizeEvidence(headerValue),
		recommendation: `Increase max-age to at least ${HSTS_MIN_MAX_AGE} (1 year). Current value: ${maxAge}.`,
		reference: REFERENCE$7
	});
	if (!/includeSubDomains/i.test(headerValue)) findings.push({
		ruleId: "HSTS-003",
		category: "transport",
		severity: "low",
		title: "Strict-Transport-Security is missing the includeSubDomains directive",
		impact: "Subdomains are not forced to HTTPS, leaving them vulnerable to unencrypted network eavesdropping and cookie injection.",
		evidence: sanitizeEvidence(headerValue),
		recommendation: "Add the \"includeSubDomains\" directive to ensure all subdomains are protected.",
		reference: REFERENCE$7
	});
	const hasIncludeSubdomains = /includeSubDomains/i.test(headerValue);
	const hasPreload = /(?:^|;)\s*preload\s*(?:;|$)/i.test(headerValue);
	const meetsBasicPreloadRequirements = maxAge >= HSTS_PRELOAD_MAX_AGE && hasIncludeSubdomains;
	if (hasPreload && !meetsBasicPreloadRequirements) findings.push({
		ruleId: "HSTS-004",
		category: "transport",
		severity: "info",
		title: "HSTS preload token is present but basic preload directives are incomplete",
		evidence: sanitizeEvidence(headerValue),
		recommendation: "HSTS preload submissions require max-age of at least 31536000 (1 year) and includeSubDomains. Verify all subdomains support HTTPS before submitting.",
		reference: "https://hstspreload.org/"
	});
	else if (!hasPreload && meetsBasicPreloadRequirements) findings.push({
		ruleId: "HSTS-005",
		category: "transport",
		severity: "info",
		title: "HSTS header meets basic preload directives; preload-list membership is not checked",
		evidence: sanitizeEvidence(headerValue),
		recommendation: "If preload is desired, review all hstspreload.org requirements and submit the domain; these header checks do not verify certificate, redirect, subdomain, or list status.",
		reference: "https://hstspreload.org/"
	});
	return findings;
}
//#endregion
//#region node_modules/csp_evaluator/dist/allowlist_bypasses/jsonp.js
var require_jsonp = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.URLS = exports.NEEDS_EVAL = void 0;
	exports.NEEDS_EVAL = [
		"googletagmanager.com",
		"www.googletagmanager.com",
		"www.googleadservices.com",
		"google-analytics.com",
		"ssl.google-analytics.com",
		"www.google-analytics.com"
	];
	exports.URLS = [
		"//bebezoo.1688.com/fragment/index.htm",
		"//www.google-analytics.com/gtm/js",
		"//googleads.g.doubleclick.net/pagead/conversion/1036918760/wcm",
		"//www.googleadservices.com/pagead/conversion/1070110417/wcm",
		"//www.google.com/tools/feedback/escalation-options",
		"//pin.aliyun.com/check_audio",
		"//offer.alibaba.com/market/CID100002954/5/fetchKeyword.do",
		"//ccrprod.alipay.com/ccr/arriveTime.json",
		"//group.aliexpress.com/ajaxAcquireGroupbuyProduct.do",
		"//detector.alicdn.com/2.7.3/index.php",
		"//suggest.taobao.com/sug",
		"//translate.google.com/translate_a/l",
		"//count.tbcdn.cn//counter3",
		"//wb.amap.com/channel.php",
		"//translate.googleapis.com/translate_a/l",
		"//afpeng.alimama.com/ex",
		"//accounts.google.com/o/oauth2/revoke",
		"//pagead2.googlesyndication.com/relatedsearch",
		"//yandex.ru/soft/browsers/check",
		"//api.facebook.com/restserver.php",
		"//mts0.googleapis.com/maps/vt",
		"//syndication.twitter.com/widgets/timelines/765840589183213568",
		"//www.youtube.com/profile_style",
		"//googletagmanager.com/gtm/js",
		"//mc.yandex.ru/watch/24306916/1",
		"//share.yandex.net/counter/gpp/",
		"//ok.go.mail.ru/lady_on_lady_recipes_r.json",
		"//d1f69o4buvlrj5.cloudfront.net/__efa_15_1_ornpba.xekq.arg/optout_check",
		"//www.googletagmanager.com/gtm/js",
		"//api.vk.com/method/wall.get",
		"//www.sharethis.com/get-publisher-info.php",
		"//google.ru/maps/vt",
		"//pro.netrox.sc/oapi/h_checksite.ashx",
		"//vimeo.com/api/oembed.json/",
		"//de.blog.newrelic.com/wp-admin/admin-ajax.php",
		"//ajax.googleapis.com/ajax/services/search/news",
		"//ssl.google-analytics.com/gtm/js",
		"//pubsub.pubnub.com/subscribe/demo/hello_world/",
		"//pass.yandex.ua/services",
		"//id.rambler.ru/script/topline_info.js",
		"//m.addthis.com/live/red_lojson/100eng.json",
		"//passport.ngs.ru/ajax/check",
		"//catalog.api.2gis.ru/ads/search",
		"//gum.criteo.com/sync",
		"//maps.google.com/maps/vt",
		"//ynuf.alipay.com/service/um.json",
		"//securepubads.g.doubleclick.net/gampad/ads",
		"//c.tiles.mapbox.com/v3/texastribune.tx-congress-cvap/6/15/26.grid.json",
		"//rexchange.begun.ru/banners",
		"//an.yandex.ru/page/147484",
		"//links.services.disqus.com/api/ping",
		"//api.map.baidu.com/",
		"//tj.gongchang.com/api/keywordrecomm/",
		"//data.gongchang.com/livegrail/",
		"//ulogin.ru/token.php",
		"//beta.gismeteo.ru/api/informer/layout.js/120x240-3/ru/",
		"//maps.googleapis.com/maps/api/js/GeoPhotoService.GetMetadata",
		"//a.config.skype.com/config/v1/Skype/908_1.33.0.111/SkypePersonalization",
		"//maps.beeline.ru/w",
		"//target.ukr.net/",
		"//www.meteoprog.ua/data/weather/informer/Poltava.js",
		"//cdn.syndication.twimg.com/widgets/timelines/599200054310604802",
		"//wslocker.ru/client/user.chk.php",
		"//community.adobe.com/CommunityPod/getJSON",
		"//maps.google.lv/maps/vt",
		"//dev.virtualearth.net/REST/V1/Imagery/Metadata/AerialWithLabels/26.318581",
		"//awaps.yandex.ru/10/8938/02400400.",
		"//a248.e.akamai.net/h5.hulu.com/h5.mp4",
		"//nominatim.openstreetmap.org/",
		"//plugins.mozilla.org/en-us/plugins_list.json",
		"//h.cackle.me/widget/32153/bootstrap",
		"//graph.facebook.com/1/",
		"//fellowes.ugc.bazaarvoice.com/data/reviews.json",
		"//widgets.pinterest.com/v3/pidgets/boards/ciciwin/hedgehog-squirrel-crafts/pins/",
		"//se.wikipedia.org/w/api.php",
		"//cse.google.com/api/007627024705277327428/cse/r3vs7b0fcli/queries/js",
		"//relap.io/api/v2/similar_pages_jsonp.js",
		"//c1n3.hypercomments.com/stream/subscribe",
		"//maps.google.de/maps/vt",
		"//books.google.com/books",
		"//connect.mail.ru/share_count",
		"//tr.indeed.com/m/newjobs",
		"//www-onepick-opensocial.googleusercontent.com/gadgets/proxy",
		"//www.panoramio.com/map/get_panoramas.php",
		"//client.siteheart.com/streamcli/client",
		"//www.facebook.com/restserver.php",
		"//autocomplete.travelpayouts.com/avia",
		"//www.googleapis.com/freebase/v1/topic/m/0344_",
		"//mts1.googleapis.com/mapslt/ft",
		"//publish.twitter.com/oembed",
		"//fast.wistia.com/embed/medias/o75jtw7654.json",
		"//partner.googleadservices.com/gampad/ads",
		"//pass.yandex.ru/services",
		"//gupiao.baidu.com/stocks/stockbets",
		"//widget.admitad.com/widget/init",
		"//api.instagram.com/v1/tags/partykungen23328/media/recent",
		"//video.media.yql.yahoo.com/v1/video/sapi/streams/063fb76c-6c70-38c5-9bbc-04b7c384de2b",
		"//ib.adnxs.com/jpt",
		"//pass.yandex.com/services",
		"//www.google.de/maps/vt",
		"//clients1.google.com/complete/search",
		"//api.userlike.com/api/chat/slot/proactive/",
		"//www.youku.com/index_cookielist/s/jsonp",
		"//mt1.googleapis.com/mapslt/ft",
		"//api.mixpanel.com/track/",
		"//wpd.b.qq.com/cgi/get_sign.php",
		"//pipes.yahooapis.com/pipes/pipe.run",
		"//gdata.youtube.com/feeds/api/videos/WsJIHN1kNWc",
		"//9.chart.apis.google.com/chart",
		"//cdn.syndication.twitter.com/moments/709229296800440320",
		"//api.flickr.com/services/feeds/photos_friends.gne",
		"//cbks0.googleapis.com/cbk",
		"//www.blogger.com/feeds/5578653387562324002/posts/summary/4427562025302749269",
		"//query.yahooapis.com/v1/public/yql",
		"//kecngantang.blogspot.com/feeds/posts/default/-/Komik",
		"//www.travelpayouts.com/widgets/50f53ce9ada1b54bcc000031.json",
		"//i.cackle.me/widget/32586/bootstrap",
		"//translate.yandex.net/api/v1.5/tr.json/detect",
		"//a.tiles.mapbox.com/v3/zentralmedia.map-n2raeauc.jsonp",
		"//maps.google.ru/maps/vt",
		"//c1n2.hypercomments.com/stream/subscribe",
		"//rec.ydf.yandex.ru/cookie",
		"//cdn.jsdelivr.net"
	];
}));
//#endregion
//#region node_modules/csp_evaluator/dist/finding.js
var require_finding = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.Type = exports.Severity = exports.Finding = void 0;
	exports.Finding = class Finding {
		constructor(type, description, severity, directive, value) {
			this.type = type;
			this.description = description;
			this.severity = severity;
			this.directive = directive;
			this.value = value;
		}
		static getHighestSeverity(findings) {
			if (findings.length === 0) return Severity.NONE;
			const severities = findings.map((finding) => finding.severity);
			const min = (prev, cur) => prev < cur ? prev : cur;
			return severities.reduce(min, Severity.NONE);
		}
		equals(obj) {
			if (!(obj instanceof Finding)) return false;
			return obj.type === this.type && obj.description === this.description && obj.severity === this.severity && obj.directive === this.directive && obj.value === this.value;
		}
	};
	var Severity;
	(function(Severity) {
		Severity[Severity["HIGH"] = 10] = "HIGH";
		Severity[Severity["SYNTAX"] = 20] = "SYNTAX";
		Severity[Severity["MEDIUM"] = 30] = "MEDIUM";
		Severity[Severity["HIGH_MAYBE"] = 40] = "HIGH_MAYBE";
		Severity[Severity["STRICT_CSP"] = 45] = "STRICT_CSP";
		Severity[Severity["MEDIUM_MAYBE"] = 50] = "MEDIUM_MAYBE";
		Severity[Severity["INFO"] = 60] = "INFO";
		Severity[Severity["NONE"] = 100] = "NONE";
	})(Severity = exports.Severity || (exports.Severity = {}));
	(function(Type) {
		Type[Type["MISSING_SEMICOLON"] = 100] = "MISSING_SEMICOLON";
		Type[Type["UNKNOWN_DIRECTIVE"] = 101] = "UNKNOWN_DIRECTIVE";
		Type[Type["INVALID_KEYWORD"] = 102] = "INVALID_KEYWORD";
		Type[Type["NONCE_CHARSET"] = 106] = "NONCE_CHARSET";
		Type[Type["MISSING_DIRECTIVES"] = 300] = "MISSING_DIRECTIVES";
		Type[Type["SCRIPT_UNSAFE_INLINE"] = 301] = "SCRIPT_UNSAFE_INLINE";
		Type[Type["SCRIPT_UNSAFE_EVAL"] = 302] = "SCRIPT_UNSAFE_EVAL";
		Type[Type["PLAIN_URL_SCHEMES"] = 303] = "PLAIN_URL_SCHEMES";
		Type[Type["PLAIN_WILDCARD"] = 304] = "PLAIN_WILDCARD";
		Type[Type["SCRIPT_ALLOWLIST_BYPASS"] = 305] = "SCRIPT_ALLOWLIST_BYPASS";
		Type[Type["OBJECT_ALLOWLIST_BYPASS"] = 306] = "OBJECT_ALLOWLIST_BYPASS";
		Type[Type["NONCE_LENGTH"] = 307] = "NONCE_LENGTH";
		Type[Type["IP_SOURCE"] = 308] = "IP_SOURCE";
		Type[Type["DEPRECATED_DIRECTIVE"] = 309] = "DEPRECATED_DIRECTIVE";
		Type[Type["SRC_HTTP"] = 310] = "SRC_HTTP";
		Type[Type["SRC_NO_PROTOCOL"] = 311] = "SRC_NO_PROTOCOL";
		Type[Type["EXPERIMENTAL"] = 312] = "EXPERIMENTAL";
		Type[Type["WILDCARD_URL"] = 313] = "WILDCARD_URL";
		Type[Type["X_FRAME_OPTIONS_OBSOLETED"] = 314] = "X_FRAME_OPTIONS_OBSOLETED";
		Type[Type["STYLE_UNSAFE_INLINE"] = 315] = "STYLE_UNSAFE_INLINE";
		Type[Type["STATIC_NONCE"] = 316] = "STATIC_NONCE";
		Type[Type["SCRIPT_UNSAFE_HASHES"] = 317] = "SCRIPT_UNSAFE_HASHES";
		Type[Type["STRICT_DYNAMIC"] = 400] = "STRICT_DYNAMIC";
		Type[Type["STRICT_DYNAMIC_NOT_STANDALONE"] = 401] = "STRICT_DYNAMIC_NOT_STANDALONE";
		Type[Type["NONCE_HASH"] = 402] = "NONCE_HASH";
		Type[Type["UNSAFE_INLINE_FALLBACK"] = 403] = "UNSAFE_INLINE_FALLBACK";
		Type[Type["ALLOWLIST_FALLBACK"] = 404] = "ALLOWLIST_FALLBACK";
		Type[Type["IGNORED"] = 405] = "IGNORED";
		Type[Type["REQUIRE_TRUSTED_TYPES_FOR_SCRIPTS"] = 500] = "REQUIRE_TRUSTED_TYPES_FOR_SCRIPTS";
		Type[Type["REPORTING_DESTINATION_MISSING"] = 600] = "REPORTING_DESTINATION_MISSING";
		Type[Type["REPORT_TO_ONLY"] = 601] = "REPORT_TO_ONLY";
	})(exports.Type || (exports.Type = {}));
}));
//#endregion
//#region node_modules/csp_evaluator/dist/csp.js
var require_csp = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.CspError = exports.isHash = exports.HASH_PATTERN = exports.STRICT_HASH_PATTERN = exports.isNonce = exports.NONCE_PATTERN = exports.STRICT_NONCE_PATTERN = exports.isUrlScheme = exports.isKeyword = exports.isDirective = exports.Version = exports.FETCH_DIRECTIVES = exports.Directive = exports.TrustedTypesSink = exports.Keyword = exports.Csp = void 0;
	var finding_1 = require_finding();
	exports.Csp = class Csp {
		constructor(directives = {}) {
			this.directives = {};
			for (const [directive, directiveValues] of Object.entries(directives)) if (directiveValues) this.directives[directive] = [...directiveValues];
		}
		clone() {
			return new Csp(this.directives);
		}
		convertToString() {
			let cspString = "";
			for (const [directive, directiveValues] of Object.entries(this.directives)) {
				cspString += directive;
				if (directiveValues !== void 0) for (let value, i = 0; value = directiveValues[i]; i++) {
					cspString += " ";
					cspString += value;
				}
				cspString += "; ";
			}
			return cspString;
		}
		getEffectiveCsp(cspVersion, optFindings) {
			const findings = optFindings || [];
			const effectiveCsp = this.clone();
			[
				Directive.SCRIPT_SRC,
				Directive.SCRIPT_SRC_ATTR,
				Directive.SCRIPT_SRC_ELEM
			].forEach((directiveToNormalize) => {
				const directive = effectiveCsp.getEffectiveDirective(directiveToNormalize);
				const values = this.directives[directive] || [];
				const effectiveCspValues = effectiveCsp.directives[directive];
				if (effectiveCspValues && (effectiveCsp.policyHasScriptNonces(directive) || effectiveCsp.policyHasScriptHashes(directive))) {
					if (cspVersion >= Version.CSP2) {
						if (values.includes(Keyword.UNSAFE_INLINE)) {
							arrayRemove(effectiveCspValues, Keyword.UNSAFE_INLINE);
							findings.push(new finding_1.Finding(finding_1.Type.IGNORED, "unsafe-inline is ignored if a nonce or a hash is present. (CSP2 and above)", finding_1.Severity.NONE, directive, Keyword.UNSAFE_INLINE));
						}
					} else for (const value of values) if (value.startsWith("'nonce-") || value.startsWith("'sha")) arrayRemove(effectiveCspValues, value);
				}
				if (effectiveCspValues && this.policyHasStrictDynamic(directive)) {
					if (cspVersion >= Version.CSP3) {
						for (const value of values) if (!value.startsWith("'") || value === Keyword.SELF || value === Keyword.UNSAFE_INLINE) {
							arrayRemove(effectiveCspValues, value);
							findings.push(new finding_1.Finding(finding_1.Type.IGNORED, "Because of strict-dynamic this entry is ignored in CSP3 and above", finding_1.Severity.NONE, directive, value));
						}
					} else arrayRemove(effectiveCspValues, Keyword.STRICT_DYNAMIC);
				}
			});
			if (cspVersion < Version.CSP3) {
				delete effectiveCsp.directives[Directive.REPORT_TO];
				delete effectiveCsp.directives[Directive.WORKER_SRC];
				delete effectiveCsp.directives[Directive.MANIFEST_SRC];
				delete effectiveCsp.directives[Directive.TRUSTED_TYPES];
				delete effectiveCsp.directives[Directive.REQUIRE_TRUSTED_TYPES_FOR];
				delete effectiveCsp.directives[Directive.SCRIPT_SRC_ATTR];
				delete effectiveCsp.directives[Directive.SCRIPT_SRC_ELEM];
				delete effectiveCsp.directives[Directive.STYLE_SRC_ATTR];
				delete effectiveCsp.directives[Directive.STYLE_SRC_ELEM];
			}
			return effectiveCsp;
		}
		getEffectiveDirective(directive) {
			if (directive in this.directives) return directive;
			if ((directive === Directive.SCRIPT_SRC_ATTR || directive === Directive.SCRIPT_SRC_ELEM) && Directive.SCRIPT_SRC in this.directives) return Directive.SCRIPT_SRC;
			if ((directive === Directive.STYLE_SRC_ATTR || directive === Directive.STYLE_SRC_ELEM) && Directive.STYLE_SRC in this.directives) return Directive.STYLE_SRC;
			if (exports.FETCH_DIRECTIVES.includes(directive)) return Directive.DEFAULT_SRC;
			return directive;
		}
		getEffectiveDirectives(directives) {
			return [...new Set(directives.map((val) => this.getEffectiveDirective(val)))];
		}
		policyHasScriptNonces(directive) {
			const directiveName = this.getEffectiveDirective(directive || Directive.SCRIPT_SRC);
			return (this.directives[directiveName] || []).some((val) => isNonce(val, true));
		}
		policyHasScriptHashes(directive) {
			const directiveName = this.getEffectiveDirective(directive || Directive.SCRIPT_SRC);
			return (this.directives[directiveName] || []).some((val) => isHash(val, true));
		}
		policyHasStrictDynamic(directive) {
			const directiveName = this.getEffectiveDirective(directive || Directive.SCRIPT_SRC);
			return (this.directives[directiveName] || []).includes(Keyword.STRICT_DYNAMIC);
		}
	};
	var Keyword;
	(function(Keyword) {
		Keyword["SELF"] = "'self'";
		Keyword["NONE"] = "'none'";
		Keyword["UNSAFE_INLINE"] = "'unsafe-inline'";
		Keyword["UNSAFE_EVAL"] = "'unsafe-eval'";
		Keyword["WASM_EVAL"] = "'wasm-eval'";
		Keyword["WASM_UNSAFE_EVAL"] = "'wasm-unsafe-eval'";
		Keyword["STRICT_DYNAMIC"] = "'strict-dynamic'";
		Keyword["UNSAFE_HASHED_ATTRIBUTES"] = "'unsafe-hashed-attributes'";
		Keyword["UNSAFE_HASHES"] = "'unsafe-hashes'";
		Keyword["REPORT_SAMPLE"] = "'report-sample'";
		Keyword["BLOCK"] = "'block'";
		Keyword["ALLOW"] = "'allow'";
		Keyword["INLINE_SPECULATION_RULES"] = "'inline-speculation-rules'";
	})(Keyword = exports.Keyword || (exports.Keyword = {}));
	(function(TrustedTypesSink) {
		TrustedTypesSink["SCRIPT"] = "'script'";
	})(exports.TrustedTypesSink || (exports.TrustedTypesSink = {}));
	var Directive;
	(function(Directive) {
		Directive["CHILD_SRC"] = "child-src";
		Directive["CONNECT_SRC"] = "connect-src";
		Directive["DEFAULT_SRC"] = "default-src";
		Directive["FONT_SRC"] = "font-src";
		Directive["FRAME_SRC"] = "frame-src";
		Directive["IMG_SRC"] = "img-src";
		Directive["MEDIA_SRC"] = "media-src";
		Directive["OBJECT_SRC"] = "object-src";
		Directive["SCRIPT_SRC"] = "script-src";
		Directive["SCRIPT_SRC_ATTR"] = "script-src-attr";
		Directive["SCRIPT_SRC_ELEM"] = "script-src-elem";
		Directive["STYLE_SRC"] = "style-src";
		Directive["STYLE_SRC_ATTR"] = "style-src-attr";
		Directive["STYLE_SRC_ELEM"] = "style-src-elem";
		Directive["PREFETCH_SRC"] = "prefetch-src";
		Directive["MANIFEST_SRC"] = "manifest-src";
		Directive["WORKER_SRC"] = "worker-src";
		Directive["BASE_URI"] = "base-uri";
		Directive["PLUGIN_TYPES"] = "plugin-types";
		Directive["SANDBOX"] = "sandbox";
		Directive["DISOWN_OPENER"] = "disown-opener";
		Directive["FORM_ACTION"] = "form-action";
		Directive["FRAME_ANCESTORS"] = "frame-ancestors";
		Directive["NAVIGATE_TO"] = "navigate-to";
		Directive["REPORT_TO"] = "report-to";
		Directive["REPORT_URI"] = "report-uri";
		Directive["BLOCK_ALL_MIXED_CONTENT"] = "block-all-mixed-content";
		Directive["UPGRADE_INSECURE_REQUESTS"] = "upgrade-insecure-requests";
		Directive["REFLECTED_XSS"] = "reflected-xss";
		Directive["REFERRER"] = "referrer";
		Directive["REQUIRE_SRI_FOR"] = "require-sri-for";
		Directive["TRUSTED_TYPES"] = "trusted-types";
		Directive["REQUIRE_TRUSTED_TYPES_FOR"] = "require-trusted-types-for";
		Directive["WEBRTC"] = "webrtc";
	})(Directive = exports.Directive || (exports.Directive = {}));
	exports.FETCH_DIRECTIVES = [
		Directive.CHILD_SRC,
		Directive.CONNECT_SRC,
		Directive.DEFAULT_SRC,
		Directive.FONT_SRC,
		Directive.FRAME_SRC,
		Directive.IMG_SRC,
		Directive.MANIFEST_SRC,
		Directive.MEDIA_SRC,
		Directive.OBJECT_SRC,
		Directive.SCRIPT_SRC,
		Directive.SCRIPT_SRC_ATTR,
		Directive.SCRIPT_SRC_ELEM,
		Directive.STYLE_SRC,
		Directive.STYLE_SRC_ATTR,
		Directive.STYLE_SRC_ELEM,
		Directive.WORKER_SRC
	];
	var Version;
	(function(Version) {
		Version[Version["CSP1"] = 1] = "CSP1";
		Version[Version["CSP2"] = 2] = "CSP2";
		Version[Version["CSP3"] = 3] = "CSP3";
	})(Version = exports.Version || (exports.Version = {}));
	function isDirective(directive) {
		return Object.values(Directive).includes(directive);
	}
	exports.isDirective = isDirective;
	function isKeyword(keyword) {
		return Object.values(Keyword).includes(keyword);
	}
	exports.isKeyword = isKeyword;
	function isUrlScheme(urlScheme) {
		return (/* @__PURE__ */ new RegExp("^[a-zA-Z][+a-zA-Z0-9.-]*:$")).test(urlScheme);
	}
	exports.isUrlScheme = isUrlScheme;
	exports.STRICT_NONCE_PATTERN = /* @__PURE__ */ new RegExp("^'nonce-[a-zA-Z0-9+/_-]+[=]{0,2}'$");
	exports.NONCE_PATTERN = /* @__PURE__ */ new RegExp("^'nonce-(.+)'$");
	function isNonce(nonce, strictCheck) {
		return (strictCheck ? exports.STRICT_NONCE_PATTERN : exports.NONCE_PATTERN).test(nonce);
	}
	exports.isNonce = isNonce;
	exports.STRICT_HASH_PATTERN = /* @__PURE__ */ new RegExp("^'(sha256|sha384|sha512)-[a-zA-Z0-9+/_-]+[=]{0,2}'$");
	exports.HASH_PATTERN = /* @__PURE__ */ new RegExp("^'(sha256|sha384|sha512)-(.+)'$");
	function isHash(hash, strictCheck) {
		return (strictCheck ? exports.STRICT_HASH_PATTERN : exports.HASH_PATTERN).test(hash);
	}
	exports.isHash = isHash;
	var CspError = class extends Error {
		constructor(message) {
			super(message);
		}
	};
	exports.CspError = CspError;
	function arrayRemove(arr, item) {
		if (arr.includes(item)) {
			const idx = arr.findIndex((elem) => item === elem);
			arr.splice(idx, 1);
		}
	}
}));
//#endregion
//#region node_modules/csp_evaluator/dist/checks/parser_checks.js
var require_parser_checks = /* @__PURE__ */ __commonJSMin(((exports) => {
	var __createBinding = exports && exports.__createBinding || (Object.create ? (function(o, m, k, k2) {
		if (k2 === void 0) k2 = k;
		Object.defineProperty(o, k2, {
			enumerable: true,
			get: function() {
				return m[k];
			}
		});
	}) : (function(o, m, k, k2) {
		if (k2 === void 0) k2 = k;
		o[k2] = m[k];
	}));
	var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? (function(o, v) {
		Object.defineProperty(o, "default", {
			enumerable: true,
			value: v
		});
	}) : function(o, v) {
		o["default"] = v;
	});
	var __importStar = exports && exports.__importStar || function(mod) {
		if (mod && mod.__esModule) return mod;
		var result = {};
		if (mod != null) {
			for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
		}
		__setModuleDefault(result, mod);
		return result;
	};
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.checkInvalidKeyword = exports.checkMissingSemicolon = exports.checkUnknownDirective = void 0;
	var csp = __importStar(require_csp());
	var csp_1 = require_csp();
	var finding_1 = require_finding();
	function checkUnknownDirective(parsedCsp) {
		const findings = [];
		for (const directive of Object.keys(parsedCsp.directives)) {
			if (csp.isDirective(directive)) continue;
			if (directive.endsWith(":")) findings.push(new finding_1.Finding(finding_1.Type.UNKNOWN_DIRECTIVE, "CSP directives don't end with a colon.", finding_1.Severity.SYNTAX, directive));
			else findings.push(new finding_1.Finding(finding_1.Type.UNKNOWN_DIRECTIVE, "Directive \"" + directive + "\" is not a known CSP directive.", finding_1.Severity.SYNTAX, directive));
		}
		return findings;
	}
	exports.checkUnknownDirective = checkUnknownDirective;
	function checkMissingSemicolon(parsedCsp) {
		const findings = [];
		for (const [directive, directiveValues] of Object.entries(parsedCsp.directives)) {
			if (directiveValues === void 0) continue;
			for (const value of directiveValues) if (csp.isDirective(value)) findings.push(new finding_1.Finding(finding_1.Type.MISSING_SEMICOLON, "Did you forget the semicolon? \"" + value + "\" seems to be a directive, not a value.", finding_1.Severity.SYNTAX, directive, value));
		}
		return findings;
	}
	exports.checkMissingSemicolon = checkMissingSemicolon;
	function checkInvalidKeyword(parsedCsp) {
		const findings = [];
		const keywordsNoTicks = Object.values(csp_1.Keyword).map((k) => k.replace(/'/g, ""));
		for (const [directive, directiveValues] of Object.entries(parsedCsp.directives)) {
			if (directiveValues === void 0) continue;
			for (const value of directiveValues) {
				if (keywordsNoTicks.some((k) => k === value) || value.startsWith("nonce-") || value.match(/^(sha256|sha384|sha512)-/)) {
					findings.push(new finding_1.Finding(finding_1.Type.INVALID_KEYWORD, "Did you forget to surround \"" + value + "\" with single-ticks?", finding_1.Severity.SYNTAX, directive, value));
					continue;
				}
				if (!value.startsWith("'")) continue;
				if (directive === csp.Directive.REQUIRE_TRUSTED_TYPES_FOR) {
					if (value === csp.TrustedTypesSink.SCRIPT) continue;
				} else if (directive === csp.Directive.TRUSTED_TYPES) {
					if (value === "'allow-duplicates'" || value === "'none'") continue;
				} else if (csp.isKeyword(value) || csp.isHash(value, true) || csp.isNonce(value, true)) continue;
				findings.push(new finding_1.Finding(finding_1.Type.INVALID_KEYWORD, value + " seems to be an invalid CSP keyword.", finding_1.Severity.SYNTAX, directive, value));
			}
		}
		return findings;
	}
	exports.checkInvalidKeyword = checkInvalidKeyword;
}));
//#endregion
//#region node_modules/csp_evaluator/dist/allowlist_bypasses/angular.js
var require_angular = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.URLS = void 0;
	exports.URLS = [
		"//gstatic.com/fsn/angular_js-bundle1.js",
		"//www.gstatic.com/fsn/angular_js-bundle1.js",
		"//www.googleadservices.com/pageadimg/imgad",
		"//yandex.st/angularjs/1.2.16/angular-cookies.min.js",
		"//yastatic.net/angularjs/1.2.23/angular.min.js",
		"//yuedust.yuedu.126.net/js/components/angular/angular.js",
		"//art.jobs.netease.com/script/angular.js",
		"//csu-c45.kxcdn.com/angular/angular.js",
		"//elysiumwebsite.s3.amazonaws.com/uploads/blog-media/rockstar/angular.min.js",
		"//inno.blob.core.windows.net/new/libs/AngularJS/1.2.1/angular.min.js",
		"//gift-talk.kakao.com/public/javascripts/angular.min.js",
		"//ajax.googleapis.com/ajax/libs/angularjs/1.2.0rc1/angular-route.min.js",
		"//master-sumok.ru/vendors/angular/angular-cookies.js",
		"//ayicommon-a.akamaihd.net/static/vendor/angular-1.4.2.min.js",
		"//pangxiehaitao.com/framework/angular-1.3.9/angular-animate.min.js",
		"//cdnjs.cloudflare.com/ajax/libs/angular.js/1.2.16/angular.min.js",
		"//96fe3ee995e96e922b6b-d10c35bd0a0de2c718b252bc575fdb73.ssl.cf1.rackcdn.com/angular.js",
		"//oss.maxcdn.com/angularjs/1.2.20/angular.min.js",
		"//reports.zemanta.com/smedia/common/angularjs/1.2.11/angular.js",
		"//cdn.shopify.com/s/files/1/0225/6463/t/1/assets/angular-animate.min.js",
		"//parademanagement.com.s3-website-ap-southeast-1.amazonaws.com/js/angular.min.js",
		"//cdn.jsdelivr.net/angularjs/1.1.2/angular.min.js",
		"//eb2883ede55c53e09fd5-9c145fb03d93709ea57875d307e2d82e.ssl.cf3.rackcdn.com/components/angular-resource.min.js",
		"//andors-trail.googlecode.com/git/AndorsTrailEdit/lib/angular.min.js",
		"//cdn.walkme.com/General/EnvironmentTests/angular/angular.min.js",
		"//laundrymail.com/angular/angular.js",
		"//s3-eu-west-1.amazonaws.com/staticancpa/js/angular-cookies.min.js",
		"//collade.demo.stswp.com/js/vendor/angular.min.js",
		"//mrfishie.github.io/sailor/bower_components/angular/angular.min.js",
		"//askgithub.com/static/js/angular.min.js",
		"//services.amazon.com/solution-providers/assets/vendor/angular-cookies.min.js",
		"//raw.githubusercontent.com/angular/code.angularjs.org/master/1.0.7/angular-resource.js",
		"//prb-resume.appspot.com/bower_components/angular-animate/angular-animate.js",
		"//dl.dropboxusercontent.com/u/30877786/angular.min.js",
		"//static.tumblr.com/x5qdx0r/nPOnngtff/angular-resource.min_1_.js",
		"//storage.googleapis.com/assets-prod.urbansitter.net/us-sym/assets/vendor/angular-sanitize/angular-sanitize.min.js",
		"//twitter.github.io/labella.js/bower_components/angular/angular.min.js",
		"//cdn2-casinoroom.global.ssl.fastly.net/js/lib/angular-animate.min.js",
		"//www.adobe.com/devnet-apps/flashshowcase/lib/angular/angular.1.1.5.min.js",
		"//eternal-sunset.herokuapp.com/bower_components/angular/angular.js",
		"//cdn.bootcss.com/angular.js/1.2.0/angular.min.js"
	];
}));
//#endregion
//#region node_modules/csp_evaluator/dist/allowlist_bypasses/flash.js
var require_flash = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.URLS = void 0;
	exports.URLS = ["//vk.com/swf/video.swf", "//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf"];
}));
//#endregion
//#region node_modules/csp_evaluator/dist/utils.js
var require_utils = /* @__PURE__ */ __commonJSMin(((exports) => {
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.applyCheckFunktionToDirectives = exports.matchWildcardUrls = exports.getHostname = exports.getSchemeFreeUrl = void 0;
	function getSchemeFreeUrl(url) {
		url = url.replace(/^\w[+\w.-]*:\/\//i, "");
		url = url.replace(/^\/\//, "");
		return url;
	}
	exports.getSchemeFreeUrl = getSchemeFreeUrl;
	function getHostname(url) {
		const hostname = new URL("https://" + getSchemeFreeUrl(url).replace(":*", "").replace("*", "wildcard_placeholder")).hostname.replace("wildcard_placeholder", "*");
		const ipv6Regex = /^\[[\d:]+\]/;
		if (getSchemeFreeUrl(url).match(ipv6Regex) && !hostname.match(ipv6Regex)) return "[" + hostname + "]";
		return hostname;
	}
	exports.getHostname = getHostname;
	function setScheme(u) {
		if (u.startsWith("//")) return u.replace("//", "https://");
		return u;
	}
	function matchWildcardUrls(cspUrlString, listOfUrlStrings) {
		const cspUrl = new URL(setScheme(cspUrlString.replace(":*", "").replace("*", "wildcard_placeholder")));
		const listOfUrls = listOfUrlStrings.map((u) => new URL(setScheme(u)));
		const host = cspUrl.hostname.toLowerCase();
		const hostHasWildcard = host.startsWith("wildcard_placeholder.");
		const wildcardFreeHost = host.replace(/^\wildcard_placeholder/i, "");
		const path = cspUrl.pathname;
		const hasPath = path !== "/";
		for (const url of listOfUrls) {
			const domain = url.hostname;
			if (!domain.endsWith(wildcardFreeHost)) continue;
			if (!hostHasWildcard && host !== domain) continue;
			if (hasPath) {
				if (path.endsWith("/")) {
					if (!url.pathname.startsWith(path)) continue;
				} else if (url.pathname !== path) continue;
			}
			return url;
		}
		return null;
	}
	exports.matchWildcardUrls = matchWildcardUrls;
	function applyCheckFunktionToDirectives(parsedCsp, check) {
		const directiveNames = Object.keys(parsedCsp.directives);
		for (const directive of directiveNames) {
			const directiveValues = parsedCsp.directives[directive];
			if (directiveValues) check(directive, directiveValues);
		}
	}
	exports.applyCheckFunktionToDirectives = applyCheckFunktionToDirectives;
}));
//#endregion
//#region node_modules/csp_evaluator/dist/checks/security_checks.js
var require_security_checks = /* @__PURE__ */ __commonJSMin(((exports) => {
	var __createBinding = exports && exports.__createBinding || (Object.create ? (function(o, m, k, k2) {
		if (k2 === void 0) k2 = k;
		Object.defineProperty(o, k2, {
			enumerable: true,
			get: function() {
				return m[k];
			}
		});
	}) : (function(o, m, k, k2) {
		if (k2 === void 0) k2 = k;
		o[k2] = m[k];
	}));
	var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? (function(o, v) {
		Object.defineProperty(o, "default", {
			enumerable: true,
			value: v
		});
	}) : function(o, v) {
		o["default"] = v;
	});
	var __importStar = exports && exports.__importStar || function(mod) {
		if (mod && mod.__esModule) return mod;
		var result = {};
		if (mod != null) {
			for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
		}
		__setModuleDefault(result, mod);
		return result;
	};
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.checkHasConfiguredReporting = exports.checkSrcHttp = exports.checkNonceLength = exports.checkDeprecatedDirective = exports.checkIpSource = exports.looksLikeIpAddress = exports.checkFlashObjectAllowlistBypass = exports.checkScriptAllowlistBypass = exports.checkMissingDirectives = exports.checkMultipleMissingBaseUriDirective = exports.checkMissingBaseUriDirective = exports.checkMissingScriptSrcDirective = exports.checkMissingObjectSrcDirective = exports.checkWildcards = exports.checkPlainUrlSchemes = exports.checkScriptUnsafeEval = exports.checkScriptUnsafeInline = exports.URL_SCHEMES_CAUSING_XSS = exports.DIRECTIVES_CAUSING_XSS = void 0;
	var angular = __importStar(require_angular());
	var flash = __importStar(require_flash());
	var jsonp = __importStar(require_jsonp());
	var csp = __importStar(require_csp());
	var csp_1 = require_csp();
	var finding_1 = require_finding();
	var utils = __importStar(require_utils());
	exports.DIRECTIVES_CAUSING_XSS = [
		csp_1.Directive.SCRIPT_SRC,
		csp_1.Directive.SCRIPT_SRC_ATTR,
		csp_1.Directive.SCRIPT_SRC_ELEM,
		csp_1.Directive.OBJECT_SRC,
		csp_1.Directive.BASE_URI
	];
	exports.URL_SCHEMES_CAUSING_XSS = [
		"data:",
		"http:",
		"https:"
	];
	function checkScriptUnsafeInline(effectiveCsp) {
		const violations = [];
		const directivesToCheck = effectiveCsp.getEffectiveDirectives([
			csp_1.Directive.SCRIPT_SRC,
			csp_1.Directive.SCRIPT_SRC_ATTR,
			csp_1.Directive.SCRIPT_SRC_ELEM
		]);
		for (const directive of directivesToCheck) {
			const values = effectiveCsp.directives[directive] || [];
			if (values.includes(csp_1.Keyword.UNSAFE_INLINE)) violations.push(new finding_1.Finding(finding_1.Type.SCRIPT_UNSAFE_INLINE, "'unsafe-inline' allows the execution of unsafe in-page scripts and event handlers.", finding_1.Severity.HIGH, directive, csp_1.Keyword.UNSAFE_INLINE));
			if (values.includes(csp_1.Keyword.UNSAFE_HASHES)) violations.push(new finding_1.Finding(finding_1.Type.SCRIPT_UNSAFE_HASHES, `'unsafe-hashes', while safer than 'unsafe-inline', allows the execution of unsafe in-page scripts and event handlers as long as their hashes appear in the CSP. Please refactor them to no longer use inline scripts if possible.`, finding_1.Severity.MEDIUM_MAYBE, directive, csp_1.Keyword.UNSAFE_HASHES));
		}
		return violations;
	}
	exports.checkScriptUnsafeInline = checkScriptUnsafeInline;
	function checkScriptUnsafeEval(parsedCsp) {
		const violations = [];
		const directivesToCheck = parsedCsp.getEffectiveDirectives([
			csp_1.Directive.SCRIPT_SRC,
			csp_1.Directive.SCRIPT_SRC_ATTR,
			csp_1.Directive.SCRIPT_SRC_ELEM
		]);
		for (const directive of directivesToCheck) if ((parsedCsp.directives[directive] || []).includes(csp_1.Keyword.UNSAFE_EVAL)) violations.push(new finding_1.Finding(finding_1.Type.SCRIPT_UNSAFE_EVAL, "'unsafe-eval' allows the execution of code injected into DOM APIs such as eval().", finding_1.Severity.MEDIUM_MAYBE, directive, csp_1.Keyword.UNSAFE_EVAL));
		return violations;
	}
	exports.checkScriptUnsafeEval = checkScriptUnsafeEval;
	function checkPlainUrlSchemes(parsedCsp) {
		const violations = [];
		const directivesToCheck = parsedCsp.getEffectiveDirectives(exports.DIRECTIVES_CAUSING_XSS);
		for (const directive of directivesToCheck) {
			const values = parsedCsp.directives[directive] || [];
			for (const value of values) if (exports.URL_SCHEMES_CAUSING_XSS.includes(value)) violations.push(new finding_1.Finding(finding_1.Type.PLAIN_URL_SCHEMES, value + " URI in " + directive + " allows the execution of unsafe scripts.", finding_1.Severity.HIGH, directive, value));
		}
		return violations;
	}
	exports.checkPlainUrlSchemes = checkPlainUrlSchemes;
	function checkWildcards(parsedCsp) {
		const violations = [];
		const directivesToCheck = parsedCsp.getEffectiveDirectives(exports.DIRECTIVES_CAUSING_XSS);
		for (const directive of directivesToCheck) {
			const values = parsedCsp.directives[directive] || [];
			for (const value of values) if (utils.getSchemeFreeUrl(value) === "*") {
				violations.push(new finding_1.Finding(finding_1.Type.PLAIN_WILDCARD, directive + ` should not allow '*' as source`, finding_1.Severity.HIGH, directive, value));
				continue;
			}
		}
		return violations;
	}
	exports.checkWildcards = checkWildcards;
	function checkMissingObjectSrcDirective(parsedCsp) {
		let objectRestrictions = [];
		if (csp_1.Directive.OBJECT_SRC in parsedCsp.directives) objectRestrictions = parsedCsp.directives[csp_1.Directive.OBJECT_SRC];
		else if (csp_1.Directive.DEFAULT_SRC in parsedCsp.directives) objectRestrictions = parsedCsp.directives[csp_1.Directive.DEFAULT_SRC];
		if (objectRestrictions !== void 0 && objectRestrictions.length >= 1) return [];
		return [new finding_1.Finding(finding_1.Type.MISSING_DIRECTIVES, `Missing object-src allows the injection of plugins which can execute JavaScript. Can you set it to 'none'?`, finding_1.Severity.HIGH, csp_1.Directive.OBJECT_SRC)];
	}
	exports.checkMissingObjectSrcDirective = checkMissingObjectSrcDirective;
	function checkMissingScriptSrcDirective(parsedCsp) {
		if (csp_1.Directive.SCRIPT_SRC in parsedCsp.directives || csp_1.Directive.DEFAULT_SRC in parsedCsp.directives) return [];
		return [new finding_1.Finding(finding_1.Type.MISSING_DIRECTIVES, "script-src directive is missing.", finding_1.Severity.HIGH, csp_1.Directive.SCRIPT_SRC)];
	}
	exports.checkMissingScriptSrcDirective = checkMissingScriptSrcDirective;
	function checkMissingBaseUriDirective(parsedCsp) {
		return checkMultipleMissingBaseUriDirective([parsedCsp]);
	}
	exports.checkMissingBaseUriDirective = checkMissingBaseUriDirective;
	function checkMultipleMissingBaseUriDirective(parsedCsps) {
		const needsBaseUri = (csp) => csp.policyHasScriptNonces() || csp.policyHasScriptHashes() && csp.policyHasStrictDynamic();
		const hasBaseUri = (csp) => csp_1.Directive.BASE_URI in csp.directives;
		if (parsedCsps.some(needsBaseUri) && !parsedCsps.some(hasBaseUri)) return [new finding_1.Finding(finding_1.Type.MISSING_DIRECTIVES, "Missing base-uri allows the injection of base tags. They can be used to set the base URL for all relative (script) URLs to an attacker controlled domain. Can you set it to 'none' or 'self'?", finding_1.Severity.HIGH, csp_1.Directive.BASE_URI)];
		return [];
	}
	exports.checkMultipleMissingBaseUriDirective = checkMultipleMissingBaseUriDirective;
	function checkMissingDirectives(parsedCsp) {
		return [
			...checkMissingObjectSrcDirective(parsedCsp),
			...checkMissingScriptSrcDirective(parsedCsp),
			...checkMissingBaseUriDirective(parsedCsp)
		];
	}
	exports.checkMissingDirectives = checkMissingDirectives;
	function checkScriptAllowlistBypass(parsedCsp) {
		const violations = [];
		parsedCsp.getEffectiveDirectives([csp_1.Directive.SCRIPT_SRC, csp_1.Directive.SCRIPT_SRC_ELEM]).forEach((effectiveScriptSrcDirective) => {
			const scriptSrcValues = parsedCsp.directives[effectiveScriptSrcDirective] || [];
			if (scriptSrcValues.includes(csp_1.Keyword.NONE)) return;
			for (const value of scriptSrcValues) {
				if (value === csp_1.Keyword.SELF) {
					violations.push(new finding_1.Finding(finding_1.Type.SCRIPT_ALLOWLIST_BYPASS, "'self' can be problematic if you host JSONP, AngularJS or user uploaded files.", finding_1.Severity.MEDIUM_MAYBE, effectiveScriptSrcDirective, value));
					continue;
				}
				if (value.startsWith("'")) continue;
				if (csp.isUrlScheme(value) || value.indexOf(".") === -1) continue;
				const url = "//" + utils.getSchemeFreeUrl(value);
				const angularBypass = utils.matchWildcardUrls(url, angular.URLS);
				let jsonpBypass = utils.matchWildcardUrls(url, jsonp.URLS);
				if (jsonpBypass) {
					const evalRequired = jsonp.NEEDS_EVAL.includes(jsonpBypass.hostname);
					const evalPresent = scriptSrcValues.includes(csp_1.Keyword.UNSAFE_EVAL);
					if (evalRequired && !evalPresent) jsonpBypass = null;
				}
				if (jsonpBypass || angularBypass) {
					let bypassDomain = "";
					let bypassTxt = "";
					if (jsonpBypass) {
						bypassDomain = jsonpBypass.hostname;
						bypassTxt = " JSONP endpoints";
					}
					if (angularBypass) {
						bypassDomain = angularBypass.hostname;
						bypassTxt += bypassTxt.trim() === "" ? "" : " and";
						bypassTxt += " Angular libraries";
					}
					violations.push(new finding_1.Finding(finding_1.Type.SCRIPT_ALLOWLIST_BYPASS, bypassDomain + " is known to host" + bypassTxt + " which allow to bypass this CSP.", finding_1.Severity.HIGH, effectiveScriptSrcDirective, value));
				} else violations.push(new finding_1.Finding(finding_1.Type.SCRIPT_ALLOWLIST_BYPASS, "No bypass found; make sure that this URL doesn't serve JSONP replies or Angular libraries.", finding_1.Severity.MEDIUM_MAYBE, effectiveScriptSrcDirective, value));
			}
		});
		return violations;
	}
	exports.checkScriptAllowlistBypass = checkScriptAllowlistBypass;
	function checkFlashObjectAllowlistBypass(parsedCsp) {
		const violations = [];
		const effectiveObjectSrcDirective = parsedCsp.getEffectiveDirective(csp_1.Directive.OBJECT_SRC);
		const objectSrcValues = parsedCsp.directives[effectiveObjectSrcDirective] || [];
		const pluginTypes = parsedCsp.directives[csp_1.Directive.PLUGIN_TYPES];
		if (pluginTypes && !pluginTypes.includes("application/x-shockwave-flash")) return [];
		for (const value of objectSrcValues) {
			if (value === csp_1.Keyword.NONE) return [];
			const url = "//" + utils.getSchemeFreeUrl(value);
			const flashBypass = utils.matchWildcardUrls(url, flash.URLS);
			if (flashBypass) violations.push(new finding_1.Finding(finding_1.Type.OBJECT_ALLOWLIST_BYPASS, flashBypass.hostname + " is known to host Flash files which allow to bypass this CSP.", finding_1.Severity.HIGH, effectiveObjectSrcDirective, value));
			else if (effectiveObjectSrcDirective === csp_1.Directive.OBJECT_SRC) violations.push(new finding_1.Finding(finding_1.Type.OBJECT_ALLOWLIST_BYPASS, `Can you restrict object-src to 'none' only?`, finding_1.Severity.MEDIUM_MAYBE, effectiveObjectSrcDirective, value));
		}
		return violations;
	}
	exports.checkFlashObjectAllowlistBypass = checkFlashObjectAllowlistBypass;
	function looksLikeIpAddress(maybeIp) {
		if (maybeIp.startsWith("[") && maybeIp.endsWith("]")) return true;
		if (/^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(maybeIp)) return true;
		return false;
	}
	exports.looksLikeIpAddress = looksLikeIpAddress;
	function checkIpSource(parsedCsp) {
		const violations = [];
		const checkIp = (directive, directiveValues) => {
			for (const value of directiveValues) {
				const host = utils.getHostname(value);
				if (looksLikeIpAddress(host)) {
					if (host === "127.0.0.1") violations.push(new finding_1.Finding(finding_1.Type.IP_SOURCE, directive + " directive allows localhost as source. Please make sure to remove this in production environments.", finding_1.Severity.INFO, directive, value));
					else violations.push(new finding_1.Finding(finding_1.Type.IP_SOURCE, directive + " directive has an IP-Address as source: " + host + " (will be ignored by browsers!). ", finding_1.Severity.INFO, directive, value));
				}
			}
		};
		utils.applyCheckFunktionToDirectives(parsedCsp, checkIp);
		return violations;
	}
	exports.checkIpSource = checkIpSource;
	function checkDeprecatedDirective(parsedCsp) {
		const violations = [];
		if (csp_1.Directive.REFLECTED_XSS in parsedCsp.directives) violations.push(new finding_1.Finding(finding_1.Type.DEPRECATED_DIRECTIVE, "reflected-xss is deprecated since CSP2. Please, use the X-XSS-Protection header instead.", finding_1.Severity.INFO, csp_1.Directive.REFLECTED_XSS));
		if (csp_1.Directive.REFERRER in parsedCsp.directives) violations.push(new finding_1.Finding(finding_1.Type.DEPRECATED_DIRECTIVE, "referrer is deprecated since CSP2. Please, use the Referrer-Policy header instead.", finding_1.Severity.INFO, csp_1.Directive.REFERRER));
		if (csp_1.Directive.DISOWN_OPENER in parsedCsp.directives) violations.push(new finding_1.Finding(finding_1.Type.DEPRECATED_DIRECTIVE, "disown-opener is deprecated since CSP3. Please, use the Cross Origin Opener Policy header instead.", finding_1.Severity.INFO, csp_1.Directive.DISOWN_OPENER));
		if (csp_1.Directive.PREFETCH_SRC in parsedCsp.directives) violations.push(new finding_1.Finding(finding_1.Type.DEPRECATED_DIRECTIVE, "prefetch-src is deprecated since CSP3. Be aware that this feature may cease to work at any time.", finding_1.Severity.INFO, csp_1.Directive.PREFETCH_SRC));
		return violations;
	}
	exports.checkDeprecatedDirective = checkDeprecatedDirective;
	function checkNonceLength(parsedCsp) {
		const noncePattern = /* @__PURE__ */ new RegExp("^'nonce-(.+)'$");
		const violations = [];
		utils.applyCheckFunktionToDirectives(parsedCsp, (directive, directiveValues) => {
			for (const value of directiveValues) {
				const match = value.match(noncePattern);
				if (!match) continue;
				if (match[1].length < 8) violations.push(new finding_1.Finding(finding_1.Type.NONCE_LENGTH, "Nonces should be at least 8 characters long.", finding_1.Severity.MEDIUM, directive, value));
				if (!csp.isNonce(value, true)) violations.push(new finding_1.Finding(finding_1.Type.NONCE_CHARSET, "Nonces should only use the base64 charset.", finding_1.Severity.INFO, directive, value));
			}
		});
		return violations;
	}
	exports.checkNonceLength = checkNonceLength;
	function checkSrcHttp(parsedCsp) {
		const violations = [];
		utils.applyCheckFunktionToDirectives(parsedCsp, (directive, directiveValues) => {
			for (const value of directiveValues) {
				const description = directive === csp_1.Directive.REPORT_URI ? "Use HTTPS to send violation reports securely." : "Allow only resources downloaded over HTTPS.";
				if (value.startsWith("http://")) violations.push(new finding_1.Finding(finding_1.Type.SRC_HTTP, description, finding_1.Severity.MEDIUM, directive, value));
			}
		});
		return violations;
	}
	exports.checkSrcHttp = checkSrcHttp;
	function checkHasConfiguredReporting(parsedCsp) {
		if ((parsedCsp.directives[csp_1.Directive.REPORT_URI] || []).length > 0) return [];
		if ((parsedCsp.directives[csp_1.Directive.REPORT_TO] || []).length > 0) return [new finding_1.Finding(finding_1.Type.REPORT_TO_ONLY, `This CSP policy only provides a reporting destination via the 'report-to' directive. This directive is only supported in Chromium-based browsers so it is recommended to also use a 'report-uri' directive.`, finding_1.Severity.INFO, csp_1.Directive.REPORT_TO)];
		return [new finding_1.Finding(finding_1.Type.REPORTING_DESTINATION_MISSING, "This CSP policy does not configure a reporting destination. This makes it difficult to maintain the CSP policy over time and monitor for any breakages.", finding_1.Severity.INFO, csp_1.Directive.REPORT_URI)];
	}
	exports.checkHasConfiguredReporting = checkHasConfiguredReporting;
}));
//#endregion
//#region node_modules/csp_evaluator/dist/checks/strictcsp_checks.js
var require_strictcsp_checks = /* @__PURE__ */ __commonJSMin(((exports) => {
	var __createBinding = exports && exports.__createBinding || (Object.create ? (function(o, m, k, k2) {
		if (k2 === void 0) k2 = k;
		Object.defineProperty(o, k2, {
			enumerable: true,
			get: function() {
				return m[k];
			}
		});
	}) : (function(o, m, k, k2) {
		if (k2 === void 0) k2 = k;
		o[k2] = m[k];
	}));
	var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? (function(o, v) {
		Object.defineProperty(o, "default", {
			enumerable: true,
			value: v
		});
	}) : function(o, v) {
		o["default"] = v;
	});
	var __importStar = exports && exports.__importStar || function(mod) {
		if (mod && mod.__esModule) return mod;
		var result = {};
		if (mod != null) {
			for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
		}
		__setModuleDefault(result, mod);
		return result;
	};
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.checkRequiresTrustedTypesForScripts = exports.checkAllowlistFallback = exports.checkUnsafeInlineFallback = exports.checkStrictDynamicNotStandalone = exports.checkStrictDynamic = void 0;
	var csp = __importStar(require_csp());
	var csp_1 = require_csp();
	var finding_1 = require_finding();
	function checkStrictDynamic(parsedCsp) {
		const directiveName = parsedCsp.getEffectiveDirective(csp.Directive.SCRIPT_SRC);
		const values = parsedCsp.directives[directiveName] || [];
		if (values.some((v) => !v.startsWith("'")) && !values.includes(csp_1.Keyword.STRICT_DYNAMIC)) return [new finding_1.Finding(finding_1.Type.STRICT_DYNAMIC, "Host allowlists can frequently be bypassed. Consider using 'strict-dynamic' in combination with CSP nonces or hashes.", finding_1.Severity.STRICT_CSP, directiveName)];
		return [];
	}
	exports.checkStrictDynamic = checkStrictDynamic;
	function checkStrictDynamicNotStandalone(parsedCsp) {
		const directiveName = parsedCsp.getEffectiveDirective(csp.Directive.SCRIPT_SRC);
		if ((parsedCsp.directives[directiveName] || []).includes(csp_1.Keyword.STRICT_DYNAMIC) && !parsedCsp.policyHasScriptNonces() && !parsedCsp.policyHasScriptHashes()) return [new finding_1.Finding(finding_1.Type.STRICT_DYNAMIC_NOT_STANDALONE, "'strict-dynamic' without a CSP nonce/hash will block all scripts.", finding_1.Severity.INFO, directiveName)];
		return [];
	}
	exports.checkStrictDynamicNotStandalone = checkStrictDynamicNotStandalone;
	function checkUnsafeInlineFallback(parsedCsp) {
		if (!parsedCsp.policyHasScriptNonces() && !parsedCsp.policyHasScriptHashes()) return [];
		const directiveName = parsedCsp.getEffectiveDirective(csp.Directive.SCRIPT_SRC);
		if (!(parsedCsp.directives[directiveName] || []).includes(csp_1.Keyword.UNSAFE_INLINE)) return [new finding_1.Finding(finding_1.Type.UNSAFE_INLINE_FALLBACK, "Consider adding 'unsafe-inline' (ignored by browsers supporting nonces/hashes) to be backward compatible with older browsers.", finding_1.Severity.STRICT_CSP, directiveName)];
		return [];
	}
	exports.checkUnsafeInlineFallback = checkUnsafeInlineFallback;
	function checkAllowlistFallback(parsedCsp) {
		const directiveName = parsedCsp.getEffectiveDirective(csp.Directive.SCRIPT_SRC);
		const values = parsedCsp.directives[directiveName] || [];
		if (!values.includes(csp_1.Keyword.STRICT_DYNAMIC)) return [];
		if (!values.some((v) => [
			"http:",
			"https:",
			"*"
		].includes(v) || v.includes("."))) return [new finding_1.Finding(finding_1.Type.ALLOWLIST_FALLBACK, "Consider adding https: and http: url schemes (ignored by browsers supporting 'strict-dynamic') to be backward compatible with older browsers.", finding_1.Severity.STRICT_CSP, directiveName)];
		return [];
	}
	exports.checkAllowlistFallback = checkAllowlistFallback;
	function checkRequiresTrustedTypesForScripts(parsedCsp) {
		const directiveName = parsedCsp.getEffectiveDirective(csp.Directive.REQUIRE_TRUSTED_TYPES_FOR);
		if (!(parsedCsp.directives[directiveName] || []).includes(csp.TrustedTypesSink.SCRIPT)) return [new finding_1.Finding(finding_1.Type.REQUIRE_TRUSTED_TYPES_FOR_SCRIPTS, "Consider requiring Trusted Types for scripts to lock down DOM XSS injection sinks. You can do this by adding \"require-trusted-types-for 'script'\" to your policy.", finding_1.Severity.INFO, csp.Directive.REQUIRE_TRUSTED_TYPES_FOR)];
		return [];
	}
	exports.checkRequiresTrustedTypesForScripts = checkRequiresTrustedTypesForScripts;
}));
//#endregion
//#region node_modules/csp_evaluator/dist/evaluator.js
var require_evaluator = /* @__PURE__ */ __commonJSMin(((exports) => {
	var __createBinding = exports && exports.__createBinding || (Object.create ? (function(o, m, k, k2) {
		if (k2 === void 0) k2 = k;
		Object.defineProperty(o, k2, {
			enumerable: true,
			get: function() {
				return m[k];
			}
		});
	}) : (function(o, m, k, k2) {
		if (k2 === void 0) k2 = k;
		o[k2] = m[k];
	}));
	var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? (function(o, v) {
		Object.defineProperty(o, "default", {
			enumerable: true,
			value: v
		});
	}) : function(o, v) {
		o["default"] = v;
	});
	var __importStar = exports && exports.__importStar || function(mod) {
		if (mod && mod.__esModule) return mod;
		var result = {};
		if (mod != null) {
			for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
		}
		__setModuleDefault(result, mod);
		return result;
	};
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.STRICTCSP_CHECKS = exports.DEFAULT_CHECKS = exports.CspEvaluator = void 0;
	var parserChecks = __importStar(require_parser_checks());
	var securityChecks = __importStar(require_security_checks());
	var strictcspChecks = __importStar(require_strictcsp_checks());
	var csp = __importStar(require_csp());
	var CspEvaluator = class {
		constructor(parsedCsp, cspVersion, findings) {
			this.findings = [];
			this.version = cspVersion || csp.Version.CSP3;
			this.csp = parsedCsp;
			this.findings = findings || [];
		}
		evaluate(parsedCspChecks, effectiveCspChecks) {
			this.findings = [];
			const checks = effectiveCspChecks || exports.DEFAULT_CHECKS;
			const effectiveCsp = this.csp.getEffectiveCsp(this.version, this.findings);
			if (parsedCspChecks) for (const check of parsedCspChecks) this.findings = this.findings.concat(check(this.csp));
			for (const check of checks) this.findings = this.findings.concat(check(effectiveCsp));
			return this.findings;
		}
	};
	exports.CspEvaluator = CspEvaluator;
	exports.DEFAULT_CHECKS = [
		securityChecks.checkScriptUnsafeInline,
		securityChecks.checkScriptUnsafeEval,
		securityChecks.checkPlainUrlSchemes,
		securityChecks.checkWildcards,
		securityChecks.checkMissingDirectives,
		securityChecks.checkScriptAllowlistBypass,
		securityChecks.checkFlashObjectAllowlistBypass,
		securityChecks.checkIpSource,
		securityChecks.checkNonceLength,
		securityChecks.checkSrcHttp,
		securityChecks.checkDeprecatedDirective,
		parserChecks.checkUnknownDirective,
		parserChecks.checkMissingSemicolon,
		parserChecks.checkInvalidKeyword
	];
	exports.STRICTCSP_CHECKS = [
		strictcspChecks.checkStrictDynamic,
		strictcspChecks.checkStrictDynamicNotStandalone,
		strictcspChecks.checkUnsafeInlineFallback,
		strictcspChecks.checkAllowlistFallback,
		strictcspChecks.checkRequiresTrustedTypesForScripts
	];
}));
//#endregion
//#region node_modules/csp_evaluator/dist/parser.js
var require_parser = /* @__PURE__ */ __commonJSMin(((exports) => {
	var __createBinding = exports && exports.__createBinding || (Object.create ? (function(o, m, k, k2) {
		if (k2 === void 0) k2 = k;
		Object.defineProperty(o, k2, {
			enumerable: true,
			get: function() {
				return m[k];
			}
		});
	}) : (function(o, m, k, k2) {
		if (k2 === void 0) k2 = k;
		o[k2] = m[k];
	}));
	var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? (function(o, v) {
		Object.defineProperty(o, "default", {
			enumerable: true,
			value: v
		});
	}) : function(o, v) {
		o["default"] = v;
	});
	var __importStar = exports && exports.__importStar || function(mod) {
		if (mod && mod.__esModule) return mod;
		var result = {};
		if (mod != null) {
			for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
		}
		__setModuleDefault(result, mod);
		return result;
	};
	Object.defineProperty(exports, "__esModule", { value: true });
	exports.TEST_ONLY = exports.CspParser = void 0;
	var csp = __importStar(require_csp());
	var CspParser = class {
		constructor(unparsedCsp) {
			this.csp = new csp.Csp();
			this.parse(unparsedCsp);
		}
		parse(unparsedCsp) {
			this.csp = new csp.Csp();
			const directiveTokens = unparsedCsp.split(";");
			for (let i = 0; i < directiveTokens.length; i++) {
				const directiveParts = directiveTokens[i].trim().match(/\S+/g);
				if (Array.isArray(directiveParts)) {
					const directiveName = directiveParts[0].toLowerCase();
					if (directiveName in this.csp.directives) continue;
					if (!csp.isDirective(directiveName)) {}
					const directiveValues = [];
					for (let directiveValue, j = 1; directiveValue = directiveParts[j]; j++) {
						directiveValue = normalizeDirectiveValue(directiveValue);
						if (!directiveValues.includes(directiveValue)) directiveValues.push(directiveValue);
					}
					this.csp.directives[directiveName] = directiveValues;
				}
			}
			return this.csp;
		}
	};
	exports.CspParser = CspParser;
	function normalizeDirectiveValue(directiveValue) {
		directiveValue = directiveValue.trim();
		const directiveValueLower = directiveValue.toLowerCase();
		if (csp.isKeyword(directiveValueLower) || csp.isUrlScheme(directiveValue)) return directiveValueLower;
		return directiveValue;
	}
	exports.TEST_ONLY = { normalizeDirectiveValue };
}));
//#endregion
//#region src/rules/headers/csp.ts
var import_jsonp = require_jsonp();
var import_evaluator = require_evaluator();
var import_parser = require_parser();
var import_finding = require_finding();
var REFERENCE$6 = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy";
var CSP_HEADER = "content-security-policy";
/**
* Bypass-prone hosts derived from Google's csp_evaluator maintained JSONP list.
* Extracted at module-load time: strip scheme/path from each URL and deduplicate.
*
* This replaces the hand-written 4-item list with the package's curated set,
* which Google keeps up to date with real-world bypass-prone endpoints.
*/
var CSP_BYPASS_HOSTS = new Set(import_jsonp.URLS.map((url) => {
	return (url.replace(/^(https?:)?\/\//, "").split("/")[0] ?? "").toLowerCase();
}).filter((host) => host.length > 0));
/**
* Resolve the effective source list for a directive, falling back to
* default-src when the specific directive is absent.
*
* Returns undefined when neither the specific directive nor default-src exists.
*/
function resolveEffective(directives, directive) {
	return directives.get(directive) ?? directives.get("default-src");
}
/**
* Split a CSP source-list string on whitespace and return individual tokens.
*/
function sourceTokens(sourceList) {
	return sourceList.split(/\s+/).filter((t) => t.length > 0);
}
/**
* Returns true when the source list contains a truly open wildcard or insecure scheme:
*   - exactly '*' (allows script execution from any origin or scheme)
*   - exactly 'http:' (allows unencrypted scripts subject to MITM)
*   - exactly 'https:' when NOT protected by 'strict-dynamic' or nonces
*
* Scoped domain wildcards (e.g. '*.example.com', '*.muscache.com') are legitimate
* CDN/subdomain patterns and are evaluated under subdomain trust, not as open wildcards.
*/
function hasWildcardSource(sourceList, isModernStrict) {
	if (isModernStrict) return false;
	return sourceTokens(sourceList).some((token) => token === "*" || token === "http:" || token === "https:");
}
function findBypassProneHosts(sourceList) {
	const matched = /* @__PURE__ */ new Set();
	for (const token of sourceTokens(sourceList)) {
		if (token.startsWith("'") || token === "*") continue;
		const hostSource = token.replace(/^https?:\/\//i, "").split("/")[0]?.toLowerCase() ?? "";
		const wildcard = hostSource.startsWith("*.");
		const host = hostSource.replace(/^\*\./, "").replace(/:\d+$/, "");
		if (host.length === 0) continue;
		for (const riskyHost of CSP_BYPASS_HOSTS) if (host === riskyHost || host.endsWith(`.${riskyHost}`) || wildcard && riskyHost.endsWith(`.${host}`)) matched.add(riskyHost);
	}
	return [...matched];
}
/**
* Evaluate the Content-Security-Policy header for the final response hop.
* This function is pure — no browser APIs are used.
*
* @param finalHop - The last hop in the redirect chain.
* @returns An object containing all findings and the parsed directives map.
*/
function checkCsp(finalHop, metaCspFound = false) {
	const findings = [];
	const cspValue = finalHop.headers[CSP_HEADER];
	if (cspValue === void 0) {
		const reportOnlyValue = finalHop.headers["content-security-policy-report-only"];
		if (metaCspFound) findings.push({
			ruleId: "CSP-008",
			category: "header",
			severity: "info",
			title: "CSP detected in a meta tag; policy details are not evaluated",
			impact: "A meta CSP can enforce some policy directives, but it cannot replace response-header protections such as frame-ancestors and may take effect later in document parsing.",
			evidence: sanitizeEvidence("<meta http-equiv=\"Content-Security-Policy\">"),
			recommendation: "Also send Content-Security-Policy as an HTTP response header for complete coverage. This report does not assess the meta policy contents.",
			reference: REFERENCE$6
		});
		else if (reportOnlyValue !== void 0) findings.push({
			ruleId: "CSP-001",
			category: "header",
			severity: "high",
			title: "Only Content-Security-Policy-Report-Only is present; no enforcing CSP is configured",
			impact: "Report-Only policies observe violations but do not block unsafe content, so they do not provide CSP enforcement.",
			evidence: sanitizeEvidence(reportOnlyValue),
			recommendation: "After validating reports, deploy the intended policy as Content-Security-Policy. Keep Report-Only separately if continued monitoring is desired.",
			reference: REFERENCE$6
		});
		else findings.push({
			ruleId: "CSP-001",
			category: "header",
			severity: "high",
			title: "Content-Security-Policy header is missing",
			impact: "Without a CSP, any Cross-Site Scripting (XSS) vulnerability can execute malicious scripts, steal login cookies, or take over user accounts.",
			evidence: sanitizeEvidence("(header absent)"),
			recommendation: "Add a Content-Security-Policy header. Start with a strict base policy such as \"default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'\".",
			reference: REFERENCE$6
		});
		return {
			findings,
			directives: /* @__PURE__ */ new Map()
		};
	}
	const directives = parseCspDirectives(cspValue);
	if (!directives.has("default-src") && !directives.has("script-src")) findings.push({
		ruleId: "CSP-010",
		category: "header",
		severity: "info",
		title: "CSP has no default-src or script-src fallback",
		impact: "The policy does not establish a general resource fallback or an explicit script source policy.",
		evidence: sanitizeEvidence(cspValue),
		recommendation: "Add default-src as a baseline and define script-src explicitly where script loading needs a different policy.",
		reference: REFERENCE$6
	});
	const effectiveScriptSrc = resolveEffective(directives, "script-src");
	if (effectiveScriptSrc !== void 0) {
		const { isModernStrict } = hasCspBypassProtection(effectiveScriptSrc);
		const bypassProneHosts = isModernStrict ? [] : findBypassProneHosts(effectiveScriptSrc);
		if (bypassProneHosts.length > 0) findings.push({
			ruleId: "CSP-009",
			category: "header",
			severity: "info",
			title: "CSP script-src trusts host(s) with historically bypass-prone endpoints or libraries",
			impact: "Some allowlisted hosts expose JSONP endpoints or host libraries with script gadgets; actual exploitability depends on the specific endpoint, path, and version.",
			evidence: sanitizeEvidence(bypassProneHosts.join(", ")),
			recommendation: "Review whether each host is required, restrict paths where practical, pin library versions, and prefer nonces or hashes. This curated host match is a heuristic, not proof of a bypass.",
			reference: "https://csp-evaluator.withgoogle.com/"
		});
		if (effectiveScriptSrc.includes("'unsafe-inline'")) {
			if (isModernStrict) findings.push({
				ruleId: "CSP-002",
				category: "header",
				severity: "info",
				title: "CSP script-src includes 'unsafe-inline' as a legacy fallback (safely ignored due to nonce/strict-dynamic)",
				impact: "Older browsers may allow inline scripts, but modern browsers safely ignore this fallback because a nonce or strict-dynamic is present.",
				evidence: sanitizeEvidence(effectiveScriptSrc),
				recommendation: "No action needed for modern browsers. 'unsafe-inline' is ignored by CSP Level 3 browsers when a nonce or 'strict-dynamic' is present.",
				reference: REFERENCE$6
			});
			else findings.push({
				ruleId: "CSP-002",
				category: "header",
				severity: "high",
				title: "CSP script-src contains 'unsafe-inline'",
				impact: "Injected HTML tags (like <script> or event handlers) can execute arbitrary JavaScript directly inside victim browsers.",
				evidence: sanitizeEvidence(effectiveScriptSrc),
				recommendation: "Remove 'unsafe-inline' and use nonces or hashes to allow specific inline scripts.",
				reference: REFERENCE$6
			});
		}
		if (effectiveScriptSrc.includes("'unsafe-eval'")) findings.push({
			ruleId: "CSP-003",
			category: "header",
			severity: "high",
			title: "CSP script-src contains 'unsafe-eval'",
			impact: "Allows dynamic code execution via eval() and new Function(), enabling attackers who control string inputs to run arbitrary JavaScript.",
			evidence: sanitizeEvidence(effectiveScriptSrc),
			recommendation: "Remove 'unsafe-eval'. Refactor code that uses eval(), new Function(), or similar dynamic evaluation.",
			reference: REFERENCE$6
		});
		if (hasWildcardSource(effectiveScriptSrc, isModernStrict)) findings.push({
			ruleId: "CSP-004",
			category: "header",
			severity: "medium",
			title: "CSP script-src contains an overly broad wildcard or scheme-only source",
			impact: "Open wildcard sources allow scripts to be loaded and executed from any external host on the web.",
			evidence: sanitizeEvidence(effectiveScriptSrc),
			recommendation: "Replace wildcard or scheme-only sources (*, http:, https:) with explicit allowlisted hostnames or use nonces/hashes.",
			reference: REFERENCE$6
		});
	}
	if (!directives.has("frame-ancestors")) {
		const xfo = finalHop.headers["x-frame-options"]?.trim().toUpperCase();
		const hasValidXfo = xfo === "DENY" || xfo === "SAMEORIGIN";
		findings.push({
			ruleId: "CSP-005",
			category: "header",
			severity: hasValidXfo ? "info" : "medium",
			title: hasValidXfo ? "CSP is missing 'frame-ancestors' (mitigated by X-Frame-Options)" : "CSP is missing the 'frame-ancestors' directive",
			impact: hasValidXfo ? "Legacy browsers without XFO support could potentially embed this page, but modern browsers are protected by X-Frame-Options." : "Malicious websites can embed your site in an invisible iframe to trick users into clicking buttons they cannot see (Clickjacking).",
			evidence: sanitizeEvidence(cspValue),
			recommendation: "Add \"frame-ancestors 'none'\" (or \"'self'\") to control which origins may embed this page.",
			reference: REFERENCE$6
		});
	}
	const effectiveObjectSrc = resolveEffective(directives, "object-src");
	if (effectiveObjectSrc === void 0 || !sourceTokens(effectiveObjectSrc).includes("'none'")) findings.push({
		ruleId: "CSP-006",
		category: "header",
		severity: "medium",
		title: "CSP object-src is absent or not restricted to 'none'",
		impact: "Allows plugins (Flash, Java applets, PDF objects) to load untrusted resources that can bypass standard script constraints.",
		evidence: sanitizeEvidence(effectiveObjectSrc ?? "(directive absent)"),
		recommendation: "Add \"object-src 'none'\" to block plugin-based content (Flash, Java applets, etc.).",
		reference: REFERENCE$6
	});
	if (!directives.has("base-uri")) findings.push({
		ruleId: "CSP-007",
		category: "header",
		severity: "low",
		title: "CSP is missing the 'base-uri' directive",
		impact: "An attacker injecting a <base> tag can redirect all relative script, image, and form action URLs to an external phishing/exfiltration server.",
		evidence: sanitizeEvidence(cspValue),
		recommendation: "Add \"base-uri 'none'\" (or \"'self'\") to prevent base-tag injection attacks.",
		reference: REFERENCE$6
	});
	try {
		const parsed = new import_parser.CspParser(cspValue).csp;
		const evalFindings = new import_evaluator.CspEvaluator(parsed).evaluate();
		const existingRules = new Set(findings.map((f) => f.ruleId));
		for (const f of evalFindings) {
			if (f.severity === import_finding.Severity.STRICT_CSP || f.severity === import_finding.Severity.NONE) continue;
			if (f.type === import_finding.Type.STYLE_UNSAFE_INLINE) {
				if (!existingRules.has("CSP-002S")) {
					findings.push({
						ruleId: "CSP-002S",
						category: "header",
						severity: "low",
						title: "CSP style-src contains 'unsafe-inline'",
						impact: "Allows injection of malicious CSS which can exfiltrate data via attribute selectors or deface the site.",
						evidence: sanitizeEvidence(`${f.directive}: ${f.value ?? ""}`),
						recommendation: "Remove unsafe-inline from style-src and use external stylesheets or nonces/hashes for inline styles.",
						reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/style-src"
					});
					existingRules.add("CSP-002S");
				}
			} else if (f.type === import_finding.Type.SCRIPT_ALLOWLIST_BYPASS || f.type === import_finding.Type.OBJECT_ALLOWLIST_BYPASS) {
				if (f.value !== "'self'" && !existingRules.has("CSP-009")) {
					findings.push({
						ruleId: "CSP-009",
						category: "header",
						severity: "info",
						title: "CSP allowlist bypass or structural weakness",
						impact: f.description,
						evidence: sanitizeEvidence(`${f.directive}: ${f.value ?? ""}`),
						recommendation: "Remove the bypass host or use strict-dynamic / nonces instead of an allowlist.",
						reference: "https://csp-evaluator.withgoogle.com/"
					});
					existingRules.add("CSP-009");
				}
			} else if ((f.severity === import_finding.Severity.SYNTAX || f.type === import_finding.Type.NONCE_CHARSET || f.type === import_finding.Type.NONCE_LENGTH || f.type === import_finding.Type.STATIC_NONCE || f.type === import_finding.Type.MISSING_SEMICOLON || f.type === import_finding.Type.UNKNOWN_DIRECTIVE || f.type === import_finding.Type.INVALID_KEYWORD) && !existingRules.has("CSP-SYNTAX-001")) {
				findings.push({
					ruleId: "CSP-SYNTAX-001",
					category: "header",
					severity: "info",
					title: "CSP Syntax or Nonce Issue",
					impact: f.description,
					evidence: sanitizeEvidence(`${f.directive}: ${f.value ?? ""}`),
					recommendation: "Review CSP syntax.",
					reference: "https://csp-evaluator.withgoogle.com/"
				});
				existingRules.add("CSP-SYNTAX-001");
			}
		}
	} catch {}
	return {
		findings,
		directives
	};
}
//#endregion
//#region src/rules/headers/xfo.ts
var REFERENCE$5 = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options";
var XFO_HEADER = "x-frame-options";
/** Valid X-Frame-Options directive values (case-insensitive comparison done via uppercase). */
var VALID_VALUES = /* @__PURE__ */ new Set(["DENY", "SAMEORIGIN"]);
/**
* Evaluate the X-Frame-Options header for the final response hop.
* This function is pure — no browser APIs are used.
*
* @param finalHop       - The last hop in the redirect chain.
* @param cspDirectives  - Already-parsed CSP directives from checkCsp().
* @returns An array of zero or one finding.
*/
function checkXfo(finalHop, cspDirectives) {
	if (cspDirectives.has("frame-ancestors")) return [];
	const rawValue = finalHop.headers[XFO_HEADER];
	if (rawValue === void 0) return [{
		ruleId: "XFO-001",
		category: "header",
		severity: "medium",
		title: "X-Frame-Options header is missing",
		impact: "Attackers can frame your site in an invisible iframe and overlay malicious decoy elements to hijack clicks and actions (Clickjacking).",
		evidence: sanitizeEvidence("(header absent)"),
		recommendation: "Add \"X-Frame-Options: DENY\" (or SAMEORIGIN) to prevent clickjacking. Alternatively, use CSP frame-ancestors.",
		reference: REFERENCE$5
	}];
	const normalised = rawValue.trim().toUpperCase();
	if (!VALID_VALUES.has(normalised)) return [{
		ruleId: "XFO-001",
		category: "header",
		severity: "medium",
		title: "X-Frame-Options header has an unrecognised value",
		impact: "Unrecognized values (such as deprecated ALLOW-FROM) are ignored by modern browsers, leaving the site vulnerable to iframe embedding and Clickjacking.",
		evidence: sanitizeEvidence(rawValue),
		recommendation: "Set X-Frame-Options to either \"DENY\" or \"SAMEORIGIN\". The value \"ALLOW-FROM\" is deprecated and not supported in most browsers.",
		reference: REFERENCE$5
	}];
	return [];
}
//#endregion
//#region src/rules/headers/xcto.ts
var REFERENCE$4 = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options";
var XCTO_HEADER = "x-content-type-options";
/**
* Evaluate the X-Content-Type-Options header for the final response hop.
* This function is pure — no browser APIs are used.
*
* @param finalHop - The last hop in the redirect chain.
* @returns An array of zero or one finding.
*/
function checkXcto(finalHop) {
	const rawValue = finalHop.headers[XCTO_HEADER];
	if (rawValue === void 0) return [{
		ruleId: "XCTO-001",
		category: "header",
		severity: "medium",
		title: "X-Content-Type-Options header is missing",
		impact: "Browsers may guess (\"sniff\") response types, executing user-uploaded text or image files as malicious JavaScript (MIME-confusion XSS).",
		evidence: sanitizeEvidence("(header absent)"),
		recommendation: "Add \"X-Content-Type-Options: nosniff\" to prevent MIME-type sniffing attacks.",
		reference: REFERENCE$4
	}];
	if (rawValue.trim().toLowerCase() !== "nosniff") return [{
		ruleId: "XCTO-001",
		category: "header",
		severity: "medium",
		title: "X-Content-Type-Options header has an invalid value",
		impact: "Browsers do not recognize invalid values and fall back to content sniffing, re-opening MIME confusion attack vectors.",
		evidence: sanitizeEvidence(rawValue),
		recommendation: "Set X-Content-Type-Options to exactly \"nosniff\". No other values are recognised by browsers.",
		reference: REFERENCE$4
	}];
	return [];
}
//#endregion
//#region src/rules/headers/referrer.ts
var REFERENCE$3 = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy";
var REFERRER_HEADER = "referrer-policy";
/**
* Policies considered weak because they expose the full URL to cross-origin
* destinations, or because they are the unsafe browser default.
*/
var WEAK_POLICIES = /* @__PURE__ */ new Set([
	"unsafe-url",
	"no-referrer-when-downgrade",
	""
]);
/**
* Evaluate the Referrer-Policy header for the final response hop.
* This function is pure — no browser APIs are used.
*
* @param finalHop - The last hop in the redirect chain.
* @returns An array of zero or one finding.
*/
function checkReferrer(finalHop) {
	const rawValue = finalHop.headers[REFERRER_HEADER];
	if (rawValue === void 0) return [{
		ruleId: "REF-001",
		category: "header",
		severity: "low",
		title: "Referrer-Policy header is missing",
		impact: "Modern browsers default to strict-origin-when-cross-origin, but older browsers may leak full URL query parameters (tokens, IDs, search terms) to external sites in the Referer header.",
		evidence: sanitizeEvidence("(header absent)"),
		recommendation: "Set Referrer-Policy to \"strict-origin-when-cross-origin\" or stricter to limit referrer leakage to third-party sites.",
		reference: REFERENCE$3
	}];
	const trimmedValue = rawValue.trim().toLowerCase();
	if (WEAK_POLICIES.has(trimmedValue)) return [{
		ruleId: "REF-001",
		category: "header",
		severity: "low",
		title: "Referrer-Policy is set to a weak or privacy-leaking value",
		impact: "Transmits the full URL path and sensitive query parameters to third-party destinations when links are clicked.",
		evidence: sanitizeEvidence(rawValue),
		recommendation: "Replace the current value with \"strict-origin-when-cross-origin\" or \"no-referrer\" to minimise referrer leakage.",
		reference: REFERENCE$3
	}];
	return [];
}
//#endregion
//#region src/rules/headers/deprecated.ts
var REFERENCE$2 = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection";
/**
* Detect deprecated security-related response headers.
* This function is pure — no browser APIs are used.
*
* @param finalHop - The last hop in the redirect chain.
* @returns An array of zero or one finding.
*/
function checkDeprecated(finalHop) {
	const findings = [];
	const xssProtection = finalHop.headers["x-xss-protection"];
	if (xssProtection !== void 0) findings.push({
		ruleId: "DEP-001",
		category: "header",
		severity: "info",
		title: "X-XSS-Protection is deprecated and should be removed",
		impact: "This legacy browser auditor is obsolete and can introduce client-side side-channel leaks or bypasses in older browsers. Modern security relies on CSP.",
		evidence: sanitizeEvidence(xssProtection),
		recommendation: "Remove this header and rely on Content-Security-Policy instead.",
		reference: REFERENCE$2
	});
	for (const deprecated of [
		{
			name: "public-key-pins",
			ruleId: "DEP-002",
			title: "Public-Key-Pins (HPKP) is obsolete",
			note: "HPKP was removed from major browsers and can cause sites to become inaccessible when pins expire or are misconfigured."
		},
		{
			name: "p3p",
			ruleId: "DEP-003",
			title: "P3P privacy header is obsolete",
			note: "Modern browsers ignore P3P; it does not provide enforceable privacy protection."
		},
		{
			name: "feature-policy",
			ruleId: "DEP-004",
			title: "Feature-Policy has been superseded by Permissions-Policy",
			note: "Use the standardized Permissions-Policy header; legacy Feature-Policy syntax is not consistently supported."
		},
		{
			name: "x-ua-compatible",
			ruleId: "DEP-005",
			title: "X-UA-Compatible is obsolete",
			note: "The header only targeted legacy Internet Explorer document modes and is ignored by modern browsers."
		},
		{
			name: "expect-ct",
			ruleId: "DEP-006",
			title: "Expect-CT is obsolete",
			note: "Certificate Transparency enforcement is built into modern browsers; the Expect-CT header is no longer needed."
		},
		{
			name: "x-content-security-policy",
			ruleId: "DEP-007",
			title: "X-Content-Security-Policy is a legacy non-standard header",
			note: "Use the standardized Content-Security-Policy response header."
		},
		{
			name: "x-webkit-csp",
			ruleId: "DEP-008",
			title: "X-WebKit-CSP is a legacy non-standard header",
			note: "Use the standardized Content-Security-Policy response header."
		},
		{
			name: "public-key-pins-report-only",
			ruleId: "DEP-009",
			title: "Public-Key-Pins-Report-Only (HPKP) is obsolete",
			note: "HPKP reporting was removed from major browsers and is no longer useful."
		},
		{
			name: "x-content-security-policy-report-only",
			ruleId: "DEP-010",
			title: "X-Content-Security-Policy-Report-Only is a legacy non-standard header",
			note: "Use the standardized Content-Security-Policy-Report-Only response header."
		},
		{
			name: "x-webkit-csp-report-only",
			ruleId: "DEP-011",
			title: "X-WebKit-CSP-Report-Only is a legacy non-standard header",
			note: "Use the standardized Content-Security-Policy-Report-Only response header."
		},
		{
			name: "x-download-options",
			ruleId: "DEP-012",
			title: "X-Download-Options is a legacy browser-specific header",
			note: "This header only affects legacy Internet Explorer download behavior and is ignored by modern browsers."
		}
	]) {
		const value = finalHop.headers[deprecated.name];
		if (value === void 0) continue;
		findings.push({
			ruleId: deprecated.ruleId,
			category: "header",
			severity: "info",
			title: deprecated.title,
			impact: deprecated.note,
			evidence: sanitizeEvidence(value),
			recommendation: `Remove ${deprecated.name} unless a documented legacy-client requirement still depends on it.`,
			reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
		});
	}
	return findings;
}
//#endregion
//#region src/rules/headers/info-leak.ts
var REFERENCE$1 = "https://owasp.org/www-project-secure-headers/#server";
/**
* Headers that may inadvertently reveal server/framework version information.
* All values must be lowercase (matching the normalised keys in Hop.headers).
*/
var LEAKY_HEADERS = [
	"server",
	"x-powered-by",
	"x-aspnet-version",
	"x-aspnetmvc-version",
	"x-generator"
];
/**
* Matches explicit version numbers prefixed by a product or technology name 
* (e.g. "nginx/1.24.0", "Apache/2.4", "PHP/8.1", "Express 4.x")
* or bare versions if the header implies it (e.g. X-AspNet-Version: 4.0.30319).
*/
var VERSION_PATTERN = /[0-9]+\.[0-9]+/;
var PRODUCT_VERSION_PATTERN = /(?:microsoft-iis|apache|nginx|php|express|rails|django|laravel|node|openresty|litespeed|envoy|caddy|haproxy|tomcat|jetty|glassfish|jboss|weblogic|websphere)[\/\s-]*v?[0-9]+\.[0-9x]+/i;
/**
* Returns true when the header value exposes a specific technology version.
* Tightened to require product/version pairs, avoiding 
* false positives on simple numeric headers, UNLESS the header name explicitly implies a version.
*/
function isLeaky(value, headerName) {
	if (headerName.includes("-version")) return VERSION_PATTERN.test(value);
	return PRODUCT_VERSION_PATTERN.test(value);
}
/**
* Detect version strings or technology fingerprints in common response headers.
* This function is pure — no browser APIs are used.
*
* @param finalHop - The last hop in the redirect chain.
* @returns An array of findings, one per leaking header.
*/
function checkInfoLeak(finalHop) {
	const findings = [];
	for (const headerName of LEAKY_HEADERS) {
		const value = finalHop.headers[headerName];
		if (value !== void 0 && isLeaky(value, headerName)) findings.push({
			ruleId: "LEAK-001",
			category: "header",
			severity: "low",
			title: `Version string in ${headerName} response header`,
			impact: "Broadcasting software and framework versions assists attackers in looking up known CVE exploits targeted specifically at your technology stack.",
			evidence: sanitizeEvidence(value),
			recommendation: "Remove or redact this header at your web server / reverse proxy.",
			reference: REFERENCE$1
		});
	}
	return findings;
}
//#endregion
//#region src/rules/headers/cache-cookie.ts
var REFERENCE = "https://owasp.org/www-project-secure-headers/#cache-control";
var CACHE_CONTROL_HEADER = "cache-control";
/**
* Check that responses setting sensitive session/auth cookies include
* Cache-Control: no-store.
*
* Responses setting purely non-sensitive cookies (consent, theme, language,
* client-side analytics) are intentionally exempt so as not to penalize
* standard Back-Forward Cache (bfcache) optimizations.
*
* @param finalHop - The last hop in the redirect chain.
* @returns An array of zero or one finding.
*/
function checkCacheCookie(finalHop, alwaysSensitive = [], alwaysIgnore = []) {
	const setCookieHeaders = finalHop.rawHeaders.filter((h) => h.name.toLowerCase() === "set-cookie").map((h) => h.value);
	if (setCookieHeaders.length === 0) return [];
	if (setCookieHeaders.filter((headerVal) => {
		const name = headerVal.split("=")[0]?.trim() ?? "";
		return /;\s*httponly/i.test(headerVal) || isSensitiveCookie(name, alwaysSensitive, alwaysIgnore).isSensitive;
	}).length === 0) return [];
	const cacheControlValue = finalHop.headers[CACHE_CONTROL_HEADER];
	if (cacheControlValue === void 0) return [{
		ruleId: "CACHE-001",
		category: "header",
		severity: "medium",
		title: "Cache-Control: no-store missing on a response that sets sensitive cookies",
		impact: "Responses setting authentication cookies may be stored by intermediate web caches or proxy servers, exposing user session tokens to unauthorized parties.",
		evidence: sanitizeEvidence("(header absent)"),
		recommendation: "Add \"Cache-Control: no-store\" to responses that set authentication or session cookies.",
		reference: REFERENCE
	}];
	const normalised = cacheControlValue.toLowerCase();
	if (normalised.includes("no-store")) return [];
	if (normalised.includes("private") || normalised.includes("no-cache")) return [{
		ruleId: "CACHE-001",
		category: "header",
		severity: "info",
		title: "Cache-Control allows local caching for response with sensitive cookies (mitigated by private/no-cache)",
		impact: "Intermediate proxy/CDN caching is prevented by \"private\", but local browser storage persists the response, which could be exposed on shared kiosk computers.",
		evidence: sanitizeEvidence(cacheControlValue),
		recommendation: "Shared CDN caching is prevented by \"private\", but consider \"no-store\" if shared/public computers are in scope.",
		reference: REFERENCE
	}];
	return [{
		ruleId: "CACHE-001",
		category: "header",
		severity: "medium",
		title: "Cache-Control: no-store missing on a response that sets sensitive cookies",
		impact: "Sensitive authentication tokens and responses can be cached by shared CDN or proxy servers, allowing other users to retrieve session data.",
		evidence: sanitizeEvidence(cacheControlValue),
		recommendation: "Add \"Cache-Control: no-store\" to responses setting sensitive session cookies.",
		reference: REFERENCE
	}];
}
//#endregion
//#region src/rules/cookies/cookies.ts
var REF_COOKIES = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies";
var REF_PREFIX = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes";
var REF_SAMESITE = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite";
function checkSecure(cookie, isHttps, alwaysSensitive = [], alwaysIgnore = []) {
	if (!isHttps) return null;
	if (cookie.secure) return null;
	const { isSensitive, reason } = isSensitiveCookie(cookie.name, alwaysSensitive, alwaysIgnore);
	const isRegexHeuristic = reason === "regex";
	const hasStrongSignal = cookie.httpOnly || reason === "override" || reason === "prefix";
	const effectiveSeverity = isSensitive ? isRegexHeuristic && !hasStrongSignal ? "medium" : "high" : "low";
	const heuristicLabel = isSensitive && isRegexHeuristic && !hasStrongSignal ? " (name-based heuristic)" : "";
	return {
		ruleId: "COOK-001",
		category: "cookie",
		severity: effectiveSeverity,
		title: `${isSensitive ? "Sensitive cookie" : "Cookie"} "${sanitizeEvidence(cookie.name)}" is missing the Secure flag${heuristicLabel}`,
		impact: "The cookie can be transmitted across unencrypted HTTP links, allowing network eavesdroppers to intercept session tokens or user data in cleartext.",
		evidence: sanitizeEvidence(cookie.name),
		recommendation: "Add the Secure attribute so the cookie is never sent over plain HTTP.",
		reference: REF_COOKIES
	};
}
function checkHttpOnly(cookie, alwaysSensitive = [], alwaysIgnore = []) {
	if (cookie.httpOnly) return null;
	if (cookie.setByJs === true) return null;
	const { isSensitive, reason } = isSensitiveCookie(cookie.name, alwaysSensitive, alwaysIgnore);
	if (!isSensitive) return null;
	const isRegexHeuristic = reason === "regex";
	const hasStrongSignal = cookie.secure || reason === "override" || reason === "prefix";
	const heuristicLabel = isRegexHeuristic && !hasStrongSignal ? " (name-based heuristic)" : "";
	return {
		ruleId: "COOK-002",
		category: "cookie",
		severity: "medium",
		title: `Sensitive cookie "${sanitizeEvidence(cookie.name)}" is missing the HttpOnly flag${heuristicLabel}`,
		impact: "This sensitive session cookie is readable by JavaScript via document.cookie, meaning any Cross-Site Scripting (XSS) attack can immediately steal it.",
		evidence: sanitizeEvidence(cookie.name),
		recommendation: "Add HttpOnly so this sensitive session/auth cookie cannot be read by JavaScript (mitigates XSS cookie theft).",
		reference: REF_COOKIES
	};
}
function checkSameSiteNone(cookie) {
	if (cookie.sameSite !== "none") return null;
	if (cookie.secure) return null;
	return {
		ruleId: "COOK-003",
		category: "cookie",
		severity: "high",
		title: `Cookie "${sanitizeEvidence(cookie.name)}" uses SameSite=None without Secure`,
		impact: "SameSite=None permits cross-site requests to send this cookie, but omitting Secure allows it to travel unencrypted, violating modern browser security standards.",
		evidence: sanitizeEvidence(cookie.name),
		recommendation: "Add the Secure attribute or change SameSite to Strict or Lax.",
		reference: REF_SAMESITE
	};
}
function checkSameSiteMissing(cookie) {
	if (cookie.sameSite !== "") return null;
	return {
		ruleId: "COOK-004",
		category: "cookie",
		severity: "info",
		title: `Cookie "${sanitizeEvidence(cookie.name)}" has no explicit SameSite attribute (defaults to Lax in modern browsers)`,
		impact: "Modern browsers automatically enforce SameSite=Lax for this cookie, though older clients without Lax-by-default support may still attach it to cross-site requests.",
		evidence: sanitizeEvidence(cookie.name),
		recommendation: "Modern browsers (Chrome 80+, Firefox, Safari) enforce SameSite=Lax by default. Explicitly setting SameSite=Lax or Strict is recommended for defense-in-depth on legacy clients.",
		reference: REF_SAMESITE
	};
}
function checkHostPrefix(cookie) {
	if (!cookie.name.startsWith("__Host-")) return null;
	const violations = [];
	if (!cookie.secure) violations.push("Secure flag missing");
	if (cookie.path !== "/") violations.push(`Path is "${cookie.path}" (must be /)`);
	if (cookie.domainAttributePresent === true) violations.push("Domain attribute must be absent");
	if (violations.length === 0) return null;
	return {
		ruleId: "COOK-005",
		category: "cookie",
		severity: "high",
		title: `Cookie "${sanitizeEvidence(cookie.name)}" violates __Host- prefix requirements`,
		impact: "Failing __Host- prefix requirements breaks browser isolation guarantees, allowing subdomains or subpaths to overwrite or shadow the main session cookie.",
		evidence: sanitizeEvidence(violations.join("; ")),
		recommendation: "Fix the cookie so it has Secure=true, Path=/, and no Domain attribute.",
		reference: REF_PREFIX
	};
}
function checkSecurePrefix(cookie) {
	if (!cookie.name.startsWith("__Secure-")) return null;
	if (cookie.secure) return null;
	return {
		ruleId: "COOK-006",
		category: "cookie",
		severity: "high",
		title: `Cookie "${sanitizeEvidence(cookie.name)}" violates __Secure- prefix requirements`,
		impact: "The __Secure- prefix explicitly promises the cookie will only be sent over HTTPS. Omitting Secure causes browsers to reject the cookie or allow plaintext transmission.",
		evidence: sanitizeEvidence(cookie.name),
		recommendation: "Add the Secure attribute — the __Secure- prefix requires it.",
		reference: REF_PREFIX
	};
}
function checkHttpPrefix(cookie) {
	const hostHttp = cookie.name.startsWith("__Host-Http-");
	if (!(hostHttp || cookie.name.startsWith("__Http-"))) return null;
	const violations = [];
	if (!cookie.secure) violations.push("Secure flag missing");
	if (!cookie.httpOnly) violations.push("HttpOnly flag missing");
	if (hostHttp) {
		if (cookie.path !== "/") violations.push(`Path is "${cookie.path}" (must be /)`);
		if (cookie.domainAttributePresent === true) violations.push("Domain attribute must be absent");
	}
	if (violations.length === 0) return null;
	return {
		ruleId: "COOK-007",
		category: "cookie",
		severity: "high",
		title: `Cookie "${sanitizeEvidence(cookie.name)}" violates ${hostHttp ? "__Host-Http-" : "__Http-"} prefix requirements`,
		impact: "The browser-enforced prefix requirements are not met, so the cookie may be rejected or lose the server-only and host-bound protections its name claims.",
		evidence: sanitizeEvidence(violations.join("; ")),
		recommendation: hostHttp ? "Use Secure, HttpOnly, Path=/, and omit Domain." : "Use both Secure and HttpOnly.",
		reference: REF_PREFIX
	};
}
/**
* Run all cookie security rules against the list of cookie metadata records.
*
* Cookie *values* are never accessed. Evidence strings contain only the
* sanitized cookie name and/or attribute information.
*
* @param cookies - Metadata-only cookie records for the current page.
* @param isHttps - Whether the final hop was served over HTTPS.
* @returns An array of findings, one per violated rule per cookie.
*/
function checkCookies(cookies, isHttps, alwaysSensitive = [], alwaysIgnore = []) {
	const findings = [];
	for (const cookie of cookies) {
		const secure = checkSecure(cookie, isHttps, alwaysSensitive, alwaysIgnore);
		const httpOnly = checkHttpOnly(cookie, alwaysSensitive, alwaysIgnore);
		const sameNone = checkSameSiteNone(cookie);
		const sameMiss = checkSameSiteMissing(cookie);
		const host = checkHostPrefix(cookie);
		const secPfx = checkSecurePrefix(cookie);
		const httpPfx = checkHttpPrefix(cookie);
		if (secure !== null) findings.push(secure);
		if (httpOnly !== null) findings.push(httpOnly);
		if (sameNone !== null) findings.push(sameNone);
		if (sameMiss !== null) findings.push(sameMiss);
		if (host !== null) findings.push(host);
		if (secPfx !== null) findings.push(secPfx);
		if (httpPfx !== null) findings.push(httpPfx);
	}
	return findings;
}
//#endregion
//#region src/rules/headers/isolation.ts
var REF_COEP = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy";
var REF_CORP = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy";
var REF_PERMISSIONS_POLICY = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy";
function checkIsolationHeaders(hop) {
	const findings = [];
	const coep = (hop.headers["cross-origin-embedder-policy"]?.trim().toLowerCase())?.split(";", 1)[0]?.trim();
	const corp = hop.headers["cross-origin-resource-policy"]?.trim().toLowerCase();
	const permissionsPolicy = hop.headers["permissions-policy"] ?? "";
	if (coep === void 0 || coep === "unsafe-none") findings.push({
		ruleId: "COEP-001",
		category: "header",
		severity: "info",
		title: "Cross-Origin-Embedder-Policy does not enable cross-origin isolation",
		impact: "Features requiring cross-origin isolation, such as SharedArrayBuffer in some contexts, may be unavailable.",
		evidence: sanitizeEvidence(coep ?? "(header absent; browser default is unsafe-none)"),
		recommendation: "If the application needs cross-origin isolation, evaluate COEP: require-corp or credentialless together with COOP: same-origin and compatible resource policies.",
		reference: REF_COEP
	});
	else if (coep !== "require-corp" && coep !== "credentialless") findings.push({
		ruleId: "COEP-002",
		category: "header",
		severity: "info",
		title: "Cross-Origin-Embedder-Policy has an unrecognized value",
		evidence: sanitizeEvidence(coep),
		recommendation: "Use a supported COEP value (require-corp or credentialless) when cross-origin isolation is required.",
		reference: REF_COEP
	});
	if (corp === void 0) findings.push({
		ruleId: "CORP-001",
		category: "header",
		severity: "info",
		title: "Cross-Origin-Resource-Policy is not explicitly set",
		impact: "Other sites may be able to embed this resource unless another browser policy or CORS rule limits access.",
		evidence: sanitizeEvidence("(header absent)"),
		recommendation: "Set same-origin or same-site when the resource should not be embedded cross-origin; use cross-origin only when intended.",
		reference: REF_CORP
	});
	else if (corp !== "same-origin" && corp !== "same-site" && corp !== "cross-origin") findings.push({
		ruleId: "CORP-002",
		category: "header",
		severity: "info",
		title: "Cross-Origin-Resource-Policy has an unrecognized value",
		evidence: sanitizeEvidence(corp),
		recommendation: "Use same-origin, same-site, or cross-origin according to the resource sharing requirements.",
		reference: REF_CORP
	});
	else if (corp === "cross-origin") findings.push({
		ruleId: "CORP-003",
		category: "header",
		severity: "info",
		title: "Cross-Origin-Resource-Policy permits cross-origin embedding",
		evidence: sanitizeEvidence(corp),
		recommendation: "Confirm cross-origin embedding is intended for this resource; choose same-origin or same-site if not.",
		reference: REF_CORP
	});
	const permissiveFeatures = permissionsPolicy.split(",").map((directive) => directive.trim()).filter((directive) => /^[a-z0-9-]+\s*=\s*\(\s*\*\s*\)$/i.test(directive));
	if (permissiveFeatures.length > 0) findings.push({
		ruleId: "PERMPOLICY-001",
		category: "header",
		severity: "info",
		title: "Permissions-Policy allows features in all origins",
		evidence: sanitizeEvidence(permissiveFeatures.join(", ")),
		recommendation: "Restrict sensitive features to self or an explicit origin allowlist, or disable unused features with an empty allowlist.",
		reference: REF_PERMISSIONS_POLICY
	});
	return findings;
}
//#endregion
//#region src/rules/headers/reporting.ts
var REF_REPORTING = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Reporting-Endpoints";
var REF_NEL = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Network_Error_Logging";
var REF_CSP = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to";
function endpointGroups(value) {
	return new Set([...value.matchAll(/(?:^|,)\s*([a-zA-Z0-9_-]+)\s*=/g)].map((match) => (match[1] ?? "").toLowerCase()).filter(Boolean));
}
function checkReportingHeaders(hop) {
	const findings = [];
	const csp = hop.headers["content-security-policy"] ?? "";
	const endpoints = hop.headers["reporting-endpoints"] ?? "";
	const nel = hop.headers["nel"];
	const groups = endpointGroups(endpoints);
	if (csp.length > 0 && !/\breport-to\b|\breport-uri\b/i.test(csp)) findings.push({
		ruleId: "CSP-REPORT-001",
		category: "header",
		severity: "info",
		title: "CSP violation reporting is not configured",
		evidence: sanitizeEvidence("(neither report-to nor report-uri directive found)"),
		recommendation: "Consider configuring report-to with a Reporting-Endpoints group to observe policy violations; report-uri is deprecated but remains a compatibility fallback.",
		reference: REF_CSP
	});
	if (endpoints.length === 0) findings.push({
		ruleId: "REPORT-001",
		category: "header",
		severity: "info",
		title: "Reporting-Endpoints header is not configured",
		evidence: sanitizeEvidence("(header absent)"),
		recommendation: "Configure Reporting-Endpoints if the application intends to receive browser-generated CSP, deprecation, or network reports.",
		reference: REF_REPORTING
	});
	if (nel !== void 0) {
		let reportTo;
		try {
			const parsed = JSON.parse(nel);
			if (typeof parsed === "object" && parsed !== null && "report_to" in parsed) {
				const value = parsed.report_to;
				if (typeof value === "string") reportTo = value.toLowerCase();
			}
		} catch {
			findings.push({
				ruleId: "REPORT-003",
				category: "header",
				severity: "info",
				title: "NEL header is not valid JSON",
				evidence: sanitizeEvidence(nel),
				recommendation: "Provide a valid Network Error Logging JSON object and verify its report_to group.",
				reference: REF_NEL
			});
			return findings;
		}
		if (reportTo === void 0 || !groups.has(reportTo)) findings.push({
			ruleId: "REPORT-002",
			category: "header",
			severity: "info",
			title: "NEL report_to group does not match Reporting-Endpoints",
			evidence: sanitizeEvidence(`NEL report_to=${reportTo ?? "(missing)"}; configured groups=${[...groups].join(", ") || "(none)"}`),
			recommendation: "Set NEL report_to to a group name declared in Reporting-Endpoints.",
			reference: REF_NEL
		});
	}
	return findings;
}
//#endregion
//#region src/rules/headers/policy-hardening.ts
var REF_DOCUMENT_POLICY = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Document-Policy";
var REF_INTEGRITY_POLICY = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Integrity-Policy";
function checkPolicyHardeningHeaders(hop) {
	const findings = [];
	const documentPolicy = hop.headers["document-policy"];
	const integrityPolicy = hop.headers["integrity-policy"];
	const integrityReportOnly = hop.headers["integrity-policy-report-only"];
	if (documentPolicy === void 0) findings.push({
		ruleId: "DOC-001",
		category: "header",
		severity: "info",
		title: "Document-Policy is not configured",
		evidence: sanitizeEvidence("(header absent)"),
		recommendation: "Consider disabling document features the application does not need using browser-supported Document-Policy directives.",
		reference: REF_DOCUMENT_POLICY
	});
	if (integrityPolicy === void 0 && integrityReportOnly !== void 0) findings.push({
		ruleId: "INTEGRITY-002",
		category: "header",
		severity: "info",
		title: "Integrity-Policy-Report-Only is configured without enforcement",
		evidence: sanitizeEvidence(integrityReportOnly),
		recommendation: "Review reports and consider promoting supported directives to Integrity-Policy after verifying resources have integrity metadata.",
		reference: REF_INTEGRITY_POLICY
	});
	else if (integrityPolicy === void 0) findings.push({
		ruleId: "INTEGRITY-001",
		category: "header",
		severity: "info",
		title: "Integrity-Policy is not configured",
		evidence: sanitizeEvidence("(header absent)"),
		recommendation: "Consider Integrity-Policy for enforcing integrity metadata on script resources after checking browser support and application compatibility.",
		reference: REF_INTEGRITY_POLICY
	});
	return findings;
}
//#endregion
//#region src/rules/headers/cors.ts
var REF_CORS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS";
function checkCors(hop) {
	const isApi = "method" in hop || "normalizedPath" in hop;
	const contentType = hop.headers["content-type"]?.toLowerCase() ?? "";
	if (!isApi && (contentType.includes("text/html") || contentType === "")) return [];
	const allowOrigin = hop.headers["access-control-allow-origin"]?.trim();
	if (allowOrigin === void 0) return [];
	const credentials = hop.headers["access-control-allow-credentials"]?.trim().toLowerCase() === "true";
	const lowerOrigin = allowOrigin.toLowerCase();
	const requestOrigin = hop.requestOrigin;
	if (credentials && requestOrigin !== void 0 && requestOrigin.length > 0 && allowOrigin === requestOrigin) return [{
		ruleId: "CORS-001",
		category: "cors",
		severity: "medium",
		confidence: "heuristic",
		title: "CORS allows request Origin with credentials (potential reflection)",
		impact: "Any website can induce a user browser to make requests to this endpoint and read the response using the victim ambient credentials (cookies/auth) if the server dynamically reflects the origin.",
		evidence: sanitizeEvidence(`Request Origin: ${requestOrigin} -> ACAO: ${allowOrigin}; ACAC: true`),
		recommendation: "Verify that the server does not dynamically reflect arbitrary Origin headers when Access-Control-Allow-Credentials is true. Validate incoming Origin headers against a strict, static allowlist.",
		reference: REF_CORS
	}];
	if (lowerOrigin === "null") return [{
		ruleId: "CORS-001",
		category: "cors",
		severity: credentials ? "high" : "medium",
		confidence: "deterministic",
		title: "CORS allows the 'null' origin to read this response",
		impact: "Allowing the \"null\" origin permits sandboxed iframes, local files, and data: URIs from arbitrary origins to read sensitive data.",
		evidence: sanitizeEvidence(`Access-Control-Allow-Origin: null${credentials ? "; Access-Control-Allow-Credentials: true" : ""}`),
		recommendation: "Remove \"null\" from CORS allowlists. Sandboxed attacker iframes can forge a null origin.",
		reference: REF_CORS
	}];
	if (allowOrigin === "*") return [{
		ruleId: "CORS-001",
		category: "cors",
		severity: "medium",
		confidence: "deterministic",
		title: "CORS allows every origin to read this response",
		impact: "Any website can read this response through browser JavaScript; this is risky when the response contains non-public data.",
		evidence: sanitizeEvidence(`Access-Control-Allow-Origin: *${credentials ? "; Access-Control-Allow-Credentials: true (credentials are ignored with wildcard origin)" : ""}`),
		recommendation: "Replace the wildcard with an explicit allowlist of trusted origins when this response contains data that should not be public.",
		reference: REF_CORS
	}];
	return [];
}
//#endregion
//#region src/rules/scoring.ts
var WEIGHTS = {
	version: "1.7.0",
	rules: {
		"HSTS-001": {
			"penalty": 20,
			"rationale": "Missing HSTS enables MITM downgrade attacks"
		},
		"HSTS-002": {
			"penalty": 5,
			"rationale": "Short max-age provides insufficient protection window"
		},
		"HSTS-003": {
			"penalty": 3,
			"rationale": "Missing includeSubDomains exposes subdomains to downgrade"
		},
		"CSP-001": {
			"penalty": 20,
			"rationale": "Missing CSP allows XSS payload execution without restriction"
		},
		"CSP-002": {
			"penalty": 15,
			"rationale": "unsafe-inline allows arbitrary script execution"
		},
		"CSP-002S": {
			"penalty": 2,
			"rationale": "unsafe-inline style allows CSS injection"
		},
		"CSP-003": {
			"penalty": 10,
			"rationale": "unsafe-eval allows eval()-based code injection"
		},
		"CSP-004": {
			"penalty": 5,
			"rationale": "Wildcard source allows script from any host"
		},
		"CSP-005": {
			"penalty": 5,
			"rationale": "frame-ancestors absent - clickjacking risk"
		},
		"CSP-006": {
			"penalty": 5,
			"rationale": "object-src not restricted - plugin injection risk"
		},
		"CSP-007": {
			"penalty": 3,
			"rationale": "base-uri absent - base-tag injection risk"
		},
		"CSP-009": {
			"penalty": 0,
			"rationale": "Informational heuristic - allowlisted host may expose JSONP endpoints or script gadgets"
		},
		"CSP-SYNTAX-001": {
			"penalty": 0,
			"rationale": "Informational - CSP syntax issue or weak nonce"
		},
		"XCTO-001": {
			"penalty": 8,
			"rationale": "MIME sniffing enables content-type confusion attacks"
		},
		"XFO-001": {
			"penalty": 8,
			"rationale": "Clickjacking protection missing"
		},
		"REF-001": {
			"penalty": 5,
			"rationale": "Weak referrer policy leaks URL to third parties"
		},
		"DEP-001": {
			"penalty": 0,
			"rationale": "X-XSS-Protection is deprecated - informational only"
		},
		"LEAK-001": {
			"penalty": 3,
			"rationale": "Version disclosure aids targeted exploitation"
		},
		"DEP-002": {
			"penalty": 0,
			"rationale": "Public-Key-Pins is obsolete - informational only"
		},
		"DEP-003": {
			"penalty": 0,
			"rationale": "P3P is obsolete - informational only"
		},
		"DEP-004": {
			"penalty": 0,
			"rationale": "Feature-Policy is superseded - informational only"
		},
		"DEP-005": {
			"penalty": 0,
			"rationale": "X-UA-Compatible is obsolete - informational only"
		},
		"CACHE-001": {
			"penalty": 5,
			"rationale": "Cached cookie-setting responses expose session data"
		},
		"COOK-001": {
			"penalty": 10,
			"rationale": "OWASP ASVS 3.4.1 - Secure flag required on HTTPS"
		},
		"COOK-002": {
			"penalty": 7,
			"rationale": "OWASP ASVS 3.4.2 - HttpOnly prevents JS cookie theft"
		},
		"COOK-003": {
			"penalty": 10,
			"rationale": "RFC 6265bis A 8.8 - SameSite=None requires Secure"
		},
		"COOK-004": {
			"penalty": 0,
			"rationale": "Informational - modern browsers default missing SameSite to Lax automatically"
		},
		"COOK-005": {
			"penalty": 10,
			"rationale": "RFC 6265bis A 4.1.3 - __Host- prefix requires Secure+Path=/+no Domain"
		},
		"COOK-006": {
			"penalty": 10,
			"rationale": "RFC 6265bis A 4.1.3 - __Secure- prefix requires Secure flag"
		},
		"COOK-007": {
			"penalty": 10,
			"rationale": "__Http- and __Host-Http- prefixes require server-only cookie attributes"
		},
		"DUP-001": {
			"penalty": 0,
			"rationale": "Informational - conflicting repeated security header values"
		},
		"CSP-010": {
			"penalty": 0,
			"rationale": "Informational - CSP has neither default-src nor script-src fallback"
		},
		"DEP-009": {
			"penalty": 0,
			"rationale": "Informational - obsolete HPKP report-only header"
		},
		"DEP-010": {
			"penalty": 0,
			"rationale": "Informational - legacy non-standard report-only CSP header"
		},
		"DEP-011": {
			"penalty": 0,
			"rationale": "Informational - legacy non-standard report-only CSP header"
		},
		"DEP-012": {
			"penalty": 0,
			"rationale": "Informational - legacy Internet Explorer download header"
		},
		"SUB-001": {
			"penalty": 15,
			"rationale": "Domain-wide cookie scope lets subdomain attacker steal main-domain session"
		},
		"SUB-002": {
			"penalty": 10,
			"rationale": "CSP wildcard subdomain trust allows XSS pivot from any compromised subdomain"
		},
		"SUB-003": {
			"penalty": 12,
			"rationale": "CORS trusts subdomain origin - credentialed API data exposed cross-subdomain"
		},
		"SUB-003H": {
			"penalty": 3,
			"rationale": "Vary: Origin indicates possible dynamic reflection, but lacks confirmed cross-subdomain ACAO"
		},
		"SUB-004": {
			"penalty": 10,
			"rationale": "Page frameable by subdomains - postMessage confusion / clickjacking pivot"
		},
		"SUB-005": {
			"penalty": 4,
			"rationale": "Common advisory: sensitive cookies lack __Host- prefix - vulnerable to Cookie Tossing from subdomains"
		},
		"SUB-006": {
			"penalty": 4,
			"rationale": "Missing Cross-Origin-Opener-Policy allows window.opener manipulation from subdomains"
		},
		"SUB-007": {
			"penalty": 2,
			"rationale": "Missing Origin-Agent-Cluster allows document.domain relaxation cross-subdomain"
		},
		"SUB-008": {
			"penalty": 0,
			"rationale": "Informational - Subdomain isolated with no trust bridges to main domain"
		},
		"REDIR-001": {
			"penalty": 0,
			"rationale": "Informational - a later redirect response omitted a header present earlier in the chain"
		},
		"CORS-001": {
			"penalty": 6,
			"rationale": "Wildcard CORS policy lets arbitrary origins read the response"
		},
		"SRI-001": {
			"penalty": 5,
			"rationale": "External scripts without integrity can be modified by a compromised provider"
		},
		"DEP-006": {
			"penalty": 1,
			"rationale": "Obsolete Expect-CT header remains configured"
		},
		"DEP-007": {
			"penalty": 1,
			"rationale": "Legacy non-standard CSP header remains configured"
		},
		"DEP-008": {
			"penalty": 1,
			"rationale": "Legacy non-standard CSP header remains configured"
		}
	},
	qualityRules: {
		"HSTS-004": {
			"penalty": 2,
			"rationale": "Declared preload intent lacks the required max-age or includeSubDomains directive"
		},
		"HSTS-005": {
			"penalty": 2,
			"rationale": "HSTS preload is not requested despite meeting basic header prerequisites"
		},
		"DOC-001": {
			"penalty": 2,
			"rationale": "Optional Document-Policy feature restrictions are not configured"
		},
		"INTEGRITY-001": {
			"penalty": 3,
			"rationale": "Optional Integrity-Policy enforcement is not configured"
		},
		"INTEGRITY-002": {
			"penalty": 1,
			"rationale": "Integrity-Policy is report-only and not enforcing"
		},
		"CSP-009": {
			"penalty": 4,
			"rationale": "Curated CSP allowlist host heuristic merits manual review"
		},
		"COEP-001": {
			"penalty": 8,
			"rationale": "Optional cross-origin isolation hardening is not enabled"
		},
		"COEP-002": {
			"penalty": 5,
			"rationale": "COEP value is not recognized"
		},
		"CORP-001": {
			"penalty": 5,
			"rationale": "Resource sharing policy is not explicitly declared"
		},
		"CORP-002": {
			"penalty": 4,
			"rationale": "CORP value is not recognized"
		},
		"CORP-003": {
			"penalty": 3,
			"rationale": "Resource policy intentionally permits cross-origin embedding"
		},
		"PERMPOLICY-001": {
			"penalty": 6,
			"rationale": "Sensitive browser features are allowed in all origins"
		},
		"CSP-REPORT-001": {
			"penalty": 3,
			"rationale": "CSP violation reporting is not configured"
		},
		"REPORT-001": {
			"penalty": 2,
			"rationale": "Browser reporting endpoints are not configured"
		},
		"REPORT-002": {
			"penalty": 4,
			"rationale": "NEL references an undeclared Reporting-Endpoints group"
		},
		"REPORT-003": {
			"penalty": 4,
			"rationale": "NEL header is malformed"
		},
		"DUP-001": {
			"penalty": 1,
			"rationale": "Conflicting repeated security header values may be interpreted inconsistently"
		},
		"CSP-010": {
			"penalty": 3,
			"rationale": "CSP policy has no default-src or script-src fallback"
		},
		"DEP-009": {
			"penalty": 1,
			"rationale": "Obsolete HPKP report-only header remains configured"
		},
		"DEP-010": {
			"penalty": 1,
			"rationale": "Legacy non-standard report-only CSP header remains configured"
		},
		"DEP-011": {
			"penalty": 1,
			"rationale": "Legacy non-standard report-only CSP header remains configured"
		},
		"DEP-012": {
			"penalty": 1,
			"rationale": "Legacy Internet Explorer download header remains configured"
		},
		"CSP-META-001": {
			"penalty": 0,
			"rationale": "Meta-tag CSP is informational: documents a real limitation without penalising the security score."
		}
	}
};
var CATEGORY_CAPS = {
	cookie: 25,
	transport: 25,
	header: 55,
	cors: 20
};
/**
* Compute a 0–100 security score from a list of findings.
*
* Improvements:
*  - Findings with severity 'pass' or 'info' do not affect the score.
*  - Deduplicates by ruleId: multiple occurrences of the same rule (e.g. 10 cookies)
*    do not stack multiplicatively (prevents score crash on normal multi-cookie sites).
*  - Enforces category caps so one category doesn't push a site to an F grade.
*  - Accounts for `fromCache`: missing-header penalties on cached responses are discounted
*    since browser caches often omit response headers.
*
* @param findings - All findings produced by the rule engine.
* @param fromCache - Whether the response was served from cache (unverified headers).
* @returns Score result including numeric score, grade, per-rule breakdown,
*          and the version string of the scoring algorithm.
*/
function computeScore(findings, fromCache = false) {
	let score = 100;
	const breakdown = [];
	const findingsByRule = /* @__PURE__ */ new Map();
	for (const finding of findings) {
		if (finding.severity === "pass" || finding.severity === "info") continue;
		const list = findingsByRule.get(finding.ruleId) ?? [];
		list.push(finding);
		findingsByRule.set(finding.ruleId, list);
	}
	const deductionsByCategory = /* @__PURE__ */ new Map();
	for (const [ruleId, ruleFindings] of findingsByRule.entries()) {
		const first = ruleFindings[0];
		if (!first) continue;
		const weightConfig = WEIGHTS.rules[ruleId];
		let basePenalty = weightConfig?.penalty ?? 0;
		if (fromCache && (ruleId.startsWith("CSP-001") || ruleId.startsWith("HSTS-001") || ruleId.startsWith("XFO-001") || ruleId.startsWith("CACHE-001"))) basePenalty = Math.round(basePenalty * .5);
		let appliedPenalty = basePenalty;
		if (ruleFindings.length > 1 && basePenalty > 0) appliedPenalty = Math.min(Math.round(basePenalty * 1.25), basePenalty + 5);
		const category = first.category ?? "header";
		const currentCatDeduction = deductionsByCategory.get(category) ?? 0;
		const catCap = CATEGORY_CAPS[category] ?? 100;
		const allowableDeduction = Math.max(0, Math.min(appliedPenalty, catCap - currentCatDeduction));
		deductionsByCategory.set(category, currentCatDeduction + allowableDeduction);
		score -= allowableDeduction;
		const countSuffix = ruleFindings.length > 1 ? ` (${ruleFindings.length} items affected)` : "";
		const cacheSuffix = fromCache && basePenalty !== (weightConfig?.penalty ?? 0) ? " [cached — unverified]" : "";
		breakdown.push({
			ruleId,
			title: `${first.title}${countSuffix}${cacheSuffix}`,
			severity: first.severity,
			weight: weightConfig?.penalty ?? 0,
			penalty: allowableDeduction
		});
	}
	const clampedScore = Math.max(0, Math.min(100, score));
	const grade = GRADE_THRESHOLDS.find((entry) => clampedScore >= entry.min)?.grade ?? "F";
	const qualityRuleIds = /* @__PURE__ */ new Set();
	for (const finding of findings) if (WEIGHTS.qualityRules[finding.ruleId]) qualityRuleIds.add(finding.ruleId);
	const qualityPenalty = [...qualityRuleIds].reduce((total, ruleId) => total + (WEIGHTS.qualityRules[ruleId]?.penalty ?? 0), 0);
	const qualityScore = Math.max(0, 100 - Math.min(50, qualityPenalty));
	return {
		score: clampedScore,
		grade,
		breakdown,
		qualityScore,
		qualityGrade: GRADE_THRESHOLDS.find((entry) => qualityScore >= entry.min)?.grade ?? "F",
		scoreVersion: SCORE_VERSION
	};
}
//#endregion
//#region src/rules/engine.ts
/**
* Run all security rules against captured hop and cookie data.
*
* Execution order:
*  1. checkHsts         — transport security
*  2. checkCsp          — content security policy (also yields directives map)
*  3. checkXfo          — framing protection (uses CSP directives)
*  4. checkXcto         — MIME-type sniffing
*  5. checkReferrer     — referrer policy
*  6. checkDeprecated   — deprecated headers
*  7. checkInfoLeak     — information leakage
*  8. checkCacheCookie  — cache control on cookie-setting responses
*
* @param input - Captured hops, cookies, and origin.
* @returns Aggregated findings, score, grade, breakdown, and score version.
*/
function runRules(input) {
	const { hops } = input;
	const emptySubdomainTrust = {
		hasEscalationPath: false,
		vectors: []
	};
	if (hops.length === 0) return {
		findings: [],
		score: 100,
		grade: "A",
		qualityScore: 100,
		qualityGrade: "A",
		breakdown: [],
		scoreVersion: "",
		subdomainTrust: emptySubdomainTrust
	};
	const finalHop = hops[hops.length - 1];
	if (finalHop === void 0) return {
		findings: [],
		score: 100,
		grade: "A",
		qualityScore: 100,
		qualityGrade: "A",
		breakdown: [],
		scoreVersion: "",
		subdomainTrust: emptySubdomainTrust
	};
	const findings = [];
	const redirectFindings = detectRedirectDegradation(hops);
	findings.push(...redirectFindings);
	findings.push(...input.captureFindings ?? []);
	findings.push(...checkDuplicateHeaders(finalHop));
	findings.push(...checkHsts(finalHop));
	const { findings: cspFindings, directives } = checkCsp(finalHop, input.metaCspFound);
	findings.push(...cspFindings);
	findings.push(...checkXfo(finalHop, directives));
	findings.push(...checkXcto(finalHop));
	findings.push(...checkReferrer(finalHop));
	findings.push(...checkIsolationHeaders(finalHop));
	findings.push(...checkReportingHeaders(finalHop));
	findings.push(...checkPolicyHardeningHeaders(finalHop));
	findings.push(...checkCors(finalHop));
	findings.push(...checkDeprecated(finalHop));
	findings.push(...checkInfoLeak(finalHop));
	findings.push(...checkCacheCookie(finalHop, input.cookieSettings?.alwaysSensitive, input.cookieSettings?.alwaysIgnore));
	const isHttps = finalHop.url.startsWith("https://");
	findings.push(...checkCookies(input.cookies, isHttps, input.cookieSettings?.alwaysSensitive, input.cookieSettings?.alwaysIgnore));
	const subdomainResult = checkSubdomainTrust(finalHop, input.cookies, input.cookieSettings?.alwaysSensitive, input.cookieSettings?.alwaysIgnore);
	findings.push(...subdomainResult.findings);
	const heuristicRules = /* @__PURE__ */ new Set([
		"LEAK-001",
		"CSP-009",
		"CSP-008",
		"CSP-META-001",
		"SUB-001",
		"SUB-002",
		"SUB-003H",
		"SUB-004",
		"SUB-005",
		"SUB-006",
		"SUB-007",
		"SUB-008"
	]);
	const findingsWithSource = findings.map((finding) => {
		const isHeuristic = heuristicRules.has(finding.ruleId) || finding.title.includes("(name-based heuristic)");
		return {
			...finding,
			sourceUrl: finding.sourceUrl ?? finalHop.url,
			confidence: finding.confidence ?? (isHeuristic ? "heuristic" : "deterministic")
		};
	});
	const { score, grade, qualityScore, qualityGrade, breakdown, scoreVersion } = computeScore(findingsWithSource, finalHop.fromCache);
	return {
		findings: findingsWithSource,
		score,
		grade,
		qualityScore,
		qualityGrade,
		breakdown,
		scoreVersion,
		subdomainTrust: {
			hasEscalationPath: subdomainResult.hasEscalationPath,
			vectors: subdomainResult.vectors
		}
	};
}
function runApiRules(apiHop, cookieSettings) {
	const hopLike = apiHop;
	const findings = [];
	findings.push(...checkCors(hopLike));
	findings.push(...checkXcto(hopLike));
	findings.push(...checkInfoLeak(hopLike));
	findings.push(...checkCacheCookie(hopLike, cookieSettings?.alwaysSensitive, cookieSettings?.alwaysIgnore));
	return findings.map((f) => ({
		...f,
		sourceUrl: apiHop.url,
		confidence: f.confidence ?? (f.ruleId === "LEAK-001" ? "heuristic" : "deterministic")
	}));
}
var REDIRECT_SECURITY_HEADERS = [
	"content-security-policy",
	"strict-transport-security",
	"x-frame-options",
	"x-content-type-options",
	"referrer-policy",
	"permissions-policy",
	"cross-origin-opener-policy",
	"cross-origin-resource-policy",
	"cross-origin-embedder-policy"
];
function safeHopLabel(hop) {
	try {
		const url = new URL(hop.url);
		return `${url.origin}${url.pathname}`;
	} catch {
		return hop.url.slice(0, 160);
	}
}
function detectRedirectDegradation(hops) {
	const findings = [];
	for (let index = 1; index < hops.length; index += 1) {
		const previous = hops[index - 1];
		const current = hops[index];
		if (!previous || !current) continue;
		const removed = REDIRECT_SECURITY_HEADERS.filter((header) => {
			const previousValue = previous.headers[header]?.trim();
			const currentValue = current.headers[header]?.trim();
			return previousValue !== void 0 && previousValue.length > 0 && (currentValue === void 0 || currentValue.length === 0);
		});
		if (removed.length === 0) continue;
		findings.push({
			ruleId: "REDIR-001",
			category: "header",
			severity: "info",
			title: `Redirect response drops ${removed.length} previously present security header(s)`,
			impact: "A protection present on an earlier redirect response is absent from the next response; review whether the destination needs its own policy.",
			evidence: `${safeHopLabel(previous)} -> ${safeHopLabel(current)}: ${removed.join(", ")}`,
			recommendation: "Review the redirect chain and configure the destination response to send the protections required for that origin. Header policies do not automatically carry across responses.",
			reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
			sourceUrl: current.url
		});
	}
	return findings;
}
//#endregion
//#region src/rules/auth-diff.ts
/**
* Checks if a cookie list contains an authentication or session token.
* Requires both a sensitive naming pattern and either the session or httpOnly flag
* to prevent false positives from client-side consent or tracking cookies.
*/
function detectSensitiveAuthCookie(cookies, alwaysSensitive = [], alwaysIgnore = []) {
	for (const c of cookies) {
		const { isSensitive } = isSensitiveCookie(c.name, alwaysSensitive, alwaysIgnore);
		if (isSensitive && (c.session || c.httpOnly)) return c;
	}
	return null;
}
/**
* Computes which findings were added or removed between pre-auth and post-auth states.
*/
function computeFindingChanges(pre, post) {
	const preMap = new Map(pre.map((f) => [f.ruleId, f]));
	const postMap = new Map(post.map((f) => [f.ruleId, f]));
	const changes = [];
	for (const [ruleId, postFinding] of postMap.entries()) if (!preMap.has(ruleId)) changes.push({
		ruleId,
		title: postFinding.title,
		severity: postFinding.severity,
		type: "added"
	});
	for (const [ruleId, preFinding] of preMap.entries()) if (!postMap.has(ruleId)) changes.push({
		ruleId,
		title: preFinding.title,
		severity: preFinding.severity,
		type: "removed"
	});
	return changes;
}
/**
* Evaluates whether an origin transition represents a login event.
* If transitioning from pre-auth (no sensitive session cookie) to post-auth (sensitive session cookie),
* emits an AuthDiffRecord and updates the baseline.
*/
function checkAuthTransition(origin, baseline, currentCookies, currentFindings, currentScore, currentGrade, alwaysSensitive = [], alwaysIgnore = []) {
	const authCookie = detectSensitiveAuthCookie(currentCookies, alwaysSensitive, alwaysIgnore);
	const hasAuthNow = authCookie !== null;
	const currentBaseline = {
		origin,
		cookies: currentCookies,
		findings: currentFindings,
		score: currentScore,
		grade: currentGrade,
		timestamp: Date.now(),
		hasSensitiveCookie: hasAuthNow
	};
	if (!baseline) return {
		isAuthEvent: false,
		record: null,
		newBaseline: currentBaseline
	};
	if (!baseline.hasSensitiveCookie && hasAuthNow) {
		const preScore = baseline.score;
		const postScore = currentScore;
		const scoreDelta = postScore - preScore;
		const changes = computeFindingChanges(baseline.findings, currentFindings);
		return {
			isAuthEvent: true,
			record: {
				origin,
				timestamp: Date.now(),
				triggeredByCookie: authCookie.name,
				preAuthScore: preScore,
				postAuthScore: postScore,
				scoreDelta,
				preAuthGrade: baseline.grade,
				postAuthGrade: currentGrade,
				preAuthFindings: baseline.findings,
				postAuthFindings: currentFindings,
				changes
			},
			newBaseline: currentBaseline
		};
	}
	if (baseline.hasSensitiveCookie && !hasAuthNow) return {
		isAuthEvent: false,
		record: null,
		newBaseline: currentBaseline
	};
	return {
		isAuthEvent: false,
		record: null,
		newBaseline: {
			...baseline,
			cookies: currentCookies,
			findings: currentFindings,
			score: currentScore,
			grade: currentGrade,
			timestamp: Date.now()
		}
	};
}
//#endregion
//#region src/rules/graph-discovery.ts
/**
* Extracts candidate hostnames from a CSP source token.
* Strips scheme (https://), port (:443), and paths (/api).
* Returns null if token is a keyword ('self'), wildcard (*), or scheme-only (https:).
*/
function extractHostnameFromCspToken(token) {
	const trimmed = token.trim().toLowerCase();
	if (!trimmed || trimmed.startsWith("'") || trimmed.endsWith("'")) return null;
	if (trimmed === "*" || trimmed.startsWith("*.") || trimmed.endsWith(":")) return null;
	try {
		if (trimmed.includes("://")) return new URL(trimmed).hostname;
		const withoutPort = (trimmed.split("/")[0] ?? "").split(":")[0] ?? "";
		if (withoutPort.includes(".") && !withoutPort.includes("*")) return withoutPort;
	} catch {
		return null;
	}
	return null;
}
/**
* Scans captured hops and cookies for concrete hostnames belonging to the apex domain.
*/
function discoverNodes(currentHostname, hops, cookies, apiEndpoints) {
	const apex = registrableDomain(currentHostname) ?? currentHostname;
	const discoveredMap = /* @__PURE__ */ new Map();
	discoveredMap.set(currentHostname.toLowerCase(), { via: "navigation" });
	for (const hop of hops) {
		const csp = hop.headers["content-security-policy"] ?? hop.headers["content-security-policy-report-only"];
		if (csp != null && csp.length > 0) {
			const tokens = csp.split(/[\s;]+/);
			for (const token of tokens) {
				const host = extractHostnameFromCspToken(token);
				if (host != null && host.length > 0 && (host === apex || host.endsWith(`.${apex}`))) {
					if (!discoveredMap.has(host)) discoveredMap.set(host, { via: "csp" });
				}
			}
		}
	}
	for (const cookie of cookies) if (cookie.domain != null && cookie.domain.length > 0) {
		const cleanDomain = cookie.domain.replace(/^\./, "").toLowerCase();
		if (cleanDomain.length > 0 && (cleanDomain === apex || cleanDomain.endsWith(`.${apex}`))) {
			if (!discoveredMap.has(cleanDomain)) discoveredMap.set(cleanDomain, { via: "cookie" });
		}
	}
	for (const hop of hops) {
		const acao = hop.headers["access-control-allow-origin"]?.trim();
		if (acao != null && acao.length > 0 && acao !== "*" && acao !== "null") try {
			const host = new URL(acao).hostname.toLowerCase();
			let hopHost;
			try {
				hopHost = new URL(hop.url).hostname.toLowerCase();
			} catch {}
			if (host === apex || host.endsWith(`.${apex}`)) {
				if (!discoveredMap.has(host)) discoveredMap.set(host, {
					via: "cors",
					sourceHost: hopHost
				});
			}
		} catch {}
	}
	if (apiEndpoints != null) for (const endpoint of apiEndpoints.values()) {
		const hop = endpoint.lastHop;
		try {
			const host = new URL(hop.url).hostname.toLowerCase();
			if (host === apex || host.endsWith(`.${apex}`)) {
				if (!discoveredMap.has(host)) discoveredMap.set(host, { via: "api" });
			}
		} catch {}
		const acao = hop.headers["access-control-allow-origin"]?.trim();
		if (acao != null && acao.length > 0 && acao !== "*" && acao !== "null") try {
			const host = new URL(acao).hostname.toLowerCase();
			let hopHost;
			try {
				hopHost = new URL(hop.url).hostname.toLowerCase();
			} catch {}
			if (host === apex || host.endsWith(`.${apex}`)) {
				if (!discoveredMap.has(host)) discoveredMap.set(host, {
					via: "cors",
					sourceHost: hopHost
				});
			}
		} catch {}
	}
	return Array.from(discoveredMap.entries()).map(([hostname, info]) => ({
		hostname,
		discoveredVia: info.via,
		sourceHost: info.sourceHost
	}));
}
/**
* Merges freshly discovered nodes and current score/grade into an accumulated AttackSurfaceGraph.
*/
function mergeIntoGraph(existingGraph, currentHostname, score, grade, discovered, isPro = false) {
	const apex = registrableDomain(currentHostname) ?? currentHostname;
	const now = Date.now();
	const nodeMap = /* @__PURE__ */ new Map();
	nodeMap.set(apex, {
		hostname: apex,
		isApex: true,
		lastSeen: now,
		discoveredVia: ["navigation"]
	});
	if (existingGraph && existingGraph.apexDomain === apex) for (const n of existingGraph.nodes) nodeMap.set(n.hostname, { ...n });
	const currentNode = nodeMap.get(currentHostname) ?? {
		hostname: currentHostname,
		isApex: currentHostname === apex,
		lastSeen: now,
		discoveredVia: ["navigation"]
	};
	currentNode.score = score;
	currentNode.grade = grade;
	currentNode.lastSeen = now;
	if (!currentNode.discoveredVia.includes("navigation")) currentNode.discoveredVia.push("navigation");
	nodeMap.set(currentHostname, currentNode);
	for (const d of discovered) {
		const host = d.hostname.toLowerCase();
		if (host !== apex && !host.endsWith(`.${apex}`)) continue;
		const existing = nodeMap.get(host);
		if (existing !== void 0) {
			existing.lastSeen = now;
			if (!existing.discoveredVia.includes(d.discoveredVia)) existing.discoveredVia.push(d.discoveredVia);
		} else nodeMap.set(host, {
			hostname: host,
			isApex: host === apex,
			lastSeen: now,
			discoveredVia: [d.discoveredVia]
		});
	}
	const MAX_GRAPH_NODES = 100;
	if (nodeMap.size > MAX_GRAPH_NODES) {
		const allNodes = Array.from(nodeMap.values());
		const essentialNodes = allNodes.filter((n) => n.isApex || n.hostname === currentHostname);
		const nonEssentialNodes = allNodes.filter((n) => !n.isApex && n.hostname !== currentHostname).sort((a, b) => b.lastSeen - a.lastSeen);
		const retained = [...essentialNodes, ...nonEssentialNodes.slice(0, MAX_GRAPH_NODES - essentialNodes.length)];
		nodeMap.clear();
		for (const n of retained) nodeMap.set(n.hostname, n);
	}
	const edges = [];
	const edgeSet = /* @__PURE__ */ new Set();
	for (const d of discovered) if (d.discoveredVia === "cors" && d.sourceHost !== void 0 && d.sourceHost.length > 0 && d.sourceHost !== d.hostname) {
		const source = d.sourceHost.toLowerCase();
		const target = d.hostname.toLowerCase();
		const edgeKey = `${source}->${target}:cors-observed`;
		if (!edgeSet.has(edgeKey)) {
			edgeSet.add(edgeKey);
			edges.push({
				source,
				target,
				type: "cors",
				severity: "medium",
				provenance: "observed"
			});
		}
	}
	for (const node of nodeMap.values()) {
		if (node.hostname === apex) continue;
		for (const via of node.discoveredVia) {
			const edgeKey = `${node.hostname}->${apex}:${via}`;
			if (!edgeSet.has(edgeKey)) {
				edgeSet.add(edgeKey);
				let severity = "low";
				let edgeType = "csp";
				if (via === "cookie") {
					edgeType = "cookie";
					severity = "high";
				} else if (via === "cors") {
					edgeType = "cors";
					severity = "medium";
				} else if (via === "csp") {
					edgeType = "csp";
					severity = "medium";
				} else if (via === "api") {
					edgeType = "cors";
					severity = "low";
				}
				edges.push({
					source: node.hostname,
					target: apex,
					type: edgeType,
					severity,
					provenance: "inferred"
				});
			}
		}
	}
	return {
		apexDomain: apex,
		nodes: Array.from(nodeMap.values()),
		edges,
		isPro,
		lastUpdated: now
	};
}
//#endregion
//#region src/background/index.ts
/**
* index.ts
*
* Main service-worker entry point for the Header & Cookie Security Checker
* extension.  Wires together:
*
*   • lifecycle    — keepalive alarms + session-storage hydration
*   • capture      — WebRequest listeners (two-stage header snapshotting)
*   • correlate    — Set-Cookie ↔ chrome.cookies reconciliation
*   • rules engine — scoring, findings, grade computation
*   • port registry— live push to popup / sidepanel
*   • badge        — per-tab grade display
*
* All side-effects are confined to listener callbacks; no top-level async
* work is performed so the module is safe to import during SW startup.
*/
var portRegistry = new PortRegistry();
var pendingServiceWorkerReports = /* @__PURE__ */ new Map();
var pendingMetaCspReports = /* @__PURE__ */ new Set();
var currentSettings = DEFAULT_SETTINGS;
SettingsService.getSettings().then((s) => {
	currentSettings = s;
}).catch(() => {});
SettingsService.onSettingsChanged((s) => {
	currentSettings = s;
});
function recomputeTabState(tabId, state) {
	const result = runRules({
		hops: state.hops,
		cookies: state.cookies,
		origin: state.origin,
		metaCspFound: state.coverage.metaCspFound,
		captureFindings: state.captureFindings ?? [],
		cookieSettings: {
			alwaysSensitive: currentSettings.sensitiveCookieNames ?? currentSettings.alwaysSensitiveCookies ?? [],
			alwaysIgnore: currentSettings.ignoredCookieNames ?? currentSettings.alwaysIgnoreCookies ?? []
		}
	});
	state.findings = result.findings;
	state.score = result.score;
	state.grade = result.grade;
	state.qualityScore = result.qualityScore;
	state.qualityGrade = result.qualityGrade;
	state.scoreBreakdown = result.breakdown;
	state.scoreVersion = result.scoreVersion;
	state.subdomainTrust = result.subdomainTrust;
	state.coverage.blindSpots = computeBlindSpots(state.coverage);
	state.updatedAt = Date.now();
	tabStates.set(tabId, state);
	SessionStorage.setTabState(state);
	if (state.monitoredByUser && state.origin) {
		LocalStorage.recordOriginHistory(state.origin, {
			timestamp: state.updatedAt,
			score: state.score,
			grade: state.grade
		});
		const baseline = originAuthBaselines.get(state.origin);
		const { isAuthEvent, record, newBaseline } = checkAuthTransition(state.origin, baseline, state.cookies, state.findings, state.score, state.grade, currentSettings.alwaysSensitiveCookies, currentSettings.alwaysIgnoreCookies);
		originAuthBaselines.set(state.origin, newBaseline);
		SessionStorage.setAuthBaseline(state.origin, newBaseline);
		if (isAuthEvent && record !== null) LocalStorage.recordAuthDiff(state.origin, record);
		(async () => {
			try {
				const hostname = new URL(state.origin).hostname;
				const apex = registrableDomain(hostname) ?? hostname;
				const discovered = discoverNodes(hostname, state.hops, state.cookies, state.apiEndpoints);
				const updatedGraph = mergeIntoGraph(await LocalStorage.getGraph(apex), hostname, state.score, state.grade, discovered, Boolean(currentSettings.isPro));
				await LocalStorage.saveGraph(updatedGraph);
			} catch {}
		})();
	}
	setBadgeForTab(tabId, state.grade);
	portRegistry.broadcast(tabId, {
		type: "TAB_STATE_UPDATE",
		state
	});
}
/**
* Returns true when the URL belongs to a restricted scheme (chrome://, etc.)
* that the extension cannot inspect.
*/
function isRestrictedUrl(url) {
	return RESTRICTED_SCHEMES.some((scheme) => url.startsWith(scheme));
}
/**
* Updates the action badge text and background colour for the given tab.
* Silently swallows errors (e.g. tab already closed).
*/
function setBadgeForTab(tabId, grade) {
	if (!Number.isInteger(tabId) || tabId < 0) return;
	const color = BADGE_COLORS[grade];
	const text = grade === "?" ? "?" : grade;
	chrome.action.setBadgeText({
		text,
		tabId
	}).catch(() => void 0);
	chrome.action.setBadgeBackgroundColor({
		color,
		tabId
	}).catch(() => void 0);
}
function computeBlindSpots(coverage) {
	const spots = [];
	if (coverage.isRestricted) spots.push("Restricted URL: browser security policy blocks inspection of internal browser pages.");
	if (coverage.hasCache) spots.push("Cached response: headers reflect browser cache; live server headers may have evolved.");
	if (coverage.hasServiceWorker) spots.push("Active Service Worker: responses may be generated or modified client-side without reaching origin server.");
	if (coverage.hopsExpected > coverage.hopsCaptured) spots.push(`${coverage.hopsExpected - coverage.hopsCaptured} intermediate redirect hop(s) were missed during capture.`);
	return spots;
}
function pushLedgerEntry(state, entry) {
	const ledger = state.coverage.ledger ?? (state.coverage.ledger = []);
	ledger.push(entry);
	if (ledger.length > 50) state.coverage.ledger = ledger.slice(-50);
}
function createDefaultTabState(tabId, url) {
	const origin = originFromUrl(url) ?? url;
	const serviceWorkerReport = pendingServiceWorkerReports.get(tabId);
	return {
		tabId,
		origin,
		url,
		hops: [],
		cookies: [],
		findings: [],
		captureFindings: [],
		grade: "F",
		score: 0,
		qualityScore: 100,
		qualityGrade: "A",
		scoreVersion: "",
		scoreBreakdown: [],
		coverage: {
			hopsExpected: 1,
			hopsCaptured: 0,
			hasCache: false,
			hasServiceWorker: serviceWorkerReport?.status === "controlled",
			serviceWorkerStatus: serviceWorkerReport?.status ?? "unknown",
			serviceWorkerUrl: serviceWorkerReport?.serviceWorkerUrl ?? null,
			isRestricted: isRestrictedUrl(url),
			metaCspFound: pendingMetaCspReports.has(tabId),
			ledger: [],
			blindSpots: []
		},
		subdomainTrust: {
			hasEscalationPath: false,
			vectors: []
		},
		monitoredByUser: false,
		updatedAt: Date.now()
	};
}
/**
* Invoked by capture.ts after both WebRequest stages have completed for a
* given request.  Runs the full analysis pipeline and pushes updates to all
* connected ports.
*/
async function onHopComplete(tabId, hop) {
	if (!Number.isInteger(tabId) || tabId < 0) return;
	const state = tabStates.get(tabId) ?? createDefaultTabState(tabId, hop.url);
	state.url = hop.url;
	state.origin = originFromUrl(hop.url) ?? hop.url;
	if (isRestrictedUrl(hop.url)) {
		state.coverage.isRestricted = true;
		tabStates.set(tabId, state);
		setBadgeForTab(tabId, "?");
		return;
	}
	const origin = state.origin;
	if (!origin || origin === hop.url) return;
	if (!await PermissionsService.hasPermissionForOrigin(origin)) {
		state.coverage.isRestricted = false;
		setBadgeForTab(tabId, "?");
		return;
	}
	state.coverage.metaCspFound ||= pendingMetaCspReports.has(tabId);
	state.monitoredByUser = true;
	state.hops = [...state.hops, hop].sort((left, right) => left.timestamp - right.timestamp);
	const minExpectedHops = hop.status >= 300 && hop.status < 400 ? state.hops.length + 1 : state.hops.length;
	state.coverage.hopsExpected = Math.max(state.coverage.hopsExpected, minExpectedHops);
	state.coverage.hopsCaptured = state.hops.length;
	state.coverage.hasCache = state.coverage.hasCache || hop.fromCache;
	const ledgerSource = hop.fromCache ? "cache" : hop.isHstsUpgrade ? "hsts-upgrade" : "network";
	pushLedgerEntry(state, {
		type: hop.isHstsUpgrade ? "redirect" : "navigation",
		url: hop.url,
		source: ledgerSource,
		status: hop.status,
		timestamp: hop.timestamp,
		notes: hop.headersDiffer ? "Headers modified by extension" : void 0
	});
	const setCookieValues = extractSetCookieHeaders(hop.rawHeaders);
	const correlation = await correlateCookies(tabId, hop.url, setCookieValues);
	state.cookies = correlation.records;
	state.captureFindings = [...new Map([...state.captureFindings ?? [], ...correlation.findings].map((finding) => [`${finding.ruleId}:${finding.sourceUrl ?? ""}:${finding.evidence}`, finding])).values()];
	recomputeTabState(tabId, state);
}
/**
* Clears stale analysis state when the user navigates away from a page.
* Runs before the network request for the new page fires so there is no
* flash of old data.
*/
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
	if (details.frameId !== 0) return;
	const { tabId } = details;
	pendingServiceWorkerReports.delete(tabId);
	pendingMetaCspReports.delete(tabId);
	tabStates.delete(tabId);
	SessionStorage.removeTabState(tabId).catch(() => void 0);
	for (const [requestId, partial] of captureMap.entries()) if (partial.tabId === tabId) captureMap.delete(requestId);
	setBadgeForTab(tabId, "?");
});
registerPageSignalInjection();
chrome.sidePanel?.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => void 0);
/**
* Handles live cookie mutations (including JS-set cookies).
* Re-correlates and re-scores every tab whose origin matches the affected
* cookie domain.
*/
chrome.cookies.onChanged.addListener((changeInfo) => {
	if (changeInfo.removed) return;
	const affectedDomain = changeInfo.cookie.domain.replace(/^\./, "");
	for (const [tabId, state] of tabStates.entries()) {
		if (!(() => {
			try {
				return new URL(state.url).hostname;
			} catch {
				return "";
			}
		})().endsWith(affectedDomain)) continue;
		(async () => {
			try {
				const correlation = await correlateCookies(tabId, state.url, []);
				state.cookies = correlation.records;
				recomputeTabState(tabId, state);
			} catch {}
		})();
	}
});
chrome.tabs.onRemoved.addListener((tabId) => {
	tabStates.delete(tabId);
	pendingMetaCspReports.delete(tabId);
	SessionStorage.removeTabState(tabId).catch(() => void 0);
});
chrome.runtime.onConnect.addListener((port) => {
	const isPopup = port.name === POPUP_PORT_NAME;
	const isSidePanel = port.name === SIDEPANEL_PORT_NAME;
	if (!isPopup && !isSidePanel) return;
	const senderTabId = port.sender?.tab?.id;
	if (senderTabId !== void 0) {
		portRegistry.register(port, senderTabId);
		const current = tabStates.get(senderTabId);
		if (current) portSend(port, {
			type: "STATE_RESPONSE",
			state: current
		});
	}
	port.onMessage.addListener((msg) => {
		if (msg.type === "REQUEST_STATE") {
			const resolvedTabId = msg.tabId ?? senderTabId;
			if (resolvedTabId === void 0) return;
			portRegistry.register(port, resolvedTabId);
			const response = {
				type: "STATE_RESPONSE",
				state: tabStates.get(resolvedTabId) ?? null
			};
			portSend(port, response);
		}
	});
});
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
	if (message.type === "REQUEST_STATE") {
		sendResponse({
			type: "STATE_RESPONSE",
			state: message.tabId !== void 0 ? tabStates.get(message.tabId) ?? null : null
		});
		return false;
	}
	if (message.type === "PERMISSIONS_CHANGED") {
		(async () => {
			try {
				if (!message.granted && message.origins.length > 0) await reconcilePermissionsOnRemoved(message.origins, {
					tabStates,
					pendingServiceWorkerReports,
					pendingMetaCspReports,
					setBadge: (t, text) => {
						if (text === "") chrome.action?.setBadgeText({
							tabId: t,
							text: ""
						})?.catch?.(() => void 0);
						else setBadgeForTab(t, text);
					},
					broadcast: (t, msg) => portRegistry.broadcast(t, msg)
				});
				const settingsMsg = {
					type: "SETTINGS_CHANGED",
					settings: await LocalStorage.getSettings()
				};
				portRegistry.broadcastAll(settingsMsg);
			} catch {}
		})();
		return false;
	}
	if (message.type === "SETTINGS_CHANGED") {
		currentSettings = message.settings;
		portRegistry.broadcastAll(message);
		sendResponse(message);
		return false;
	}
	if (message.type === "SERVICE_WORKER_STATUS") {
		const senderTabId = _sender.tab?.id;
		if (senderTabId !== void 0) {
			const report = {
				status: message.status,
				serviceWorkerUrl: message.serviceWorkerUrl
			};
			pendingServiceWorkerReports.set(senderTabId, report);
			const state = tabStates.get(senderTabId);
			if (state) {
				state.coverage.serviceWorkerStatus = report.status;
				state.coverage.serviceWorkerUrl = report.serviceWorkerUrl;
				state.coverage.hasServiceWorker = report.status === "controlled";
				if (report.status === "controlled") pushLedgerEntry(state, {
					type: "service-worker",
					url: report.serviceWorkerUrl ?? state.url,
					source: "service-worker",
					timestamp: Date.now(),
					notes: "Page is controlled by active service worker"
				});
				recomputeTabState(senderTabId, state);
			}
		}
		return false;
	}
	if (message.type === "META_CSP_FOUND") {
		const senderTabId = _sender.tab?.id;
		if (senderTabId !== void 0) {
			pendingMetaCspReports.add(senderTabId);
			const state = tabStates.get(senderTabId);
			if (state) {
				state.coverage.metaCspFound = true;
				if (message.policies !== void 0 && message.policies.length > 0) {
					state.coverage.metaCspPolicies = message.policies.slice(0, 5).map((p) => p.slice(0, 2048));
					pushLedgerEntry(state, {
						type: "subresource",
						url: state.url,
						source: "dom",
						timestamp: Date.now(),
						notes: `${message.policies.length} <meta> CSP tag(s) detected in DOM`
					});
					if (!(state.hops.at(-1)?.headers["content-security-policy"] !== void 0)) {
						if (!(state.captureFindings ?? []).some((f) => f.ruleId === "CSP-META-001")) (state.captureFindings ?? (state.captureFindings = [])).push({
							ruleId: "CSP-META-001",
							category: "header",
							severity: "info",
							title: "CSP delivered via <meta> tag, not HTTP header",
							impact: "Meta-tag CSP cannot restrict navigation, workers, or plugin content. HTTP header CSP provides broader enforcement.",
							evidence: `${message.policies.length} meta-CSP policy/policies found`,
							recommendation: "Prefer Content-Security-Policy HTTP response header; keep the meta tag as a fallback only.",
							reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy#meta"
						});
					}
				}
				recomputeTabState(senderTabId, state);
			}
		}
		return false;
	}
	if (message.type === "SRI_SCAN") {
		const senderTabId = _sender.tab?.id;
		const state = senderTabId === void 0 ? void 0 : tabStates.get(senderTabId);
		if (senderTabId !== void 0 && state) {
			state.captureFindings = (state.captureFindings ?? []).filter((finding) => finding.ruleId !== "SRI-001");
			const missingScripts = message.missingIntegrity ?? 0;
			const missingStyles = message.missingStyleIntegrity ?? 0;
			const totalMissing = missingScripts + missingStyles;
			if (totalMissing > 0) {
				const parts = [];
				if (missingScripts > 0) parts.push(`${missingScripts}/${message.externalScripts ?? 0} script(s)`);
				if (missingStyles > 0) parts.push(`${missingStyles}/${message.externalStylesheets ?? 0} stylesheet(s)`);
				state.captureFindings.push({
					ruleId: "SRI-001",
					category: "header",
					severity: "medium",
					title: `${totalMissing} external resource(s) lack Subresource Integrity`,
					impact: "A compromised or modified third-party script or stylesheet may run with the privileges of this page.",
					evidence: `Missing integrity attribute on: ${parts.join(", ")}`,
					recommendation: "Add integrity hashes and crossorigin=\"anonymous\" to external scripts and stylesheets, or self-host resources whose content you control.",
					reference: "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"
				});
			}
			recomputeTabState(senderTabId, state);
		}
		return false;
	}
	if (message.type === "REQUEST_GRAPH") {
		(async () => {
			try {
				const apex = message.apexDomain;
				const graph = await LocalStorage.getGraph(apex);
				const isPro = Boolean(currentSettings.isPro);
				if (!graph) {
					sendResponse({
						type: "GRAPH_RESPONSE",
						graph: {
							apexDomain: apex,
							nodes: [{
								hostname: apex,
								isApex: true,
								lastSeen: Date.now(),
								discoveredVia: ["navigation"]
							}],
							edges: [],
							isPro,
							lastUpdated: Date.now()
						}
					});
					return;
				}
				if (!isPro) {
					let tabHost = "";
					if (message.tabId !== void 0) {
						const tabState = tabStates.get(message.tabId);
						tabHost = tabState ? originFromUrl(tabState.url) !== null ? new URL(tabState.origin).hostname : "" : "";
					}
					const filteredNodes = graph.nodes.filter((n) => n.isApex || tabHost.length > 0 && n.hostname === tabHost);
					const nodeHosts = new Set(filteredNodes.map((n) => n.hostname));
					const filteredEdges = graph.edges.filter((e) => nodeHosts.has(e.source) && nodeHosts.has(e.target));
					sendResponse({
						type: "GRAPH_RESPONSE",
						graph: {
							...graph,
							nodes: filteredNodes,
							edges: filteredEdges,
							isPro: false
						}
					});
					return;
				}
				sendResponse({
					type: "GRAPH_RESPONSE",
					graph: {
						...graph,
						isPro
					}
				});
			} catch {}
		})();
		return true;
	}
	if (message.type === "GENERATE_POC") {
		const state = tabStates.get(message.tabId);
		if (!state || !state.monitoredByUser) {
			sendResponse({
				type: "GENERATE_POC_RESPONSE",
				success: false,
				error: "Site must be monitored before generating verification sandbox."
			});
			return false;
		}
		const pocUrl = chrome.runtime.getURL("src/sandbox/poc.html") + `?target=${encodeURIComponent(state.url)}&type=${encodeURIComponent(message.pocType)}`;
		chrome.tabs.create({ url: pocUrl }).then(() => {
			sendResponse({
				type: "GENERATE_POC_RESPONSE",
				success: true,
				url: pocUrl
			});
		}).catch((err) => {
			sendResponse({
				type: "GENERATE_POC_RESPONSE",
				success: false,
				error: err.message
			});
		});
		return true;
	}
	return false;
});
chrome.storage.local.onChanged.addListener((changes) => {
	if (changes.settings?.newValue !== void 0) currentSettings = {
		...DEFAULT_SETTINGS,
		...changes.settings.newValue
	};
});
initLifecycle();
registerCaptureListeners((tabId, hop) => {
	onHopComplete(tabId, hop);
}, (apiHop) => {
	const state = tabStates.get(apiHop.tabId);
	if (!state) return;
	const targetOrigin = originFromUrl(apiHop.url);
	const isFirstParty = state.origin === targetOrigin;
	apiHop.isThirdParty = !isFirstParty;
	const findings = runApiRules(apiHop, {
		alwaysSensitive: currentSettings.sensitiveCookieNames ?? currentSettings.alwaysSensitiveCookies ?? [],
		alwaysIgnore: currentSettings.ignoredCookieNames ?? currentSettings.alwaysIgnoreCookies ?? []
	});
	if (!state.apiEndpoints) state.apiEndpoints = /* @__PURE__ */ new Map();
	const endpointState = {
		normalizedPath: apiHop.normalizedPath,
		lastHop: apiHop,
		findings,
		isFirstParty
	};
	state.apiEndpoints.set(apiHop.normalizedPath, endpointState);
	if (state.apiEndpoints.size > 50) {
		const firstKey = state.apiEndpoints.keys().next().value;
		if (firstKey !== void 0) state.apiEndpoints.delete(firstKey);
	}
	pushLedgerEntry(state, {
		type: "api",
		url: apiHop.url,
		source: apiHop.fromCache === true ? "cache" : "network",
		status: apiHop.status,
		timestamp: apiHop.timestamp ?? Date.now(),
		notes: `${apiHop.method} ${apiHop.isThirdParty === true ? "(third-party)" : "(first-party)"}`
	});
	state.updatedAt = Date.now();
	SessionStorage.setTabState(state);
	(async () => {
		try {
			const hostname = new URL(state.origin).hostname;
			const apex = registrableDomain(hostname) ?? hostname;
			const discovered = discoverNodes(hostname, state.hops, state.cookies, state.apiEndpoints);
			const updatedGraph = mergeIntoGraph(await LocalStorage.getGraph(apex), hostname, state.score, state.grade, discovered, Boolean(currentSettings.isPro));
			await LocalStorage.saveGraph(updatedGraph);
		} catch {}
	})();
	portRegistry.broadcast(apiHop.tabId, {
		type: "TAB_STATE_UPDATE",
		state
	});
});
hydrateFromSession().then(async () => {
	await reconcilePermissionsOnStartup({
		tabStates,
		pendingServiceWorkerReports,
		pendingMetaCspReports,
		setBadge: (t, text) => {
			if (text === "") chrome.action?.setBadgeText({
				tabId: t,
				text: ""
			})?.catch?.(() => void 0);
			else setBadgeForTab(t, text);
		},
		broadcast: (t, msg) => portRegistry.broadcast(t, msg)
	});
});
if (typeof chrome !== "undefined" && typeof chrome.permissions !== "undefined" && typeof chrome.permissions.onRemoved !== "undefined") chrome.permissions.onRemoved.addListener((removed) => {
	const origins = removed.origins ?? [];
	reconcilePermissionsOnRemoved(origins, {
		tabStates,
		pendingServiceWorkerReports,
		pendingMetaCspReports,
		setBadge: (t, text) => {
			if (text === "") chrome.action?.setBadgeText({
				tabId: t,
				text: ""
			})?.catch?.(() => void 0);
			else setBadgeForTab(t, text);
		},
		broadcast: (t, msg) => portRegistry.broadcast(t, msg)
	});
});
//#endregion

//# sourceMappingURL=index.ts-NWe8Qpy8.js.map