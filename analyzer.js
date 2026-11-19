// Phishing URL heuristics. Pure functions (no DOM), shared by the web page and the tests.
// A high score means "looks like phishing", not proof. A low score is not a guarantee of safety.

/** Brands commonly impersonated, with the domain names they really use. */
export const BRANDS = {
  microsoft: ["microsoft", "microsoftonline", "live", "office", "office365", "outlook", "windows", "azure", "bing"],
  outlook: ["outlook", "live", "microsoft", "office"],
  office365: ["office365", "office", "microsoft"],
  google: ["google", "gmail", "youtube", "googleusercontent", "gstatic"],
  gmail: ["gmail", "google"],
  apple: ["apple", "icloud"],
  icloud: ["icloud", "apple"],
  amazon: ["amazon", "amazonaws"],
  paypal: ["paypal"],
  netflix: ["netflix"],
  facebook: ["facebook", "fb", "meta"],
  instagram: ["instagram"],
  whatsapp: ["whatsapp"],
  linkedin: ["linkedin"],
  dropbox: ["dropbox"],
  docusign: ["docusign"],
  // South African brands often used in local phishing
  absa: ["absa"],
  fnb: ["fnb"],
  capitec: ["capitecbank", "capitec"],
  standardbank: ["standardbank"],
  nedbank: ["nedbank"],
  sars: ["sars"],
  dhl: ["dhl"],
};

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
  "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "t.ly", "lnkd.in",
]);

/** Top-level domains that are cheap, abused often, or confusing (e.g. .zip looks like a file). */
const RISKY_TLDS = new Set([
  "zip", "mov", "xyz", "top", "click", "tk", "ml", "ga", "cf", "gq", "work", "support",
  "rest", "cam", "icu", "monster", "buzz", "country", "loan", "win", "bid", "live", "online", "site",
]);

/** Two-part public suffixes, so "bank.co.za" is treated as the registered domain, not "co.za". */
const MULTI_PART_SUFFIXES = new Set([
  "co.za", "org.za", "gov.za", "ac.za", "net.za", "co.uk", "org.uk", "ac.uk", "gov.uk",
  "com.au", "net.au", "org.au", "com.br", "co.in", "co.nz", "co.jp", "com.ng", "co.ke",
]);

const LURE_WORDS = [
  "login", "log-in", "signin", "sign-in", "verify", "verification", "update", "secure", "account",
  "password", "banking", "confirm", "wallet", "unlock", "suspended", "invoice", "payment", "reset",
];

const RISKY_EXTENSIONS = /\.(exe|scr|bat|cmd|msi|js|vbs|jar|apk|iso|img|zip|rar|7z|html?)$/i;

const SHORT_BRAND_MIN = 5; // brands shorter than this must match a whole word, to avoid false hits

// ---------- helpers ----------

export function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return dp[a.length][b.length];
}

/** Undo common character swaps attackers use: paypa1 → paypal, rnicrosoft → microsoft. */
export function normalizeHomoglyphs(s) {
  return s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/1/g, "l")
    .replace(/3/g, "e").replace(/5/g, "s").replace(/@/g, "a").replace(/\$/g, "s");
}

export function isIPv4(host) {
  const parts = host.split(".");
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

/** "login.secure.paypal.com.evil.xyz" → "evil.xyz"; "www.fnb.co.za" → "fnb.co.za". */
export function registeredDomain(host) {
  const labels = host.split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  return (MULTI_PART_SUFFIXES.has(lastTwo) ? labels.slice(-3) : labels.slice(-2)).join(".");
}

/** The name part of the registered domain: "fnb.co.za" → "fnb", "paypal.com" → "paypal". */
function secondLevel(regDomain) {
  return regDomain.split(".")[0] ?? "";
}

// ---------- main ----------

/**
 * Analyses one URL.
 * @returns {{ ok: true, url: string, host: string, registeredDomain: string, score: number,
 *            level: "Low"|"Medium"|"High", findings: {id: string, points: number, title: string, detail: string}[] }
 *          | { ok: false, error: string }}
 */
export function analyzeUrl(input) {
  const raw = String(input ?? "").trim();
  if (!raw) return { ok: false, error: "Paste a link to analyse." };
  if (raw.length > 2048) return { ok: false, error: "That link is too long to analyse (over 2,048 characters)." };

  const findings = [];
  const add = (id, points, title, detail) => findings.push({ id, points, title, detail });

  if (/^(javascript|data|vbscript):/i.test(raw)) {
    add("script-scheme", 60, "Runs code instead of opening a page",
      "Links starting with javascript:, data: or vbscript: can run code or show a fake page straight from the link.");
    return finish(raw, "", "", findings);
  }

  let url;
  const hadScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
  try {
    url = new URL(hadScheme ? raw : `http://${raw}`);
  } catch {
    return { ok: false, error: "That doesn't look like a valid web address." };
  }
  if (!["http:", "https:"].includes(url.protocol)) {
    return { ok: false, error: `Only http and https links can be analysed (got ${url.protocol}).` };
  }

  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  const reg = registeredDomain(host);
  const sld = secondLevel(reg);
  const labels = host.split(".");
  const tld = labels[labels.length - 1] ?? "";
  const tokens = host.split(/[.-]/).filter(Boolean);

  // Connection and address
  if (url.protocol === "http:") {
    add("no-https", 10, "Not encrypted (http)",
      "Anything you type on this page, like passwords, is sent without encryption. Real login pages use https.");
  }
  if (isIPv4(host) || host.startsWith("[")) {
    add("ip-host", 25, "Uses a raw IP address instead of a name",
      `The link goes to ${host}. Real companies use their domain name, not a bare IP address.`);
  }
  if (url.username || url.password) {
    add("userinfo", 30, "Hides the real destination with an @",
      `Browsers ignore everything before the @. "${url.username}" is decoration; the real site is ${host}.`);
  }
  if (url.port && !["80", "443"].includes(url.port)) {
    add("odd-port", 10, `Unusual port (${url.port})`,
      "Normal websites don't need a port number in the link. Phishing kits often run on unusual ports.");
  }

  // Domain tricks
  if (labels.some((l) => l.startsWith("xn--"))) {
    add("punycode", 30, "Uses look-alike international characters",
      "Part of the domain is encoded (xn--). This is used to swap letters for look-alikes, e.g. a Cyrillic 'а' for 'a'.");
  }
  if (SHORTENERS.has(host)) {
    add("shortener", 15, "Link shortener hides the destination",
      `${host} redirects somewhere else, and you can't see where until you click. Expand it with a preview service first.`);
  }
  if (RISKY_TLDS.has(tld)) {
    add("risky-tld", 15, `Domain ending often used for abuse (.${tld})`,
      `.${tld} domains are cheap and appear often in phishing. That's not proof, but it's worth extra care.`);
  }
  if (labels.length >= 5) {
    add("deep-subdomains", 10, "Lots of subdomains",
      `${labels.length} levels deep. Attackers stack words like "secure.login.bank" in front of their own domain.`);
  }
  if ((host.match(/-/g) ?? []).length >= 3) {
    add("many-hyphens", 10, "Many hyphens in the domain",
      "Domains like secure-account-verify-login are a common phishing pattern.");
  }

  // Brand impersonation
  const official = (brand) => (BRANDS[brand] ?? []).includes(sld);
  const brandMentioned = Object.keys(BRANDS).filter((b) =>
    b.length < SHORT_BRAND_MIN ? tokens.includes(b) : tokens.some((t) => t.includes(b)));
  const impersonated = brandMentioned.filter((b) => !official(b));
  if (impersonated.length && !isIPv4(host)) {
    const b = impersonated[0];
    add("brand-impersonation", 30, `Mentions ${b} but isn't ${b}'s website`,
      `The real site behind this link is ${reg}, which isn't owned by ${b}. The brand name is only there to look trustworthy.`);
  }

  const lookalike = sld.split("-").map((t) => {
    if (!t || Object.values(BRANDS).some((d) => d.includes(t))) return null;
    const norm = normalizeHomoglyphs(t);
    const exact = Object.keys(BRANDS).find((b) => norm === b);
    if (exact) return { token: t, brand: exact };
    const near = Object.keys(BRANDS).find((b) => b.length >= 6 && levenshtein(t, b) === 1);
    return near ? { token: t, brand: near } : null;
  }).find(Boolean);
  if (lookalike && !findings.some((f) => f.id === "brand-impersonation")) {
    add("lookalike", 35, `"${lookalike.token}" looks like "${lookalike.brand}"`,
      `The domain is spelled to look like ${lookalike.brand} at a glance (swapped or extra letters).`);
  } else if (lookalike) {
    add("lookalike", 20, `"${lookalike.token}" also looks like "${lookalike.brand}"`,
      "The domain is spelled to resemble a known brand.");
  }

  // Path and query
  const pathAndQuery = decodeSafe(url.pathname + url.search).toLowerCase();
  const lures = LURE_WORDS.filter((w) => pathAndQuery.includes(w) || host.includes(w));
  if (lures.length) {
    add("lure-words", Math.min(15, 5 * lures.length), "Pressure words in the link",
      `Contains: ${lures.slice(0, 5).join(", ")}. Phishing links often push you to "verify" or "update" an account.`);
  }
  if (/(https?:\/\/|https?%3a%2f%2f)/i.test(url.search) || url.pathname.includes("//")) {
    add("redirect", 10, "Contains another link inside it",
      "A second web address is embedded in the link, which is often used to bounce you to a different site.");
  }
  if (RISKY_EXTENSIONS.test(url.pathname)) {
    add("download", 20, "Downloads a file",
      `The link points straight to a file (${url.pathname.split("/").pop()}). Don't open files from unexpected messages.`);
  }
  if (raw.length > 100) {
    add("long-url", 5, "Very long link",
      "Long links can hide the real domain off-screen, especially on phones.");
  }

  return finish(url.href, host, reg, findings);
}

function decodeSafe(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

function finish(url, host, reg, findings) {
  findings.sort((a, b) => b.points - a.points);
  const score = Math.min(100, findings.reduce((sum, f) => sum + f.points, 0));
  const level = score >= 50 ? "High" : score >= 25 ? "Medium" : "Low";
  return { ok: true, url, host, registeredDomain: reg, score, level, findings };
}
