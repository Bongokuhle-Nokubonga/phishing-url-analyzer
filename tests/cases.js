// Test cases shared by tests.html (browser) and tests/run.mjs (Node).
import { analyzeUrl, levenshtein, normalizeHomoglyphs, registeredDomain, isIPv4 } from "../analyzer.js";

function eq(actual, expected, what) {
  const a = JSON.stringify(actual), e = JSON.stringify(expected);
  if (a !== e) throw new Error(`${what}: expected ${e}, got ${a}`);
}
function ok(cond, what) { if (!cond) throw new Error(what); }
const ids = (r) => r.findings.map((f) => f.id);

export const cases = [
  ["helpers: levenshtein, homoglyphs, IPv4, registered domain", () => {
    eq(levenshtein("paypal", "paypa1"), 1, "levenshtein");
    eq(normalizeHomoglyphs("rnicr0soft"), "microsoft", "homoglyphs");
    ok(isIPv4("192.168.1.10") && !isIPv4("256.1.1.1") && !isIPv4("example.com"), "IPv4");
    eq(registeredDomain("login.secure.paypal.com.evil.xyz"), "evil.xyz", "takes last two labels");
    eq(registeredDomain("www.fnb.co.za"), "fnb.co.za", "handles co.za");
  }],
  ["real sites score Low with no brand warnings", () => {
    for (const u of [
      "https://www.microsoft.com/en-za",
      "https://login.microsoftonline.com/",
      "https://accounts.google.com/signin",
      "https://www.fnb.co.za/",
      "https://www.capitecbank.co.za/",
      "https://github.com/Bongokuhle-Nokubonga",
    ]) {
      const r = analyzeUrl(u);
      ok(r.ok && r.level === "Low", `${u} should be Low, got ${r.level} (${ids(r)})`);
      ok(!ids(r).includes("brand-impersonation") && !ids(r).includes("lookalike"), `${u} wrongly flagged as impersonation`);
    }
  }],
  ["brand name in front of someone else's domain is High", () => {
    const r = analyzeUrl("http://paypal.com.account-verify.xyz/login");
    eq(r.registeredDomain, "account-verify.xyz", "real domain");
    ok(ids(r).includes("brand-impersonation"), "impersonation");
    ok(ids(r).includes("risky-tld") && ids(r).includes("no-https"), "tld and http");
    eq(r.level, "High", "level");
  }],
  ["look-alike spellings are caught", () => {
    ok(ids(analyzeUrl("https://rnicrosoft-support.com/")).includes("lookalike"), "rn → m");
    ok(ids(analyzeUrl("https://paypa1.com/")).includes("lookalike"), "1 → l");
    ok(ids(analyzeUrl("https://netfliix.com/")).includes("lookalike"), "extra letter");
  }],
  ["South African banks are covered", () => {
    const r = analyzeUrl("https://fnb-secure-update.co/verify");
    ok(ids(r).includes("brand-impersonation"), "fnb impersonation");
    ok(analyzeUrl("https://capitec-login.online/").level !== "Low", "capitec on .online");
  }],
  ["IP address, odd port and @ trick", () => {
    const ip = analyzeUrl("http://192.168.10.5:8080/secure/update.php");
    ok(ids(ip).includes("ip-host") && ids(ip).includes("odd-port"), "IP and port");
    const at = analyzeUrl("https://www.microsoft.com@evil.example/login");
    ok(ids(at).includes("userinfo"), "@ trick");
    eq(at.host, "evil.example", "real host after @");
  }],
  ["punycode, shorteners, downloads and embedded redirects", () => {
    ok(ids(analyzeUrl("https://xn--pple-43d.com/")).includes("punycode"), "punycode");
    ok(ids(analyzeUrl("https://bit.ly/3abcde")).includes("shortener"), "shortener");
    ok(ids(analyzeUrl("https://example.com/files/invoice.exe")).includes("download"), "download");
    ok(ids(analyzeUrl("https://example.com/r?u=https://evil.example")).includes("redirect"), "redirect");
  }],
  ["javascript: and data: links are High immediately", () => {
    eq(analyzeUrl("javascript:alert(document.cookie)").level, "High", "javascript:");
    eq(analyzeUrl("data:text/html;base64,PHNjcmlwdD4=").level, "High", "data:");
  }],
  ["adds http:// when there is no scheme, rejects junk", () => {
    const r = analyzeUrl("paypal.com.secure-login.top");
    ok(r.ok && ids(r).includes("brand-impersonation"), "no scheme still analysed");
    eq(analyzeUrl("").ok, false, "empty");
    eq(analyzeUrl("ftp://example.com").ok, false, "ftp not supported");
    eq(analyzeUrl("http://").ok, false, "invalid");
    eq(analyzeUrl("a".repeat(3000)).ok, false, "too long");
  }],
  ["score is capped at 100 and findings are sorted by weight", () => {
    const r = analyzeUrl("http://paypal.secure.login.verify.account-update-now.xyz:8080/login/verify.php?next=http://x.example");
    ok(r.score <= 100, "capped");
    const pts = r.findings.map((f) => f.points);
    eq(pts, [...pts].sort((a, b) => b - a), "sorted");
  }],
];
