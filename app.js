import { analyzeUrl } from "./analyzer.js";

const $ = (id) => document.getElementById(id);
const RING = 326.7; // circumference of the r=52 gauge circle

const SUMMARY = {
  High: "Strong signs of phishing. Don't open this link or enter any details.",
  Medium: "Some warning signs. Check the real website below before trusting it.",
  Low: "No strong warning signs, but stay careful with unexpected links.",
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

/** Splits the link into parts and highlights the registered (real) domain. textContent only. */
function renderAnatomy(r) {
  const box = $("anatomy");
  box.replaceChildren();
  let u;
  try { u = new URL(r.url); } catch { box.textContent = r.url; return; }
  if (!r.host) { box.append(el("span", "dim", r.url.slice(0, 200))); return; }

  const host = r.host;
  const reg = r.registeredDomain || host;
  const idx = host.toLowerCase().lastIndexOf(reg.toLowerCase());
  const before = idx > 0 ? host.slice(0, idx) : "";
  const rest = `${u.port ? ":" + u.port : ""}${u.pathname}${u.search}${u.hash}`;

  box.append(el("span", "dim", `${u.protocol}//`));
  if (u.username || u.password) box.append(el("span", "dim", "(hidden login)@"));
  if (before) box.append(el("span", "dim", before));
  box.append(el("span", "key", reg));
  if (rest && rest !== "/") box.append(el("span", "dim", rest.length > 120 ? rest.slice(0, 117) + "..." : rest));
}

function show(input) {
  const r = analyzeUrl(input);
  if (!r.ok) {
    $("error").textContent = r.error;
    $("result").hidden = true;
    return;
  }
  $("error").textContent = "";
  const result = $("result");
  result.hidden = false;
  result.dataset.level = r.level.toLowerCase();
  $("score").textContent = String(r.score);
  $("level").textContent = `${r.level} risk`;
  $("summary").textContent = SUMMARY[r.level];
  $("arc").style.strokeDashoffset = String(RING * (1 - Math.max(r.score, 2) / 100));

  renderAnatomy(r);

  const list = $("findings");
  list.replaceChildren();
  $("count").textContent = r.findings.length ? `${r.findings.length} warning${r.findings.length > 1 ? "s" : ""}` : "";
  if (r.findings.length === 0) {
    list.append(el("li", "none", "No common phishing signs found."));
  }
  for (const f of r.findings) {
    const sev = f.points >= 25 ? "high" : f.points >= 15 ? "medium" : "low";
    const li = el("li", sev);
    li.append(el("span", "sev", sev), el("strong", "", f.title), el("span", "pts", `+${f.points}`), el("p", "", f.detail));
    list.append(li);
  }
  if (window.matchMedia("(max-width: 860px)").matches) result.scrollIntoView({ behavior: "smooth", block: "start" });
}

$("form").addEventListener("submit", (e) => {
  e.preventDefault();
  show($("url").value);
});

document.querySelectorAll("[data-url]").forEach((b) =>
  b.addEventListener("click", () => {
    $("url").value = b.dataset.url;
    show(b.dataset.url);
  }));
