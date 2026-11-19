import { analyzeUrl } from "./analyzer.js";

const $ = (id) => document.getElementById(id);

// Everything shown comes from untrusted input, so the page only ever uses textContent (never innerHTML).
function show(input) {
  const r = analyzeUrl(input);
  if (!r.ok) {
    $("error").textContent = r.error;
    $("result").hidden = true;
    return;
  }
  $("error").textContent = "";
  $("result").hidden = false;
  $("result").dataset.level = r.level.toLowerCase();
  $("level").textContent = r.level;
  $("score").textContent = `${r.score}/100`;
  $("bar").style.width = `${Math.max(4, r.score)}%`;
  $("domain").textContent = r.registeredDomain || "(none)";

  const list = $("findings");
  list.replaceChildren();
  if (r.findings.length === 0) {
    const li = document.createElement("li");
    li.className = "none";
    li.textContent = "No common phishing signs found. Still be careful with unexpected links.";
    list.append(li);
  }
  for (const f of r.findings) {
    const li = document.createElement("li");
    li.className = f.points >= 25 ? "high" : f.points >= 15 ? "medium" : "low";
    const title = document.createElement("strong");
    title.textContent = f.title;
    const pts = document.createElement("span");
    pts.className = "pts";
    pts.textContent = `+${f.points}`;
    const detail = document.createElement("p");
    detail.textContent = f.detail;
    li.append(title, pts, detail);
    list.append(li);
  }
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
