// NexGuard AI — warning interstitial logic.
// Reads the threat details from the query string and wires the action buttons.

const params = new URLSearchParams(location.search);
const target = params.get("url") || "";
const verdict = (params.get("verdict") || "MALICIOUS").toUpperCase();
const score = params.get("score") || "?";

let reasons = [];
try { reasons = JSON.parse(params.get("reasons") || "[]"); } catch { reasons = []; }

// ── Populate ────────────────────────────────────────────────────────────────
document.getElementById("score").textContent = score;
document.getElementById("target").textContent = target;

const pill = document.getElementById("verdict");
pill.textContent = verdict;
if (verdict === "SUSPICIOUS") pill.classList.add("susp");

const list = document.getElementById("reasons");
if (reasons.length) {
  reasons.forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    list.appendChild(li);
  });
} else {
  const li = document.createElement("li");
  li.className = "empty";
  li.textContent = "Flagged by NexGuard's AI/reputation analysis as high-risk.";
  list.appendChild(li);
}

let hostname = "";
try { hostname = new URL(target).hostname; } catch {}

// ── Back to safety ────────────────────────────────────────────────────────────
document.getElementById("backBtn").addEventListener("click", () => {
  if (history.length > 1) history.back();
  else location.href = "about:blank";
});

// ── Proceed anyway (optionally whitelist first) ───────────────────────────────
document.getElementById("proceedBtn").addEventListener("click", () => {
  const always = document.getElementById("alwaysAllow").checked;

  const go = () => {
    // Grant a one-time bypass in the background, then navigate to the original URL.
    chrome.runtime.sendMessage({ type: "PROCEED", url: target }, () => {
      location.href = target;
    });
  };

  if (always && hostname) {
    chrome.runtime.sendMessage({ type: "WHITELIST_ADD", host: hostname }, () => go());
  } else {
    go();
  }
});
