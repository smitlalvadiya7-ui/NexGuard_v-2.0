// NexGuard AI - content script
// Shows a NON-BLOCKING, dismissible warning bar. The page always loads.
// Hardened (E7): the bar is built with createElement/textContent only —
// message fields are never parsed as HTML.
chrome.runtime.onMessage.addListener((message) => {
  if (message.type !== "SHOW_WARNING") return;
  if (document.getElementById("nexguard-warning")) return;
  if (!document.body) return;   // e.g. XML/plugin documents

  const bar = document.createElement("div");
  bar.id = "nexguard-warning";
  bar.style.cssText = [
    "position:fixed", "top:0", "left:0", "width:100%",
    "background:#EF4444", "color:#fff", "z-index:2147483647",
    "padding:14px 20px", "font:600 16px Arial, sans-serif",
    "text-align:center", "box-shadow:0 2px 12px rgba(0,0,0,.4)",
    "box-sizing:border-box",
  ].join(";");

  const verdict = String(message.verdict || "SUSPICIOUS");
  const score = (message.score !== undefined) ? String(message.score) : "?";

  bar.appendChild(document.createTextNode("⚠ NexGuard AI: this page looks "));
  const verdictEl = document.createElement("b");
  verdictEl.textContent = verdict;
  bar.appendChild(verdictEl);
  bar.appendChild(document.createTextNode(
    " (risk score " + score + "/100). Be careful with logins or payments."
  ));

  const btn = document.createElement("button");
  btn.id = "nexguard-dismiss";
  btn.textContent = "Dismiss";
  btn.style.cssText = [
    "margin-left:18px", "background:#fff", "color:#EF4444", "border:none",
    "padding:6px 14px", "border-radius:6px", "font-weight:700", "cursor:pointer",
  ].join(";");
  btn.addEventListener("click", () => bar.remove());
  bar.appendChild(btn);

  document.body.prepend(bar);
});
