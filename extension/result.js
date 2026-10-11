// NexGuard AI — right-click scan result page (E4).
//
// Opened by the context-menu items with ?mode=url|image|text&target=…
//   url   -> POST /scan with the link
//   image -> download the image, POST /scan-qr (decodes a QR and scans it);
//            when no QR is in the image, falls back to scanning the image URL
//   text  -> POST the selection to /analyze-email as a .txt message
// Rendering reuses the popup's view-model (popup_render.js) with safe DOM.

const MODE_LABELS = {
  url: "Link scan",
  image: "Image / QR scan",
  text: "Selected-text scan",
};

const { mode, target } = parseResultParams(location.search);
let lastScanResult = null;

document.getElementById("modeLabel").textContent = MODE_LABELS[mode] || "Scan result";
document.getElementById("target").textContent =
  mode === "text" ? target.slice(0, 300) + (target.length > 300 ? "…" : "") : target;

function showError(message) {
  document.getElementById("status").style.display = "none";
  const err = document.getElementById("scanError");
  err.textContent = message;
  err.style.display = "block";
}

function setNote(text) {
  const note = document.getElementById("note");
  note.textContent = text;
  note.style.display = "block";
}

function setListItems(listEl, items, makeItem) {
  listEl.textContent = "";
  for (const item of items) listEl.appendChild(makeItem(item));
}

function renderResult(data) {
  const model = buildResultModel(data);
  if (!model) return;
  document.getElementById("status").style.display = "none";

  const box = document.getElementById("resultBox");
  box.style.display = "block";
  box.className = "result " + model.verdictClass + "-border";

  const verdictEl = document.getElementById("verdict");
  verdictEl.textContent = model.verdict;
  verdictEl.className = model.verdictClass;

  const confEl = document.getElementById("confidence");
  confEl.style.display = model.confidenceText ? "inline-block" : "none";
  confEl.textContent = model.confidenceText || "";

  const fill = document.getElementById("riskFill");
  fill.style.width = Math.max(0, Math.min(100, model.riskScore)) + "%";
  fill.className = "risk-fill " + model.verdictClass + "-fill";
  document.getElementById("score").textContent = "Risk score: " + model.riskScore + " / 100";

  const summaryEl = document.getElementById("summary");
  summaryEl.style.display = model.summary ? "block" : "none";
  summaryEl.textContent = model.summary;

  const whySection = document.getElementById("whySection");
  whySection.style.display = model.reasons.length ? "block" : "none";
  setListItems(document.getElementById("reasonList"), model.reasons, (reason) => {
    const li = document.createElement("li");
    li.textContent = reason;
    return li;
  });

  const sourcesSection = document.getElementById("sourcesSection");
  sourcesSection.style.display = model.sources.length ? "block" : "none";
  setListItems(document.getElementById("sourceList"), model.sources, (src) => {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = src.name;
    const status = document.createElement("span");
    status.textContent = src.text;
    status.className = "source-status" + (src.flagged ? " flagged" : "");
    li.append(name, status);
    return li;
  });
}

async function postJson(path, body) {
  const backend = await getBackendUrl();
  return fetch(backend + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(await getAuthHeaders()) },
    body: JSON.stringify(body),
  });
}

async function postFile(path, blob, filename) {
  const backend = await getBackendUrl();
  const form = new FormData();
  form.append("file", blob, filename);
  return fetch(backend + path, {
    method: "POST",
    headers: { ...(await getAuthHeaders()) },   // browser sets multipart boundary
    body: form,
  });
}

async function readResult(response) {
  let data = null;
  try { data = await response.json(); } catch { /* non-JSON body */ }
  if (!response.ok || !data || !data.verdict) {
    showError(scanErrorMessage(response.status, data));
    return null;
  }
  return data;
}

async function scanUrlTarget(url) {
  const res = await postJson("/scan", { url });
  return readResult(res);
}

async function checkImageOrigin(blob) {
  // AI-or-real ride-along — best-effort: a failure here must never touch
  // the main verdict, so every error path just leaves the line hidden.
  try {
    const res = await postFile("/analyze-image-origin", blob, "image.png");
    if (!res.ok) return;
    const line = originLine(await res.json());
    if (!line) return;
    const el = document.getElementById("originLine");
    el.textContent = line;
    el.style.display = "block";
  } catch { /* line stays hidden */ }
}

async function scanImageTarget(src) {
  // Download the image (page context may be needed for cookies; best-effort).
  let blob;
  try {
    const imgRes = await fetch(src);
    blob = await imgRes.blob();
  } catch {
    setNote("Could not download the image — scanned its address instead.");
    return scanUrlTarget(src);
  }
  const originPromise = checkImageOrigin(blob);
  const res = await postFile("/scan-qr", blob, "image.png");
  const data = await readResult(res);
  await originPromise.catch(() => {});
  if (!data) return null;
  if (String(data.verdict).toUpperCase() === "UNKNOWN") {
    setNote("No QR code found in the image — scanned the image address instead.");
    return scanUrlTarget(src);
  }
  setNote("A QR code was found in the image; its link was scanned.");
  return data;
}

async function scanTextTarget(text) {
  const blob = new Blob([text], { type: "text/plain" });
  const res = await postFile("/analyze-email", blob, "selection.txt");
  setNote("Selected text analyzed as a message (scam wording + links).");
  return readResult(res);
}

async function run() {
  if (!target) {
    showError("Nothing to scan.");
    return;
  }
  try {
    let data = null;
    if (mode === "image") data = await scanImageTarget(target);
    else if (mode === "text") data = await scanTextTarget(target);
    else data = await scanUrlTarget(target);
    if (data) {
      lastScanResult = data;
      renderResult(data);
    }
  } catch {
    showError("Could not reach the backend. Is it running?");
  }
}

// Report wrong verdict — same feedback loop as the popup (E3).
document.getElementById("reportBtn").addEventListener("click", async () => {
  if (!lastScanResult) return;
  const btn = document.getElementById("reportBtn");
  const status = document.getElementById("reportStatus");
  btn.disabled = true;
  try {
    const reportTarget = mode === "text" ? (lastScanResult.url || "pasted text") : target;
    const res = await postJson("/feedback", feedbackPayload(lastScanResult, reportTarget));
    if (res.ok) {
      btn.textContent = "Reported — thank you";
      status.textContent = "Our team will review this verdict.";
    } else {
      btn.disabled = false;
      status.textContent = "Could not send the report. Try again.";
    }
  } catch {
    btn.disabled = false;
    status.textContent = "Could not send the report. Try again.";
  }
});

run();
