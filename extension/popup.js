// NexGuard AI — popup (E3 rich result + E2 sign-in).
//
// Scans the current tab through the backend and renders the same rich result
// the web app shows: verdict + confidence, risk meter, "why this verdict",
// named threat-intel sources, and a "report wrong verdict" button that feeds
// the backend's verdict-feedback loop. All rendering uses safe DOM APIs
// (textContent / createElement) — never innerHTML with backend data.

let currentTabUrl = "";
let lastScanResult = null;   // raw /scan response, for the feedback payload

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    currentTabUrl = tabs[0].url;
    document.getElementById("currentUrl").textContent = currentTabUrl;
    renderLiveStatus(tabs[0].id);
    // C4: the quick question only appears on scannable web pages.
    if (pageQuestion(currentTabUrl)) {
        document.getElementById("askPageBtn").style.display = "block";
    }
});

// ── E10 — live-protection status for this tab ───────────────────────────────
// Asks the background what it did with this tab's navigation (scanned /
// trusted / backend unreachable / off) so the popup always says something
// honest instead of showing a blank "normal page".
function renderLiveStatus(tabId) {
    try {
        chrome.runtime.sendMessage({ type: "GET_TAB_STATE", tabId }, (state) => {
            void chrome.runtime.lastError;          // worker asleep => no status
            const d = describeState(state || null);
            const box = document.getElementById("liveStatus");
            box.className = "live-status " + (d.tone || "muted");
            document.getElementById("liveText").textContent = d.text;
            box.style.display = "flex";
        });
    } catch {
        /* popup opened without a background worker — leave the strip hidden */
    }
}

// ── Rendering ────────────────────────────────────────────────────────────────

function setListItems(listEl, items, makeItem) {
    listEl.textContent = "";                     // clear previous render
    for (const item of items) listEl.appendChild(makeItem(item));
}

function renderResult(data) {
    const model = buildResultModel(data);
    if (!model) return;

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

    const reportBtn = document.getElementById("reportBtn");
    reportBtn.disabled = false;
    reportBtn.textContent = "Report wrong verdict";
    document.getElementById("reportStatus").textContent = "";
}

function showScanError(message) {
    const err = document.getElementById("scanError");
    err.textContent = message;
    err.style.display = "block";
}

// ── Scan the current tab ─────────────────────────────────────────────────────

document.getElementById("scanBtn").addEventListener("click", async () => {
    const btn = document.getElementById("scanBtn");
    const errEl = document.getElementById("scanError");
    errEl.style.display = "none";
    btn.disabled = true;
    btn.textContent = "Scanning…";
    try {
        const backend = await getBackendUrl();
        const response = await fetch(backend + "/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                ...(await getAuthHeaders()),
            },
            body: JSON.stringify({ url: currentTabUrl }),
        });
        let data = null;
        try { data = await response.json(); } catch { /* non-JSON body */ }

        if (!response.ok || !data || !data.verdict) {
            document.getElementById("resultBox").style.display = "none";
            showScanError(scanErrorMessage(response.status, data));
            return;
        }
        lastScanResult = data;
        renderResult(data);
    } catch {
        document.getElementById("resultBox").style.display = "none";
        showScanError("Could not reach the backend. Is it running?");
    } finally {
        btn.disabled = false;
        btn.textContent = "Scan Website";
    }
});

// ── E3 — report a wrong verdict (feeds the active-learning loop) ─────────────

document.getElementById("reportBtn").addEventListener("click", async () => {
    if (!lastScanResult) return;
    const btn = document.getElementById("reportBtn");
    const status = document.getElementById("reportStatus");
    btn.disabled = true;
    try {
        const backend = await getBackendUrl();
        const res = await fetch(backend + "/feedback", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                ...(await getAuthHeaders()),
            },
            body: JSON.stringify(feedbackPayload(lastScanResult, currentTabUrl)),
        });
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

// ── C4 — Ask NexGuard: the support bot (with real scan tools) in the popup ──

function appendChatMessage(role, entry) {
    const log = document.getElementById("chatLog");
    const div = document.createElement("div");
    div.className = "chat-msg " + role;
    if (role === "bot" && entry.scan) {
        const chip = document.createElement("span");
        chip.className = "chat-chip " + entry.scan.verdictClass;
        chip.textContent = entry.scan.verdict + " · risk " + entry.scan.risk + "/100";
        div.appendChild(chip);
        div.appendChild(document.createElement("br"));
    }
    div.appendChild(document.createTextNode(entry.text));
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
}

const chatHistory = [];   // C3 — last turns, sent so "scan it again" works

async function sendChatQuestion(question) {
    const q = (question || "").trim();
    if (!q) return;
    const input = document.getElementById("chatInput");
    const sendBtn = document.getElementById("chatSendBtn");
    appendChatMessage("user", { text: q, scan: null });
    input.value = "";
    input.disabled = true;
    sendBtn.disabled = true;
    sendBtn.textContent = "…";
    try {
        const backend = await getBackendUrl();
        const res = await fetch(backend + "/support/ask", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                ...(await getAuthHeaders()),
            },
            body: JSON.stringify(chatRequestPayload(q, chatHistory)),
        });
        let data = null;
        try { data = await res.json(); } catch { /* non-JSON body */ }
        const entry = composeChatEntry(res.ok ? data : null);
        appendChatMessage("bot", entry);
        chatHistory.push({ role: "user", text: q }, { role: "bot", text: entry.text });
    } catch {
        appendChatMessage("bot", composeChatEntry(null));
    } finally {
        input.disabled = false;
        sendBtn.disabled = false;
        sendBtn.textContent = "Ask";
        input.focus();
    }
}

document.getElementById("chatSendBtn").addEventListener("click", () => {
    sendChatQuestion(document.getElementById("chatInput").value);
});
document.getElementById("chatInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendChatQuestion(e.target.value);
});
document.getElementById("askPageBtn").addEventListener("click", () => {
    const q = pageQuestion(currentTabUrl);
    if (q) sendChatQuestion(q);
});

// Open the settings/options page (E1 — configurable backend URL).
document.getElementById("settingsLink").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
});

// ── E2 — account: sign in / sign out from the popup ─────────────────────────

async function renderAccount() {
    const state = await getAuthState();
    document.getElementById("signedIn").style.display =
        state.signedIn ? "block" : "none";
    document.getElementById("signedOut").style.display =
        state.signedIn ? "none" : "block";
    if (state.signedIn) {
        document.getElementById("whoEmail").textContent = state.email || "your account";
        document.getElementById("whoTier").textContent = state.tier || "free";
    }
}

document.getElementById("signInBtn").addEventListener("click", async () => {
    const errBox = document.getElementById("authError");
    errBox.textContent = "";
    const btn = document.getElementById("signInBtn");
    btn.disabled = true;
    btn.textContent = "Signing in…";
    try {
        const backend = await getBackendUrl();
        const result = await signIn(
            backend,
            document.getElementById("authEmail").value,
            document.getElementById("authPassword").value
        );
        if (result.ok) {
            document.getElementById("authPassword").value = "";
            await renderAccount();
        } else {
            errBox.textContent = result.error;
        }
    } finally {
        btn.disabled = false;
        btn.textContent = "Sign in";
    }
});

document.getElementById("signOutLink").addEventListener("click", async (e) => {
    e.preventDefault();
    await signOut();
    await renderAccount();
});

renderAccount();
