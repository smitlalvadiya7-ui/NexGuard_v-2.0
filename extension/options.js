// NexGuard AI — options page (E1 backend URL + E6 protection level,
// whitelist manager and sign-in). Helpers come from config.js / auth.js /
// settings.js, loaded before this script.
const input = document.getElementById("backendUrl");
const status = document.getElementById("status");

function show(msg, ok) {
  status.textContent = msg;
  status.className = ok ? "ok" : "err";
}

// ── E1 — backend URL ─────────────────────────────────────────────────────────

getBackendUrl().then((url) => {
  input.value = url;
});

document.getElementById("saveBtn").addEventListener("click", async () => {
  const raw = input.value;
  if (normalizeBackendUrl(raw) === "") {
    show("That doesn't look like a valid URL — using the default instead.", false);
  }
  const saved = await setBackendUrl(raw);
  input.value = saved;
  show(`Saved. Scans now go to ${saved}`, true);
});

document.getElementById("resetBtn").addEventListener("click", async () => {
  const saved = await setBackendUrl(NEXGUARD_DEFAULT_BACKEND);
  input.value = saved;
  show(`Reset to the default ${saved}`, true);
});

// ── E6 — protection level + hover-scan toggle ───────────────────────────────

async function renderProtection() {
  const { protectionLevel, hoverScan, webmailBadges, blockSuspiciousAt } =
    await getSettings();
  const radio = document.querySelector(`input[name="level"][value="${protectionLevel}"]`);
  if (radio) radio.checked = true;
  document.getElementById("hoverScan").checked = hoverScan;
  document.getElementById("webmailBadges").checked = webmailBadges;
  document.getElementById("blockAt").value = blockSuspiciousAt;
  document.getElementById("blockAtValue").textContent = blockSuspiciousAt;
}

// M6 — per-surface block threshold slider
document.getElementById("blockAt").addEventListener("input", (e) => {
  document.getElementById("blockAtValue").textContent = e.target.value;
});
document.getElementById("blockAt").addEventListener("change", async (e) => {
  const saved = await setBlockSuspiciousAt(e.target.value);
  e.target.value = saved;
  document.getElementById("blockAtValue").textContent = saved;
  show(`Suspicious pages with risk score ${saved} or higher are now treated like malicious ones.`, true);
});

for (const radio of document.querySelectorAll('input[name="level"]')) {
  radio.addEventListener("change", async (e) => {
    const saved = await setProtectionLevel(e.target.value);
    show(
      saved === "off"
        ? "Automatic protection is OFF — pages are no longer scanned while you browse."
        : saved === "warn"
          ? "Warn-only mode: risky pages load with a warning bar, nothing is blocked."
          : "Blocking mode: dangerous pages are stopped before they load.",
      saved !== "off"
    );
  });
}

document.getElementById("hoverScan").addEventListener("change", async (e) => {
  await setHoverScan(e.target.checked);
  show(
    e.target.checked
      ? "Risky links on pages will be marked when you hover them."
      : "Link hover scanning turned off.",
    true
  );
});

document.getElementById("webmailBadges").addEventListener("change", async (e) => {
  await setWebmailBadges(e.target.checked);
  show(
    e.target.checked
      ? "Brand senders in Gmail / Outlook will get a ✓ / ⚠ badge."
      : "Webmail sender badges turned off.",
    true
  );
});

// ── E6 — whitelist manager ──────────────────────────────────────────────────

function renderWhitelist(list) {
  const ul = document.getElementById("wlList");
  ul.textContent = "";
  document.getElementById("wlEmpty").style.display = list.length ? "none" : "block";
  for (const host of list) {
    const li = document.createElement("li");
    const span = document.createElement("span");
    span.className = "wl-host";
    span.textContent = host;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "wl-remove";
    btn.textContent = "Remove";
    btn.addEventListener("click", async () => {
      renderWhitelist(await removeFromWhitelist(host));
    });
    li.append(span, btn);
    ul.appendChild(li);
  }
}

document.getElementById("wlAddBtn").addEventListener("click", async () => {
  const field = document.getElementById("wlInput");
  const hint = document.getElementById("wlHint");
  const host = normalizeHost(field.value);
  if (!host) {
    hint.textContent = "Enter a site like example.com";
    return;
  }
  hint.textContent = "";
  renderWhitelist(await addToWhitelist(field.value));
  field.value = "";
});

// ── E6 — account (sign in / out, same session as the popup) ─────────────────

async function renderAccount() {
  const state = await getAuthState();
  document.getElementById("signedIn").style.display = state.signedIn ? "block" : "none";
  document.getElementById("signedOut").style.display = state.signedIn ? "none" : "block";
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

// ── initial render ──────────────────────────────────────────────────────────
renderProtection();
getWhitelist().then(renderWhitelist);
renderAccount();
