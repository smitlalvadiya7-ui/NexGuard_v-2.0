import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import UploadDropzone from "../src/components/UploadDropzone.jsx";
import QrPanel from "../src/pages/Scan/QrPanel.jsx";
import EmailPanel from "../src/pages/Scan/EmailPanel.jsx";
import ScreenshotPanel from "../src/pages/Scan/ScreenshotPanel.jsx";
import VoicePanel from "../src/pages/Scan/VoicePanel.jsx";
import GmailPanel from "../src/pages/Scan/GmailPanel.jsx";
import Scan from "../src/pages/Scan/index.jsx";
import { ToastProvider } from "../src/components/Toast.jsx";
import { API_BASE } from "../src/api.js";

function mockResponse(status, body) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    headers: { get: () => "application/json" },
  });
}

function wrap(ui, initialEntries = ["/scan"]) {
  return render(
    <ToastProvider>
      <MemoryRouter initialEntries={initialEntries}>{ui}</MemoryRouter>
    </ToastProvider>
  );
}

function pickFile(file) {
  fireEvent.change(screen.getByTestId("dropzone-input"), { target: { files: [file] } });
}

beforeEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// UploadDropzone
// ---------------------------------------------------------------------------
test("UploadDropzone fires onFile for browsed files and shows the file chip", () => {
  const onFile = vi.fn();
  wrap(<UploadDropzone accept="image/*" label="Upload QR image" onFile={onFile} />);

  const file = new File(["png-bytes"], "qr-code.png", { type: "image/png" });
  pickFile(file);

  expect(onFile).toHaveBeenCalledTimes(1);
  expect(onFile).toHaveBeenCalledWith(file);
  expect(screen.getByText(/qr-code\.png/)).toBeInTheDocument();
});

test("UploadDropzone accepts a dragged-and-dropped file", () => {
  const onFile = vi.fn();
  wrap(<UploadDropzone accept="image/*" label="Upload screenshot" onFile={onFile} />);

  const file = new File(["png-bytes"], "shot.png", { type: "image/png" });
  fireEvent.drop(screen.getByRole("button", { name: /upload screenshot/i }), {
    dataTransfer: { files: [file] },
  });

  expect(onFile).toHaveBeenCalledWith(file);
  expect(screen.getByText(/shot\.png/)).toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// QrPanel
// ---------------------------------------------------------------------------
test("QrPanel posts the image as FormData to /scan-qr and renders the verdict", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      url: "https://evil.example/login",
      verdict: "MALICIOUS",
      risk_score: 91,
      confidence: 90,
      flags: ["Typosquatted brand domain"],
      analysis: "QR URL analyzed with the main URL scanner.",
      tier_locked: [],
    })
  );
  wrap(<QrPanel />);

  const file = new File(["png-bytes"], "qr.png", { type: "image/png" });
  pickFile(file);
  fireEvent.click(screen.getByRole("button", { name: /scan qr/i }));

  expect(await screen.findByText(/^malicious$/i)).toBeInTheDocument();
  // decoded payload from the QR is surfaced
  expect(screen.getByText("https://evil.example/login")).toBeInTheDocument();

  expect(global.fetch).toHaveBeenCalledTimes(1);
  const [calledUrl, opts] = global.fetch.mock.calls[0];
  expect(calledUrl).toBe(API_BASE + "/scan-qr");
  expect(opts.method).toBe("POST");
  expect(opts.body).toBeInstanceOf(FormData);
  expect(opts.body.get("file")).toBe(file);
});

test("QrPanel does nothing without a selected file", () => {
  global.fetch = vi.fn();
  wrap(<QrPanel />);

  fireEvent.click(screen.getByRole("button", { name: /scan qr/i }));

  expect(global.fetch).not.toHaveBeenCalled();
});

test("QrPanel renders FreeLimitCard on a 429 free_limit response", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(429, { error: "free_limit", message: "Upgrade to Premium for unlimited scans." })
  );
  wrap(<QrPanel />);

  pickFile(new File(["x"], "qr.png", { type: "image/png" }));
  fireEvent.click(screen.getByRole("button", { name: /scan qr/i }));

  expect(await screen.findByText(/daily free limit reached/i)).toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// EmailPanel
// ---------------------------------------------------------------------------
test("EmailPanel posts pasted text wrapped as a file to /analyze-email", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      verdict: "SUSPICIOUS",
      risk_score: 55,
      subject: "Verify your account",
      sender: "security@paypa1.example",
      reasons: ["SPF check failed — sender not authorized to send from this domain"],
      auth_results: { spf: "fail", dkim: "none", dmarc: "fail" },
      links_found: 1,
      scanned_links: [{ url: "https://paypa1.example/verify", verdict: "MALICIOUS" }],
      tier_locked: [],
    })
  );
  wrap(<EmailPanel />);

  const raw = "Subject: Verify your account\nFrom: security@paypa1.example\n\nClick here";
  fireEvent.change(screen.getByLabelText(/paste raw email/i), { target: { value: raw } });
  fireEvent.click(screen.getByRole("button", { name: /analyze email/i }));

  expect(await screen.findByText(/^suspicious$/i)).toBeInTheDocument();

  const [calledUrl, opts] = global.fetch.mock.calls[0];
  expect(calledUrl).toBe(API_BASE + "/analyze-email");
  expect(opts.method).toBe("POST");
  expect(opts.body).toBeInstanceOf(FormData);
  const sent = opts.body.get("file");
  expect(sent).toBeInstanceOf(File);
  expect(await sent.text()).toBe(raw);

  // SPF/DKIM/DMARC results are rendered
  expect(screen.getByText(/^spf$/i)).toBeInTheDocument();
  expect(screen.getByText(/^dkim$/i)).toBeInTheDocument();
  expect(screen.getByText(/^dmarc$/i)).toBeInTheDocument();
  // embedded-link scan is rendered
  expect(screen.getByText("https://paypa1.example/verify")).toBeInTheDocument();
});

test("EmailPanel posts an uploaded .eml file untouched", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      verdict: "SAFE",
      risk_score: 4,
      reasons: [],
      auth_results: { spf: "pass", dkim: "pass", dmarc: "pass" },
      tier_locked: [],
    })
  );
  wrap(<EmailPanel />);

  const file = new File(["raw eml"], "sample.eml", { type: "message/rfc822" });
  pickFile(file);
  fireEvent.click(screen.getByRole("button", { name: /analyze email/i }));

  expect(await screen.findByText(/^safe$/i)).toBeInTheDocument();
  expect(global.fetch.mock.calls[0][1].body.get("file")).toBe(file);
});

test("EmailPanel shows a verified-sender badge with the genuine ratio", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      verdict: "SAFE",
      risk_score: 5,
      reasons: [],
      auth_results: { spf: "pass", dkim: "pass", dmarc: "pass" },
      sender_origin: {
        status: "verified",
        claimed_brand: "icici",
        sender_domain: "alerts.icicibank.com",
        expected_domains: ["icicibank.com"],
        detail:
          "Verified sender — genuinely from 'alerts.icicibank.com', an official icici domain, with passing authentication.",
      },
      genuine_ratio: 95,
      tier_locked: [],
    })
  );
  wrap(<EmailPanel />);

  pickFile(new File(["raw"], "bank.eml", { type: "message/rfc822" }));
  fireEvent.click(screen.getByRole("button", { name: /analyze email/i }));

  expect((await screen.findAllByText(/verified sender/i)).length).toBeGreaterThanOrEqual(1);
  expect(screen.getByText(/genuinely from 'alerts\.icicibank\.com'/i)).toBeInTheDocument();
  expect(screen.getByText(/95% genuine/i)).toBeInTheDocument();
});

test("EmailPanel shows an impersonation warning on origin mismatch", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      verdict: "MALICIOUS",
      risk_score: 88,
      reasons: [],
      auth_results: { spf: "none", dkim: "none", dmarc: "none" },
      sender_origin: {
        status: "mismatch",
        claimed_brand: "icici",
        sender_domain: "icici-verify.top",
        expected_domains: ["icicibank.com"],
        detail:
          "Claims to be 'icici' but was sent from 'icici-verify.top', which does not belong to icici (official: icicibank.com).",
      },
      genuine_ratio: 12,
      tier_locked: [],
    })
  );
  wrap(<EmailPanel />);

  pickFile(new File(["raw"], "phish.eml", { type: "message/rfc822" }));
  fireEvent.click(screen.getByRole("button", { name: /analyze email/i }));

  expect(await screen.findByText(/sender impersonation/i)).toBeInTheDocument();
  expect(screen.getByText(/does not belong to icici/i)).toBeInTheDocument();
  expect(screen.getByText(/12% genuine/i)).toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// ScreenshotPanel
// ---------------------------------------------------------------------------
test("ScreenshotPanel renders the verdict and the OCR extracted text block", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      verdict: "MALICIOUS",
      risk_score: 80,
      text: "Enter your card PIN to unlock your account",
      reasons: ["Scam indicator detected: PIN"],
      tier_locked: [],
    })
  );
  wrap(<ScreenshotPanel />);

  pickFile(new File(["png"], "shot.png", { type: "image/png" }));
  fireEvent.click(screen.getByRole("button", { name: /analyze screenshot/i }));

  expect(await screen.findByText(/^malicious$/i)).toBeInTheDocument();
  expect(global.fetch.mock.calls[0][0]).toBe(API_BASE + "/analyze-screenshot");
  expect(screen.getByText(/enter your card pin to unlock/i)).toBeInTheDocument();
  expect(screen.getByText(/scam indicator detected: pin/i)).toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// VoicePanel
// ---------------------------------------------------------------------------
test("VoicePanel renders the verdict, transcript and scam reasons", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      verdict: "SUSPICIOUS",
      risk_score: 62,
      text: "Your account is blocked, share the OTP now",
      reasons: ["OTP harvesting phrase detected"],
      tier_locked: [],
    })
  );
  wrap(<VoicePanel />);

  pickFile(new File(["wav"], "call.wav", { type: "audio/wav" }));
  fireEvent.click(screen.getByRole("button", { name: /analyze voice/i }));

  expect(await screen.findByText(/^suspicious$/i)).toBeInTheDocument();
  expect(global.fetch.mock.calls[0][0]).toBe(API_BASE + "/analyze-voice");
  expect(screen.getByText(/share the otp now/i)).toBeInTheDocument();
  expect(screen.getByText(/otp harvesting phrase detected/i)).toBeInTheDocument();
});

test("VoicePanel shows the fake ratio, confidence and detected language", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      verdict: "MALICIOUS",
      risk_score: 87,
      text: "your bank account will be blocked, share the one time password",
      reasons: ["Scam intent (code_request): request to share a one-time / verification code"],
      scam_ratio: 87,
      genuine_ratio: 13,
      confidence: "High",
      language: "hi",
      tier_locked: [],
    })
  );
  wrap(<VoicePanel />);

  pickFile(new File(["wav"], "call.wav", { type: "audio/wav" }));
  fireEvent.click(screen.getByRole("button", { name: /analyze voice/i }));

  expect(await screen.findByText(/87% likely scam/i)).toBeInTheDocument();
  // confidence now shows both in the result header chip and the voice strip
  expect(screen.getAllByText(/high confidence/i).length).toBeGreaterThanOrEqual(1);
  expect(screen.getByText(/hindi/i)).toBeInTheDocument();
});

test("VoicePanel is honest when the audio could not be analyzed", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      verdict: "UNKNOWN",
      risk_score: 0,
      text: "No transcript returned. Enable STT or upload a .txt transcript for accurate voice testing.",
      reasons: ["No transcript available — the audio could not be analyzed. This is NOT a safe verdict."],
      scam_ratio: null,
      genuine_ratio: null,
      confidence: "Low",
      language: null,
      tier_locked: [],
    })
  );
  wrap(<VoicePanel />);

  pickFile(new File(["wav"], "silent.wav", { type: "audio/wav" }));
  fireEvent.click(screen.getByRole("button", { name: /analyze voice/i }));

  expect(await screen.findByText(/could not be analyzed/i)).toBeInTheDocument();
  // no fake percentage is invented when nothing was analyzed
  expect(screen.queryByText(/% likely scam/i)).not.toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// GmailPanel
// ---------------------------------------------------------------------------
test("GmailPanel scans the inbox and renders one card per email", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      status: "connected",
      emails: [
      {
        subject: "Verify your account",
        from: "security@paypa1.example",
        verdict: "MALICIOUS",
        risk_score: 88,
        reasons: ["Brand impersonation"],
        auth_results: { spf: "fail", dkim: "none", dmarc: "fail" },
        links_found: 2,
        source: "gmail",
      },
      {
        subject: "Team lunch Friday",
        from: "boss@company.example",
        verdict: "SAFE",
        risk_score: 3,
        reasons: [],
        auth_results: { spf: "pass", dkim: "pass", dmarc: "pass" },
        links_found: 0,
        source: "gmail",
      },
      ],
    })
  );
  wrap(<GmailPanel />);

  fireEvent.click(screen.getByRole("button", { name: /scan gmail inbox/i }));

  expect(await screen.findByText("Verify your account")).toBeInTheDocument();
  expect(screen.getByText("Team lunch Friday")).toBeInTheDocument();
  expect(screen.getByText(/^malicious$/i)).toBeInTheDocument();
  expect(screen.getByText(/^safe$/i)).toBeInTheDocument();
  expect(screen.getByText(/security@paypa1\.example/)).toBeInTheDocument();
  expect(screen.getByText(/brand impersonation/i)).toBeInTheDocument();
  expect(global.fetch.mock.calls[0][0]).toBe(API_BASE + "/gmail-emails");
});

test("GmailPanel shows sender-origin verdicts on inbox cards", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      status: "connected",
      emails: [
        {
          subject: "Your statement is ready",
          from: "ICICI Bank <alerts@icicibank.com>",
          verdict: "SAFE",
          risk_score: 5,
          reasons: [],
          auth_results: { spf: "pass", dkim: "pass", dmarc: "pass" },
          sender_origin: {
            status: "verified",
            claimed_brand: "icici",
            sender_domain: "alerts.icicibank.com",
            expected_domains: ["icicibank.com"],
            detail: "Verified sender — genuinely from 'alerts.icicibank.com', an official icici domain, with passing authentication.",
          },
          genuine_ratio: 95,
          links_found: 2,
          source: "gmail",
        },
      ],
    })
  );
  wrap(<GmailPanel />);

  fireEvent.click(screen.getByRole("button", { name: /scan gmail inbox/i }));

  expect((await screen.findAllByText(/verified sender/i)).length).toBeGreaterThanOrEqual(1);
  expect(screen.getByText(/95% genuine/i)).toBeInTheDocument();
});

test("GmailPanel renders the Connect Gmail setup card when not connected", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      status: "not_connected",
      detail: "backend/credentials.json not found. Add your Google OAuth client file to enable live inbox scanning.",
      emails: [],
    })
  );
  wrap(<GmailPanel />);

  fireEvent.click(screen.getByRole("button", { name: /scan gmail inbox/i }));

  expect(await screen.findByText(/connect gmail/i)).toBeInTheDocument();
  expect(screen.getAllByText(/credentials\.json/).length).toBeGreaterThan(0);
  // an explicit, clearly-labeled way to preview with bundled samples
  expect(screen.getByRole("button", { name: /try with sample emails/i })).toBeInTheDocument();
  // the setup card must NOT read as a scanned-safe inbox
  expect(screen.queryByText(/^safe$/i)).not.toBeInTheDocument();
});

test("GmailPanel sample mode is explicit and clearly labeled", async () => {
  global.fetch = vi
    .fn()
    .mockImplementationOnce(() =>
      mockResponse(200, { status: "not_connected", detail: "no credentials", emails: [] })
    )
    .mockImplementationOnce(() =>
      mockResponse(200, {
        status: "demo",
        emails: [
          {
            subject: "Sample phishing email",
            from: "attacker@example",
            verdict: "MALICIOUS",
            score: 90,
            risk_score: 90,
            reasons: ["Urgency"],
            auth_results: { spf: "none", dkim: "none", dmarc: "none" },
            links_found: 0,
            source: "sample",
          },
        ],
      })
    );
  wrap(<GmailPanel />);

  fireEvent.click(screen.getByRole("button", { name: /scan gmail inbox/i }));
  fireEvent.click(await screen.findByRole("button", { name: /try with sample emails/i }));

  expect(await screen.findByText("Sample phishing email")).toBeInTheDocument();
  // clearly labeled as bundled sample data, not the user's inbox
  expect(screen.getByText(/sample data/i)).toBeInTheDocument();
  expect(global.fetch.mock.calls[1][0]).toBe(API_BASE + "/gmail-emails?demo=1");
});

test("GmailPanel shows an honest error state instead of fake rows", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      status: "error",
      detail: "Gmail scan failed: token refresh failed",
      emails: [],
    })
  );
  wrap(<GmailPanel />);

  fireEvent.click(screen.getByRole("button", { name: /scan gmail inbox/i }));

  expect(await screen.findByText(/token refresh failed/i)).toBeInTheDocument();
  // no fabricated email cards
  expect(screen.queryByText(/^suspicious$/i)).not.toBeInTheDocument();
});

test("GmailPanel reports an empty connected inbox honestly", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, { status: "connected", emails: [] })
  );
  wrap(<GmailPanel />);

  fireEvent.click(screen.getByRole("button", { name: /scan gmail inbox/i }));

  expect(await screen.findByText(/no emails found/i)).toBeInTheDocument();
});

test("GmailPanel renders FreeLimitCard on a 429 free_limit response", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(429, { error: "free_limit", message: "Upgrade to Premium for unlimited scans." })
  );
  wrap(<GmailPanel />);

  fireEvent.click(screen.getByRole("button", { name: /scan gmail inbox/i }));

  expect(await screen.findByText(/daily free limit reached/i)).toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// Scan hub registration
// ---------------------------------------------------------------------------
test("the scan hub registers the upload panels", () => {
  const cases = [
    ["qr", /scan qr/i],
    ["email", /analyze email/i],
    ["voice", /analyze voice/i],
    ["screenshot", /analyze screenshot/i],
  ];
  for (const [type, buttonName] of cases) {
    const { unmount } = wrap(<Scan />, [`/scan?type=${type}`]);
    expect(screen.getByRole("button", { name: buttonName })).toBeInTheDocument();
    unmount();
  }
});

// ---------------------------------------------------------------------------
// Unified Email box (WORK_PLAN Task 8): upload + inbox in ONE panel
// ---------------------------------------------------------------------------
test("the email box has upload and inbox modes in one panel", () => {
  wrap(<Scan />, ["/scan?type=email"]);

  // upload mode is the default
  expect(screen.getByRole("button", { name: /analyze email/i })).toBeInTheDocument();

  // switching to the inbox mode shows the Gmail scanner without leaving the panel
  fireEvent.click(screen.getByRole("tab", { name: /scan inbox/i }));
  expect(screen.getByRole("button", { name: /scan gmail inbox/i })).toBeInTheDocument();
});

test("there is no separate Gmail card anymore, but ?type=gmail still works", () => {
  wrap(<Scan />, ["/scan?type=gmail"]);

  // the old deep link (Dashboard quick action) lands on the email box, inbox mode
  expect(screen.getByRole("button", { name: /scan gmail inbox/i })).toBeInTheDocument();
  // only ONE email-ish card in the type grid
  expect(screen.queryByRole("tab", { name: /^gmail$/i })).not.toBeInTheDocument();
  expect(screen.getByRole("tab", { name: /^email$/i })).toBeInTheDocument();
});
