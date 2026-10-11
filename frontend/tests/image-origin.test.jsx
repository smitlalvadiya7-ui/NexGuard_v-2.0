import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import ImageOriginPanel from "../src/pages/Scan/ImageOriginPanel.jsx";
import Scan from "../src/pages/Scan/index.jsx";
import { ToastProvider } from "../src/components/Toast.jsx";

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

function pickFile(name = "pic.png") {
  fireEvent.change(screen.getByTestId("dropzone-input"), {
    target: { files: [new File(["png-bytes"], name, { type: "image/png" })] },
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
});

test("ImageOriginPanel posts to /analyze-image-origin and shows a confirmed AI verdict with the generator link", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      verdict: "AI_GENERATED",
      confidence: 100,
      generator: "Midjourney",
      generator_link: "https://www.midjourney.com",
      ai_probability: null,
      reasons: ["The file's metadata names Midjourney as the creator — proof it was AI-generated."],
      actions: [
        { label: "Verify Content Credentials yourself", url: "https://contentcredentials.org/verify" },
      ],
      analysis: "AI-generated — confirmed by the file's own metadata, made with Midjourney.",
    })
  );
  wrap(<ImageOriginPanel />);

  pickFile();
  fireEvent.click(screen.getByRole("button", { name: /check image/i }));

  expect(await screen.findByText(/AI-generated — confirmed/i)).toBeInTheDocument();
  const [url, opts] = global.fetch.mock.calls[0];
  expect(url).toContain("/analyze-image-origin");
  expect(opts.body).toBeInstanceOf(FormData);
  const genLink = screen.getByRole("link", { name: /midjourney/i });
  expect(genLink).toHaveAttribute("href", "https://www.midjourney.com");
  expect(screen.getByText(/names Midjourney as the creator/i)).toBeInTheDocument();
});

test("ImageOriginPanel shows LIKELY_REAL with confidence and the why list", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      verdict: "LIKELY_REAL",
      confidence: 95,
      generator: null,
      generator_link: null,
      ai_probability: 8,
      reasons: ["Camera EXIF present: Apple iPhone 13 — points to a real photo."],
      actions: [],
      analysis: "Likely a real photo (confidence 95%).",
    })
  );
  wrap(<ImageOriginPanel />);

  pickFile("photo.jpg");
  fireEvent.click(screen.getByRole("button", { name: /check image/i }));

  expect(await screen.findAllByText(/likely a real photo/i)).not.toHaveLength(0);
  expect(screen.getByText("confidence 95%")).toBeInTheDocument();
  expect(screen.getByText(/iPhone 13/)).toBeInTheDocument();
});

test("ImageOriginPanel is honest on UNCERTAIN and always shows the action links", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      verdict: "UNCERTAIN",
      confidence: 0,
      generator: null,
      generator_link: null,
      ai_probability: 55,
      reasons: ["No provenance metadata, no camera EXIF and no strong visual cues were found."],
      actions: [
        { label: "Verify Content Credentials yourself", url: "https://contentcredentials.org/verify" },
        { label: "Reverse-search with Google Lens", url: "https://lens.google.com" },
        { label: "Reverse-search with TinEye", url: "https://tineye.com" },
        { label: "Being used in a scam? Report it via the Support page", url: null },
      ],
      analysis: "Not enough evidence either way — metadata, the local detector model and visual cues were checked.",
    })
  );
  wrap(<ImageOriginPanel />);

  pickFile();
  fireEvent.click(screen.getByRole("button", { name: /check image/i }));

  expect(await screen.findByText(/not enough evidence/i)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /google lens/i }))
    .toHaveAttribute("href", "https://lens.google.com");
  expect(screen.getByRole("link", { name: /tineye/i }))
    .toHaveAttribute("href", "https://tineye.com");
  expect(screen.getByText(/report it via the support page/i)).toBeInTheDocument();
});

test("ImageOriginPanel renders FreeLimitCard on a 429 free_limit response", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(429, { error: "free_limit", message: "Upgrade to Premium for unlimited scans." })
  );
  wrap(<ImageOriginPanel />);

  pickFile();
  fireEvent.click(screen.getByRole("button", { name: /check image/i }));

  expect(await screen.findByText(/daily free limit reached/i)).toBeInTheDocument();
});

test("Scan page offers the AI Image tab and mounts the panel", () => {
  wrap(<Scan />, ["/scan?type=aiimage"]);
  expect(screen.getByRole("tab", { name: /ai image/i })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /check image/i })).toBeInTheDocument();
});
