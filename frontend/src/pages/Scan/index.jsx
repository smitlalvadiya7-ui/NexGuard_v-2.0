import { useSearchParams } from "react-router-dom";
import UrlPanel from "./UrlPanel.jsx";
import QrPanel from "./QrPanel.jsx";
import EmailHub from "./EmailHub.jsx";
import VoicePanel from "./VoicePanel.jsx";
import ScreenshotPanel from "./ScreenshotPanel.jsx";
import ImageOriginPanel from "./ImageOriginPanel.jsx";
import BatchPanel from "./BatchPanel.jsx";
import {
  LinkIcon,
  QrCodeIcon,
  MailIcon,
  MicIcon,
  ImageIcon,
  SparklesIcon,
  LayersIcon,
} from "../../components/Icons.jsx";

/*
 * Scan-type selector: a card grid instead of a cramped pill row. Each card
 * names the scanner and says in one line what it checks, so first-time users
 * can pick without guessing. aria-label keeps the tab's accessible name to
 * the short title (the description is visual detail, not part of the name).
 *
 * Email is ONE box (Task 8): upload + Gmail inbox live inside EmailHub.
 * The old ?type=gmail deep link (Dashboard quick action) stays working as an
 * alias that opens the email box in inbox mode.
 */
const TYPES = [
  { key: "url", label: "URL", desc: "Check a link before you open it", Icon: LinkIcon },
  { key: "qr", label: "QR code", desc: "Decode an image and scan its link", Icon: QrCodeIcon },
  { key: "email", label: "Email", desc: "Upload a mail or scan your inbox", Icon: MailIcon },
  { key: "voice", label: "Voice", desc: "Detect scam calls in audio", Icon: MicIcon },
  { key: "screenshot", label: "Screenshot", desc: "Analyze a message capture", Icon: ImageIcon },
  { key: "aiimage", label: "AI Image", desc: "Is this picture AI-made or real?", Icon: SparklesIcon },
  { key: "batch", label: "Batch", desc: "Scan many URLs at once", Icon: LayersIcon },
];

const VALID_KEYS = new Set(TYPES.map((t) => t.key));
const ALIASES = { gmail: "email" };

function cardClass(active) {
  return [
    "flex flex-col items-start gap-1.5 rounded-lg border p-3 text-left transition-colors",
    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent",
    active
      ? "border-accent bg-accent/10 text-text"
      : "border-border bg-panel text-muted hover:border-accent/40 hover:text-text",
  ].join(" ");
}

const PANELS = {
  url: UrlPanel,
  qr: QrPanel,
  email: EmailHub,
  voice: VoicePanel,
  screenshot: ScreenshotPanel,
  aiimage: ImageOriginPanel,
  batch: BatchPanel,
};

export default function Scan() {
  const [searchParams, setSearchParams] = useSearchParams();
  const requested = searchParams.get("type");
  const resolved = ALIASES[requested] || requested;
  const activeType = VALID_KEYS.has(resolved) ? resolved : "url";
  const ActivePanel = PANELS[activeType];
  // ?type=gmail opens the email box directly in inbox mode
  const initialMode = requested === "gmail" ? "inbox" : undefined;

  function selectType(key) {
    setSearchParams({ type: key });
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Scan</h1>
        <p className="mt-0.5 text-sm text-muted">Pick what you want to check.</p>
      </div>

      <div
        role="tablist"
        aria-label="Scan type"
        className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7"
      >
        {TYPES.map(({ key, label, desc, Icon }) => {
          const active = activeType === key;
          return (
            <button
              key={key}
              type="button"
              role="tab"
              aria-selected={active}
              aria-label={label}
              onClick={() => selectType(key)}
              className={cardClass(active)}
            >
              <span className="flex items-center gap-2">
                <Icon size={18} className={active ? "text-accent" : ""} />
                <span className="text-sm font-semibold">{label}</span>
              </span>
              <span className="text-xs leading-snug">{desc}</span>
            </button>
          );
        })}
      </div>

      <ActivePanel key={activeType + (initialMode || "")} initialMode={initialMode} />
    </div>
  );
}
