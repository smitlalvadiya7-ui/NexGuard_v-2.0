import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { VerdictBadge } from "../src/components/VerdictBadge.jsx";
import { RiskMeter } from "../src/components/RiskMeter.jsx";
import { FlagList } from "../src/components/FlagList.jsx";
import { LockOverlay } from "../src/components/LockOverlay.jsx";
import { ResultPanel } from "../src/components/ResultPanel.jsx";

function withRouter(ui) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

// ---------------------------------------------------------------------------
// VerdictBadge — verdict -> style/label mapping (all four cases)
// ---------------------------------------------------------------------------
describe("VerdictBadge", () => {
  test("SAFE renders a safe-styled badge", () => {
    render(<VerdictBadge verdict="SAFE" />);
    const badge = screen.getByText(/^safe$/i);
    expect(badge).toHaveClass("text-safe");
  });

  test("SUSPICIOUS renders a warn-styled badge", () => {
    render(<VerdictBadge verdict="SUSPICIOUS" />);
    const badge = screen.getByText(/^suspicious$/i);
    expect(badge).toHaveClass("text-warn");
  });

  test("MALICIOUS renders a danger-styled badge", () => {
    render(<VerdictBadge verdict="MALICIOUS" />);
    const badge = screen.getByText(/^malicious$/i);
    expect(badge).toHaveClass("text-danger");
  });

  test("an unrecognized verdict (e.g. ERROR/unknown/missing) renders a muted ERROR badge", () => {
    render(<VerdictBadge verdict="ERROR" />);
    const badge = screen.getByText(/^error$/i);
    expect(badge).toHaveClass("text-muted");

    render(<VerdictBadge verdict={undefined} />);
    expect(screen.getAllByText(/^error$/i).length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// RiskMeter — 0-100 bar, color by threshold, numeric score shown
// ---------------------------------------------------------------------------
describe("RiskMeter", () => {
  test("shows the numeric score", () => {
    render(<RiskMeter score={57} />);
    expect(screen.getByText("57")).toBeInTheDocument();
  });

  test("scores under 40 use the safe color", () => {
    render(<RiskMeter score={10} />);
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "10");
    expect(document.querySelector(".bg-safe")).not.toBeNull();
  });

  test("scores from 40-69 use the warn color", () => {
    render(<RiskMeter score={55} />);
    expect(document.querySelector(".bg-warn")).not.toBeNull();
  });

  test("scores 70+ use the danger color", () => {
    render(<RiskMeter score={90} />);
    expect(document.querySelector(".bg-danger")).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// FlagList — compact list; empty/undefined renders nothing
// ---------------------------------------------------------------------------
describe("FlagList", () => {
  test("renders each flag", () => {
    render(<FlagList flags={["Newly registered domain", "No SSL certificate"]} />);
    expect(screen.getByText(/newly registered domain/i)).toBeInTheDocument();
    expect(screen.getByText(/no ssl certificate/i)).toBeInTheDocument();
  });

  test("renders nothing for an empty array", () => {
    const { container } = render(<FlagList flags={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  test("renders nothing when flags is undefined", () => {
    const { container } = render(<FlagList flags={undefined} />);
    expect(container).toBeEmptyDOMElement();
  });
});

// ---------------------------------------------------------------------------
// LockOverlay — CTA when locked, plain children when not
// ---------------------------------------------------------------------------
describe("LockOverlay", () => {
  test("locked renders the Upgrade to Premium CTA linking to /settings", () => {
    withRouter(
      <LockOverlay locked>
        <p>secret intel</p>
      </LockOverlay>
    );
    const cta = screen.getByRole("link", { name: /upgrade to premium/i });
    expect(cta).toHaveAttribute("href", "/settings");
  });

  test("not locked renders children plainly with no CTA", () => {
    withRouter(
      <LockOverlay locked={false}>
        <p>visible intel</p>
      </LockOverlay>
    );
    expect(screen.getByText(/visible intel/i)).toBeInTheDocument();
    expect(screen.queryByText(/upgrade to premium/i)).not.toBeInTheDocument();
  });

  test("not locked with no children at all does not crash", () => {
    expect(() => withRouter(<LockOverlay locked={false} />)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// ResultPanel — single renderer for a full scan result
// ---------------------------------------------------------------------------
describe("ResultPanel", () => {
  const fullResult = {
    url: "https://example.com/login",
    domain: "example.com",
    resolved_ip: "93.184.216.34",
    verdict: "SUSPICIOUS",
    risk_score: 55,
    confidence: 80,
    ml_probability: 0.61,
    plain_summary: "Suspicious: newly registered domain with a free certificate.",
    sources: [
      { name: "VirusTotal", status: "flag", detail: "2/92 engines flagged" },
      { name: "Safe Browsing", status: "clean", detail: "not listed" },
      { name: "URLHaus", status: "clean", detail: "clean" },
      { name: "Community Blocklist", status: "clean", detail: "clean" },
    ],
    explainability: {
      method: "shap",
      ml_probability: 0.61,
      top_features: [
        { feature: "tld_risk", value: "3", contribution: 0.12 },
        { feature: "nb_hyphens", value: "2", contribution: 0.05 },
        { feature: "ng_042", value: "1", contribution: 0.03 },
      ],
    },
    flags: ["Newly registered domain", "Free SSL certificate authority"],
    ip_location: "Ashburn, US",
    ip_country: "US",
    asn: "AS15133",
    hosting: "Edgecast Inc.",
    whois: {
      registrar: "Example Registrar LLC",
      age: "12 days",
      age_days: 12,
      created: "2026-07-02",
      country: "US",
    },
    ssl_cert: {
      has_cert: true,
      issuer: "Let's Encrypt",
      is_free_ca: true,
      issued: "2026-07-01",
      expires: "2026-10-01",
      subject_cn: "example.com",
    },
    // Production-true shape (aggregator.py:695, :1167-1168): `redirects` is
    // [] or the FULL >=2-hop chain, and `redirect_chain` duplicates it.
    redirects: ["https://example.com/login", "https://example.com/login/final"],
    redirect_chain: ["https://example.com/login", "https://example.com/login/final"],
    screenshot_url: "https://cdn.example.com/shot.png",
    page_title: "Example — Sign in",
    tier_locked: ["resolved_ip"],
  };

  test("renders header verdict, risk score, confidence and the scanned target", () => {
    withRouter(<ResultPanel result={fullResult} />);
    expect(screen.getByText(/^suspicious$/i)).toBeInTheDocument();
    expect(screen.getByText("55")).toBeInTheDocument();
    // confidence 80 -> High confidence, with the percentage shown
    expect(screen.getByText(/high confidence/i)).toBeInTheDocument();
    expect(screen.getByText(/80%/)).toBeInTheDocument();
    expect(screen.getByText("https://example.com/login")).toBeInTheDocument();
  });

  test("renders the flags list", () => {
    withRouter(<ResultPanel result={fullResult} />);
    // (also appears in the plain summary, so at least one match)
    expect(screen.getAllByText(/newly registered domain/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/free ssl certificate authority/i)).toBeInTheDocument();
  });

  test("shows a 'Why this verdict' section with the plain summary and readable ML factors", () => {
    withRouter(<ResultPanel result={fullResult} />);
    expect(screen.getByText(/why this verdict/i)).toBeInTheDocument();
    expect(screen.getByText(/newly registered domain with a free certificate/i)).toBeInTheDocument();
    // technical feature names are shown in plain language, not raw
    expect(screen.getByText(/risky top-level domain/i)).toBeInTheDocument();
    expect(screen.queryByText(/tld_risk/i)).not.toBeInTheDocument();
  });

  test("char-model factors show the actual URL text; hashed n-gram buckets stay generic", () => {
    const charResult = {
      ...fullResult,
      explainability: {
        method: "linear",
        ml_probability: 0.8,
        top_features: [
          { feature: "ng_login-", value: "login-", contribution: 0.21 },
          { feature: "ng_042", value: "1", contribution: 0.03 },
          { feature: "ng_hub", value: "hub", contribution: -0.05 },
        ],
      },
    };
    withRouter(<ResultPanel result={charResult} />);
    expect(screen.getByText(/suspicious text "login-" in the address/i)).toBeInTheDocument();
    expect(screen.getByText(/suspicious text pattern in the url/i)).toBeInTheDocument();
    expect(screen.getByText("+21%")).toBeInTheDocument();
    // safe-ward (negative) factors are filtered out of the risk list by design
    expect(screen.queryByText(/suspicious text "hub"/i)).not.toBeInTheDocument();
  });

  test("shows which threat-intel sources flagged the URL", () => {
    withRouter(<ResultPanel result={fullResult} />);
    expect(screen.getByText(/threat intelligence/i)).toBeInTheDocument();
    // every source is named; the flagged one carries its detail
    expect(screen.getByText("VirusTotal")).toBeInTheDocument();
    expect(screen.getByText("Safe Browsing")).toBeInTheDocument();
    expect(screen.getByText(/2\/92 engines flagged/i)).toBeInTheDocument();
  });

  test("locks only the tier_locked section (resolved_ip) behind a single overlay CTA", () => {
    withRouter(<ResultPanel result={fullResult} />);
    // Exactly one section is gated -> exactly one CTA on the page.
    expect(screen.getAllByRole("link", { name: /upgrade to premium/i })).toHaveLength(1);
  });

  test("unlocked premium sections render their real data plainly", () => {
    withRouter(<ResultPanel result={fullResult} />);
    expect(screen.getByText(/example registrar llc/i)).toBeInTheDocument();
    expect(screen.getByText(/let's encrypt/i)).toBeInTheDocument();
    expect(screen.getByText(/ashburn, us/i)).toBeInTheDocument();
  });

  // Backend contract (aggregator.py:695, :1167-1168): `redirects` is either
  // [] (no hops) or the FULL chain of >=2 URLs, and it is the field
  // strip_premium() gates. It is therefore the only redirect source the UI
  // may read, and any entries in it must all be visible when unlocked.
  test("an unlocked multi-hop redirect chain renders every hop URL", () => {
    withRouter(<ResultPanel result={fullResult} />);
    expect(screen.getByText(/^redirect chain$/i)).toBeInTheDocument();
    expect(screen.getByText("1. https://example.com/login")).toBeInTheDocument();
    expect(screen.getByText("2. https://example.com/login/final")).toBeInTheDocument();
  });

  test("redirects: [] hides the redirect-chain section entirely (redirect_chain is never a data source)", () => {
    // Production emits redirects=[] only when the chain had a single entry,
    // but the component contract is stronger: redirect_chain is NEVER read,
    // so even a (hypothetical) populated one must not resurrect the section
    // when the gated `redirects` field says there are no hops.
    const noHops = {
      verdict: "SAFE",
      risk_score: 3,
      flags: [],
      redirects: [],
      redirect_chain: ["https://a.example/", "https://b.example/"],
      tier_locked: [],
    };
    withRouter(<ResultPanel result={noHops} />);
    expect(screen.queryByText(/redirect chain/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/a\.example/)).not.toBeInTheDocument();
  });

  test("does not crash on a minimal result and hides empty premium sections", () => {
    withRouter(<ResultPanel result={{ verdict: "SAFE", risk_score: 0, flags: [] }} />);
    expect(screen.getByText(/^safe$/i)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /upgrade to premium/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/resolved ip/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/geolocation/i)).not.toBeInTheDocument();
  });

  test("does not crash when result is null/undefined", () => {
    expect(() => withRouter(<ResultPanel result={null} />)).not.toThrow();
    expect(() => withRouter(<ResultPanel result={undefined} />)).not.toThrow();
  });

  // Backend note: strip_premium() nulls "redirects" for a locked viewer but
  // does NOT strip "redirect_chain" (it isn't in _PREMIUM_FIELDS). A naive
  // implementation that displays redirect_chain would leak the real chain
  // underneath the blur even though the section is reported as locked.
  test("a locked redirect-chain section never leaks real hops via the un-stripped redirect_chain field", () => {
    const locked = {
      verdict: "SUSPICIOUS",
      risk_score: 50,
      flags: [],
      redirects: null,
      redirect_chain: ["https://example.com/a", "https://evil-real-hop.example/b"],
      tier_locked: ["redirects"],
    };
    withRouter(<ResultPanel result={locked} />);
    expect(screen.getByRole("link", { name: /upgrade to premium/i })).toBeInTheDocument();
    expect(screen.queryByText(/evil-real-hop/i)).not.toBeInTheDocument();
  });
});
