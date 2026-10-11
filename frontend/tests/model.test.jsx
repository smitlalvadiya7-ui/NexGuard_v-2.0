import { render, screen, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import Model from "../src/pages/Model.jsx";
import ConfusionMatrix from "../src/components/ConfusionMatrix.jsx";
import { ToastProvider } from "../src/components/Toast.jsx";

function mockResponse(status, body) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    headers: { get: () => "application/json" },
  });
}

const offlineFixture = {
  available: true,
  model: "SoftVotingEnsemble",
  selection_metric: "roc_auc",
  generated_at: "2026-06-10T11:19:34.769000+00:00",
  headline: { accuracy: 0.8915, precision: 0.8978, recall: 0.8836, f1: 0.8907, roc_auc: 0.9612 },
  models: {
    RandomForest: { accuracy: 0.8749, precision: 0.8762, recall: 0.8731, f1: 0.8747, roc_auc: 0.9531 },
    XGBoost: { accuracy: 0.8937, precision: 0.8968, recall: 0.8898, f1: 0.8933, roc_auc: 0.9601 },
    SoftVotingEnsemble: { accuracy: 0.8915, precision: 0.8978, recall: 0.8836, f1: 0.8907, roc_auc: 0.9612 },
  },
  dataset: { n_samples: 11430, n_phishing: 5715, n_legitimate: 5715, n_features: 24, test_size: 0.2, n_test: 2286 },
  confusion_matrix: { labels: ["legitimate", "phishing"], matrix: [[1021, 122], [124, 1019]], tn: 1021, fp: 122, fn: 124, tp: 1019 },
  roc_curve: { fpr: [0, 0.1, 1], tpr: [0, 0.8, 1], thresholds: [1, 0.5, 0] },
  feature_importances: [
    { feature: "nb_digits", importance: 0.10177 },
    { feature: "nb_phish_hints", importance: 0.1016 },
  ],
};

const realworldFixture = {
  available: true,
  generated_at: "2026-07-14T14:29:38.365434+00:00",
  evaluated_on_date: "2026-07-14",
  precision: 0.9737,
  recall: 0.9737,
  f1: 0.9737,
  false_positive_rate: 0.0116,
  false_negative_rate: 0.0263,
  true_positive_rate: 0.9737,
  median_scan_time_ms: 3106,
  p95_scan_time_ms: 5859,
  wall_time_s: 109.4,
  threat_positive_class: "verdict in {SUSPICIOUS, MALICIOUS}",
  confusion_matrix: { tp: 37, fp: 1, tn: 85, fn: 1 },
  counts: { legit_total: 86, legit_scored: 86, legit_errors: 0, phish_total: 40, phish_scored: 38, phish_dead_excluded: 2, phish_errors: 0 },
  examples: {
    false_positives: ["https://googledomains.com"],
    false_negatives: ["https://metmskaiilizwalet.gitbook.io/"],
  },
  dataset_sources: { legit: "tranco", phish: "openphish" },
};

function mockBoth(offline = offlineFixture, realworld = realworldFixture) {
  global.fetch = vi.fn((url) => {
    const u = String(url);
    if (u.endsWith("/model-metrics")) return mockResponse(200, offline);
    if (u.endsWith("/model-metrics-realworld")) return mockResponse(200, realworld);
    return mockResponse(404, {});
  });
}

async function renderModel() {
  await act(async () => {
    render(
      <ToastProvider>
        <MemoryRouter>
          <Model />
        </MemoryRouter>
      </ToastProvider>
    );
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
});

test("ConfusionMatrix renders all four quadrants with labels", () => {
  render(<ConfusionMatrix tp={37} fp={1} tn={85} fn={2} />);

  expect(screen.getByText("37")).toBeInTheDocument();
  expect(screen.getByText("85")).toBeInTheDocument();
  expect(screen.getByText("2")).toBeInTheDocument();
  expect(screen.getByText(/true positives/i)).toBeInTheDocument();
  expect(screen.getByText(/false negatives/i)).toBeInTheDocument();
});

test("renders offline headline tiles, best model and the comparison table", async () => {
  mockBoth();
  await renderModel();

  expect(screen.getAllByText("SoftVotingEnsemble").length).toBeGreaterThanOrEqual(1);
  // headline accuracy 0.8915 -> 89.1% (toFixed on the float 89.1499…);
  // appears in the tile and again in the ensemble's comparison-table row
  expect(screen.getAllByText("89.1%").length).toBeGreaterThanOrEqual(1);
  expect(screen.getByText("RandomForest")).toBeInTheDocument();
  expect(screen.getByText("XGBoost")).toBeInTheDocument();
  // offline confusion matrix counts
  expect(screen.getByText("1,021")).toBeInTheDocument();
  expect(screen.getByText("1,019")).toBeInTheDocument();
});

test("renders real-world metric tiles and FP/FN example lists", async () => {
  mockBoth();
  await renderModel();

  // precision/recall/f1 are all 97.4% in the fixture
  expect(screen.getAllByText("97.4%").length).toBeGreaterThanOrEqual(1);
  expect(screen.getByText("https://googledomains.com")).toBeInTheDocument();
  expect(screen.getByText("https://metmskaiilizwalet.gitbook.io/")).toBeInTheDocument();
});

test("real-world results lead the page; offline is a labeled component benchmark", async () => {
  // WORK_PLAN Task 3: 97.37% real-world pipeline accuracy is the headline —
  // the 89% offline score is only the ML component and must say so.
  mockBoth();
  await renderModel();

  const realworldHeading = screen.getByText(/real-world evaluation/i);
  const offlineHeading = screen.getByText(/offline ml component benchmark/i);
  expect(
    realworldHeading.compareDocumentPosition(offlineHeading) &
      Node.DOCUMENT_POSITION_FOLLOWING
  ).toBeTruthy();
  // the offline section explains it is NOT the product's accuracy
  expect(screen.getAllByText(/full pipeline/i).length).toBeGreaterThanOrEqual(1);
});

test("shows a friendly empty state when metrics are unavailable", async () => {
  mockBoth({ available: false }, { available: false });
  await renderModel();

  expect(screen.getAllByText(/not available yet/i).length).toBeGreaterThanOrEqual(2);
});

test("shows the empty state when the endpoints fail entirely", async () => {
  global.fetch = vi.fn(() => mockResponse(500, { detail: "boom" }));
  await renderModel();

  expect(screen.getAllByText(/not available yet/i).length).toBeGreaterThanOrEqual(2);
});
