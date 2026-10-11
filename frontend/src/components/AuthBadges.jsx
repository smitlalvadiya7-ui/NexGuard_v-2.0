/*
 * SPF / DKIM / DMARC chip row for email scan results (`result.auth_results`,
 * shape {spf, dkim, dmarc} with values pass|fail|softfail|none — see
 * backend/email_parser.py). Renders nothing when the result carries no
 * auth_results at all.
 */
function toneClass(value) {
  if (value === "pass") return "bg-safe/15 text-safe";
  if (value === "fail" || value === "softfail") return "bg-danger/15 text-danger";
  return "bg-muted/15 text-muted";
}

export default function AuthBadges({ auth }) {
  if (!auth || typeof auth !== "object") return null;

  return (
    <div className="flex flex-wrap items-center gap-3">
      {["spf", "dkim", "dmarc"].map((key) => (
        <span key={key} className="inline-flex items-center gap-1.5 text-xs">
          <span className="font-semibold uppercase tracking-wide text-muted">{key}</span>
          <span className={`rounded-full px-2 py-0.5 font-medium ${toneClass(auth[key])}`}>
            {auth[key] || "none"}
          </span>
        </span>
      ))}
    </div>
  );
}
