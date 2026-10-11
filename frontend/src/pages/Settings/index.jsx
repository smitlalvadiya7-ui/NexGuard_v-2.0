import Account from "./Account.jsx";
import ApiKeys from "./ApiKeys.jsx";

/*
 * Settings — account & plan (upgrade flows) + developer API keys. Composes
 * the two sections; each talks to its own endpoints (see Account.jsx and
 * ApiKeys.jsx headers).
 */
export default function Settings() {
  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="text-xl font-semibold">Settings</h1>
        <p className="text-sm text-muted">
          Manage your account, plan and developer API keys.
        </p>
      </header>

      <Account />
      <ApiKeys />
    </div>
  );
}
