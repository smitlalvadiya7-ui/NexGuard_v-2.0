import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthContext.jsx";
import { ToastProvider } from "./components/Toast.jsx";
import Layout from "./components/Layout.jsx";
import Login from "./pages/Login.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Scan from "./pages/Scan/index.jsx";
import Activity from "./pages/Activity/index.jsx";
import Reports from "./pages/Reports.jsx";
import Model from "./pages/Model.jsx";
import Settings from "./pages/Settings/index.jsx";
import Support from "./pages/Support.jsx";
import Admin from "./pages/Admin/index.jsx";

// Logged-out (user === null) bounces to /login. Anonymous (skip-auth) and any
// authenticated user object are both allowed through. The attempted location
// rides along in route state so Login can return there once a stored session
// finishes hydrating (during /auth/me revalidation `user` is still null, so
// deep links always pass through this redirect first).
export function RequireAuth({ children }) {
  const { user } = useAuth();
  const location = useLocation();
  if (user === null) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }
  return children;
}

// Only role admin/superadmin may pass; everyone else (including anonymous,
// whose role is not an object property) is sent back to the dashboard.
export function RequireAdmin({ children }) {
  const { user } = useAuth();
  const role = user && typeof user === "object" ? user.role : null;
  if (role !== "admin" && role !== "superadmin") {
    return <Navigate to="/" replace />;
  }
  return children;
}

// Router-less route tree so tests can render it inside a MemoryRouter; the
// real app wraps this in BrowserRouter (see App() below).
export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan" element={<Scan />} />
        <Route path="/activity" element={<Activity />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/model" element={<Model />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/support" element={<Support />} />
        <Route
          path="/admin"
          element={
            <RequireAdmin>
              <Admin />
            </RequireAdmin>
          }
        />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <BrowserRouter>
          <AppRoutes />
        </BrowserRouter>
      </ToastProvider>
    </AuthProvider>
  );
}
