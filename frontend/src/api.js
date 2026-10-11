const TOKEN_KEY = "nexguard.token";

export const API_BASE =
  import.meta.env.VITE_API_BASE ??
  (import.meta.env.DEV ? "http://127.0.0.1:8000" : "");

export function wsUrl(path) {
  const base = API_BASE || window.location.origin;
  return base.replace(/^http/, "ws") + path;
}

export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

export class FreeLimitError extends Error {
  constructor(info) {
    super((info && (info.message || info.detail)) || "Free daily scan limit reached");
    this.name = "FreeLimitError";
    this.info = info;
  }
}

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

let onUnauthorized = null;

export function setOnUnauthorized(fn) {
  onUnauthorized = fn;
}

function extractMessage(data, status) {
  return (data && (data.detail || data.message)) || `HTTP ${status}`;
}

export async function apiFetch(path, { method = "GET", body, headers = {} } = {}) {
  const isFormData = typeof FormData !== "undefined" && body instanceof FormData;
  const isPlainBody = body !== undefined && body !== null && typeof body === "object" && !isFormData;

  const finalHeaders = { ...headers };
  let finalBody = body;

  if (isPlainBody) {
    finalHeaders["Content-Type"] = "application/json";
    finalBody = JSON.stringify(body);
  }

  const token = getToken();
  if (token) {
    finalHeaders.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(API_BASE + path, {
    method,
    headers: finalHeaders,
    body: finalBody,
  });

  if (res.status === 204) {
    return null;
  }

  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }

  if (res.status === 429 && data && data.error === "free_limit") {
    throw new FreeLimitError(data);
  }

  if (res.status === 401) {
    if (onUnauthorized) onUnauthorized();
    throw new ApiError(401, extractMessage(data, 401));
  }

  if (!res.ok) {
    throw new ApiError(res.status, extractMessage(data, res.status));
  }

  return data;
}

// Authenticated file download. Defaults to GET; pass {method, body} for
// endpoints like POST /export-report that stream a PDF back from a JSON body.
export async function downloadBlob(path, filename, { method = "GET", body } = {}) {
  const token = getToken();
  const headers = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const options = { method, headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }

  const res = await fetch(API_BASE + path, options);

  if (!res.ok) {
    let data = null;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    throw new ApiError(res.status, extractMessage(data, res.status));
  }

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
