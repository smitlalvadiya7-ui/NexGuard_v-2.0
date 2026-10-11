import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import { initTheme } from "./theme.js";
import "./styles/index.css";

initTheme();

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
