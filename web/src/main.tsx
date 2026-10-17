import React, { lazy, Suspense } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";

const Prototype = lazy(() => import("./prototype/App"));
const isPrototype = /^\/prototype(?:\/|$)/.test(window.location.pathname);
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    {isPrototype ? (
      <Suspense fallback={<p role="status">正在加载交互原型…</p>}>
        <Prototype />
      </Suspense>
    ) : (
      <App />
    )}
  </React.StrictMode>,
);
