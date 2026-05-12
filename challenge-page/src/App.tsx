import { useEffect, useRef } from "react";
import Cookies from "js-cookie";
import "altcha";
import "altcha/types/react";
import type { Payload } from "altcha/types";

import "./App.css";

function App() {
  const widgetRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const el = widgetRef.current;
    if (!el) return;

    const onVerified = async (e: Event) => {
      const payload = (e as CustomEvent<{ payload: string }>).detail.payload;

      const decoded = JSON.parse(atob(payload)) as Payload;

      let expires = new Date(Date.now() + 5 * 60 * 1000);
      if (decoded.challenge?.parameters?.expiresAt) {
        expires = new Date(decoded.challenge.parameters.expiresAt * 1000);
      }

      Cookies.set("altcha", payload, {
        path: "/",
        sameSite: "lax",
        expires,
      });

      try {
        const res = await fetch("/altcha/verify", {
          credentials: "same-origin",
        });
        const data: { verified?: boolean } = await res.json().catch(() => ({}));
        if (res.ok && data.verified) {
          setTimeout(() => location.reload(), 400);
        }
      } catch (err) {
        console.error(`Network error: ${String(err)}`);
      }
    };

    const onState = (e: Event) => {
      const state = (e as CustomEvent<{ state: string }>).detail.state;
      if (state === "error" || state === "expired") {
        console.error("Challenge expired, please try again.");
      }
    };

    el.addEventListener("verified", onVerified);
    el.addEventListener("statechange", onState);

    return () => {
      el.removeEventListener("verified", onVerified);
      el.removeEventListener("statechange", onState);
    };
  }, []);

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-linear-to-br from-slate-50 via-white to-indigo-50 dark:from-slate-950 dark:via-slate-900 dark:to-indigo-950">
      <div className="w-full max-w-md">
        <h1 className="mt-5 text-center text-xl font-semibold tracking-tight text-slate-900 dark:text-slate-50">
          Please confirm you&rsquo;re human
        </h1>
        <div className="mt-7 flex justify-center">
          <altcha-widget
            ref={widgetRef}
            challenge="http://localhost:8080/altcha/challenge"
            configuration='{"hideLogo":true,"hideFooter":true}'
          ></altcha-widget>
        </div>
      </div>
    </div>
  );
}

export default App;
