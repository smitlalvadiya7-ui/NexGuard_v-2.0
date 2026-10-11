import { useEffect, useRef } from "react";
import { getToken, wsUrl } from "../api.js";

/*
 * Live-alert WebSocket hook (backend/main.py /ws/live-alerts).
 * Opens the socket once per mount, JSON-parses each frame and forwards it to
 * onAlert — except the server's 20s {type:"heartbeat"} keep-alives, which no
 * consumer cares about. Reconnects with capped exponential backoff
 * (1s → 30s; a successful open resets it) and tears everything down on
 * unmount. onAlert is kept in a ref so consumers may pass a fresh closure
 * every render without re-opening the socket.
 *
 * The feed is per-user: the server requires a JWT on the handshake and only
 * sends a user their own alerts, so signed-out visitors open no socket at all
 * rather than retry-looping against a handshake that will always be refused.
 * A WebSocket handshake carries no Authorization header, hence ?token=.
 */
export default function useLiveAlerts(onAlert) {
  const cbRef = useRef(onAlert);
  cbRef.current = onAlert;

  useEffect(() => {
    if (typeof WebSocket === "undefined") return undefined;

    let ws = null;
    let timer = null;
    let attempt = 0;
    let stopped = false;

    function connect() {
      if (stopped) return;
      const token = getToken();
      if (!token) return; // signed out — the server would refuse the handshake
      ws = new WebSocket(
        wsUrl(`/ws/live-alerts?token=${encodeURIComponent(token)}`),
      );
      ws.onopen = () => {
        attempt = 0;
      };
      ws.onmessage = (event) => {
        let payload;
        try {
          payload = JSON.parse(event.data);
        } catch {
          return;
        }
        if (payload && payload.type !== "heartbeat") {
          cbRef.current?.(payload);
        }
      };
      ws.onclose = () => {
        if (stopped) return;
        const delay = Math.min(1000 * 2 ** attempt, 30000);
        attempt += 1;
        timer = setTimeout(connect, delay);
      };
    }

    connect();

    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      try {
        ws?.close();
      } catch {
        /* already closed */
      }
    };
  }, []);
}
