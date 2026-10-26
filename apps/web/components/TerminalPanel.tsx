import type { FitAddon } from "@xterm/addon-fit";
import type { Terminal } from "@xterm/xterm";
import { useCallback, useEffect, useRef, useState } from "react";

import { describeFailure, issueTerminal } from "../lib/api.ts";
import {
  type TerminalBounds,
  type TerminalSize,
  authorizeFrame,
  closeFrame,
  closeMessage,
  fitSize,
  inputFrames,
  parseServerMessage,
  resizeFrame,
  terminalUrl,
} from "../lib/terminal-protocol.ts";

type Connection = "idle" | "connecting" | "open" | "closed";

const LABELS: Record<Connection, string> = {
  idle: "Not connected",
  connecting: "Connecting",
  open: "Connected",
  closed: "Disconnected",
};

// The server ends a terminal whose sandbox goes away without saying why, so
// the Room's own state explains a close while it is reset or ended.
const ROOM_CLOSED = "The terminal closed because the Room was reset or ended.";
// The starting size while the terminal's element cannot be measured.
const STARTING_SIZE: TerminalSize = { rows: 24, columns: 80 };

type Props = {
  attemptId: string;
  /** Whether the Room can attach a new terminal now. */
  connectable: boolean;
  /** False once the Room is being reset or left; an open terminal closes. */
  retained: boolean;
  onSignedOut: () => void;
  /** Called whenever the terminal closes, so the page can learn why. */
  onClosed: () => void;
};

/**
 * A real PTY in the Room's sandbox, relayed over /v1/terminal. Each
 * connection uses a fresh single-use capability that is never stored.
 */
export function TerminalPanel({
  attemptId,
  connectable,
  retained,
  onSignedOut,
  onClosed,
}: Props) {
  const surface = useRef<HTMLDivElement>(null);
  const terminal = useRef<Terminal | null>(null);
  const fit = useRef<FitAddon | null>(null);
  const loaded = useRef<Promise<void> | null>(null);
  const socket = useRef<WebSocket | null>(null);
  const authorized = useRef(false);
  const bounds = useRef<TerminalBounds | null>(null);
  // The size the server last received; only a change is sent again.
  const sent = useRef<TerminalSize | null>(null);
  const retainedNow = useRef(retained);
  const [connection, setConnection] = useState<Connection>("idle");
  const [notice, setNotice] = useState("");
  const [closedByRoom, setClosedByRoom] = useState(false);

  /** Fit the terminal to its element within the bounds; null if unmeasurable. */
  const fitted = useCallback((): TerminalSize | null => {
    const opened = terminal.current;
    const proposed = fit.current?.proposeDimensions();
    const size = proposed
      ? fitSize({ rows: proposed.rows, columns: proposed.cols }, bounds.current)
      : null;
    if (!opened || !size) {
      return null;
    }
    if (size.rows !== opened.rows || size.columns !== opened.cols) {
      opened.resize(size.columns, size.rows);
    }
    return size;
  }, []);

  const resize = useCallback(() => {
    const size = fitted();
    const open = socket.current;
    if (!size || open?.readyState !== WebSocket.OPEN || !authorized.current) {
      return;
    }
    if (size.rows !== sent.current?.rows || size.columns !== sent.current?.columns) {
      open.send(resizeFrame(size.rows, size.columns));
      sent.current = size;
    }
  }, [fitted]);

  const disconnect = useCallback(() => {
    const open = socket.current;
    if (open?.readyState === WebSocket.OPEN && authorized.current) {
      // The server closes the socket once the PTY session has closed.
      open.send(closeFrame());
    } else {
      open?.close();
    }
  }, []);

  useEffect(() => {
    let disposed = false;
    let observer: ResizeObserver | null = null;
    loaded.current = (async () => {
      const [{ Terminal }, { FitAddon }] = await Promise.all([
        import("@xterm/xterm"),
        import("@xterm/addon-fit"),
      ]);
      const element = surface.current;
      if (disposed || !element) {
        return;
      }
      const opened = new Terminal({ cursorBlink: true, scrollback: 2000 });
      const fitAddon = new FitAddon();
      opened.loadAddon(fitAddon);
      opened.open(element);
      opened.onData((data) => {
        const open = socket.current;
        if (open?.readyState === WebSocket.OPEN && authorized.current && bounds.current) {
          for (const frame of inputFrames(data, bounds.current)) {
            open.send(frame);
          }
        }
      });
      terminal.current = opened;
      fit.current = fitAddon;
      observer = new ResizeObserver(resize);
      observer.observe(element);
      resize();
    })();
    return () => {
      disposed = true;
      observer?.disconnect();
      socket.current?.close();
      socket.current = null;
      terminal.current?.dispose();
      terminal.current = null;
      fit.current = null;
    };
  }, [resize]);

  useEffect(() => {
    retainedNow.current = retained;
    if (!retained) {
      disconnect();
    }
  }, [retained, disconnect]);

  const connect = useCallback(async () => {
    if (socket.current) {
      return;
    }
    setConnection("connecting");
    setNotice("");
    setClosedByRoom(false);
    const grant = await issueTerminal(attemptId);
    if (!grant.ok) {
      setConnection("closed");
      if (grant.status === 401) {
        onSignedOut();
      } else {
        setNotice(describeFailure(grant));
      }
      return;
    }
    bounds.current = grant.value.bounds;
    authorized.current = false;
    // The shell opens at the terminal's current size, sent with the
    // authorization: a resize sent right after it could be missed.
    await loaded.current;
    const size = fitted() ?? fitSize(STARTING_SIZE, grant.value.bounds) ?? STARTING_SIZE;
    sent.current = size;
    const opened = new WebSocket(terminalUrl(window.location));
    socket.current = opened;
    opened.onopen = () => opened.send(authorizeFrame(grant.value.capability, size));
    opened.onmessage = (event) => {
      const message = parseServerMessage(event.data);
      if (message?.type === "authorized") {
        authorized.current = true;
        setConnection("open");
        // Sends the size again only if it changed while connecting.
        resize();
        terminal.current?.focus();
      } else if (message?.type === "output") {
        terminal.current?.write(message.data);
      }
    };
    opened.onclose = (event) => {
      if (socket.current === opened) {
        socket.current = null;
      }
      authorized.current = false;
      setConnection("closed");
      setNotice(closeMessage(event.code));
      setClosedByRoom(!retainedNow.current);
      onClosed();
    };
  }, [attemptId, onSignedOut, onClosed, fitted, resize]);

  const active = connection === "connecting" || connection === "open";
  const shown = connection === "closed" && (closedByRoom || !retained) ? ROOM_CLOSED : notice;
  return (
    <section className="panel" aria-labelledby="terminal-heading">
      <div className="panel-header">
        <h2 id="terminal-heading">Terminal</h2>
        <span className="badge" role="status">
          {LABELS[connection]}
        </span>
        {active ? (
          <button type="button" onClick={disconnect}>
            Disconnect
          </button>
        ) : (
          <button type="button" onClick={() => void connect()} disabled={!connectable}>
            Connect terminal
          </button>
        )}
      </div>
      {shown ? <p className="notice">{shown}</p> : null}
      <div ref={surface} className="terminal-surface" />
    </section>
  );
}
