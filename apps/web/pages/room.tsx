import { useRouter } from "next/router";
import { useCallback, useEffect, useRef, useState } from "react";

import { TerminalPanel } from "../components/TerminalPanel.tsx";
import {
  type ApiResult,
  type RoomStatus,
  describeFailure,
  enterRoom,
  getRoomStatus,
  leaveRoom,
  resetRoom,
  signOut,
  verifyRecovery,
} from "../lib/api.ts";
import { useHydrated } from "../lib/use-hydrated.ts";

// The only reviewed Room this runtime serves.
const ROOM_ID = "disk-full";
// A new terminal attaches only while the sandbox is ready or running.
const ATTACHABLE = new Set(["READY", "RUNNING"]);
// An open terminal closes once the Room is being reset or left.
const ENDING = new Set(["RESETTING", "STOPPING", "DESTROYED", "FAILED"]);
// An ended Room changes no more.
const ENDED = new Set(["DESTROYED", "FAILED"]);
// A live Room changes on its own only when it ends at its end time; the other
// states change on their own, so the page polls Room Status meanwhile.
const LIVE = new Set(["READY", "RUNNING", "RESOLVED"]);
const POLL_MILLISECONDS = 2000;
const END_GRACE_MILLISECONDS = 1000;

export default function RoomPage() {
  const router = useRouter();
  // The query is read only after hydration; the exported HTML knows none.
  const ready = useHydrated() && router.isReady;
  const attemptId =
    ready && typeof router.query.attempt === "string" ? router.query.attempt : null;
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const signedOut = useCallback(() => {
    void router.replace({ pathname: "/", query: { ended: "1" } });
  }, [router]);

  async function enter() {
    setBusy(true);
    setMessage("");
    const result = await enterRoom(ROOM_ID);
    setBusy(false);
    if (result.ok) {
      await router.replace({ pathname: "/room/", query: { attempt: result.value.attemptId } });
    } else if (result.status === 401) {
      signedOut();
    } else {
      setMessage(describeFailure(result));
    }
  }

  async function signOutNow() {
    const result = await signOut();
    if (result.ok || result.status === 401) {
      await router.replace("/");
    } else {
      setMessage(describeFailure(result));
    }
  }

  return (
    <main className="page">
      <header className="masthead">
        <h1>Failroom</h1>
        <button type="button" className="quiet" onClick={() => void signOutNow()}>
          Sign out
        </button>
      </header>
      {ready && !attemptId ? (
        <section className="panel" aria-labelledby="room-heading">
          <h2 id="room-heading">Disk Full Room</h2>
          <p>A service&apos;s disk is full. Investigate it in a real terminal and recover it.</p>
          <button type="button" disabled={busy} onClick={() => void enter()}>
            Enter Room
          </button>
        </section>
      ) : null}
      {message ? (
        <p className="notice" role="alert">
          {message}
        </p>
      ) : null}
      {attemptId ? (
        // Keyed by attempt, so another attempt starts from a clean view.
        <AttemptView
          key={attemptId}
          attemptId={attemptId}
          onSignedOut={signedOut}
          onEnterAgain={() => void router.replace("/room/")}
        />
      ) : null}
    </main>
  );
}

type AttemptProps = {
  attemptId: string;
  onSignedOut: () => void;
  onEnterAgain: () => void;
};

function AttemptView({ attemptId, onSignedOut, onEnterAgain }: AttemptProps) {
  const [status, setStatus] = useState<RoomStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  const apply = useCallback(
    (result: ApiResult<RoomStatus>): RoomStatus | null => {
      if (result.ok) {
        setStatus(result.value);
        return result.value;
      }
      if (result.status === 401) {
        onSignedOut();
      } else {
        setMessage(describeFailure(result));
      }
      return null;
    },
    [onSignedOut],
  );

  // Status requests overlap, for example a refresh after the terminal closes
  // and the action that closed it; only the latest one's answer is applied, so
  // an older answer never replaces a newer one.
  const latest = useRef(0);
  const settle = useCallback(
    async (call: () => Promise<ApiResult<RoomStatus>>): Promise<RoomStatus | null> => {
      const ticket = ++latest.current;
      const result = await call();
      return ticket === latest.current ? apply(result) : null;
    },
    [apply],
  );

  const refresh = useCallback(async () => {
    await settle(() => getRoomStatus(attemptId));
  }, [attemptId, settle]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!status || ENDED.has(status.state)) {
      return;
    }
    const end = Date.parse(status.expiresAt);
    const delay =
      LIVE.has(status.state) && Number.isFinite(end)
        ? Math.max(POLL_MILLISECONDS, end - Date.now() + END_GRACE_MILLISECONDS)
        : POLL_MILLISECONDS;
    const timer = window.setTimeout(() => void refresh(), delay);
    return () => window.clearTimeout(timer);
  }, [status, refresh]);

  async function act(
    action: () => Promise<ApiResult<RoomStatus>>,
  ): Promise<RoomStatus | null> {
    setBusy(true);
    setMessage("");
    const result = await settle(action);
    setBusy(false);
    return result;
  }

  async function verify() {
    const verified = await act(() => verifyRecovery(attemptId));
    if (verified?.state === "RESOLVED") {
      setMessage("Recovery verified. The Room is resolved.");
    }
  }

  async function reset() {
    if (window.confirm("Reset Room? The sandbox is replaced and the terminal closes.")) {
      await act(() => resetRoom(attemptId));
    }
  }

  async function leave() {
    if (window.confirm("Leave Room? The sandbox is destroyed.")) {
      await act(() => leaveRoom(attemptId));
    }
  }

  const ended = status !== null && ENDED.has(status.state);
  return (
    <>
      <section className="panel" aria-labelledby="status-heading">
        <div className="panel-header">
          <h2 id="status-heading">Room Status</h2>
          <span className="badge" role="status">
            {status ? status.state : "Loading"}
          </span>
        </div>
        {status ? (
          <dl className="facts">
            <dt>Room</dt>
            <dd>{status.roomId}</dd>
            <dt>Ends at</dt>
            <dd>{new Date(status.expiresAt).toLocaleString()}</dd>
            <dt>Leaving</dt>
            <dd>{status.destroyIntent ? "Yes" : "No"}</dd>
          </dl>
        ) : null}
        <div className="actions">
          <button type="button" className="quiet" disabled={busy} onClick={() => void refresh()}>
            Refresh
          </button>
          <button type="button" disabled={busy || ended} onClick={() => void verify()}>
            Verify recovery
          </button>
          <button type="button" disabled={busy || ended} onClick={() => void reset()}>
            Reset Room
          </button>
          <button
            type="button"
            className="danger"
            disabled={busy || ended}
            onClick={() => void leave()}
          >
            Leave Room
          </button>
        </div>
        {ended ? (
          <p>
            This Room has ended.{" "}
            <button type="button" className="link" onClick={onEnterAgain}>
              Enter the Room again
            </button>
          </p>
        ) : null}
        {message ? (
          <p className="notice" role="alert">
            {message}
          </p>
        ) : null}
      </section>
      <TerminalPanel
        attemptId={attemptId}
        connectable={!busy && status !== null && ATTACHABLE.has(status.state)}
        retained={status === null || !ENDING.has(status.state)}
        onSignedOut={onSignedOut}
        onClosed={() => void refresh()}
      />
    </>
  );
}
