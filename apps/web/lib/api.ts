// Same-origin calls to the local runtime API described in
// services/control-plane/README.md. The browser sends the HttpOnly session
// cookie and its Origin on its own; this module never stores a credential.

import type { TerminalBounds } from "./terminal-protocol.ts";

export type RoomStatus = {
  attemptId: string;
  roomId: string;
  state: string;
  expiresAt: string;
  destroyIntent: boolean;
};

export type TerminalGrant = {
  capability: string;
  bounds: TerminalBounds;
};

export type ApiResult<T> =
  | { ok: true; value: T }
  | { ok: false; status: number; code: string };

type Reply = { status: number; body: unknown };

async function call(path: string, init: RequestInit): Promise<Reply | null> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    return null;
  }
  let body: unknown = null;
  if (response.status !== 204) {
    try {
      body = await response.json();
    } catch {
      body = null;
    }
  }
  return { status: response.status, body };
}

function field(body: unknown, name: string): unknown {
  return typeof body === "object" && body !== null
    ? (body as Record<string, unknown>)[name]
    : undefined;
}

function failure<T>(reply: Reply | null): ApiResult<T> {
  if (reply === null) {
    return { ok: false, status: 0, code: "NETWORK_ERROR" };
  }
  const code = field(reply.body, "code");
  return {
    ok: false,
    status: reply.status,
    code: typeof code === "string" ? code : `HTTP_${reply.status}`,
  };
}

function invalid<T>(reply: Reply): ApiResult<T> {
  return { ok: false, status: reply.status, code: "INVALID_RESPONSE" };
}

function roomStatus(body: unknown): RoomStatus | null {
  const attemptId = field(body, "attempt_id");
  const roomId = field(body, "room_id");
  const state = field(body, "state");
  const expiresAt = field(body, "expires_at");
  const destroyIntent = field(body, "destroy_intent") ?? false;
  if (
    typeof attemptId !== "string" ||
    typeof roomId !== "string" ||
    typeof state !== "string" ||
    typeof expiresAt !== "string" ||
    typeof destroyIntent !== "boolean"
  ) {
    return null;
  }
  return { attemptId, roomId, state, expiresAt, destroyIntent };
}

function terminalBounds(body: unknown): TerminalBounds | null {
  const rows = field(body, "rows");
  const columns = field(body, "columns");
  const inputBytes = field(body, "input_bytes");
  const frameBytes = field(body, "frame_bytes");
  if (
    !Number.isInteger(rows) ||
    !Number.isInteger(columns) ||
    !Number.isInteger(inputBytes) ||
    !Number.isInteger(frameBytes)
  ) {
    return null;
  }
  return {
    rows: rows as number,
    columns: columns as number,
    inputBytes: inputBytes as number,
    frameBytes: frameBytes as number,
  };
}

async function statusCall(
  path: string,
  init: RequestInit,
  expected: number,
): Promise<ApiResult<RoomStatus>> {
  const reply = await call(path, init);
  if (reply === null || reply.status !== expected) {
    return failure(reply);
  }
  const status = roomStatus(reply.body);
  return status === null ? invalid(reply) : { ok: true, value: status };
}

function attemptPath(attemptId: string, action: string): string {
  return `/v1/attempts/${encodeURIComponent(attemptId)}/${action}`;
}

function idempotent(): HeadersInit {
  return { "Idempotency-Key": crypto.randomUUID() };
}

export async function signIn(token: string): Promise<ApiResult<null>> {
  const reply = await call("/v1/session", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  return reply?.status === 201 ? { ok: true, value: null } : failure(reply);
}

export async function signOut(): Promise<ApiResult<null>> {
  const reply = await call("/v1/session", { method: "DELETE" });
  return reply?.status === 204 ? { ok: true, value: null } : failure(reply);
}

export function enterRoom(roomId: string): Promise<ApiResult<RoomStatus>> {
  return statusCall(
    `/v1/rooms/${encodeURIComponent(roomId)}/attempts`,
    { method: "POST", headers: idempotent() },
    201,
  );
}

export function getRoomStatus(attemptId: string): Promise<ApiResult<RoomStatus>> {
  return statusCall(attemptPath(attemptId, "status"), { method: "GET" }, 200);
}

export function resetRoom(attemptId: string): Promise<ApiResult<RoomStatus>> {
  return statusCall(
    attemptPath(attemptId, "reset"),
    { method: "POST", headers: idempotent() },
    202,
  );
}

export function leaveRoom(attemptId: string): Promise<ApiResult<RoomStatus>> {
  return statusCall(
    attemptPath(attemptId, "leave"),
    { method: "POST", headers: idempotent() },
    202,
  );
}

export function verifyRecovery(attemptId: string): Promise<ApiResult<RoomStatus>> {
  return statusCall(
    attemptPath(attemptId, "verify-recovery"),
    { method: "POST", headers: idempotent() },
    200,
  );
}

export async function issueTerminal(
  attemptId: string,
): Promise<ApiResult<TerminalGrant>> {
  const reply = await call(attemptPath(attemptId, "terminal-capability"), {
    method: "POST",
  });
  if (reply === null || reply.status !== 200) {
    return failure(reply);
  }
  const capability = field(reply.body, "capability");
  const bounds = terminalBounds(field(reply.body, "terminal"));
  if (typeof capability !== "string" || capability === "" || bounds === null) {
    return invalid(reply);
  }
  return { ok: true, value: { capability, bounds } };
}

/** A short explanation of a failed call for the learner. */
export function describeFailure(result: { status: number; code: string }): string {
  if (result.code === "NETWORK_ERROR") {
    return "The local runtime did not answer. Check that it is running.";
  }
  if (result.status === 401) {
    return "Your session ended. Sign in again.";
  }
  if (result.code === "AUTHORIZATION_FAILED") {
    return "This account may not do that in this Room.";
  }
  if (result.code === "ATTEMPT_UNAVAILABLE") {
    return "The Room cannot do that in its current state.";
  }
  if (result.code === "RECOVERY_NOT_VERIFIED") {
    return "The recovery is not verified yet. Keep investigating in the terminal.";
  }
  return `The request failed (${result.code}).`;
}
