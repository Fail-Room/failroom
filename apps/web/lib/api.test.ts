import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import {
  describeFailure,
  enterRoom,
  getRoomStatus,
  issueTerminal,
  leaveRoom,
  signIn,
  signOut,
} from "./api.ts";

type Recorded = { url: string; init: RequestInit };

const originalFetch = globalThis.fetch;
let recorded: Recorded[] = [];

function reply(status: number, body?: unknown): void {
  globalThis.fetch = async (input, init) => {
    recorded.push({ url: String(input), init: init ?? {} });
    return new Response(body === undefined ? null : JSON.stringify(body), { status });
  };
}

afterEach(() => {
  globalThis.fetch = originalFetch;
  recorded = [];
});

const status = {
  attempt_id: "attempt-1",
  room_id: "disk-full",
  state: "READY",
  expires_at: "2026-10-26T12:00:00+00:00",
  destroy_intent: false,
};

test("signing in sends the token once and keeps nothing", async () => {
  reply(201, { expires_at: "2026-10-26T12:00:00+00:00" });

  assert.deepEqual(await signIn("secret-token"), { ok: true, value: null });
  assert.equal(recorded[0].url, "/v1/session");
  assert.equal(recorded[0].init.method, "POST");
  assert.deepEqual(recorded[0].init.headers, { Authorization: "Bearer secret-token" });
  assert.equal(recorded[0].init.credentials, "same-origin");
  assert.equal(recorded[0].init.cache, "no-store");
});

test("signing out expects 204", async () => {
  reply(204);

  assert.deepEqual(await signOut(), { ok: true, value: null });
  assert.equal(recorded[0].init.method, "DELETE");
});

test("entering a Room sends an idempotency key", async () => {
  // Enter Room answers without destroy_intent.
  reply(201, {
    attempt_id: status.attempt_id,
    room_id: status.room_id,
    state: status.state,
    expires_at: status.expires_at,
  });

  const result = await enterRoom("disk-full");

  assert.deepEqual(result, {
    ok: true,
    value: {
      attemptId: "attempt-1",
      roomId: "disk-full",
      state: "READY",
      expiresAt: "2026-10-26T12:00:00+00:00",
      destroyIntent: false,
    },
  });
  assert.equal(recorded[0].url, "/v1/rooms/disk-full/attempts");
  const headers = recorded[0].init.headers as Record<string, string>;
  assert.match(headers["Idempotency-Key"], /^[0-9a-f-]{36}$/);
});

test("each state change gets a new idempotency key", async () => {
  reply(202, { ...status, state: "STOPPING", destroy_intent: true });

  await leaveRoom("attempt-1");
  await leaveRoom("attempt-1");

  const keys = recorded.map(
    (call) => (call.init.headers as Record<string, string>)["Idempotency-Key"],
  );
  assert.notEqual(keys[0], keys[1]);
  assert.equal(recorded[0].url, "/v1/attempts/attempt-1/leave");
});

test("attempt IDs are encoded into the path", async () => {
  reply(200, status);

  await getRoomStatus("a/b?c");

  assert.equal(recorded[0].url, "/v1/attempts/a%2Fb%3Fc/status");
});

test("a terminal grant needs the capability and the terminal bounds", async () => {
  reply(200, {
    capability: "cap",
    expires_at: "2026-10-26T12:00:00+00:00",
    terminal: { rows: 40, columns: 120, input_bytes: 4096, frame_bytes: 65536 },
  });

  assert.deepEqual(await issueTerminal("attempt-1"), {
    ok: true,
    value: {
      capability: "cap",
      bounds: { rows: 40, columns: 120, inputBytes: 4096, frameBytes: 65536 },
    },
  });

  reply(200, { capability: "cap", expires_at: "2026-10-26T12:00:00+00:00" });
  assert.deepEqual(await issueTerminal("attempt-1"), {
    ok: false,
    status: 200,
    code: "INVALID_RESPONSE",
  });
});

test("failures keep the server's fixed code", async () => {
  reply(409, { code: "ATTEMPT_UNAVAILABLE" });

  const result = await getRoomStatus("attempt-1");

  assert.deepEqual(result, { ok: false, status: 409, code: "ATTEMPT_UNAVAILABLE" });
  if (!result.ok) {
    assert.match(describeFailure(result), /current state/);
  }
});

test("an unreachable runtime is a network error", async () => {
  globalThis.fetch = async () => {
    throw new TypeError("connection refused");
  };

  const result = await getRoomStatus("attempt-1");

  assert.deepEqual(result, { ok: false, status: 0, code: "NETWORK_ERROR" });
  if (!result.ok) {
    assert.match(describeFailure(result), /did not answer/);
  }
});

test("a malformed success body is rejected", async () => {
  reply(200, { ...status, state: 7 });

  assert.deepEqual(await getRoomStatus("attempt-1"), {
    ok: false,
    status: 200,
    code: "INVALID_RESPONSE",
  });
});
