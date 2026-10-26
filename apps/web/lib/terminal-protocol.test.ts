import assert from "node:assert/strict";
import { test } from "node:test";

import {
  authorizeFrame,
  closeMessage,
  fitSize,
  inputFrames,
  parseServerMessage,
  terminalUrl,
} from "./terminal-protocol.ts";

const encoder = new TextEncoder();

test("the terminal URL follows the page's scheme and host", () => {
  assert.equal(
    terminalUrl({ protocol: "http:", host: "127.0.0.1:18765" }),
    "ws://127.0.0.1:18765/v1/terminal",
  );
  assert.equal(
    terminalUrl({ protocol: "https:", host: "localhost:8443" }),
    "wss://localhost:8443/v1/terminal",
  );
});

test("the authorization frame carries the capability and the starting size", () => {
  assert.deepEqual(JSON.parse(authorizeFrame("cap", { rows: 27, columns: 100 })), {
    type: "authorize",
    capability: "cap",
    rows: 27,
    columns: 100,
  });
});

test("input frames stay within the input and frame limits", () => {
  const bounds = { inputBytes: 16, frameBytes: 64 };
  const text = "echo 한글 \u0003 done\r";
  const frames = inputFrames(text, bounds);

  assert.ok(frames.length > 1);
  assert.equal(frames.map((frame) => JSON.parse(frame).data).join(""), text);
  for (const frame of frames) {
    const parsed = JSON.parse(frame);
    assert.equal(parsed.type, "input");
    assert.ok(encoder.encode(parsed.data).length <= bounds.inputBytes);
    assert.ok(encoder.encode(frame).length <= bounds.frameBytes);
  }
});

test("control characters count with their JSON escapes", () => {
  // Each \u0003 needs six bytes in the frame but only one in the data.
  const frames = inputFrames("\u0003".repeat(20), { inputBytes: 4096, frameBytes: 60 });

  assert.ok(frames.length > 1);
  for (const frame of frames) {
    assert.ok(encoder.encode(frame).length <= 60);
  }
});

test("a lone surrogate is replaced instead of sent", () => {
  const frames = inputFrames("a\ud800b", { inputBytes: 64, frameBytes: 256 });

  assert.equal(JSON.parse(frames[0]).data, "a�b");
});

test("no frame is produced for empty input", () => {
  assert.deepEqual(inputFrames("", { inputBytes: 8, frameBytes: 64 }), []);
});

test("a measured size becomes whole cells within the server's bounds", () => {
  const bounds = { rows: 40, columns: 120 };

  assert.deepEqual(fitSize({ rows: 55.7, columns: 300 }, bounds), {
    rows: 40,
    columns: 120,
  });
  assert.deepEqual(fitSize({ rows: 24.9, columns: 80.2 }, bounds), {
    rows: 24,
    columns: 80,
  });
  assert.deepEqual(fitSize({ rows: 55.7, columns: 300.4 }, null), {
    rows: 55,
    columns: 300,
  });
});

test("an element that cannot be measured yet gives no size", () => {
  for (const proposed of [
    { rows: Number.NaN, columns: 80 },
    { rows: 24, columns: Number.POSITIVE_INFINITY },
    { rows: 0.5, columns: 80 },
    { rows: 24, columns: 0 },
  ]) {
    assert.equal(fitSize(proposed, { rows: 40, columns: 120 }), null);
  }
});

test("only known server messages are accepted", () => {
  assert.deepEqual(parseServerMessage('{"type":"authorized"}'), {
    type: "authorized",
  });
  assert.deepEqual(parseServerMessage('{"type":"output","data":"ls\\r\\n"}'), {
    type: "output",
    data: "ls\r\n",
  });
  for (const text of ["not json", "null", '{"type":"output"}', '{"type":"other"}', 42]) {
    assert.equal(parseServerMessage(text), null);
  }
});

test("every documented close code has its own message", () => {
  const codes = [1000, 1008, 1011, 4400, 4403, 4408, 4409, 4410, 4429];
  const messages = new Set(codes.map(closeMessage));

  assert.equal(messages.size, codes.length);
  assert.match(closeMessage(4999), /4999/);
});
