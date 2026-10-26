// The browser side of the /v1/terminal protocol described in
// services/control-plane/README.md.

export type TerminalBounds = {
  rows: number;
  columns: number;
  inputBytes: number;
  frameBytes: number;
};

export type TerminalSize = { rows: number; columns: number };

export type ServerMessage =
  | { type: "authorized" }
  | { type: "output"; data: string };

const encoder = new TextEncoder();
const INPUT_FRAME_BYTES = byteLength(JSON.stringify({ type: "input", data: "" }));

function byteLength(text: string): number {
  return encoder.encode(text).length;
}

export function terminalUrl(location: { protocol: string; host: string }): string {
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  return `${scheme}//${location.host}/v1/terminal`;
}

/**
 * The first frame, with the terminal's starting size: the server opens the
 * shell at that size, since it may miss a resize sent right after this.
 */
export function authorizeFrame(capability: string, size: TerminalSize): string {
  return JSON.stringify({
    type: "authorize",
    capability,
    rows: size.rows,
    columns: size.columns,
  });
}

export function closeFrame(): string {
  return JSON.stringify({ type: "close" });
}

export function resizeFrame(rows: number, columns: number): string {
  return JSON.stringify({ type: "resize", rows, columns });
}

/**
 * Split typed or pasted text into input frames the server accepts: each
 * frame's data stays within the input limit and the whole frame, after JSON
 * escaping, within the frame limit. The server closes the terminal otherwise.
 */
export function inputFrames(
  data: string,
  bounds: Pick<TerminalBounds, "inputBytes" | "frameBytes">,
): string[] {
  const frames: string[] = [];
  let chunk = "";
  let dataBytes = 0;
  let frameBytes = INPUT_FRAME_BYTES;
  // Lone surrogates cannot be encoded as UTF-8 by the server.
  for (const character of data.toWellFormed()) {
    const characterBytes = byteLength(character);
    const escapedBytes = byteLength(JSON.stringify(character)) - 2;
    if (
      chunk &&
      (dataBytes + characterBytes > bounds.inputBytes ||
        frameBytes + escapedBytes > bounds.frameBytes)
    ) {
      frames.push(JSON.stringify({ type: "input", data: chunk }));
      chunk = "";
      dataBytes = 0;
      frameBytes = INPUT_FRAME_BYTES;
    }
    chunk += character;
    dataBytes += characterBytes;
    frameBytes += escapedBytes;
  }
  if (chunk) {
    frames.push(JSON.stringify({ type: "input", data: chunk }));
  }
  return frames;
}

/**
 * A whole-cell terminal size for a measured one, within the server's bounds
 * once they are known. Null while the element cannot be measured, for
 * example before layout, when the measurement is not a positive number.
 */
export function fitSize(
  proposed: TerminalSize,
  bounds: Pick<TerminalBounds, "rows" | "columns"> | null,
): TerminalSize | null {
  const rows = Math.floor(proposed.rows);
  const columns = Math.floor(proposed.columns);
  if (!Number.isFinite(rows) || !Number.isFinite(columns) || rows < 1 || columns < 1) {
    return null;
  }
  return bounds
    ? { rows: Math.min(bounds.rows, rows), columns: Math.min(bounds.columns, columns) }
    : { rows, columns };
}

export function parseServerMessage(text: unknown): ServerMessage | null {
  if (typeof text !== "string") {
    return null;
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const message = value as Record<string, unknown>;
  if (message.type === "authorized") {
    return { type: "authorized" };
  }
  if (message.type === "output" && typeof message.data === "string") {
    return { type: "output", data: message.data };
  }
  return null;
}

/** What a close code means for the learner. */
export function closeMessage(code: number): string {
  switch (code) {
    case 1000:
      return "The terminal closed.";
    case 1008:
      return "The terminal refused this page's origin.";
    case 1011:
      return "The terminal stopped because of a runtime failure.";
    case 4400:
      return "The terminal received a frame it does not accept.";
    case 4403:
      return "The terminal capability was refused. Connect again for a new one.";
    case 4408:
      return "The terminal waited too long for authorization.";
    case 4409:
      return "The terminal received more input than it accepts at once.";
    case 4410:
      return "The terminal closed because its shell ended.";
    case 4429:
      return "This Room already has as many terminals as it allows. Close another one first.";
    default:
      return `The terminal connection ended (code ${code}).`;
  }
}
