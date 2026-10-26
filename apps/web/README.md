# Failroom Browser Interface

The browser interface for the control plane's operator-only local runtime. It
is a static Next.js export that the runtime serves from its own origin; it has
no server of its own. Like the runtime, it is a local proof of concept for the
operator on their own host and must not be offered to learners or other users.

## What it does

- **Sign in** (`/`): sends the runtime's bearer token once to
  `POST /v1/session`, which answers with an HttpOnly session cookie. The page
  clears the field and keeps the token nowhere.
- **Room** (`/room/`): enters the Disk Full Room, shows Room Status and polls
  it while the Room changes state, verifies the recovery, resets or leaves the
  Room, and signs out. It also reads Room Status again when the Room's end
  time passes and when the terminal closes, so a Room that ended shows as
  ended, and only the latest of overlapping status requests is applied. The
  attempt ID travels in the page's query string; it names the attempt but
  authorizes nothing, because every request is checked against the session's
  own attempts.
- **Terminal**: asks for a single-use capability for each connection, opens
  `/v1/terminal`, sends the capability and the terminal's current size in the
  authorization frame, and relays input, resize and output between xterm.js
  and the real PTY in the Room's sandbox; a resize is sent only when the size
  changes. When the shell ends, as after `exit`, or the Room is reset or ends,
  the terminal says so instead of reporting the server's close as a failure.
  Ctrl+C reaches the PTY as typed input. The terminal stays within the
  bounds the capability response carries: it never asks for more rows or
  columns than the server accepts, and it splits typed or pasted text so each
  frame stays within the input and frame limits after JSON escaping.

The protocol and close codes are described in the
[control-plane README](../../services/control-plane/README.md); `lib/` holds
their browser side and its unit tests.

## Page policy

The runtime serves every page with a Content Security Policy that runs only
this origin's scripts and limits fetches, WebSockets, images and fonts to that
origin. Two consequences shape the code:

- The build uses webpack (`next build --webpack`). Turbopack, the Next.js 16
  default, adds an inline script that the policy refuses; with webpack the
  exported pages contain no inline script.
- The policy allows inline `<style>` elements, because xterm.js writes them at
  run time, but blocks inline style attributes. ESLint therefore forbids the
  `style` prop and `dangerouslySetInnerHTML`, and `pages/404.tsx` replaces the
  Next.js error page, which uses style attributes.

## Checks

Use Node.js 24.22.1; `.npmrc` refuses other versions, never runs package
install scripts and saves exact versions. Set `NEXT_TELEMETRY_DISABLED=1` so
Next.js sends no usage data. From this directory, run:

```sh
npm ci
npm run lint
npm run typecheck
npm test
npm run build
```

`npm run typecheck` generates the route types with `next typegen` before
running `tsc`. `npm test` runs `lib/*.test.ts` with Node.js's built-in test
runner. `npm run build` writes the export to `out/`. The dependency policy is in
[DEVELOPMENT.md](../../docs/DEVELOPMENT.md).

## Serving it

Build the export, then start `serve-local` as the control-plane README
describes, with `FAILROOM_LOCAL_WEB_ROOT` set to the absolute path of `out/`:

```sh
npm run build
export FAILROOM_LOCAL_WEB_ROOT="$PWD/out"
```

Open `http://127.0.0.1:<FAILROOM_LOCAL_BIND_PORT>/` (or `localhost`) in a
browser on the same host; the runtime refuses any other host name. There is no
development server wired to the runtime, so rebuild after a change.

## Limitations

- It serves only the Disk Full Room and one local operator.
- The policy's `style-src-elem` needs a browser that supports Content Security
  Policy Level 3; the interface was checked in a Chromium-based browser only.
- Automated browser-to-PTY tests remain planned.
