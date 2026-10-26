import { useRouter } from "next/router";
import { type FormEvent, useState } from "react";

import { describeFailure, signIn } from "../lib/api.ts";
import { useHydrated } from "../lib/use-hydrated.ts";

export default function SignIn() {
  const router = useRouter();
  const hydrated = useHydrated();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const ended = hydrated && router.isReady && router.query.ended === "1";

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const field = event.currentTarget.elements.namedItem("token");
    if (!(field instanceof HTMLInputElement)) {
      return;
    }
    // Read once and clear, so the token stays in neither the page nor state.
    const token = field.value;
    field.value = "";
    setBusy(true);
    setError("");
    const result = await signIn(token);
    setBusy(false);
    if (result.ok) {
      await router.push("/room/");
    } else if (result.status === 401) {
      setError("The token is not valid, or it has expired.");
    } else {
      setError(describeFailure(result));
    }
  }

  return (
    <main className="page narrow">
      <h1>Failroom</h1>
      <p className="lead">
        Sign in to this local runtime with the access token its operator configured.
      </p>
      {ended && !error ? <p className="notice">Your session ended. Sign in again.</p> : null}
      <form className="stack" onSubmit={(event) => void submit(event)}>
        <label htmlFor="token">Local access token</label>
        <input
          id="token"
          name="token"
          type="password"
          autoComplete="off"
          spellCheck={false}
          required
        />
        <button type="submit" disabled={busy}>
          {busy ? "Signing in" : "Sign in"}
        </button>
      </form>
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      <p className="hint">
        The token is sent once to open an HttpOnly session cookie. This page does not
        keep it.
      </p>
    </main>
  );
}
