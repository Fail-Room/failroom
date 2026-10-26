import { useSyncExternalStore } from "react";

const subscribe = () => () => {};

/**
 * False while React hydrates the exported HTML, true from the next render on.
 * A page renders what depends on the URL's query only once this is true, so
 * its first render matches the HTML the build wrote.
 */
export function useHydrated(): boolean {
  return useSyncExternalStore(
    subscribe,
    () => true,
    () => false,
  );
}
