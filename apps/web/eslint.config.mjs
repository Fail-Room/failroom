import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

export default defineConfig([
  ...nextVitals,
  ...nextTypescript,
  {
    rules: {
      // The page policy blocks inline style attributes and leaves no room
      // for injected markup.
      "react/forbid-dom-props": ["error", { forbid: ["style"] }],
      "react/no-danger": "error",
    },
  },
  globalIgnores([".next/**", "out/**", "next-env.d.ts"]),
]);
