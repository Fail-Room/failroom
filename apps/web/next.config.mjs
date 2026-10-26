// A static export that serve-local serves from the runtime's own origin
// (services/control-plane/README.md). Build with webpack: Turbopack adds an
// inline script that the page policy refuses.
/** @type {import("next").NextConfig} */
const config = {
  output: "export",
  trailingSlash: true,
  poweredByHeader: false,
  reactStrictMode: true,
};

export default config;
