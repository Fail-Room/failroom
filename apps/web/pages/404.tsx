import Link from "next/link";

// Next's built-in error page uses inline style attributes, which the page
// policy blocks, so the export ships this one instead.
export default function NotFound() {
  return (
    <main className="page">
      <h1>Page not found</h1>
      <p>
        <Link href="/">Go to sign in</Link>
      </p>
    </main>
  );
}
