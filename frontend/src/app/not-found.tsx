import Link from "next/link";

export default function NotFound() {
  return (
    <div className="state">
      <h3>This page or record doesn&apos;t exist</h3>
      <p>
        Check the ID, or go back to <Link href="/">your cases</Link>.
      </p>
    </div>
  );
}
