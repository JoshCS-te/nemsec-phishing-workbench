"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";

const NAV = [
  { href: "/", label: "Cases" },
  { href: "/import", label: "Import email" },
  { href: "/emails", label: "All evidence" },
  { href: "/sandbox", label: "Sandbox" },
];

function BrandMark() {
  // Drop the NEMSEC logo at frontend/public/nemsec-logo.png; the letter mark is the fallback.
  const [hasLogo, setHasLogo] = useState(false);
  useEffect(() => {
    fetch("/nemsec-logo.png", { method: "HEAD" })
      .then((r) => setHasLogo(r.ok && (r.headers.get("content-type") ?? "").startsWith("image/")))
      .catch(() => setHasLogo(false));
  }, []);
  return <span className="brand-mark">{hasLogo ? <img src="/nemsec-logo.png" alt="" /> : <span aria-hidden="true">N</span>}</span>;
}

export default function Shell({ children }: { children: ReactNode }) {
  const path = usePathname();
  const isActive = (href: string) => (href === "/" ? path === "/" || path.startsWith("/cases") : path.startsWith(href));
  return (
    <div className="shell">
      <aside className="rail">
        <Link href="/" className="brand" aria-label="NEMSEC Phishing Workbench home">
          <BrandMark />
          <span className="brand-text">
            <strong>NEMSEC</strong>
            <small>Phishing Investigation Workbench</small>
          </span>
        </Link>
        <nav className="nav" aria-label="Main">
          {NAV.map((n) => (
            <Link key={n.href} href={n.href} aria-current={isActive(n.href) ? "page" : undefined}>
              {n.label}
            </Link>
          ))}
        </nav>
        <div className="rail-foot">
          Evidence stays on this machine.
          <br />
          <a href="https://nemsec.com.ng" target="_blank" rel="noopener noreferrer">
            nemsec.com.ng
          </a>
        </div>
      </aside>
      <main className="main" id="main">
        {children}
      </main>
    </div>
  );
}
