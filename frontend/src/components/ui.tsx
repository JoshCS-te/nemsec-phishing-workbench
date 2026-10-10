"use client";

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { ApiError, get } from "@/lib/api";

export type Provenance = "observed" | "inferred" | "analyst" | "unknown" | "demo";

const PROV_LABEL: Record<Provenance, string> = {
  observed: "Observed",
  inferred: "Rule inference",
  analyst: "Analyst",
  unknown: "Not established",
  demo: "Demo data",
};

export function Prov({ kind, label }: { kind: Provenance; label?: string }) {
  return <span className={`prov ${kind}`}>{label ?? PROV_LABEL[kind]}</span>;
}

export function ProvenanceLegend() {
  return (
    <div className="legend" aria-label="Provenance legend">
      <Prov kind="observed" />
      <span>in the evidence as written</span>
      <Prov kind="inferred" />
      <span>a rule&apos;s reading of it</span>
      <Prov kind="analyst" />
      <span>your conclusion</span>
      <Prov kind="unknown" />
      <span>could not be established</span>
    </div>
  );
}

type BadgeTone = "ok" | "warn" | "bad" | "neutral" | "demo";
const ICON: Record<BadgeTone, string> = { ok: "✓", warn: "!", bad: "✕", neutral: "•", demo: "⚠" };

export function Badge({ tone, children, title }: { tone: BadgeTone; children: ReactNode; title?: string }) {
  return (
    <span className={`badge ${tone}`} title={title}>
      <span aria-hidden="true">{ICON[tone]}</span>
      {children}
    </span>
  );
}

const STATIC_TONE: Record<string, [BadgeTone, string]> = {
  pending: ["neutral", "Queued"],
  running: ["neutral", "Analysing"],
  complete: ["ok", "Complete"],
  partial: ["warn", "Partial — incomplete"],
  unsupported: ["warn", "Unsupported format"],
  encrypted: ["warn", "Encrypted — not inspected"],
  failed: ["bad", "Analysis failed"],
  too_large: ["warn", "Too large — not analysed"],
};

export function StaticStatus({ status }: { status: string }) {
  const [tone, label] = STATIC_TONE[status] ?? ["neutral", status];
  return <Badge tone={tone}>{label}</Badge>;
}

const PARSE_TONE: Record<string, [BadgeTone, string]> = {
  parsed: ["ok", "Parsed"],
  partial: ["warn", "Partially parsed"],
  failed: ["bad", "Parse failed"],
};
export function ParseStatus({ status }: { status: string }) {
  const [tone, label] = PARSE_TONE[status] ?? ["neutral", status];
  return <Badge tone={tone}>{label}</Badge>;
}

const JOB_TONE: Record<string, [BadgeTone, string]> = {
  queued: ["neutral", "Queued"],
  running: ["neutral", "Running"],
  completed: ["ok", "Execution finished"],
  failed: ["bad", "Failed"],
  timed_out: ["warn", "Timed out"],
  cancelled: ["neutral", "Cancelled"],
  reset_failed: ["bad", "Reset failed"],
};
export function JobState({ state }: { state: string }) {
  const [tone, label] = JOB_TONE[state] ?? ["neutral", state];
  return <Badge tone={tone}>{label}</Badge>;
}

export function Weight({ value }: { value: "low" | "medium" | "high" }) {
  const bars = value === "high" ? "▮▮▮" : value === "medium" ? "▮▮▯" : "▮▯▯";
  return (
    <span className="weight" title="How strongly this indicator, on its own, is associated with malicious mail. Not a verdict.">
      <span aria-hidden="true">{bars}</span> {value} weight
    </span>
  );
}

export function Absent({ children = "not present in the evidence" }: { children?: ReactNode }) {
  return <span className="absent">{children}</span>;
}

export function Loading({ lines = 4 }: { lines?: number }) {
  return (
    <div aria-busy="true" aria-live="polite">
      <span className="sr-only">Loading…</span>
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className="skeleton" style={{ width: `${90 - i * 12}%` }} />
      ))}
    </div>
  );
}

export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  const msg = error instanceof ApiError ? error.message : error instanceof Error ? error.message : String(error);
  const offline = msg.includes("Failed to fetch") || msg.includes("NetworkError") || msg.includes("not running");
  return (
    <div className="state error" role="alert">
      <h3>{offline ? "Can't reach the backend" : "Something went wrong"}</h3>
      <p>{offline ? "Start the API with scripts\\start.ps1 (or uvicorn on 127.0.0.1:8000) and try again." : msg}</p>
      {retry && (
        <button className="btn secondary small" onClick={retry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="state">
      <h3>{title}</h3>
      {children}
    </div>
  );
}

export function useApi<T>(path: string | null, pollMs?: number | ((data: T | undefined) => number | undefined)) {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState<boolean>(!!path);
  const dataRef = useRef<T | undefined>(undefined);

  const load = useCallback(async () => {
    if (!path) return;
    try {
      const d = await get<T>(path);
      dataRef.current = d;
      setData(d);
      setError(null);
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    setLoading(true);
    load();
  }, [load]);

  useEffect(() => {
    if (!pollMs) return;
    let timer: ReturnType<typeof setTimeout>;
    let stopped = false;
    const tick = async () => {
      const ms = typeof pollMs === "function" ? pollMs(dataRef.current) : pollMs;
      if (!ms || stopped) {
        timer = setTimeout(tick, 2000);
        return;
      }
      timer = setTimeout(async () => {
        await load();
        tick();
      }, ms);
    };
    tick();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [pollMs, load]);

  return { data, error, loading, reload: load };
}

export function Tabs<K extends string>({
  tabs,
  active,
  onChange,
}: {
  tabs: { key: K; label: string; count?: number }[];
  active: K;
  onChange: (k: K) => void;
}) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.key} role="tab" aria-selected={active === t.key} onClick={() => onChange(t.key)}>
          {t.label}
          {t.count !== undefined && <span className="count">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function KV({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v], i) => (
        <div key={i} style={{ display: "contents" }}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Shows a decoded value with its raw header value underneath when they differ. */
export function RawValue({ decoded, raw }: { decoded: string | null | undefined; raw: string | null | undefined }) {
  if (raw === null || raw === undefined) return <Absent />;
  return (
    <>
      <span>{decoded ?? raw}</span>
      {decoded !== raw && <span className="raw">raw: {raw}</span>}
    </>
  );
}

export function Hash({ value }: { value: string | null | undefined }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <Absent>no hash</Absent>;
  return (
    <span className="hash">
      {value}{" "}
      <button
        className="btn secondary small"
        style={{ padding: "0 6px", marginLeft: 4 }}
        onClick={() => {
          navigator.clipboard?.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        }}
        aria-label="Copy SHA-256"
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </span>
  );
}
