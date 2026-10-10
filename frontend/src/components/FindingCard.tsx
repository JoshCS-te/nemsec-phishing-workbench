"use client";

import Link from "next/link";
import { useState } from "react";
import type { Finding } from "@/lib/api";
import { send } from "@/lib/api";
import { Badge, Prov, Weight } from "./ui";

const REVIEW: Record<string, ["ok" | "warn" | "bad" | "neutral", string]> = {
  unreviewed: ["neutral", "Not reviewed"],
  relevant: ["bad", "Relevant"],
  benign: ["ok", "Benign"],
  unresolved: ["warn", "Unresolved"],
};

function refLink(ref: string) {
  if (ref.startsWith("AT-")) return <Link href={`/attachments/${ref}`}>{ref}</Link>;
  if (ref.startsWith("EV-")) return <Link href={`/emails/${ref}`}>{ref}</Link>;
  return <code>{ref}</code>;
}

export default function FindingCard({
  f,
  caseId,
  editable,
  onChanged,
  defaultOpen,
}: {
  f: Finding;
  caseId?: string;
  editable?: boolean;
  onChanged?: () => void;
  defaultOpen?: boolean;
}) {
  const [comment, setComment] = useState(f.analyst_comment ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const review = f.review_status;

  async function save(patch: Record<string, unknown>) {
    if (!caseId) return;
    setBusy(true);
    setErr(null);
    try {
      await send("PATCH", `/api/cases/${caseId}/findings/${f.id}`, patch);
      onChanged?.();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <details className="finding" open={defaultOpen}>
      <summary>
        <span className="title">{f.name}</span>
        <Weight value={f.confidence} />
        <span className="meta">
          <Prov kind="inferred" />
          <span>{f.category.replace("_", " ")}</span>
          {review && (
            <Badge tone={REVIEW[review][0]}>
              {REVIEW[review][1]}
            </Badge>
          )}
          {f.include_in_report === 0 && <Badge tone="neutral">Excluded from report</Badge>}
          <span className="mono">{f.id}</span>
        </span>
      </summary>
      <div className="body">
        <p style={{ margin: 0 }}>{f.explanation}</p>
        <div className="ledger observed">
          <div style={{ marginBottom: 6 }}>
            <Prov kind="observed" label="Supporting evidence" />
          </div>
          <dl className="kv">
            {f.evidence_json.map((e, i) => (
              <div key={i} style={{ display: "contents" }}>
                <dt>{e.label}</dt>
                <dd>
                  <span className="mono">{e.value === null || e.value === undefined ? "—" : String(e.value)}</span>
                  {e.ref && <> ({refLink(e.ref)})</>}
                </dd>
              </div>
            ))}
          </dl>
          <p className="small muted" style={{ marginTop: 8 }}>
            Evidence: {refLink(f.email_evidence_id)}
            {f.subject_evidence_id && <> → {refLink(f.subject_evidence_id)}</>}
          </p>
        </div>
        {f.uncertainty && (
          <div className="ledger unknown small">
            <strong>Uncertainty.</strong> {f.uncertainty}
          </div>
        )}
        {f.benign_json.length > 0 && (
          <div className="benign">
            <strong>Could be benign if…</strong>
            <ul>
              {f.benign_json.map((b, i) => (
                <li key={i}>{b}</li>
              ))}
            </ul>
          </div>
        )}
        {editable && caseId && (
          <div className="ledger analyst stack">
            <div className="row">
              <Prov kind="analyst" label="Your review" />
              {(["relevant", "benign", "unresolved"] as const).map((s) => (
                <button
                  key={s}
                  className={`btn small ${review === s ? "" : "secondary"}`}
                  disabled={busy}
                  aria-pressed={review === s}
                  onClick={() => save({ review_status: s })}
                >
                  Mark {REVIEW[s][1].toLowerCase()}
                </button>
              ))}
              <label className="check small">
                <input
                  type="checkbox"
                  checked={f.include_in_report !== 0}
                  disabled={busy}
                  onChange={(e) => save({ include_in_report: e.target.checked })}
                />
                Include in report
              </label>
            </div>
            <label className="field">
              Analyst comment
              <textarea value={comment} onChange={(e) => setComment(e.target.value)} style={{ minHeight: 64 }} />
            </label>
            <div className="row">
              <button className="btn small secondary" disabled={busy || comment === (f.analyst_comment ?? "")} onClick={() => save({ analyst_comment: comment })}>
                Save comment
              </button>
              {err && <span role="alert" className="small" style={{ color: "var(--danger)" }}>{err}</span>}
            </div>
          </div>
        )}
      </div>
    </details>
  );
}
