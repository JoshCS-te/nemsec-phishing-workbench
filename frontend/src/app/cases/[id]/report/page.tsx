"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { Badge, Empty, ErrorState, Loading, Prov, useApi } from "@/components/ui";
import { fmtBytes, fmtTime, get, send } from "@/lib/api";

type Analyst = {
  summary: string;
  assessment: string;
  assessment_rationale: string;
  actions: string;
  recommendations: string;
  limitations: string;
  author: string;
  notes?: { facts: { id: string; body: string; refs: string[] }[]; interpretations: { id: string; body: string; refs: string[] }[]; questions: { id: string; body: string; refs: string[]; resolved: boolean }[] };
};
type Generated = {
  case: { id: string; title: string };
  snapshot_at: string;
  scope: { id: string; kind: string; filename: string | null; sha256: string; size_bytes: number; integrity_ok_at_snapshot: boolean }[];
  emails: { id: string; subject: string | null; from: string | null; reply_to: string | null; date_raw: string | null; parse_status: string; auth_claims: { authserv_id: string; methods: string[] }[] }[];
  findings: { id: string; name: string; category: string; confidence: string; review_status: string; evidence_refs: string[]; analyst_comment: string }[];
  attachments: { id: string; filename: string | null; sha256: string; detected: string | null; static_status: string }[];
  sandbox: { id: string; attachment_id: string; is_demo: boolean; state: string; reset_status: string | null }[];
  could_not_establish: string[];
};
type Revision = { id: string; revision: number; status: "draft" | "reviewed"; created_at: string; reviewed_at: string | null; reviewer: string | null; content: { generated: Generated; analyst: Analyst } };
type ReportView = { latest: Revision | null; revisions: { id: string; revision: number; status: string; created_at: string; reviewed_at: string | null; reviewer: string | null }[] };

const ASSESSMENTS: [string, string][] = [
  ["undetermined", "Undetermined"],
  ["likely_benign", "Likely benign"],
  ["suspicious", "Suspicious"],
  ["likely_malicious", "Likely malicious"],
  ["confirmed_malicious", "Confirmed malicious"],
];

function Field({ label, value, onChange, disabled, rows = 4, hint }: { label: string; value: string; onChange: (v: string) => void; disabled: boolean; rows?: number; hint?: string }) {
  return (
    <label className="field">
      {label}
      {hint && <span className="muted" style={{ fontWeight: 400 }}>{hint}</span>}
      <textarea rows={rows} value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled} />
    </label>
  );
}

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const { data, error, loading, reload } = useApi<ReportView>(`/api/cases/${id}/report`);
  const [rev, setRev] = useState<Revision | null>(null);
  const [form, setForm] = useState<Analyst | null>(null);
  const [reviewer, setReviewer] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);

  useEffect(() => {
    if (data?.latest && (!rev || rev.id === data.latest.id)) {
      setRev(data.latest);
      setForm(data.latest.content.analyst);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  async function act(fn: () => Promise<unknown>, ok: string) {
    setBusy(true);
    setMsg(null);
    try {
      await fn();
      setMsg({ tone: "ok", text: ok });
      setRev(null);
      await reload();
    } catch (e) {
      setMsg({ tone: "bad", text: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  }

  if (loading && !data) return <Loading lines={8} />;
  if (error && !data) return <ErrorState error={error} retry={reload} />;
  if (!data) return null;

  const head = (
    <div className="crumbs">
      <Link href={`/cases/${id}`}>Case {id}</Link> / report
    </div>
  );

  if (!data.latest || !rev || !form) {
    return (
      <>
        {head}
        <div className="page-head">
          <h1>Report</h1>
        </div>
        <Empty title="No report yet">
          <p>A draft takes a snapshot of the selected evidence, reviewed findings and your notes. You then write the assessment.</p>
          <button className="btn" disabled={busy} onClick={() => act(() => send("POST", `/api/cases/${id}/report/drafts`), "Draft created.")}>
            Create draft report
          </button>
          {msg && <p className="small" role="alert" style={{ color: "var(--danger)" }}>{msg.text}</p>}
        </Empty>
      </>
    );
  }

  const g = rev.content.generated;
  const isDraft = rev.status === "draft";
  const isLatest = rev.id === data.latest.id;
  const dirty = JSON.stringify(form) !== JSON.stringify(rev.content.analyst);
  const set = (k: keyof Analyst) => (v: string) => setForm({ ...form, [k]: v });

  return (
    <>
      {head}
      <div className="page-head">
        <div>
          <h1>{g.case.title}</h1>
          <p className="sub">
            Revision {rev.revision}{" "}
            {isDraft ? <Badge tone="warn">Draft — not reviewed</Badge> : <Badge tone="ok">Reviewed by {rev.reviewer}, {fmtTime(rev.reviewed_at)}</Badge>}{" "}
            <span className="small">evidence snapshot {fmtTime(g.snapshot_at)}</span>
          </p>
        </div>
        <div className="row">
          <a className="btn" href={`/api/reports/revisions/${rev.id}/pdf`}>
            Export PDF{isDraft ? " (draft)" : ""}
          </a>
          {isLatest && isDraft && (
            <button className="btn secondary" disabled={busy} onClick={() => act(() => send("POST", `/api/cases/${id}/report/drafts`), "Observations refreshed from the case.")}>
              Refresh observations
            </button>
          )}
          {isLatest && !isDraft && (
            <button className="btn secondary" disabled={busy} onClick={() => act(() => send("POST", `/api/cases/${id}/report/drafts`), "New draft revision created.")}>
              Start revision {rev.revision + 1}
            </button>
          )}
        </div>
      </div>
      {msg && (
        <div className={`notice ${msg.tone === "bad" ? "bad" : "trust"}`} role="status">
          {msg.text}
        </div>
      )}
      {!isDraft && <div className="notice trust">Reviewed revisions are frozen. Start a new revision to change anything; this one stays on record.</div>}

      <div className="grid-main">
        <div>
          <section className="panel ledger analyst stack">
            <div className="panel-head" style={{ marginBottom: 0 }}>
              <h2>Analyst sections</h2>
              <Prov kind="analyst" label="Written by you" />
            </div>
            <Field label="Case summary" value={form.summary} onChange={set("summary")} disabled={!isDraft} />
            <label className="field">
              Assessment
              <select value={form.assessment} onChange={(e) => set("assessment")(e.target.value)} disabled={!isDraft}>
                {ASSESSMENTS.map(([v, l]) => (
                  <option key={v} value={v}>
                    {l}
                  </option>
                ))}
              </select>
            </label>
            <Field label="Why you reached this assessment" hint="Cite findings and evidence IDs. Say what would change your mind." value={form.assessment_rationale} onChange={set("assessment_rationale")} disabled={!isDraft} rows={5} />
            <Field label="Actions taken" value={form.actions} onChange={set("actions")} disabled={!isDraft} rows={3} />
            <Field label="Recommendations" value={form.recommendations} onChange={set("recommendations")} disabled={!isDraft} rows={3} />
            <Field label="Limitations you want to add" value={form.limitations} onChange={set("limitations")} disabled={!isDraft} rows={3} />
            <label className="field">
              Author
              <input type="text" value={form.author} onChange={(e) => set("author")(e.target.value)} disabled={!isDraft} />
            </label>
            {isDraft && (
              <div className="row">
                <button className="btn" disabled={busy || !dirty} onClick={() => act(() => send("PATCH", `/api/reports/revisions/${rev.id}`, form), "Draft saved.")}>
                  Save draft
                </button>
                {dirty && <span className="small muted">Unsaved changes</span>}
              </div>
            )}
          </section>

          {form.notes && (
            <section className="panel ledger analyst">
              <h2>From your case notes</h2>
              <p className="small muted">Taken from the Notes tab when the snapshot was made. Edit them there, then refresh.</p>
              {(["facts", "interpretations", "questions"] as const).map((k) => (
                <div key={k} style={{ marginTop: 10 }}>
                  <h3 style={{ fontSize: "var(--step-0)" }}>{k === "facts" ? "Confirmed facts" : k === "interpretations" ? "Interpretations" : "Unanswered questions"}</h3>
                  {form.notes![k].length === 0 ? (
                    <p className="small absent">None.</p>
                  ) : (
                    <ul className="small">
                      {form.notes![k].map((n) => (
                        <li key={n.id}>
                          {n.body} {n.refs.length > 0 && <span className="mono muted">[{n.refs.join(", ")}]</span>}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
            </section>
          )}

          <section className="panel ledger observed">
            <div className="panel-head">
              <h2>Generated sections</h2>
              <Prov kind="observed" label="Snapshot, not editable" />
            </div>
            <h3 style={{ fontSize: "var(--step-0)" }}>Scope</h3>
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>Evidence</th>
                    <th>Kind</th>
                    <th>Filename</th>
                    <th>SHA-256</th>
                    <th className="num">Size</th>
                    <th>Integrity</th>
                  </tr>
                </thead>
                <tbody>
                  {g.scope.map((e) => (
                    <tr key={e.id}>
                      <td className="mono small">{e.id}</td>
                      <td className="small">{e.kind}</td>
                      <td className="small">{e.filename}</td>
                      <td className="hash" style={{ maxWidth: 200 }}>{e.sha256}</td>
                      <td className="num">{fmtBytes(e.size_bytes)}</td>
                      <td>{e.integrity_ok_at_snapshot ? <Badge tone="ok">OK</Badge> : <Badge tone="bad">Mismatch</Badge>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <h3 style={{ fontSize: "var(--step-0)", marginTop: 16 }}>Findings included ({g.findings.length})</h3>
            {g.findings.length === 0 ? (
              <p className="small absent">No findings selected.</p>
            ) : (
              <ul className="small">
                {g.findings.map((f) => (
                  <li key={f.id}>
                    <strong>{f.name}</strong> — {f.confidence} weight, review: <em>{f.review_status}</em>{" "}
                    <span className="mono muted">[{f.id}; {f.evidence_refs.join(", ")}]</span>
                    {f.analyst_comment && <div className="muted">Comment: {f.analyst_comment}</div>}
                  </li>
                ))}
              </ul>
            )}
            <h3 style={{ fontSize: "var(--step-0)", marginTop: 16 }}>Sandbox runs ({g.sandbox.length})</h3>
            {g.sandbox.length === 0 ? (
              <p className="small absent">None in scope.</p>
            ) : (
              <ul className="small">
                {g.sandbox.map((s) => (
                  <li key={s.id}>
                    <span className="mono">{s.id}</span> on {s.attachment_id}: {s.state}, reset {s.reset_status ?? "n/a"} {s.is_demo && <Badge tone="demo">DEMO</Badge>}
                  </li>
                ))}
              </ul>
            )}
          </section>
          <section className="panel ledger unknown">
            <h2>Could not be established</h2>
            <ul className="small">
              {g.could_not_establish.map((c, i) => (
                <li key={i}>{c}</li>
              ))}
            </ul>
          </section>
        </div>

        <aside>
          {isDraft && isLatest && (
            <section className="panel stack">
              <h2>Mark as reviewed</h2>
              <p className="small muted">Freezes this revision and removes the draft marking from the PDF. Summary and rationale are required.</p>
              <label className="field">
                Reviewer name
                <input type="text" value={reviewer} onChange={(e) => setReviewer(e.target.value)} />
              </label>
              <button
                className="btn"
                disabled={busy || !reviewer.trim() || dirty}
                onClick={() => act(() => send("POST", `/api/reports/revisions/${rev.id}/review`, { reviewer }), "Revision marked reviewed.")}
              >
                Mark reviewed
              </button>
              {dirty && <p className="small muted">Save the draft first.</p>}
            </section>
          )}
          <section className="panel">
            <h2>Revisions</h2>
            <ul style={{ listStyle: "none", padding: 0, margin: 0 }} className="stack">
              {data.revisions.map((r) => (
                <li key={r.id} className="small">
                  <button
                    className={`btn small ${r.id === rev.id ? "" : "secondary"}`}
                    aria-pressed={r.id === rev.id}
                    onClick={async () => {
                      const full = await get<Revision>(`/api/reports/revisions/${r.id}`);
                      setRev(full);
                      setForm(full.content.analyst);
                    }}
                  >
                    Revision {r.revision}
                  </button>{" "}
                  {r.status === "reviewed" ? <Badge tone="ok">Reviewed</Badge> : <Badge tone="warn">Draft</Badge>}
                  <div className="muted">
                    {fmtTime(r.created_at)}
                    {r.reviewer ? `, reviewed by ${r.reviewer}` : ""}
                  </div>
                </li>
              ))}
            </ul>
          </section>
        </aside>
      </div>
    </>
  );
}
