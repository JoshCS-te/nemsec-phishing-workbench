"use client";

import Link from "next/link";
import { useParams, useSearchParams } from "next/navigation";
import { Fragment, Suspense, useState } from "react";
import FindingCard from "@/components/FindingCard";
import { Badge, Empty, ErrorState, JobState, Loading, ParseStatus, Prov, StaticStatus, Tabs, useApi } from "@/components/ui";
import { fmtBytes, fmtTime, send, type Finding, type Note, type SandboxJobBrief } from "@/lib/api";

type CaseEvidence = {
  id: string;
  kind: "email" | "attachment";
  sha256: string;
  size_bytes: number;
  original_filename: string | null;
  parent_id: string | null;
  imported_at: string;
  include_in_report: number;
  subject: string | null;
  from_address: string | null;
  parse_status: string | null;
  static_status: string | null;
  detected_type: string | null;
};
type CaseDetail = {
  id: string;
  title: string;
  description: string;
  status: "open" | "closed";
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  evidence: CaseEvidence[];
  findings: Finding[];
  notes: Note[];
  references: { id: string; case_id: string | null; display_name: string; email: string | null }[];
  sandbox_jobs: SandboxJobBrief[];
};
type HistoryRow = { id: number; entity_type: string; entity_id: string; action: string; detail_json: Record<string, unknown>; at: string };
type TabKey = "evidence" | "findings" | "notes" | "sandbox" | "history";

const NOTE_KINDS: { key: Note["kind"]; label: string; hint: string; prov: "analyst" | "unknown" }[] = [
  { key: "fact", label: "Confirmed facts", hint: "Something you verified, e.g. from mail logs or the recipient.", prov: "analyst" },
  { key: "interpretation", label: "Interpretations", hint: "Your reading of the evidence.", prov: "analyst" },
  { key: "question", label: "Unanswered questions", hint: "What you still need to find out.", prov: "unknown" },
  { key: "note", label: "Working notes", hint: "Scratch notes; not included in the report.", prov: "analyst" },
];

function CaseHeader({ c, reload }: { c: CaseDetail; reload: () => void }) {
  const [editing, setEditing] = useState(false);
  const [title, setTitle] = useState(c.title);
  const [desc, setDesc] = useState(c.description);
  const [err, setErr] = useState<string | null>(null);
  async function patch(body: Record<string, unknown>) {
    setErr(null);
    try {
      await send("PATCH", `/api/cases/${c.id}`, body);
      setEditing(false);
      reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }
  return (
    <>
      <div className="crumbs">
        <Link href="/">Cases</Link> / <span className="mono">{c.id}</span>
      </div>
      {editing ? (
        <form
          className="panel stack"
          onSubmit={(e) => {
            e.preventDefault();
            patch({ title, description: desc });
          }}
        >
          <label className="field">
            Title
            <input type="text" value={title} onChange={(e) => setTitle(e.target.value)} required />
          </label>
          <label className="field">
            Description
            <textarea value={desc} onChange={(e) => setDesc(e.target.value)} />
          </label>
          <div className="row">
            <button className="btn">Save case details</button>
            <button type="button" className="btn secondary" onClick={() => setEditing(false)}>
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <div className="page-head">
          <div>
            <h1>{c.title}</h1>
            <p className="sub">
              {c.status === "open" ? <Badge tone="neutral">Open</Badge> : <Badge tone="ok">Closed {fmtTime(c.closed_at)}</Badge>}{" "}
              <span className="small">opened {fmtTime(c.created_at)}</span>
            </p>
            {c.description && <p style={{ marginTop: 8 }}>{c.description}</p>}
          </div>
          <div className="row">
            <Link className="btn" href={`/cases/${c.id}/report`}>
              Report
            </Link>
            {c.status === "open" && (
              <>
                <Link className="btn secondary" href={`/import?case=${c.id}`}>
                  Import email into case
                </Link>
                <button className="btn secondary" onClick={() => setEditing(true)}>
                  Edit details
                </button>
              </>
            )}
            <button className="btn secondary" onClick={() => patch({ status: c.status === "open" ? "closed" : "open" })}>
              {c.status === "open" ? "Close case" : "Reopen case"}
            </button>
          </div>
        </div>
      )}
      {err && <div className="notice bad" role="alert">{err}</div>}
      {c.status === "closed" && <div className="notice trust">This case is closed. Reopen it to change evidence, reviews or notes.</div>}
    </>
  );
}

function EvidenceTab({ c, reload }: { c: CaseDetail; reload: () => void }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const open = c.status === "open";
  const emails = c.evidence.filter((e) => e.kind === "email");
  const atts = (pid: string) => c.evidence.filter((e) => e.parent_id === pid);

  async function toggle(id: string, include: boolean) {
    await send("PATCH", `/api/cases/${c.id}/evidence/${id}`, { include });
    reload();
  }

  return (
    <div className="grid-main">
      <section className="panel">
        <h2>Evidence in this case</h2>
        {emails.length === 0 ? (
          <Empty title="No evidence yet">
            <p>
              <Link href={`/import?case=${c.id}`}>Import an .eml file</Link> into this case.
            </p>
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>In report</th>
                  <th>Evidence</th>
                  <th>Status</th>
                  <th className="num">Size</th>
                </tr>
              </thead>
              <tbody>
                {emails.map((e) => (
                  <Fragment key={e.id}>
                    <tr>
                      <td>
                        <input type="checkbox" aria-label={`Include ${e.id} in report`} checked={!!e.include_in_report} disabled={!open} onChange={(ev) => toggle(e.id, ev.target.checked)} />
                      </td>
                      <td>
                        <Link href={`/emails/${e.id}`}>{e.subject ?? "(no subject)"}</Link>
                        <div className="small muted">
                          <span className="mono">{e.id}</span> from <span className="mono">{e.from_address ?? "unknown"}</span>
                        </div>
                      </td>
                      <td>{e.parse_status && <ParseStatus status={e.parse_status} />}</td>
                      <td className="num">{fmtBytes(e.size_bytes)}</td>
                    </tr>
                    {atts(e.id).map((a) => (
                      <tr key={a.id}>
                        <td style={{ paddingLeft: 18 }}>
                          <input type="checkbox" aria-label={`Include ${a.id} in report`} checked={!!a.include_in_report} disabled={!open} onChange={(ev) => toggle(a.id, ev.target.checked)} />
                        </td>
                        <td style={{ paddingLeft: 18 }}>
                          ↳ <Link href={`/attachments/${a.id}`}>{a.original_filename ?? "(no filename)"}</Link>
                          <div className="small muted mono">{a.id}{a.detected_type ? `, ${a.detected_type}` : ""}</div>
                        </td>
                        <td>{a.static_status && <StaticStatus status={a.static_status} />}</td>
                        <td className="num">{fmtBytes(a.size_bytes)}</td>
                      </tr>
                    ))}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <section className="panel">
        <h2>Reference identities</h2>
        <p className="small muted">
          People or brands this email might be impersonating. Display names that resemble these but come from another address are flagged.
        </p>
        {c.references.length === 0 ? (
          <p className="small absent">None added.</p>
        ) : (
          <ul className="small" style={{ paddingLeft: 18 }}>
            {c.references.map((r) => (
              <li key={r.id}>
                {r.display_name} <span className="mono">{r.email ? `<${r.email}>` : ""}</span>
                {r.case_id === null && <span className="muted"> (all cases)</span>}{" "}
                {open && (
                  <button
                    className="btn secondary small"
                    style={{ padding: "0 6px" }}
                    onClick={async () => {
                      await send("DELETE", `/api/references/${r.id}`);
                      reload();
                    }}
                  >
                    Remove
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
        {open && (
          <form
            className="stack"
            style={{ marginTop: 10 }}
            onSubmit={async (e) => {
              e.preventDefault();
              setErr(null);
              try {
                await send("POST", "/api/references", { case_id: c.id, display_name: name, email: email || null });
                setName("");
                setEmail("");
                reload();
              } catch (ex) {
                setErr(ex instanceof Error ? ex.message : String(ex));
              }
            }}
          >
            <label className="field">
              Display name
              <input type="text" value={name} onChange={(e) => setName(e.target.value)} required placeholder="e.g. Adaeze Okafor (CFO)" />
            </label>
            <label className="field">
              Known genuine address
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="optional" />
            </label>
            <button className="btn secondary">Add reference and re-check</button>
            {err && <p role="alert" className="small" style={{ color: "var(--danger)" }}>{err}</p>}
          </form>
        )}
      </section>
    </div>
  );
}

function FindingsTab({ c, reload }: { c: CaseDetail; reload: () => void }) {
  const [filter, setFilter] = useState<"all" | "unreviewed" | "relevant" | "benign" | "unresolved">("all");
  const shown = c.findings.filter((f) => filter === "all" || f.review_status === filter);
  const count = (s: string) => c.findings.filter((f) => f.review_status === s).length;
  return (
    <section>
      <div className="row" style={{ marginBottom: 14 }} role="group" aria-label="Filter findings">
        {(["all", "unreviewed", "relevant", "benign", "unresolved"] as const).map((s) => (
          <button key={s} className={`btn small ${filter === s ? "" : "secondary"}`} aria-pressed={filter === s} onClick={() => setFilter(s)}>
            {s[0].toUpperCase() + s.slice(1)} ({s === "all" ? c.findings.length : count(s)})
          </button>
        ))}
      </div>
      <p className="small muted">
        Findings are a rule&apos;s reading of the evidence, ordered by how much weight each indicator carries on its own. There is no total score —
        the conclusion is yours.
      </p>
      {shown.length === 0 ? (
        <Empty title={c.findings.length === 0 ? "No rule findings in this case" : "Nothing matches this filter"}>
          {c.findings.length === 0 && <p className="small">That is not evidence of safety. Check attachments for incomplete analysis.</p>}
        </Empty>
      ) : (
        shown.map((f) => <FindingCard key={f.id} f={f} caseId={c.id} editable={c.status === "open"} onChanged={reload} />)
      )}
    </section>
  );
}

function NoteItem({ n, c, reload }: { n: Note; c: CaseDetail; reload: () => void }) {
  const [editing, setEditing] = useState(false);
  const [body, setBody] = useState(n.body);
  const open = c.status === "open";
  return (
    <li className="panel" style={{ marginBottom: 8, padding: "12px 14px" }}>
      {editing ? (
        <div className="stack">
          <textarea value={body} onChange={(e) => setBody(e.target.value)} />
          <div className="row">
            <button
              className="btn small"
              onClick={async () => {
                await send("PATCH", `/api/cases/${c.id}/notes/${n.id}`, { body });
                setEditing(false);
                reload();
              }}
            >
              Save note
            </button>
            <button className="btn small secondary" onClick={() => setEditing(false)}>
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <>
          <p style={{ margin: 0, whiteSpace: "pre-wrap", textDecoration: n.kind === "question" && n.resolved ? "line-through" : undefined }}>{n.body}</p>
          <div className="row small muted" style={{ marginTop: 6 }}>
            {n.evidence_refs.length > 0 && <span>refs: {n.evidence_refs.map((r) => <code key={r}>{r} </code>)}</span>}
            <span>{fmtTime(n.updated_at)}</span>
            {n.kind === "question" && n.resolved ? <Badge tone="ok">Answered</Badge> : null}
            {open && (
              <>
                <button className="btn secondary small" onClick={() => setEditing(true)}>
                  Edit
                </button>
                {n.kind === "question" && (
                  <button
                    className="btn secondary small"
                    onClick={async () => {
                      await send("PATCH", `/api/cases/${c.id}/notes/${n.id}`, { resolved: !n.resolved });
                      reload();
                    }}
                  >
                    {n.resolved ? "Mark open" : "Mark answered"}
                  </button>
                )}
                <button
                  className="btn secondary small"
                  onClick={async () => {
                    if (confirm("Delete this note?")) {
                      await send("DELETE", `/api/cases/${c.id}/notes/${n.id}`);
                      reload();
                    }
                  }}
                >
                  Delete
                </button>
              </>
            )}
          </div>
        </>
      )}
    </li>
  );
}

function NotesTab({ c, reload }: { c: CaseDetail; reload: () => void }) {
  const [kind, setKind] = useState<Note["kind"]>("fact");
  const [body, setBody] = useState("");
  const [refs, setRefs] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const refOptions = [...c.evidence.map((e) => ({ id: e.id, label: `${e.id} ${e.kind === "email" ? e.subject ?? "" : e.original_filename ?? ""}` })), ...c.findings.map((f) => ({ id: f.id, label: `${f.id} ${f.name}` })), ...c.sandbox_jobs.map((j) => ({ id: j.id, label: `${j.id} sandbox run` }))];
  return (
    <div className="grid-main">
      <div>
        {NOTE_KINDS.map((k) => {
          const items = c.notes.filter((n) => n.kind === k.key);
          return (
            <section key={k.key} className={`ledger ${k.prov}`} style={{ marginBottom: 20 }}>
              <div className="row" style={{ marginBottom: 8 }}>
                <h2 style={{ fontSize: "var(--step-1)" }}>{k.label}</h2>
                <Prov kind={k.prov} label={k.key === "question" ? "Not yet established" : "Analyst"} />
              </div>
              {items.length === 0 ? (
                <p className="small absent">None yet.</p>
              ) : (
                <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
                  {items.map((n) => (
                    <NoteItem key={n.id} n={n} c={c} reload={reload} />
                  ))}
                </ul>
              )}
            </section>
          );
        })}
      </div>
      {c.status === "open" && (
        <form
          className="panel stack"
          onSubmit={async (e) => {
            e.preventDefault();
            setErr(null);
            try {
              await send("POST", `/api/cases/${c.id}/notes`, { kind, body, evidence_refs: refs });
              setBody("");
              setRefs([]);
              reload();
            } catch (ex) {
              setErr(ex instanceof Error ? ex.message : String(ex));
            }
          }}
        >
          <h2>Add a note</h2>
          <fieldset style={{ border: 0, padding: 0, margin: 0 }} className="stack">
            <legend className="small muted" style={{ marginBottom: 6 }}>
              What kind of statement is this?
            </legend>
            {NOTE_KINDS.map((k) => (
              <label key={k.key} className="check">
                <input type="radio" name="kind" checked={kind === k.key} onChange={() => setKind(k.key)} />
                <span>
                  <strong>{k.label.replace(/s$/, "")}</strong>
                  <br />
                  <span className="small muted">{k.hint}</span>
                </span>
              </label>
            ))}
          </fieldset>
          <label className="field">
            Note
            <textarea required value={body} onChange={(e) => setBody(e.target.value)} />
          </label>
          <label className="field">
            Link to evidence (optional, hold Ctrl to pick several)
            <select multiple value={refs} onChange={(e) => setRefs(Array.from(e.target.selectedOptions).map((o) => o.value))} style={{ minHeight: 110 }}>
              {refOptions.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
          <button className="btn" disabled={!body.trim()}>
            Add note
          </button>
          {err && <p role="alert" className="small" style={{ color: "var(--danger)" }}>{err}</p>}
        </form>
      )}
    </div>
  );
}

function HistoryTab({ id }: { id: string }) {
  const { data, error, loading } = useApi<HistoryRow[]>(`/api/cases/${id}/history`);
  if (loading) return <Loading />;
  if (error) return <ErrorState error={error} />;
  return (
    <section className="panel">
      <h2>Case history</h2>
      <p className="small muted">Newest first. Credentials and tokens are redacted before anything is written here.</p>
      <ol className="timeline">
        {(data ?? []).map((h) => (
          <li key={h.id}>
            <time dateTime={h.at}>{h.at.replace("T", " ").replace("+00:00", "")}</time>
            <span>
              <strong>{h.action.replace(/_/g, " ")}</strong> <span className="mono small">{h.entity_type} {h.entity_id}</span>
              {Object.keys(h.detail_json ?? {}).length > 0 && <span className="raw">{JSON.stringify(h.detail_json)}</span>}
            </span>
          </li>
        ))}
      </ol>
    </section>
  );
}

function CaseInner() {
  const { id } = useParams<{ id: string }>();
  const qs = useSearchParams();
  const [tab, setTab] = useState<TabKey>((qs.get("tab") as TabKey) || "evidence");
  const { data: c, error, loading, reload } = useApi<CaseDetail>(`/api/cases/${id}`, (d) =>
    d && (d.evidence.some((e) => e.static_status === "pending" || e.static_status === "running") || d.sandbox_jobs.some((j) => j.reset_status === "pending" || !["completed", "failed", "timed_out", "cancelled", "reset_failed"].includes(j.state))) ? 3000 : undefined,
  );
  if (loading && !c) return <Loading lines={8} />;
  if (error && !c) return <ErrorState error={error} retry={reload} />;
  if (!c) return null;
  const unreviewed = c.findings.filter((f) => f.review_status === "unreviewed").length;
  return (
    <>
      <CaseHeader key={c.updated_at} c={c} reload={reload} />
      <Tabs<TabKey>
        active={tab}
        onChange={setTab}
        tabs={[
          { key: "evidence", label: "Evidence", count: c.evidence.length },
          { key: "findings", label: unreviewed ? `Findings (${unreviewed} to review)` : "Findings", count: c.findings.length },
          { key: "notes", label: "Notes", count: c.notes.length },
          { key: "sandbox", label: "Sandbox runs", count: c.sandbox_jobs.length },
          { key: "history", label: "History" },
        ]}
      />
      {tab === "evidence" && <EvidenceTab c={c} reload={reload} />}
      {tab === "findings" && <FindingsTab c={c} reload={reload} />}
      {tab === "notes" && <NotesTab c={c} reload={reload} />}
      {tab === "sandbox" && (
        <section className="panel">
          <h2>Sandbox runs in this case</h2>
          {c.sandbox_jobs.length === 0 ? (
            <Empty title="No sandbox runs">
              <p className="small">Open an attachment to submit it. Nothing runs unless you ask.</p>
            </Empty>
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>Run</th>
                    <th>Attachment</th>
                    <th>State</th>
                    <th>Reset</th>
                    <th>Submitted</th>
                  </tr>
                </thead>
                <tbody>
                  {c.sandbox_jobs.map((j) => (
                    <tr key={j.id}>
                      <td>
                        <Link className="mono" href={`/sandbox/jobs/${j.id}`}>{j.id}</Link> {j.is_demo ? <Badge tone="demo">DEMO</Badge> : null}
                      </td>
                      <td><Link className="mono small" href={`/attachments/${j.attachment_id}`}>{j.attachment_id}</Link></td>
                      <td><JobState state={j.state} /></td>
                      <td className="small">{j.reset_status ?? "—"}</td>
                      <td className="small">{fmtTime(j.submitted_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
      {tab === "history" && <HistoryTab id={c.id} />}
    </>
  );
}

export default function CasePage() {
  return (
    <Suspense fallback={<Loading lines={8} />}>
      <CaseInner />
    </Suspense>
  );
}
