"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Badge, Empty, ErrorState, Loading, ProvenanceLegend, useApi } from "@/components/ui";
import { fmtTime, send, type CaseSummary } from "@/lib/api";

type SandboxStatus = { mode: string; enabled: boolean; is_demo?: boolean; health?: { ok: boolean; detail: string }; worker?: { status: string; reason: string | null } };

export default function Dashboard() {
  const router = useRouter();
  const { data: cases, error, loading, reload } = useApi<CaseSummary[]>("/api/cases");
  const { data: sbx } = useApi<SandboxStatus>("/api/sandbox/status");
  const [title, setTitle] = useState("");
  const [desc, setDesc] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [filter, setFilter] = useState<"open" | "closed" | "all">("open");

  async function createCase(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      const c = await send<{ id: string }>("POST", "/api/cases", { title, description: desc });
      router.push(`/cases/${c.id}`);
    } catch (err) {
      setMsg(err instanceof Error ? err.message : String(err));
      setBusy(false);
    }
  }

  async function loadDemo() {
    setBusy(true);
    setMsg(null);
    try {
      const r = await send<{ case_id: string }>("POST", "/api/demo/load-samples");
      router.push(`/cases/${r.case_id}`);
    } catch (err) {
      setMsg(err instanceof Error ? err.message : String(err));
      setBusy(false);
    }
  }

  const shown = (cases ?? []).filter((c) => filter === "all" || c.status === filter);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Investigations</h1>
          <p className="sub">Each case keeps its evidence, rule findings, your notes and the report together.</p>
        </div>
        <div className="row">
          <Link className="btn" href="/import">
            Import an email
          </Link>
          <button className="btn secondary" onClick={loadDemo} disabled={busy}>
            Load synthetic demo case
          </button>
        </div>
      </div>

      {sbx && (
        <div className={`notice ${sbx.is_demo ? "demo" : sbx.enabled && sbx.health?.ok === false ? "bad" : "trust"}`}>
          {!sbx.enabled && <>Sandbox is off. Static analysis still runs on every attachment. Turn it on with PHB_SANDBOX_MODE.</>}
          {sbx.enabled && sbx.is_demo && <>Sandbox is in demo mode: results are synthetic and labelled as such. Nothing is executed.</>}
          {sbx.enabled && !sbx.is_demo && (
            <>
              Live sandbox: {sbx.health?.ok ? "reachable" : "not reachable"} — {sbx.health?.detail}.{" "}
              {sbx.worker?.status === "quarantined" && <strong>Worker quarantined: {sbx.worker.reason}</strong>}
            </>
          )}{" "}
          <Link href="/sandbox">Sandbox details</Link>
        </div>
      )}

      <div className="grid-main">
        <section className="panel" aria-labelledby="cases-h">
          <div className="panel-head">
            <h2 id="cases-h">Cases</h2>
            <div className="row" role="group" aria-label="Filter cases">
              {(["open", "closed", "all"] as const).map((f) => (
                <button key={f} className={`btn small ${filter === f ? "" : "secondary"}`} aria-pressed={filter === f} onClick={() => setFilter(f)}>
                  {f[0].toUpperCase() + f.slice(1)}
                </button>
              ))}
            </div>
          </div>
          {loading && <Loading />}
          {error ? <ErrorState error={error} retry={reload} /> : null}
          {!loading && !error && shown.length === 0 && (
            <Empty title={filter === "open" ? "No open cases" : "No cases here"}>
              <p>Create a case on the right, or load the synthetic demo case to see every feature with safe sample data.</p>
            </Empty>
          )}
          {shown.length > 0 && (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>Case</th>
                    <th>Status</th>
                    <th className="num">Emails</th>
                    <th>Findings to review</th>
                    <th>Report</th>
                    <th>Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((c) => (
                    <tr key={c.id}>
                      <td>
                        <Link href={`/cases/${c.id}`}>{c.title}</Link>
                        <div className="mono small muted">{c.id}</div>
                      </td>
                      <td>{c.status === "open" ? <Badge tone="neutral">Open</Badge> : <Badge tone="ok">Closed</Badge>}</td>
                      <td className="num">{c.email_count}</td>
                      <td>
                        {c.finding_count === 0 ? (
                          <span className="muted">none</span>
                        ) : c.unreviewed_count > 0 ? (
                          <Badge tone="warn">{c.unreviewed_count} of {c.finding_count} unreviewed</Badge>
                        ) : (
                          <Badge tone="ok">all {c.finding_count} reviewed</Badge>
                        )}
                      </td>
                      <td>
                        {c.report_status === "reviewed" ? <Badge tone="ok">Reviewed</Badge> : c.report_status === "draft" ? <Badge tone="warn">Draft</Badge> : <span className="muted">none</span>}
                      </td>
                      <td className="small">{fmtTime(c.updated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <div>
          <form className="panel stack" onSubmit={createCase} aria-labelledby="new-h">
            <h2 id="new-h">New case</h2>
            <label className="field">
              Title
              <input type="text" required value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Payroll update request to HR" />
            </label>
            <label className="field">
              What was reported, by whom, and when
              <textarea value={desc} onChange={(e) => setDesc(e.target.value)} />
            </label>
            <div className="row">
              <button className="btn" disabled={busy || !title.trim()}>
                Create case
              </button>
            </div>
            {msg && (
              <p role="alert" className="small" style={{ color: "var(--danger)" }}>
                {msg}
              </p>
            )}
          </form>
          <section className="panel">
            <h3>Reading the workbench</h3>
            <p className="small muted">Every value is tagged with where it came from. No score is calculated: indicators are weighed by you.</p>
            <ProvenanceLegend />
          </section>
        </div>
      </div>
    </>
  );
}
