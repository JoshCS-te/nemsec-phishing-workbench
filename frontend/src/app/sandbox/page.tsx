"use client";

import Link from "next/link";
import { useState } from "react";
import { Badge, Empty, ErrorState, JobState, KV, Loading, useApi } from "@/components/ui";
import { fmtTime, send, type SandboxJobBrief } from "@/lib/api";

type SandboxStatus = {
  mode: string;
  enabled: boolean;
  is_demo?: boolean;
  detail?: string;
  capabilities?: { engine: string; guest_platform: string; supported_types: string[]; observations: string[]; network_mode: string; notes: string[] };
  health?: { ok: boolean; detail: string };
  worker?: { name: string; adapter: string; status: string; reason: string | null; updated_at: string };
};

export default function SandboxPage() {
  const { data: st, error, loading, reload } = useApi<SandboxStatus>("/api/sandbox/status", 10000);
  const { data: jobs, reload: reloadJobs } = useApi<SandboxJobBrief[]>("/api/sandbox/jobs", 4000);
  const [analyst, setAnalyst] = useState("");
  const [note, setNote] = useState("");
  const [msg, setMsg] = useState<string | null>(null);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Sandbox</h1>
          <p className="sub">Attachments only run here after an analyst submits them. The sandbox host is a separate machine.</p>
        </div>
      </div>
      {loading && <Loading />}
      {error ? <ErrorState error={error} retry={reload} /> : null}
      {st && (
        <div className="grid-2">
          <section className="panel">
            <h2>Engine</h2>
            {!st.enabled ? (
              <Empty title="Sandbox is off">
                <p className="small">{st.detail}</p>
                <p className="small">
                  Set <code>PHB_SANDBOX_MODE=cape</code> after following docs/sandbox-deployment.md, or <code>demo</code> to try the flow
                  with synthetic results.
                </p>
              </Empty>
            ) : (
              <>
                {st.is_demo && <div className="notice demo">Demo mode. Results are synthetic and are never observations of a real file.</div>}
                <KV
                  rows={[
                    ["Mode", st.mode],
                    ["Engine", st.capabilities?.engine],
                    ["Health", st.health?.ok ? <Badge tone="ok">{st.health.detail}</Badge> : <Badge tone="bad">{st.health?.detail ?? "unknown"}</Badge>],
                    ["Guest platform", st.capabilities?.guest_platform],
                    ["Network", st.capabilities?.network_mode],
                    ["Records", st.capabilities?.observations.join(", ")],
                    ["Runs content identified as", st.capabilities?.supported_types.join(", ")],
                  ]}
                />
                <ul className="small" style={{ marginTop: 10 }}>
                  {st.capabilities?.notes.map((n, i) => (
                    <li key={i}>{n}</li>
                  ))}
                </ul>
              </>
            )}
          </section>
          {st.worker && (
            <section className="panel">
              <h2>Guest VM</h2>
              <KV
                rows={[
                  ["Name", <span key="n" className="mono">{st.worker.name}</span>],
                  [
                    "State",
                    st.worker.status === "available" ? (
                      <Badge tone="ok">Available — last reset verified</Badge>
                    ) : st.worker.status === "busy" ? (
                      <Badge tone="neutral">Busy — {st.worker.reason}</Badge>
                    ) : (
                      <Badge tone="bad">Quarantined</Badge>
                    ),
                  ],
                  ["Since", fmtTime(st.worker.updated_at)],
                ]}
              />
              {st.worker.status === "quarantined" && (
                <form
                  className="stack"
                  style={{ marginTop: 14 }}
                  onSubmit={async (e) => {
                    e.preventDefault();
                    setMsg(null);
                    try {
                      await send("POST", `/api/sandbox/workers/${st.worker!.name}/release`, { analyst, note });
                      setNote("");
                      reload();
                    } catch (ex) {
                      setMsg(ex instanceof Error ? ex.message : String(ex));
                    }
                  }}
                >
                  <div className="notice bad">
                    {st.worker.reason}. No further jobs will run on this guest until you restore it to its clean snapshot on the sandbox
                    host and record how you checked it.
                  </div>
                  <label className="field">
                    Your name
                    <input type="text" required value={analyst} onChange={(e) => setAnalyst(e.target.value)} />
                  </label>
                  <label className="field">
                    How was the guest restored and verified?
                    <textarea required value={note} onChange={(e) => setNote(e.target.value)} />
                  </label>
                  <div className="row">
                    <button className="btn" disabled={!analyst.trim() || note.trim().length < 10}>
                      Release guest
                    </button>
                    {msg && <span role="alert" className="small" style={{ color: "var(--danger)" }}>{msg}</span>}
                  </div>
                </form>
              )}
            </section>
          )}
        </div>
      )}
      <section className="panel">
        <div className="panel-head">
          <h2>Jobs</h2>
          <button className="btn secondary small" onClick={reloadJobs}>
            Refresh
          </button>
        </div>
        {!jobs ? (
          <Loading />
        ) : jobs.length === 0 ? (
          <Empty title="No sandbox jobs yet">
            <p className="small">Open an attachment and choose “Execute in sandbox”.</p>
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Job</th>
                  <th>Attachment</th>
                  <th>State</th>
                  <th>Post-run reset</th>
                  <th>Submitted</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((j) => (
                  <tr key={j.id}>
                    <td>
                      <Link href={`/sandbox/jobs/${j.id}`} className="mono">
                        {j.id}
                      </Link>{" "}
                      {j.is_demo ? <Badge tone="demo">DEMO</Badge> : null}
                    </td>
                    <td>
                      <Link href={`/attachments/${j.attachment_id}`} className="mono small">
                        {j.attachment_id}
                      </Link>
                    </td>
                    <td>
                      <JobState state={j.state} />
                    </td>
                    <td className="small">{j.reset_status ?? "—"}</td>
                    <td className="small">
                      {fmtTime(j.submitted_at)}
                      <div className="muted">{j.submitted_by}</div>
                    </td>
                    <td className="small">{j.state_detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
