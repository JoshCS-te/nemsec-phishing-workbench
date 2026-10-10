"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import { Badge, Empty, ErrorState, JobState, KV, Loading, Prov, useApi } from "@/components/ui";
import { fmtTime, send, type SandboxJobBrief } from "@/lib/api";

type Obs = {
  source: string;
  is_demo: boolean;
  demo_label?: string;
  duration_s: number | null;
  analysis_package: string | null;
  processes: { pid: number; ppid: number; name: string; path: string; command_line: string | null }[];
  files: { created: string[]; modified: string[]; deleted: string[] };
  registry: { set: string[]; deleted: string[] };
  persistence: { type: string; detail: string }[];
  network: { dns: { query: string; answers: string[] }[]; connections: { proto: string; dst: string; port: number }[]; http: { method: string; url: string }[] };
  events: { type: string; detail: string }[];
  engine_signatures: { name: string; description: string; severity: number }[];
  errors: string[];
};
type Job = SandboxJobBrief & {
  observations: Obs | null;
  coverage: { engine: string; observed_categories: string[]; network_mode: string; limitations: string[] } | null;
  artifacts: { id: string; kind: string; label: string; sha256: string; size_bytes: number }[];
  deadline_at: string;
  cancel_requested: number;
};

const TERMINAL = ["completed", "failed", "timed_out", "cancelled", "reset_failed"];

function List({ items, empty = "none recorded" }: { items: string[]; empty?: string }) {
  if (!items.length) return <span className="muted">{empty}</span>;
  return <pre className="block" style={{ maxHeight: 220 }}>{items.join("\n")}</pre>;
}

function ProcessTree({ procs }: { procs: Obs["processes"] }) {
  const pids = new Set(procs.map((p) => p.pid));
  const roots = procs.filter((p) => !pids.has(p.ppid));
  const kids = (pid: number) => procs.filter((p) => p.ppid === pid && p.pid !== pid);
  const node = (p: Obs["processes"][number], depth: number): React.ReactNode => (
    <li key={`${p.pid}-${depth}`}>
      <strong>{p.name}</strong> <span className="mono small muted">pid {p.pid}, parent {p.ppid}</span>
      {p.command_line && <span className="raw">{p.command_line}</span>}
      {depth < 20 && kids(p.pid).length > 0 && <ul>{kids(p.pid).map((k) => node(k, depth + 1))}</ul>}
    </li>
  );
  return <ul className="tree">{roots.map((r) => node(r, 0))}</ul>;
}

export default function JobPage() {
  const { id } = useParams<{ id: string }>();
  const { data: j, error, loading, reload } = useApi<Job>(`/api/sandbox/jobs/${id}`, (d) =>
    !d || !TERMINAL.includes(d.state) || d.reset_status === "pending" ? 2500 : undefined,
  );
  const [err, setErr] = useState<string | null>(null);
  if (loading && !j) return <Loading lines={8} />;
  if (error && !j) return <ErrorState error={error} retry={reload} />;
  if (!j) return null;
  const o = j.observations;
  const demo = !!j.is_demo;
  const flow = ["queued", "running", j.execution_outcome ?? (TERMINAL.includes(j.state) ? j.state : "finished"), "reset check"];
  const currentIdx = !TERMINAL.includes(j.state) ? (j.state === "running" ? 1 : 0) : j.reset_status === "pending" ? 3 : 2;
  const bad = ["failed", "reset_failed", "timed_out"].includes(j.state);

  return (
    <>
      <div className="crumbs">
        <Link href="/sandbox">Sandbox</Link> / attachment <Link href={`/attachments/${j.attachment_id}`}>{j.attachment_id}</Link>
      </div>
      <div className="page-head">
        <div>
          <h1>
            Sandbox run <span className="mono">{j.id}</span>
          </h1>
          <p className="sub">
            <JobState state={j.state} /> {demo && <Badge tone="demo">DEMO — synthetic, nothing executed</Badge>}
          </p>
        </div>
        {!TERMINAL.includes(j.state) && !j.cancel_requested && (
          <button
            className="btn secondary"
            onClick={async () => {
              try {
                await send("POST", `/api/sandbox/jobs/${id}/cancel`);
                reload();
              } catch (e) {
                setErr(e instanceof Error ? e.message : String(e));
              }
            }}
          >
            Cancel run
          </button>
        )}
      </div>
      {err && <div className="notice bad" role="alert">{err}</div>}
      {demo && <div className="notice demo">These results were produced by the demo adapter. They are not observations of the attachment and must not be used as evidence.</div>}

      <div className="states" aria-label="Job progress" style={{ marginBottom: 18 }}>
        {flow.map((s, i) => (
          <span key={s + i} className={i < currentIdx ? "done" : i === currentIdx ? `current ${bad && i >= 2 ? "bad" : ""}` : ""}>
            {i < currentIdx ? "✓ " : i === currentIdx ? "● " : ""}
            {s.replace("_", " ")}
          </span>
        ))}
      </div>

      <div className="grid-main">
        <div>
          {j.state === "completed" && (
            <div className="notice">
              <strong>Execution finished.</strong> That only means the engine ran the file and reported back — it is not a verdict that the file is safe.
            </div>
          )}
          {!o ? (
            <section className="panel">
              {TERMINAL.includes(j.state) ? (
                <Empty title="No behaviour was recorded">
                  <p className="small">{j.state_detail}</p>
                </Empty>
              ) : (
                <>
                  <h2>Waiting for results</h2>
                  <p className="small muted">{j.state_detail}</p>
                  <Loading lines={3} />
                </>
              )}
            </section>
          ) : (
            <>
              <section className={`panel ledger ${demo ? "" : "observed"}`}>
                <div className="panel-head">
                  <h2>Processes</h2>
                  <Prov kind={demo ? "demo" : "observed"} label={demo ? "Demo data" : "Observed by sandbox"} />
                </div>
                {o.processes.length ? <ProcessTree procs={o.processes} /> : <span className="muted">No process activity recorded.</span>}
              </section>
              <section className={`panel ledger ${demo ? "" : "observed"}`}>
                <h2>Files and registry</h2>
                <KV
                  rows={[
                    ["Files created / written", <List key="c" items={o.files.created} />],
                    ["Files deleted", <List key="d" items={o.files.deleted} />],
                    ["Registry values set", <List key="r" items={o.registry.set} />],
                    ["Registry deleted", <List key="rd" items={o.registry.deleted} />],
                  ]}
                />
              </section>
              <section className="panel ledger inferred">
                <h2>Persistence-related changes</h2>
                <p className="small muted">Derived by this tool from the paths and keys above (run keys, services, startup folders, scheduled tasks).</p>
                {o.persistence.length ? (
                  <ul className="small">
                    {o.persistence.map((p, i) => (
                      <li key={i}>
                        <strong>{p.type}:</strong> <span className="mono">{p.detail}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <span className="muted small">None recorded.</span>
                )}
              </section>
              <section className={`panel ledger ${demo ? "" : "observed"}`}>
                <h2>Network attempts</h2>
                <p className="small muted">Inside the isolated guest network. Answers may come from simulated services, not the internet.</p>
                <KV
                  rows={[
                    ["DNS queries", <List key="d" items={o.network.dns.map((d) => `${d.query}${d.answers?.length ? ` → ${d.answers.join(", ")}` : ""}`)} />],
                    ["Connections", <List key="c" items={o.network.connections.map((c) => `${c.proto} ${c.dst}:${c.port}`)} />],
                    ["HTTP", <List key="h" items={o.network.http.map((h) => `${h.method} ${h.url}`)} />],
                  ]}
                />
              </section>
              <section className="panel">
                <h2>Other events</h2>
                <List items={o.events.map((e) => `${e.type}: ${e.detail}`)} empty="none" />
                {o.engine_signatures.length > 0 && (
                  <div className="ledger inferred" style={{ marginTop: 14 }}>
                    <Prov kind="inferred" label="Engine's own inferences" />
                    <ul className="small">
                      {o.engine_signatures.map((s, i) => (
                        <li key={i}>
                          <strong>{s.name}</strong> (severity {s.severity}) — {s.description}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {o.errors.length > 0 && (
                  <>
                    <h3 style={{ marginTop: 12 }}>Engine errors</h3>
                    <List items={o.errors} />
                  </>
                )}
              </section>
              {j.artifacts.filter((a) => a.kind === "screenshot").length > 0 && (
                <section className="panel">
                  <h2>Screenshots</h2>
                  <div className="stack">
                    {j.artifacts
                      .filter((a) => a.kind === "screenshot")
                      .map((a) => (
                        <figure key={a.id} style={{ margin: 0 }}>
                          <img className="shot" src={`/api/sandbox/artifacts/${a.id}`} alt={`Sandbox screenshot ${a.label}`} />
                          <figcaption className="small muted">
                            {demo ? "DEMO placeholder. " : ""}
                            {a.label}, SHA-256 <span className="hash">{a.sha256}</span>
                          </figcaption>
                        </figure>
                      ))}
                  </div>
                </section>
              )}
            </>
          )}
        </div>
        <aside>
          <section className="panel">
            <h2>Run record</h2>
            <KV
              rows={[
                ["Engine", j.adapter],
                ["Engine task", j.external_task_id ?? "not yet assigned"],
                ["Guest", j.worker_name],
                ["Submitted", `${fmtTime(j.submitted_at)} by ${j.submitted_by}`],
                ["Started", fmtTime(j.started_at)],
                ["Finished", fmtTime(j.finished_at)],
                ["Run time limit", `${j.timeout_s}s`],
                ["Duration", o?.duration_s ? `${o.duration_s}s` : "—"],
                ["Outcome", j.execution_outcome ?? "—"],
                [
                  "Post-run reset",
                  j.reset_status === "verified" ? (
                    <Badge tone="ok">Verified</Badge>
                  ) : j.reset_status === "failed" ? (
                    <Badge tone="bad">Failed — guest quarantined</Badge>
                  ) : j.reset_status === "pending" ? (
                    <Badge tone="neutral">Checking</Badge>
                  ) : (
                    <span className="muted">{j.reset_status ?? "—"}</span>
                  ),
                ],
                ["Detail", j.state_detail],
              ]}
            />
            {j.reset_detail && <p className="small muted" style={{ marginTop: 8 }}>{j.reset_detail}</p>}
          </section>
          {j.coverage && (
            <section className="panel ledger unknown">
              <h2>What this run could not show</h2>
              <ul className="small">
                {j.coverage.limitations.map((l, i) => (
                  <li key={i}>{l}</li>
                ))}
              </ul>
            </section>
          )}
        </aside>
      </div>
    </>
  );
}
