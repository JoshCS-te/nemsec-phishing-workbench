"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import FindingCard from "@/components/FindingCard";
import { Absent, Badge, Empty, ErrorState, Hash, JobState, KV, Loading, Prov, StaticStatus, useApi } from "@/components/ui";
import { fmtBytes, fmtTime, send, type Finding, type SandboxJobBrief } from "@/lib/api";

type ArchiveEntry = {
  name: string;
  uncompressed_size: number;
  compressed_size: number;
  ratio: number | null;
  encrypted: boolean;
  symlink: boolean;
  path_issue: string | null;
  status: string;
  sha256: string | null;
  detected: { label: string; type: string } | null;
};
type Archive = { entries: ArchiveEntry[]; nested: { name: string; depth: number; result: Archive }[]; limits_hit: string[]; error?: string };
type StaticResult = {
  status: string;
  detected?: { type: string; label: string; family: string };
  extension?: { extension: string | null; expected_types: string[] | null; mismatch: boolean; notes: string[] };
  strings?: { total_found: number; sample: string[]; interesting: string[]; truncated: boolean };
  urls?: { original: string; normalized_host: string | null; warnings: { message: string }[] }[];
  archive?: Archive & { gzip_inner?: { size: number; ratio: number; detected: { label: string }; sha256: string } };
  office?: {
    macros: { present: boolean; modules: { name: string; stream: string; lines: number; excerpt: string }[]; keywords: { type: string; keyword: string; description: string }[]; note: string } | null;
    embedded_objects: string[];
    external_relationships: { part: string; target: string; type: string }[];
    metadata: Record<string, string>;
  };
  pdf?: { version: string | null; keyword_counts: Record<string, number>; encrypted: boolean; uris: string[]; note: string };
  pe?: { machine: string; is_dll: boolean; compile_timestamp: number; sections: { name: string; raw_size: number; entropy: number }[]; imports: { dll: string; functions: string[] }[]; has_authenticode_blob: boolean; signature_note: string; error?: string };
  text_excerpt?: string;
  limitations: string[];
  stages_completed: string[];
};
type AttachmentDetail = {
  evidence_id: string;
  email_evidence_id: string;
  filename_display: string | null;
  filename_raw: string | null;
  declared_mime: string;
  disposition: string | null;
  detected_type: string | null;
  static_status: string;
  static_result: StaticResult | null;
  static_updated_at: string | null;
  sha256: string;
  size_bytes: number;
  mime_part_ref: string;
  findings: Finding[];
  sandbox_jobs: SandboxJobBrief[];
};
type SandboxStatus = {
  mode: string;
  enabled: boolean;
  is_demo?: boolean;
  detail?: string;
  capabilities?: { engine: string; supported_types: string[]; network_mode: string; notes: string[] };
  health?: { ok: boolean; detail: string };
  worker?: { name: string; status: string; reason: string | null };
};

function ArchiveTable({ a, prefix = "" }: { a: Archive; prefix?: string }) {
  return (
    <>
      {a.entries.map((e, i) => (
        <tr key={prefix + i}>
          <td className="mono small" style={{ overflowWrap: "anywhere" }}>
            {prefix}
            {e.name}
          </td>
          <td className="small">{e.detected?.label ?? <span className="muted">—</span>}</td>
          <td className="num">{fmtBytes(e.uncompressed_size)}</td>
          <td className="num">{e.ratio ?? "—"}</td>
          <td className="small">
            {e.path_issue && <Badge tone="bad">{e.path_issue}</Badge>} {e.symlink && <Badge tone="bad">symlink</Badge>}{" "}
            {e.encrypted && <Badge tone="warn">encrypted</Badge>}{" "}
            {e.status !== "examined" && e.status !== "listed" && !e.encrypted && <Badge tone="warn">{e.status.replace("_", " ")}</Badge>}
            {e.status === "examined" && !e.path_issue && !e.symlink && <span className="muted">examined</span>}
          </td>
        </tr>
      ))}
      {a.nested.map((n, i) => (
        <ArchiveTable key={`n${i}`} a={n.result} prefix={`${prefix}${n.name} ➜ `} />
      ))}
    </>
  );
}

function SubmitPanel({ at, sbx, onSubmitted, caseIds }: { at: AttachmentDetail; sbx: SandboxStatus | undefined; onSubmitted: () => void; caseIds: string[] }) {
  const [analyst, setAnalyst] = useState("");
  const [confirm, setConfirm] = useState(false);
  const [timeout, setTimeoutS] = useState(120);
  const [caseId, setCaseId] = useState(caseIds[0] ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (!sbx) return <Loading lines={2} />;
  if (!sbx.enabled)
    return (
      <Empty title="Sandbox is off">
        <p className="small">{sbx.detail} See docs/sandbox-deployment.md to connect a CAPEv2 host, or set PHB_SANDBOX_MODE=demo to try the flow with synthetic data.</p>
      </Empty>
    );
  const unsupported = at.detected_type && sbx.capabilities && !sbx.capabilities.supported_types.includes(at.detected_type);
  const quarantined = sbx.worker?.status === "quarantined";
  return (
    <form
      className="stack"
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setErr(null);
        try {
          await send("POST", `/api/attachments/${at.evidence_id}/sandbox`, { analyst, confirm, case_id: caseId || null, timeout_s: timeout });
          setConfirm(false);
          onSubmitted();
        } catch (ex) {
          setErr(ex instanceof Error ? ex.message : String(ex));
        } finally {
          setBusy(false);
        }
      }}
    >
      {sbx.is_demo && <div className="notice demo">Demo mode: nothing will run. The result will be synthetic and labelled DEMO everywhere.</div>}
      {quarantined && <div className="notice bad">Worker quarantined: {sbx.worker?.reason}. Submissions are blocked until it is restored and released on the Sandbox page.</div>}
      {unsupported && <div className="notice">The {sbx.capabilities?.engine} guest can&apos;t meaningfully run “{at.detected_type}” content.</div>}
      <p className="small muted">
        Engine: {sbx.capabilities?.engine}. Network: {sbx.capabilities?.network_mode}
      </p>
      <label className="field">
        Your name (recorded in the audit trail)
        <input type="text" required value={analyst} onChange={(e) => setAnalyst(e.target.value)} />
      </label>
      <div className="row">
        <label className="field" style={{ flex: "1 1 120px" }}>
          Run time (seconds)
          <input type="number" min={30} max={1800} value={timeout} onChange={(e) => setTimeoutS(Number(e.target.value))} />
        </label>
        {caseIds.length > 0 && (
          <label className="field" style={{ flex: "2 1 200px" }}>
            Case
            <select value={caseId} onChange={(e) => setCaseId(e.target.value)}>
              {caseIds.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
          </label>
        )}
      </div>
      <label className="check">
        <input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} />
        <span>
          I want to execute <strong>{at.filename_display ?? at.evidence_id}</strong> (SHA-256 {at.sha256.slice(0, 16)}…) in the isolated
          sandbox VM.
        </span>
      </label>
      <div className="row">
        <button className="btn danger" disabled={busy || !confirm || !analyst.trim() || quarantined || !!unsupported}>
          {sbx.is_demo ? "Run demo submission" : "Execute in sandbox"}
        </button>
      </div>
      {err && (
        <p role="alert" className="small" style={{ color: "var(--danger)" }}>
          {err}
        </p>
      )}
    </form>
  );
}

export default function AttachmentPage() {
  const { id } = useParams<{ id: string }>();
  const { data: at, error, loading, reload } = useApi<AttachmentDetail>(`/api/attachments/${id}`, (d) =>
    d && (["pending", "running"].includes(d.static_status) || d.sandbox_jobs.some((j) => !["completed", "failed", "timed_out", "cancelled", "reset_failed"].includes(j.state) || j.reset_status === "pending")) ? 2500 : undefined,
  );
  const { data: sbx } = useApi<SandboxStatus>("/api/sandbox/status");
  const { data: email } = useApi<{ cases: string[] }>(at ? `/api/emails/${at.email_evidence_id}` : null);
  const [busy, setBusy] = useState(false);

  if (loading && !at) return <Loading lines={8} />;
  if (error && !at) return <ErrorState error={error} retry={reload} />;
  if (!at) return null;
  const r = at.static_result;
  const incomplete = ["partial", "unsupported", "encrypted", "failed", "too_large"].includes(at.static_status);

  return (
    <>
      <div className="crumbs">
        Attachment of <Link href={`/emails/${at.email_evidence_id}`}>{at.email_evidence_id}</Link>, MIME part {at.mime_part_ref}
      </div>
      <div className="page-head">
        <div>
          <h1 style={{ overflowWrap: "anywhere" }}>{at.filename_display ?? <Absent>No filename</Absent>}</h1>
          <p className="sub">
            <span className="mono">{at.evidence_id}</span> <StaticStatus status={at.static_status} />
          </p>
        </div>
        <button
          className="btn secondary"
          disabled={busy || at.static_status === "running" || at.static_status === "pending"}
          onClick={async () => {
            setBusy(true);
            await send("POST", `/api/attachments/${id}/reanalyze`);
            setBusy(false);
            reload();
          }}
        >
          Re-run static analysis
        </button>
      </div>

      {incomplete && (
        <div className="notice bad">
          <strong>Analysis is incomplete.</strong> This is not a clean result. {r?.limitations?.[0]}
        </div>
      )}

      <div className="grid-main">
        <div>
          <section className="panel">
            <h2>Identification</h2>
            <KV
              rows={[
                ["Filename (raw header)", at.filename_raw ? <span className="mono">{at.filename_raw}</span> : <Absent />],
                ["Declared MIME type", <span key="d"><Prov kind="observed" /> <span className="mono">{at.declared_mime}</span></span>],
                ["Content identified as", r?.detected ? <span key="c"><Prov kind="inferred" label="Magic bytes" /> {r.detected.label}</span> : <span className="muted">pending</span>],
                [
                  "Extension check",
                  r?.extension ? (
                    r.extension.mismatch ? (
                      <Badge tone="bad">“.{r.extension.extension}” expects {r.extension.expected_types?.join(" / ")}, content differs</Badge>
                    ) : r.extension.expected_types ? (
                      <Badge tone="ok">consistent with “.{r.extension.extension}”</Badge>
                    ) : (
                      <span className="muted">{r.extension.extension ? `no rule for .${r.extension.extension}` : "no extension"}</span>
                    )
                  ) : (
                    "—"
                  ),
                ],
                ["Size", fmtBytes(at.size_bytes)],
                ["SHA-256", <Hash key="h" value={at.sha256} />],
                ["Analysed", at.static_updated_at ? fmtTime(at.static_updated_at) : "—"],
                ["Stages completed", r?.stages_completed?.join(", ") || "none"],
              ]}
            />
            {r?.extension?.notes?.map((n, i) => (
              <p key={i} className="small" style={{ marginTop: 8 }}>
                <Badge tone="warn">Filename</Badge> {n}
              </p>
            ))}
          </section>

          {r?.archive && (r.archive.entries?.length ?? 0) > 0 && (
            <section className="panel">
              <h2>Archive contents</h2>
              <p className="small muted">Listed and read in memory only. Nothing was extracted to disk.</p>
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr>
                      <th>Entry</th>
                      <th>Identified as</th>
                      <th className="num">Size</th>
                      <th className="num">Ratio</th>
                      <th>Notes</th>
                    </tr>
                  </thead>
                  <tbody>
                    <ArchiveTable a={r.archive} />
                  </tbody>
                </table>
              </div>
            </section>
          )}
          {r?.archive?.gzip_inner && (
            <section className="panel">
              <h2>gzip content</h2>
              <KV rows={[["Inner type", r.archive.gzip_inner.detected.label], ["Size", fmtBytes(r.archive.gzip_inner.size)], ["SHA-256", <Hash key="g" value={r.archive.gzip_inner.sha256} />]]} />
            </section>
          )}

          {r?.office && (
            <section className="panel">
              <h2>Document features</h2>
              <KV
                rows={[
                  ["Macros", r.office.macros ? (r.office.macros.present ? <Badge tone="bad">VBA macros present</Badge> : <Badge tone="ok">none found by scan</Badge>) : <span className="absent">scan unavailable</span>],
                  ["External references", r.office.external_relationships.length ? r.office.external_relationships.map((x, i) => <div key={i} className="mono small">{x.type}: {x.target}</div>) : "none"],
                  ["Embedded objects", r.office.embedded_objects.length ? r.office.embedded_objects.join(", ") : "none"],
                  ...Object.entries(r.office.metadata).map(([k, v]) => [`Metadata: ${k}`, v] as [string, string]),
                ]}
              />
              {r.office.macros?.present && (
                <>
                  <p className="small muted" style={{ marginTop: 10 }}>{r.office.macros.note}</p>
                  {r.office.macros.keywords.length > 0 && (
                    <ul className="small">
                      {r.office.macros.keywords.map((k, i) => (
                        <li key={i}>
                          <strong>{k.type}</strong> <code>{k.keyword}</code> — {k.description}
                        </li>
                      ))}
                    </ul>
                  )}
                  {r.office.macros.modules.map((m, i) => (
                    <details key={i}>
                      <summary className="small">
                        Module {m.name} ({m.lines} lines) — read as text, never run
                      </summary>
                      <pre className="block">{m.excerpt}</pre>
                    </details>
                  ))}
                </>
              )}
            </section>
          )}

          {r?.pdf && (
            <section className="panel">
              <h2>PDF structure</h2>
              <div className="table-wrap">
                <table className="data">
                  <tbody>
                    {Object.entries(r.pdf.keyword_counts).map(([k, v]) => (
                      <tr key={k}>
                        <td className="mono small">{k}</td>
                        <td className="num">{v}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="small muted">{r.pdf.note}</p>
            </section>
          )}

          {r?.pe && (
            <section className="panel">
              <h2>Windows executable</h2>
              {r.pe.error ? (
                <p className="small">{r.pe.error}</p>
              ) : (
                <>
                  <KV
                    rows={[
                      ["Machine", r.pe.machine],
                      ["Type", r.pe.is_dll ? "DLL" : "Executable"],
                      ["Compile timestamp (as written)", `${r.pe.compile_timestamp} (${new Date(r.pe.compile_timestamp * 1000).toISOString()})`],
                      ["Signature blob", r.pe.has_authenticode_blob ? "present (not validated)" : "absent"],
                      ["Imports", r.pe.imports.map((d) => d.dll).join(", ")],
                    ]}
                  />
                  <p className="small muted" style={{ marginTop: 8 }}>{r.pe.signature_note} Timestamps are set by the build tool and can be faked.</p>
                </>
              )}
            </section>
          )}

          {r?.strings && (
            <section className="panel">
              <h2>Readable strings</h2>
              <p className="small muted">
                {r.strings.total_found} found{r.strings.truncated ? " (list capped)" : ""}. Strings of interest first.
              </p>
              {r.strings.interesting.length > 0 && <pre className="block">{r.strings.interesting.join("\n")}</pre>}
              <details style={{ marginTop: 8 }}>
                <summary className="small">Sample of all strings</summary>
                <pre className="block">{r.strings.sample.join("\n")}</pre>
              </details>
              {r.urls && r.urls.length > 0 && (
                <>
                  <h3 style={{ marginTop: 14 }}>URLs inside the file</h3>
                  <ul className="small">
                    {r.urls.map((u, i) => (
                      <li key={i} className="mono">
                        {u.original} {u.warnings.length > 0 && <span className="muted">— {u.warnings.map((w) => w.message).join("; ")}</span>}
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </section>
          )}
          {r?.text_excerpt && (
            <section className="panel">
              <h2>Text excerpt</h2>
              <p className="small muted">Shown as inert text.</p>
              <pre className="block">{r.text_excerpt}</pre>
            </section>
          )}

          {r && r.limitations.length > 0 && (
            <section className="panel ledger unknown">
              <h2>Limitations of this analysis</h2>
              <ul className="small">
                {r.limitations.map((l, i) => (
                  <li key={i}>{l}</li>
                ))}
              </ul>
            </section>
          )}

          <section>
            <h2 style={{ margin: "8px 0 12px" }}>Findings for this attachment</h2>
            {at.findings.length === 0 ? (
              <Empty title={incomplete ? "No findings — but analysis was incomplete" : "No rule findings"}>
                <p className="small">Rules cover known patterns only. No findings is not the same as safe.</p>
              </Empty>
            ) : (
              at.findings.map((f) => <FindingCard key={f.id} f={f} />)
            )}
          </section>
        </div>

        <aside>
          <section className="panel">
            <h2>Run in sandbox</h2>
            <p className="small muted">Execution only happens when you ask for it here. Upload and preview never run anything.</p>
            <SubmitPanel at={at} sbx={sbx} onSubmitted={reload} caseIds={email?.cases ?? []} />
          </section>
          <section className="panel">
            <h3>Sandbox runs</h3>
            {at.sandbox_jobs.length === 0 ? (
              <p className="small muted">Not submitted.</p>
            ) : (
              <ul className="stack" style={{ listStyle: "none", padding: 0, margin: 0 }}>
                {at.sandbox_jobs.map((j) => (
                  <li key={j.id} className="small">
                    <Link href={`/sandbox/jobs/${j.id}`} className="mono">
                      {j.id}
                    </Link>{" "}
                    <JobState state={j.state} /> {j.is_demo ? <Badge tone="demo">DEMO</Badge> : null}
                    <div className="muted">{fmtTime(j.submitted_at)}</div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </aside>
      </div>
    </>
  );
}
