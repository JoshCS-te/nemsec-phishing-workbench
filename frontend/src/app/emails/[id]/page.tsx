"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";
import FindingCard from "@/components/FindingCard";
import {
  Absent,
  Badge,
  Empty,
  ErrorState,
  Hash,
  KV,
  Loading,
  ParseStatus,
  Prov,
  RawValue,
  StaticStatus,
  Tabs,
  useApi,
} from "@/components/ui";
import { fmtBytes, fmtTime, get, send, type CaseSummary, type Finding } from "@/lib/api";

type Addr = { display_name: string | null; address: string | null; domain: string | null; syntax_valid: boolean };
type HeaderBlock = { raw: string | null; decoded: string | null; all_raw: string[]; addresses?: Addr[] };
type MimeNode = {
  part_ref: string;
  content_type: string;
  charset: string | null;
  transfer_encoding: string | null;
  filename: string | null;
  size_bytes: number | null;
  defects: string[];
  children: MimeNode[];
  role: string | null;
};
type UrlRow = {
  id: string;
  source: string;
  original: string;
  visible_text: string | null;
  scheme: string | null;
  hostname: string | null;
  normalized_host: string | null;
  parse_ok: number;
  warnings_json: { code: string; message: string; weight: string }[];
};
type EmailDetail = {
  evidence: { id: string; sha256: string; size_bytes: number; original_filename: string | null; imported_at: string };
  imports: { id: number; original_filename: string; imported_at: string; duplicate: number; case_id: string | null }[];
  cases: string[];
  parse_status: string;
  warnings: string[];
  errors: string[];
  parsed: {
    subject: HeaderBlock;
    from: HeaderBlock;
    sender: HeaderBlock;
    reply_to: HeaderBlock;
    return_path: HeaderBlock;
    to: HeaderBlock;
    cc: HeaderBlock;
    message_id: HeaderBlock;
    date: { raw: string | null; utc: string | null; offset: string | null; timezone_known: boolean | null; all_raw: string[] };
    received: { index: number; raw: string; from: string | null; by: string | null; with: string | null; date_raw: string | null; date_utc: string | null; bracketed_ips: string[] }[];
    authentication_results: { raw: string; authserv_id: string | null; methods: { method: string; result: string; clause: string }[] }[];
    received_spf: string[];
    dkim_signatures: { d: string | null; s: string | null }[];
    headers: { name: string; raw: string; decoded: string }[];
    text_bodies: { part_ref: string }[];
    html_bodies: { part_ref: string }[];
    mime_tree: MimeNode;
    trust_note: string;
  };
  attachments: {
    id: string;
    filename_display: string | null;
    filename_raw: string | null;
    declared_mime: string;
    disposition: string | null;
    detected_type: string | null;
    static_status: string;
    sha256: string;
    size_bytes: number;
    mime_part_ref: string;
  }[];
  urls: UrlRow[];
  findings: Finding[];
  preview_removed: Record<string, number> | null;
};

function AttachToCase({ evidenceId, existing, onDone }: { evidenceId: string; existing: string[]; onDone: () => void }) {
  const { data: cases } = useApi<CaseSummary[]>("/api/cases");
  const [sel, setSel] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const options = (cases ?? []).filter((c) => c.status === "open" && !existing.includes(c.id));
  if (options.length === 0) return null;
  return (
    <div className="row">
      <label className="sr-only" htmlFor="attach-case">Add to case</label>
      <select id="attach-case" value={sel} onChange={(e) => setSel(e.target.value)} style={{ width: "auto" }}>
        <option value="">Add to case…</option>
        {options.map((c) => (
          <option key={c.id} value={c.id}>{c.title}</option>
        ))}
      </select>
      <button
        className="btn secondary"
        disabled={!sel}
        onClick={async () => {
          try {
            await send("POST", `/api/cases/${sel}/evidence`, { evidence_id: evidenceId });
            setSel("");
            onDone();
          } catch (e) {
            setErr(e instanceof Error ? e.message : String(e));
          }
        }}
      >
        Add
      </button>
      {err && <span role="alert" className="small" style={{ color: "var(--danger)" }}>{err}</span>}
    </div>
  );
}

type TabKey = "overview" | "headers" | "links" | "attachments" | "findings" | "structure";

function addrList(b: HeaderBlock) {
  if (b.raw === null) return <Absent />;
  return (
    <>
      {(b.addresses ?? []).map((a, i) => (
        <div key={i}>
          {a.display_name && <span>{a.display_name} </span>}
          <span className="mono">&lt;{a.address ?? "unparseable"}&gt;</span>
          {!a.syntax_valid && <> <Badge tone="warn">address syntax invalid</Badge></>}
        </div>
      ))}
      {b.decoded !== b.raw && <span className="raw">raw: {b.raw}</span>}
      {b.all_raw.length > 1 && <Badge tone="warn">{b.all_raw.length} copies of this header</Badge>}
    </>
  );
}

function Tree({ node }: { node: MimeNode }) {
  return (
    <li>
      <span className="mono">{node.part_ref || "root"}</span> <strong>{node.content_type}</strong>
      {node.role && node.role !== "container" && <span className="muted"> — {node.role.replace("_", " ")}</span>}
      {node.filename && <span> “{node.filename}”</span>}
      {node.size_bytes !== null && <span className="muted"> ({fmtBytes(node.size_bytes)})</span>}
      {node.transfer_encoding && <span className="muted small"> {node.transfer_encoding}</span>}
      {node.defects.length > 0 && <> <Badge tone="warn">{node.defects.join(", ")}</Badge></>}
      {node.children.length > 0 && (
        <ul>
          {node.children.map((c) => (
            <Tree key={c.part_ref} node={c} />
          ))}
        </ul>
      )}
    </li>
  );
}

export default function EmailPage() {
  const { id } = useParams<{ id: string }>();
  const { data, error, loading, reload } = useApi<EmailDetail>(`/api/emails/${id}`, (d) =>
    d && d.attachments.some((a) => a.static_status === "pending" || a.static_status === "running") ? 2000 : undefined,
  );
  const [tab, setTab] = useState<TabKey>("overview");
  const [mode, setMode] = useState<"html" | "text">("html");
  const [verify, setVerify] = useState<{ ok: boolean; actual: string | null; meaning?: string; reason?: string } | null>(null);

  if (loading && !data) return <Loading lines={8} />;
  if (error && !data) return <ErrorState error={error} retry={reload} />;
  if (!data) return null;
  const p = data.parsed;
  if (data.parse_status === "failed" || !p.subject) {
    return (
      <>
        <div className="page-head">
          <div>
            <h1>Email could not be parsed</h1>
            <p className="sub mono">{data.evidence.id}</p>
          </div>
          <a className="btn secondary" href={`/api/emails/${id}/raw`}>Download original</a>
        </div>
        <div className="state error" role="alert">
          <h3>The original bytes are preserved (SHA-256 {data.evidence.sha256}) but no structure could be read.</h3>
          <ul>{[...data.errors, ...data.warnings].map((w, i) => <li key={i}>{w}</li>)}</ul>
        </div>
      </>
    );
  }
  const hasHtml = (p.html_bodies ?? []).length > 0;
  const subject = p.subject?.decoded;

  return (
    <>
      <div className="crumbs">
        {data.cases.length > 0 ? (
          <>
            Case{" "}
            {data.cases.map((c, i) => (
              <span key={c}>
                {i > 0 && ", "}
                <Link href={`/cases/${c}`}>{c}</Link>
              </span>
            ))}
          </>
        ) : (
          <Link href="/emails">All evidence</Link>
        )}
      </div>
      <div className="page-head">
        <div>
          <h1>{subject ?? <Absent>No subject</Absent>}</h1>
          <p className="sub">
            <span className="mono">{data.evidence.id}</span> <ParseStatus status={data.parse_status} />{" "}
            <span className="small">imported {fmtTime(data.evidence.imported_at)} from “{data.evidence.original_filename}”</span>
          </p>
        </div>
        <div className="row">
          <a className="btn secondary" href={`/api/emails/${id}/raw`}>
            Download original .eml
          </a>
          <AttachToCase evidenceId={id} existing={data.cases} onDone={reload} />
        </div>
      </div>

      {(data.errors.length > 0 || data.warnings.length > 0) && (
        <details className="notice" open={data.errors.length > 0 || data.parse_status !== "parsed"}>
          <summary>
            Parser reported {data.errors.length} error(s) and {data.warnings.length} warning(s). Values were kept as written; nothing
            was filled in.
          </summary>
          <ul>
            {[...data.errors, ...data.warnings].map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </details>
      )}

      <Tabs<TabKey>
        active={tab}
        onChange={setTab}
        tabs={[
          { key: "overview", label: "Overview & preview" },
          { key: "headers", label: "Headers & evidence" },
          { key: "links", label: "Links", count: data.urls.length },
          { key: "attachments", label: "Attachments", count: data.attachments.length },
          { key: "findings", label: "Findings", count: data.findings.length },
          { key: "structure", label: "MIME structure" },
        ]}
      />

      {tab === "overview" && (
        <div className="grid-main">
          <section className="panel">
            <div className="panel-head">
              <h2>Safe preview</h2>
              <div className="row" role="group" aria-label="Preview mode">
                <button className={`btn small ${mode === "html" ? "" : "secondary"}`} aria-pressed={mode === "html"} disabled={!hasHtml} onClick={() => setMode("html")}>
                  Sanitised HTML
                </button>
                <button className={`btn small ${mode === "text" ? "" : "secondary"}`} aria-pressed={mode === "text"} onClick={() => setMode("text")}>
                  Plain text
                </button>
              </div>
            </div>
            <p className="small muted">
              Scripts, forms, embeds and every remote resource are removed. Links show their real destination in brackets and
              can&apos;t be clicked. The frame is fully sandboxed.
            </p>
            {data.preview_removed && mode === "html" && (
              <p className="small">
                Removed from this message: {data.preview_removed.remote_resource_references} remote resource reference(s),{" "}
                {data.preview_removed.script_indicators} script indicator(s), {data.preview_removed.forms} form(s),{" "}
                {data.preview_removed.frames_or_embeds} frame/embed(s), {data.preview_removed.meta_refresh} auto-redirect(s).
              </p>
            )}
            <iframe
              key={mode}
              title="Sanitised email preview"
              className="preview-frame"
              sandbox=""
              referrerPolicy="no-referrer"
              src={`/api/emails/${id}/preview?mode=${hasHtml ? mode : "text"}`}
            />
          </section>
          <section className="panel">
            <h2 style={{ marginBottom: 6 }}>Summary</h2>
            <p className="small muted">
              <Prov kind="observed" /> Values as written in the file.
            </p>
            <KV
              rows={[
                ["From", addrList(p.from)],
                ["Reply-To", addrList(p.reply_to)],
                ["Return-Path", addrList(p.return_path)],
                ["To", addrList(p.to)],
                ["Cc", addrList(p.cc)],
                [
                  "Date",
                  p.date.raw === null ? (
                    <Absent />
                  ) : (
                    <>
                      {p.date.utc ? <span>{p.date.utc.replace("T", " ").replace("+00:00", " UTC")}</span> : <Badge tone="warn">unparseable</Badge>}
                      {p.date.offset && <span className="muted"> (sender offset {p.date.offset}{p.date.timezone_known === false ? ", zone unknown" : ""})</span>}
                      <span className="raw">raw: {p.date.raw}</span>
                    </>
                  ),
                ],
                ["Message-ID", <RawValue key="m" decoded={p.message_id.decoded} raw={p.message_id.raw} />],
                ["Attachments", data.attachments.length],
                ["Rule findings", data.findings.length],
              ]}
            />
          </section>
        </div>
      )}

      {tab === "headers" && (
        <>
          <div className="notice trust">
            <strong>Trust boundary.</strong> {p.trust_note}
          </div>
          <div className="grid-2">
            <section className="panel">
              <h2>Authentication claims</h2>
              {p.authentication_results.length === 0 && p.received_spf.length === 0 ? (
                <Empty title="No authentication headers">
                  <p className="small">Authentication status could not be established from this file.</p>
                </Empty>
              ) : (
                <div className="stack">
                  {p.authentication_results.map((a, i) => (
                    <div key={i} className="ledger unknown">
                      <div className="row" style={{ marginBottom: 4 }}>
                        <Prov kind="unknown" label="Reported claim, not verified" />
                        <span className="small">
                          by <span className="mono">{a.authserv_id ?? "unnamed server"}</span>
                        </span>
                      </div>
                      <div className="row">
                        {a.methods.map((m, j) => (
                          <Badge key={j} tone={m.result === "pass" ? "neutral" : "warn"} title={m.clause}>
                            {m.method.toUpperCase()} claimed {m.result}
                          </Badge>
                        ))}
                      </div>
                      <span className="raw">{a.raw}</span>
                    </div>
                  ))}
                  {p.received_spf.map((r, i) => (
                    <div key={`spf${i}`} className="ledger unknown">
                      <Prov kind="unknown" label="Received-SPF claim" />
                      <span className="raw">{r}</span>
                    </div>
                  ))}
                  {p.dkim_signatures.length > 0 && (
                    <p className="small">
                      {p.dkim_signatures.length} DKIM-Signature header(s) present (d={p.dkim_signatures.map((d) => d.d).join(", ")}). Signatures
                      were not cryptographically verified.
                    </p>
                  )}
                </div>
              )}
            </section>
            <section className="panel">
              <h2>Evidence record</h2>
              <KV
                rows={[
                  ["Evidence ID", <span key="i" className="mono">{data.evidence.id}</span>],
                  ["SHA-256", <Hash key="h" value={data.evidence.sha256} />],
                  ["Size", fmtBytes(data.evidence.size_bytes)],
                  ["Imports", data.imports.map((im) => (
                    <div key={im.id} className="small">
                      {fmtTime(im.imported_at)}: “{im.original_filename}”{im.duplicate ? " (duplicate upload)" : ""}{im.case_id ? ` → ${im.case_id}` : ""}
                    </div>
                  ))],
                ]}
              />
              <div className="row" style={{ marginTop: 12 }}>
                <button
                  className="btn secondary small"
                  onClick={async () => setVerify(await get(`/api/evidence/${id}/verify`))}
                >
                  Re-check stored bytes
                </button>
                {verify && (
                  <Badge tone={verify.ok ? "ok" : "bad"}>{verify.ok ? "Hash matches import" : "Hash MISMATCH — stored copy changed"}</Badge>
                )}
              </div>
              {verify?.meaning && <p className="small muted" style={{ marginTop: 6 }}>{verify.meaning}</p>}
            </section>
          </div>
          <section className="panel">
            <h2>Received path</h2>
            <p className="small muted">Top entry is the most recent hop (closest to the recipient). Every line can be forged below the first trusted server.</p>
            {p.received.length === 0 ? (
              <Empty title="No Received headers">
                <p className="small">The delivery path could not be established.</p>
              </Empty>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>From</th>
                      <th>By</th>
                      <th>Protocol</th>
                      <th>Time (UTC)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {p.received.map((h) => (
                      <tr key={h.index}>
                        <td className="mono">{h.index}</td>
                        <td className="mono small">{h.from ?? <Absent>—</Absent>}</td>
                        <td className="mono small">{h.by ?? <Absent>—</Absent>}</td>
                        <td className="small">{h.with ?? "—"}</td>
                        <td className="small">{h.date_utc ?? <span className="absent">{h.date_raw ?? "—"}</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
          <section className="panel">
            <h2>All headers in file order</h2>
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Value (decoded, raw shown when different)</th>
                  </tr>
                </thead>
                <tbody>
                  {p.headers.map((h, i) => (
                    <tr key={i}>
                      <td className="mono small">{h.name}</td>
                      <td className="small" style={{ overflowWrap: "anywhere" }}>
                        <RawValue decoded={h.decoded} raw={h.raw} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      {tab === "links" && (
        <section className="panel">
          <h2>Links found in the message</h2>
          <p className="small muted">Read as text only. No link was visited and no redirect was followed.</p>
          {data.urls.length === 0 ? (
            <Empty title="No links found" />
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>Visible text</th>
                    <th>Actual destination (original string)</th>
                    <th>Host</th>
                    <th>Indicators</th>
                  </tr>
                </thead>
                <tbody>
                  {data.urls.map((u) => (
                    <tr key={u.id}>
                      <td className="small">{u.visible_text ?? <span className="muted">—</span>}<div className="muted small">{u.source.replace(/_/g, " ")}</div></td>
                      <td className="mono small" style={{ overflowWrap: "anywhere", maxWidth: 380 }}>{u.original}</td>
                      <td className="mono small">
                        {u.normalized_host ?? u.hostname ?? <Absent>none</Absent>}
                        {u.hostname && u.normalized_host && u.hostname !== u.normalized_host && <span className="raw">as written: {u.hostname}</span>}
                      </td>
                      <td className="small">
                        {u.warnings_json.length === 0 ? (
                          <span className="muted">none</span>
                        ) : (
                          <ul style={{ margin: 0, paddingLeft: 16 }}>
                            {u.warnings_json.map((w, i) => (
                              <li key={i}>
                                {w.weight === "notable" ? <strong>{w.message}</strong> : w.message}
                              </li>
                            ))}
                          </ul>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {tab === "attachments" && (
        <section className="panel">
          <h2>Attachments</h2>
          {data.attachments.length === 0 ? (
            <Empty title="No attachments" />
          ) : (
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th>Attachment</th>
                    <th>Declared type</th>
                    <th>Identified as</th>
                    <th>Static analysis</th>
                    <th className="num">Size</th>
                    <th>SHA-256</th>
                  </tr>
                </thead>
                <tbody>
                  {data.attachments.map((a) => (
                    <tr key={a.id}>
                      <td>
                        <Link href={`/attachments/${a.id}`}>{a.filename_display ?? "(no filename)"}</Link>
                        <div className="mono small muted">
                          {a.id}, part {a.mime_part_ref}
                        </div>
                      </td>
                      <td className="mono small">{a.declared_mime}</td>
                      <td className="small">{a.detected_type ?? <span className="muted">pending</span>}</td>
                      <td>
                        <StaticStatus status={a.static_status} />
                      </td>
                      <td className="num">{fmtBytes(a.size_bytes)}</td>
                      <td className="hash" style={{ maxWidth: 220 }}>{a.sha256}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {tab === "findings" && (
        <section>
          {data.findings.length === 0 ? (
            <Empty title="No rule findings">
              <p>No rule matched. That is not evidence the email is safe — rules cover known patterns only.</p>
            </Empty>
          ) : (
            <>
              <p className="small muted">
                Review findings inside a case to mark them relevant, benign or unresolved.
                {data.cases[0] && (
                  <>
                    {" "}
                    <Link href={`/cases/${data.cases[0]}?tab=findings`}>Review in {data.cases[0]}</Link>
                  </>
                )}
              </p>
              {data.findings.map((f) => (
                <FindingCard key={f.id} f={f} />
              ))}
            </>
          )}
        </section>
      )}

      {tab === "structure" && (
        <section className="panel">
          <h2>MIME structure</h2>
          <ul className="tree">
            <Tree node={p.mime_tree} />
          </ul>
        </section>
      )}
    </>
  );
}
