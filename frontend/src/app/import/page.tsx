"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useRef, useState } from "react";
import { Badge, Loading, useApi } from "@/components/ui";
import { fmtBytes, upload, type CaseSummary } from "@/lib/api";

type ImportResult = {
  evidence_id: string;
  duplicate: boolean;
  sha256: string;
  message?: string;
  parse_status?: string;
  warnings?: string[];
  errors?: string[];
  attachments?: number;
};
type Row = { id: number; name: string; size: number; state: "uploading" | "done" | "error"; result?: ImportResult; error?: string };

function ImportInner() {
  const params = useSearchParams();
  const { data: cases } = useApi<CaseSummary[]>("/api/cases");
  const { data: settings } = useApi<{ max_upload_bytes: number }>("/api/settings");
  const [caseId, setCaseId] = useState(params.get("case") ?? "");
  const [rows, setRows] = useState<Row[]>([]);
  const [over, setOver] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const seq = useRef(0);

  async function handle(files: FileList | null) {
    if (!files) return;
    for (const file of Array.from(files)) {
      const id = ++seq.current;
      setRows((r) => [...r, { id, name: file.name, size: file.size, state: "uploading" }]);
      const update = (patch: Partial<Row>) => setRows((r) => r.map((x) => (x.id === id ? { ...x, ...patch } : x)));
      if (!file.name.toLowerCase().endsWith(".eml")) {
        update({ state: "error", error: "Only .eml files are supported. Save the message from your mail client as .eml first." });
        continue;
      }
      if (settings && file.size > settings.max_upload_bytes) {
        update({ state: "error", error: `File is ${fmtBytes(file.size)}; the limit is ${fmtBytes(settings.max_upload_bytes)}.` });
        continue;
      }
      const form = new FormData();
      form.append("file", file);
      if (caseId) form.append("case_id", caseId);
      try {
        const result = await upload<ImportResult>("/api/emails/import", form);
        update({ state: "done", result });
      } catch (e) {
        update({ state: "error", error: e instanceof Error ? e.message : String(e) });
      }
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Import an email</h1>
          <p className="sub">
            The original bytes are preserved and hashed. Nothing in the email is opened, rendered with scripts, or executed.
          </p>
        </div>
      </div>
      <div className="grid-main">
        <section className="panel stack">
          <label className="field">
            Add to case (optional)
            <select value={caseId} onChange={(e) => setCaseId(e.target.value)}>
              <option value="">No case yet</option>
              {(cases ?? [])
                .filter((c) => c.status === "open")
                .map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.title} ({c.id})
                  </option>
                ))}
            </select>
          </label>
          <div
            className={`drop ${over ? "over" : ""}`}
            role="button"
            tabIndex={0}
            onClick={() => input.current?.click()}
            onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()}
            onDragOver={(e) => {
              e.preventDefault();
              setOver(true);
            }}
            onDragLeave={() => setOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setOver(false);
              handle(e.dataTransfer.files);
            }}
          >
            <h3>Drop .eml files here</h3>
            <p className="muted" style={{ margin: "6px auto 0" }}>
              or press to choose files{settings ? ` — up to ${fmtBytes(settings.max_upload_bytes)} each` : ""}
            </p>
            <input ref={input} type="file" accept=".eml,message/rfc822" multiple hidden onChange={(e) => handle(e.target.files)} />
          </div>

          {rows.length > 0 && (
            <ul className="stack" style={{ listStyle: "none", padding: 0, margin: 0 }} aria-live="polite">
              {rows.map((r) => (
                <li key={r.id} className="panel" style={{ marginBottom: 0 }}>
                  <div className="panel-head" style={{ marginBottom: 6 }}>
                    <strong>{r.name}</strong>
                    {r.state === "uploading" && <Badge tone="neutral">Uploading</Badge>}
                    {r.state === "error" && <Badge tone="bad">Not imported</Badge>}
                    {r.state === "done" && r.result?.duplicate && <Badge tone="warn">Already imported</Badge>}
                    {r.state === "done" && !r.result?.duplicate && (
                      <Badge tone={r.result?.parse_status === "parsed" ? "ok" : "warn"}>
                        {r.result?.parse_status === "parsed" ? "Imported" : "Imported — partially parsed"}
                      </Badge>
                    )}
                  </div>
                  {r.state === "uploading" && <Loading lines={1} />}
                  {r.error && <p className="small" style={{ color: "var(--danger)" }}>{r.error}</p>}
                  {r.result && (
                    <div className="small stack" style={{ gap: 6 }}>
                      <div>
                        Evidence <Link href={`/emails/${r.result.evidence_id}`}>{r.result.evidence_id}</Link>, {fmtBytes(r.size)},{" "}
                        {r.result.attachments ?? 0} attachment(s)
                      </div>
                      <div className="hash">SHA-256 {r.result.sha256}</div>
                      {r.result.message && <div className="muted">{r.result.message}</div>}
                      {(r.result.errors?.length ?? 0) + (r.result.warnings?.length ?? 0) > 0 && (
                        <details>
                          <summary>
                            {r.result.errors?.length ?? 0} error(s), {r.result.warnings?.length ?? 0} parser warning(s)
                          </summary>
                          <ul>
                            {[...(r.result.errors ?? []), ...(r.result.warnings ?? [])].map((w, j) => (
                              <li key={j}>{w}</li>
                            ))}
                          </ul>
                        </details>
                      )}
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>
        <aside className="panel small">
          <h3>What happens on import</h3>
          <ol style={{ paddingLeft: 18, margin: "8px 0 0" }}>
            <li>The file is stored under a generated name and its SHA-256 is recorded.</li>
            <li>Headers, bodies and the MIME structure are parsed; raw values are kept.</li>
            <li>Attachments are saved byte-for-byte and queued for static analysis in a limited worker.</li>
            <li>Links are read as text. None are visited.</li>
          </ol>
          <p className="muted" style={{ marginTop: 10 }}>
            Importing the same bytes again doesn&apos;t create a second copy; the upload is recorded as another import of the
            existing evidence.
          </p>
          <p className="muted">A matching hash proves the stored copy hasn&apos;t changed. It doesn&apos;t prove the email is genuine.</p>
        </aside>
      </div>
    </>
  );
}

export default function ImportPage() {
  return (
    <Suspense fallback={<Loading />}>
      <ImportInner />
    </Suspense>
  );
}
