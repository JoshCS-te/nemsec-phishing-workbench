// Thin client for the local FastAPI backend (proxied through Next.js at /api).

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let msg = `Request failed (HTTP ${res.status}).`;
    try {
      const body = await res.json();
      if (body?.detail) msg = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* non-JSON error body */
    }
    if (res.status === 500 && msg.includes("ECONNREFUSED")) msg = "The backend is not running on 127.0.0.1:8000.";
    throw new ApiError(res.status, msg);
  }
  return res.json() as Promise<T>;
}

export async function get<T>(path: string): Promise<T> {
  return handle<T>(await fetch(path, { cache: "no-store" }));
}

export async function send<T>(method: "POST" | "PATCH" | "DELETE", path: string, body?: unknown): Promise<T> {
  return handle<T>(
    await fetch(path, {
      method,
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    }),
  );
}

export async function upload<T>(path: string, form: FormData): Promise<T> {
  return handle<T>(await fetch(path, { method: "POST", body: form }));
}

export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

// ---- shared types (subset of API payloads used by the UI) ----
export type EvidenceItem = { label: string; value: unknown; ref?: string };
export type Finding = {
  id: string;
  rule_id: string;
  name: string;
  category: string;
  explanation: string;
  evidence_json: EvidenceItem[];
  confidence: "low" | "medium" | "high";
  uncertainty: string | null;
  benign_json: string[];
  email_evidence_id: string;
  subject_evidence_id: string | null;
  review_status?: "unreviewed" | "relevant" | "benign" | "unresolved";
  analyst_comment?: string;
  include_in_report?: number;
};
export type CaseSummary = {
  id: string;
  title: string;
  description: string;
  status: "open" | "closed";
  created_at: string;
  updated_at: string;
  email_count: number;
  finding_count: number;
  unreviewed_count: number;
  report_status: string | null;
};
export type Note = { id: string; kind: "fact" | "interpretation" | "question" | "note"; body: string; evidence_refs: string[]; resolved: number; created_at: string; updated_at: string };
export type SandboxJobBrief = {
  id: string;
  attachment_id: string;
  case_id: string | null;
  adapter: string;
  is_demo: boolean | number;
  state: string;
  state_detail: string | null;
  reset_status: string | null;
  reset_detail?: string | null;
  execution_outcome?: string | null;
  submitted_by?: string;
  submitted_at: string;
  started_at?: string | null;
  finished_at: string | null;
  worker_name?: string;
  external_task_id?: string | null;
  timeout_s?: number;
  error?: string | null;
};
