"use client";

import Link from "next/link";
import { Empty, ErrorState, Loading, ParseStatus, useApi } from "@/components/ui";
import { fmtBytes, fmtTime } from "@/lib/api";

type EmailRow = {
  id: string;
  original_filename: string | null;
  sha256: string;
  size_bytes: number;
  imported_at: string;
  subject: string | null;
  from_address: string | null;
  parse_status: string;
  attachment_count: number;
  finding_count: number;
};

export default function EmailsPage() {
  const { data, error, loading, reload } = useApi<EmailRow[]>("/api/emails");
  return (
    <>
      <div className="page-head">
        <div>
          <h1>All email evidence</h1>
          <p className="sub">Every imported email, whether or not it belongs to a case.</p>
        </div>
        <Link className="btn" href="/import">
          Import an email
        </Link>
      </div>
      <section className="panel">
        {loading && <Loading />}
        {error ? <ErrorState error={error} retry={reload} /> : null}
        {data && data.length === 0 && (
          <Empty title="No evidence yet">
            <p>
              <Link href="/import">Import an .eml file</Link> to start.
            </p>
          </Empty>
        )}
        {data && data.length > 0 && (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Evidence</th>
                  <th>Subject (as written)</th>
                  <th>From address</th>
                  <th>Parse</th>
                  <th className="num">Attachments</th>
                  <th className="num">Findings</th>
                  <th className="num">Size</th>
                  <th>Imported</th>
                </tr>
              </thead>
              <tbody>
                {data.map((e) => (
                  <tr key={e.id}>
                    <td>
                      <Link href={`/emails/${e.id}`} className="mono">
                        {e.id}
                      </Link>
                      <div className="small muted">{e.original_filename}</div>
                    </td>
                    <td>{e.subject ?? <span className="absent">no subject</span>}</td>
                    <td className="mono small">{e.from_address ?? <span className="absent">none</span>}</td>
                    <td>
                      <ParseStatus status={e.parse_status} />
                    </td>
                    <td className="num">{e.attachment_count}</td>
                    <td className="num">{e.finding_count}</td>
                    <td className="num">{fmtBytes(e.size_bytes)}</td>
                    <td className="small">{fmtTime(e.imported_at)}</td>
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
