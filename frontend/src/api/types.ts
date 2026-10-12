/* The PhishHawk API as the server returns it (docs/api/openapi.json and
   docs/report.schema.json). Field names are the server's: do not rename them,
   and do not add fields the server does not send. */

export type Role = 'analyst' | 'admin';
export type Verdict = 'NO STRONG INDICATORS' | 'SUSPICIOUS' | 'LIKELY PHISHING' | 'MALICIOUS';
export type Severity = 'high' | 'medium' | 'low';
export type SubmissionStatus = 'queued' | 'running' | 'done' | 'failed';

/** GET /api/v1/session */
export type Session = {
  user_id: number | null;
  username: string;
  role: Role;
  via: 'session' | 'token';
  scope: string;
  csrf: string;
};

/** POST /api/v1/submissions, GET /api/v1/submissions/{id}, POST /api/v1/analyses/{id}/reanalyze */
export type Submission = {
  id: number;
  status: SubmissionStatus;
  error: string;
  analysis_id: number | null;
  submitted_at: string;
};

export type FileKind = 'json' | 'stix' | 'misp' | 'md' | 'csv' | 'html' | 'manifest';

export type AnalysisFile = {
  /** Server-generated; the only file name that may go into a URL. */
  name: string;
  kind: FileKind;
  type: string;
  size: number;
  sha256: string;
  available: boolean;
};

export type Lookup = { provider: string; method: string; url: string };

/** One row of GET /api/v1/analyses, and the top of GET /api/v1/analyses/{id} */
export type AnalysisSummary = {
  id: number;
  message_id: number;
  submission_id: number;
  submitted_by: number | null;
  submitted_by_name: string | null;
  source: 'upload' | 'paste' | 'batch' | 'mailbox';
  offline: boolean;
  sha256: string;
  report_id: string;
  verdict: Verdict;
  score: number;
  sender: string;
  sender_domain: string;
  /** null once the message has been deleted */
  subject: string | null;
  created_at: string;
  providers: string[];
  lookups: Lookup[];
  techniques: string[];
  hold: boolean;
  tier1_deleted_at: string | null;
  files: AnalysisFile[];
};

export type Signal = { severity: Severity; label: string; techniques: string[]; family?: string };
export type UrlFinding = {
  url: string;
  /** Use this for display; never `url`. */
  defanged: string;
  host: string;
  domain: string;
  notes: string[];
  flagged: boolean;
};
export type AttachmentFinding = {
  filename: string;
  content_type: string;
  size: number;
  sha256: string;
  true_type: string;
  notes: string[];
  flagged: boolean;
};
export type Lookalike = { domain: string; target: string; method: string; where?: string };
export type Ioc = {
  type: 'url' | 'domain' | 'ipv4' | 'ipv6' | 'email' | 'sha256' | 'crypto-wallet' | 'phone';
  value: string;
  context: string;
};
export type Technique = { id: string; name: string; evidence: string[] };
export type AuthCheck = { check: 'SPF' | 'DKIM' | 'DMARC'; result: string; domain: string; aligned: boolean | null };

/** The parts of the full report (report.schema.json) the screens use. */
export type Report = {
  report_id: string;
  generated_at: string;
  subject: string;
  from_display: string;
  from_address: string;
  to: string;
  reply_to: string;
  date: string;
  verdict: Verdict;
  score: number;
  summary: string[];
  signals: Signal[];
  analysis_status: { status: string; reasons: string[]; reputation: string; reputation_detail?: string };
  authentication: { status: string; checks: AuthCheck[]; explanation: string[] };
  urls: UrlFinding[];
  attachments: AttachmentFinding[];
  lookalikes: Lookalike[];
  iocs: Ioc[];
  techniques: Technique[];
  recommendations: string[];
  limitations: string[];
};

/** GET /api/v1/analyses/{id} */
export type Analysis = AnalysisSummary & { report: Report | null };

/** GET and PATCH /api/v1/settings */
export type Settings = {
  providers: string[];
  protected_domains: string[];
  allow_domains: string[];
  block_domains: string[];
  trusted_authserv: string[];
  retention_days: number;
  max_upload_mb: number;
  max_batch_messages: number;
  campaign_window_days: number;
  /** Only the last four characters ("...a1b2"), or "" when no key is set. Never send these back. */
  keys: Record<string, string>;
};
/** PATCH /api/v1/settings: any subset. In `keys`, send only a newly typed key, or "" to remove one. */
export type SettingsPatch = Partial<Omit<Settings, 'keys'>> & { keys?: Record<string, string> };

export type User = { id: number; username: string; role: Role; disabled: boolean; last_login_at: string | null };
export type Token = { id: number; name: string; scope: 'read' | 'submit'; user_id: number; created_at: string; revoked: boolean };
export type NewToken = { token: string; note: string };

/** GET /api/v1/audit */
export type AuditEntry = {
  id: number;
  at: string;
  actor: string;
  action: string;
  object_type: string;
  object_id: string;
  details: Record<string, unknown>;
};

/** GET /healthz */
export type Health = {
  status: string;
  version: string;
  queue: number;
  last_heartbeat: string | null;
  disk_free_mb: number;
};
