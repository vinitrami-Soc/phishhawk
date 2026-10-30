/* The PhishHawk API as the server returns it (docs/api/openapi.json and
   docs/report.schema.json). Field names are the server's: do not rename them,
   and do not add fields the server does not send. */

export type Role = 'analyst' | 'admin';
export type Verdict = 'NO STRONG INDICATORS' | 'SUSPICIOUS' | 'LIKELY PHISHING' | 'MALICIOUS';
export type Severity = 'high' | 'medium' | 'low';
export type SubmissionStatus = 'queued' | 'running' | 'done' | 'failed';

/** Where a user's data lives: an organization (a team) or one person. No workspace sees another's data. */
export type Workspace = { id: number; name: string; kind: 'organization' | 'individual' };

/** GET /api/v1/workspaces (the owner only): each workspace by name, kind and number of members, no one's profile. */
export type WorkspaceSummary = Workspace & { members: number; created_at: string };

/** A person's profile, seen only inside their workspace. */
export type Profile = { first_name: string; last_name: string; location: string; job_title: string };

/** GET /api/v1/session */
export type Session = {
  user_id: number | null;
  username: string;
  role: Role;
  via: 'session' | 'token';
  scope: string;
  csrf: string;
  /** runs the server: sign-up, the daily cap and the upload limits are theirs alone */
  owner: boolean;
  /** false until the setup after sign-up is finished or skipped; an older server leaves it out */
  onboarded?: boolean;
  workspace: Workspace | null;
  profile: Profile | null;
  /** "" when the account has none; an older server leaves both out */
  email?: string;
  /** true once the link sent to the address was opened: only then can it reset the password */
  email_verified?: boolean;
};

/** POST /api/v1/submissions (one message), GET /api/v1/submissions/{id}, POST /api/v1/analyses/{id}/reanalyze */
export type Submission = {
  id: number;
  status: SubmissionStatus;
  error: string;
  analysis_id: number | null;
  submitted_at: string;
  /** set when the submission is one message of a batch */
  batch_id: number | null;
};

/** POST /api/v1/submissions with several messages (several files, an .mbox or a .zip): one batch */
export type BatchCreated = {
  batch_id: number;
  total: number;
  submission_ids: number[];
  /** files in a .zip that are not messages */
  skipped: number;
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

export type BatchStatus = 'running' | 'finalizing' | 'done' | 'failed';

/** One message of GET /api/v1/batches/{id}, in upload order */
export type BatchMessage = {
  position: number;
  submission_id: number;
  status: SubmissionStatus;
  error: string;
  message_id: number;
  analysis_id: number | null;
  verdict: Verdict | null;
  score: number | null;
  sender: string;
  sender_domain: string;
};

/** GET /api/v1/batches/{id} */
export type Batch = {
  id: number;
  created_at: string;
  submitted_by: number | null;
  submitted_by_name: string | null;
  offline: boolean;
  total: number;
  status: BatchStatus;
  error: string;
  counts: Record<SubmissionStatus, number>;
  verdicts: Partial<Record<Verdict, number>>;
  messages: BatchMessage[];
  finished_at: string | null;
  /** the combined reports, once the batch is done */
  files: AnalysisFile[];
  files_deleted_at: string | null;
};

/** What links a campaign's messages. A subject or display name is null once no message's content is kept. */
export type SharedTrait = { kind: string; value: string | null; messages: number };

/** One row of GET /api/v1/campaigns (shared subjects and display names are always null here) */
export type CampaignSummary = {
  id: number;
  size: number;
  first_seen: string;
  last_seen: string;
  verdicts: Partial<Record<Verdict, number>>;
  worst_verdict: Verdict;
  shared: SharedTrait[];
  senders: string[];
  recipient_count: number;
  rebuilt_at: string;
};

export type CampaignMessage = {
  message_id: number;
  analysis_id: number;
  sha256: string;
  verdict: Verdict;
  score: number;
  sender: string;
  /** null once the message's content is deleted */
  subject: string | null;
  date: string;
};

/** GET /api/v1/campaigns/{id} */
export type Campaign = CampaignSummary & {
  messages: CampaignMessage[];
  /** only while the messages' content is kept */
  recipients: string[];
  recipients_complete: boolean;
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

/* ---- mailboxes (admin): report mailboxes the server reads, read-only ---- */

export type MailboxKind = 'imap' | 'graph' | 'gmail';

/** Where a mailbox is. IMAP: host, port, starttls, user, folder. Graph: tenant_id, client_id, address, folder.
    Gmail: address, label, and service_account (from its key). Never a credential. */
export type MailboxConfig = {
  host?: string;
  port?: number;
  starttls?: boolean;
  user?: string;
  folder?: string;
  tenant_id?: string;
  client_id?: string;
  address?: string;
  label?: string;
  service_account?: string;
};

export type MailboxCounts = { imported: number; duplicates: number; skipped: number };

export type Mailbox = {
  id: number;
  name: string;
  kind: MailboxKind;
  enabled: boolean;
  interval_minutes: number;
  config: MailboxConfig;
  /** the credential is stored (encrypted) and never sent back */
  secret_set: boolean;
  status: 'never' | 'ok' | 'error';
  /** why the last poll failed, in the server's words; never a credential */
  error: string;
  last_poll_at: string | null;
  next_poll_at: string | null;
  last_counts: Partial<MailboxCounts>;
  created_at: string | null;
};

/** secret: an IMAP password, a Graph client secret, or a Gmail service account's JSON key. */
export type NewMailbox = { name: string; kind: MailboxKind; config: MailboxConfig; secret: string; interval_minutes?: number; enabled?: boolean };

/** An empty or missing secret keeps the stored one. A mailbox keeps its kind. */
export type MailboxPatch = { name?: string; config?: MailboxConfig; secret?: string; interval_minutes?: number; enabled?: boolean };
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

/* ---- getting in: setup, sign-up, invitations, profile ---- */

/** A new account's own fields. A 422 or 409 `detail` starts with the field it is about ("last_name: required"). */
export type AccountFields = Profile & { username: string; password: string; email: string };

/** POST /api/v1/setup: the owner's account, with the code `phishhawk server setup-code` prints. */
export type SetupFields = AccountFields & { code: string; organization: string; signup_open: boolean };

/** POST /api/v1/signup. `organization` is needed for an organization, and optional for an individual. */
export type SignupFields = AccountFields & { kind: Workspace['kind']; organization: string };

/** GET /api/v1/join/{token}: the organization an invitation opens, and the role it gives. */
export type Invitation = { organization: string; role: Role };

/** GET /api/v1/operator: who runs this server, where to write about one's data and where it runs; empty until it says. */
export type Operator = { name: string; email: string; hosting?: string };

/** GET /api/v1/invites: an invitation that can still be used. Never its token. */
export type Invite = { id: number; role: Role; note: string; created_at: string; expires_at: string; created_by_name: string | null };

/** POST /api/v1/invites: the token is shown once; the server keeps only a hash of it. */
export type NewInvite = Invite & { token: string; link: string };

/** GET /api/v1/me */
export type Me = { username: string; role: Role; owner: boolean; profile: Profile; workspace: Workspace; email?: string; email_verified?: boolean };

/** PATCH /api/v1/me: any of these. A new password or email address needs the current password. */
export type ProfilePatch = Partial<Profile> & { organization?: string; password?: string; email?: string; current_password?: string };

/** GET /api/v1/server-settings (the owner only) */
export type ServerSettings = {
  signup_open: boolean;
  signup_daily_cap: number;
  max_upload_mb: number;
  max_batch_messages: number;
  /** messages each workspace may submit a day (UTC); past it an upload answers 429 until midnight UTC */
  daily_messages_organization: number;
  daily_messages_individual: number;
};

/* ---- feedback ---- */

export type FeedbackKind = 'bug' | 'idea' | 'question' | 'other';

/** POST /api/v1/feedback, GET /api/v1/feedback (the owner gets everyone's; anyone else their own) */
export type Feedback = {
  id: number;
  kind: FeedbackKind;
  message: string;
  /** the app path it was sent from, or "" */
  page: string;
  status: 'open' | 'done';
  created_at: string;
  username: string | null;
  workspace: { id: number; name: string };
};

export type NewFeedback = { kind: FeedbackKind; message: string; page: string };

/** right; missed: it was phishing; false_alarm: it was not */
export type Opinion = 'right' | 'missed' | 'false_alarm';

export type VerdictAnswer = {
  id: number;
  user_id: number;
  username: string | null;
  opinion: Opinion;
  note: string;
  created_at: string;
  updated_at: string;
};

export type OpinionCounts = Record<Opinion, number>;

/** GET /api/v1/analyses/{id}/feedback */
export type VerdictFeedback = { mine: VerdictAnswer | null; answers: VerdictAnswer[]; counts: OpinionCounts };

/** GET /api/v1/feedback/verdicts (admins) */
export type VerdictSummary = {
  counts: OpinionCounts;
  disputed: ({ analysis_id: number; report_id: string; verdict: Verdict; score: number; last_answer_at: string } & OpinionCounts)[];
};
