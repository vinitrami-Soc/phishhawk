/* Which analysis controls to show (frontend build brief, sections 6 and 7.5),
   and which steps the setup after sign-up has. Presentation only: the server
   checks every request again. */

import type { AnalysisSummary, Session } from '@/api/types';

export type AnalysisActions = {
  reanalyze: boolean;
  downloads: boolean;
  reportFrame: boolean;
  rawMessage: boolean;
  deleteNow: boolean;
  deleteCompletely: boolean;
  hold: boolean;
  release: boolean;
};

export function analysisActions(
  session: Pick<Session, 'role' | 'user_id'>,
  analysis: Pick<AnalysisSummary, 'submitted_by' | 'hold' | 'tier1_deleted_at'>,
): AnalysisActions {
  const admin = session.role === 'admin';
  const own = analysis.submitted_by !== null && analysis.submitted_by === session.user_id;
  const present = !analysis.tier1_deleted_at;
  const deletable = present && !analysis.hold;
  return {
    reanalyze: present,
    downloads: present,
    reportFrame: present,
    rawMessage: present && (admin || own),
    deleteNow: deletable && (admin || own),
    deleteCompletely: deletable && admin,
    hold: present && admin && !analysis.hold,
    release: present && admin && analysis.hold,
  };
}

export type OnboardingStep = 'invite' | 'mailbox' | 'providers' | 'tour';

/** An organization's admin sets it up; an individual chooses providers; anyone else is shown around. */
export function onboardingSteps(session: Pick<Session, 'role' | 'workspace'>): OnboardingStep[] {
  if (session.role !== 'admin') return ['tour'];
  return session.workspace?.kind === 'individual' ? ['providers', 'tour'] : ['invite', 'mailbox', 'providers', 'tour'];
}
