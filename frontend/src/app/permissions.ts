/* Which analysis controls to show (frontend build brief, sections 6 and 7.5).
   Presentation only: the server checks every request again. */

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
