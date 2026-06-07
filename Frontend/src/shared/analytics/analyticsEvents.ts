export const ANALYTICS_SOURCE = 'web';

export const AnalyticsEvents = {
  PAGE_VIEW: 'page_view',
  SIGN_UP_STARTED: 'sign_up_started',
  SIGN_UP_COMPLETED: 'sign_up_completed',
  LOGIN_COMPLETED: 'login_completed',
  LOGOUT_COMPLETED: 'logout_completed',
  TEST_STARTED: 'test_started',
  TEST_COMPLETED: 'test_completed',
  ANALYTICS_OPENED: 'analytics_opened',
  PERIOD_CHANGED: 'period_changed',
  PRACTICE_OPENED: 'practice_opened',
  PRACTICE_COMPLETED: 'practice_completed',
  AI_RECOMMENDATION_COMPLETED: 'ai_recommendation_completed',
  AI_MESSAGE_SENT: 'ai_message_sent',
  FEEDBACK_OPENED: 'feedback_opened',
} as const;

export type AnalyticsEventName =
  (typeof AnalyticsEvents)[keyof typeof AnalyticsEvents];

export const ANALYTICS_PAGE_NAMES = [
  'home',
  'about',
  'auth',
  'tests',
  'analytics',
  'ai_psychologist',
  'relaxation',
  'profile',
  'unknown',
] as const;

export type AnalyticsPageName = (typeof ANALYTICS_PAGE_NAMES)[number];

export const ANALYTICS_TEST_TYPES = [
  'san',
  'emotional_intelligence',
  'psm25_stress',
  'spielberger_anxiety',
  'boyko_burnout',
  'maslach_burnout',
  'self_esteem',
  'mood_scale',
] as const;

export type AnalyticsTestType = (typeof ANALYTICS_TEST_TYPES)[number];

export const ANALYTICS_PERIODS = ['week', 'month', 'all'] as const;

export type AnalyticsPeriod = (typeof ANALYTICS_PERIODS)[number];

export const ANALYTICS_PRACTICE_TYPES = [
  'breathing',
  'meditation',
  'relaxation',
] as const;

export type AnalyticsPracticeType = (typeof ANALYTICS_PRACTICE_TYPES)[number];

export const ANALYTICS_DURATION_GROUPS = [
  'under_1_min',
  '1_3_min',
  '3_5_min',
  'over_5_min',
  'unknown',
] as const;

export type AnalyticsDurationGroup =
  (typeof ANALYTICS_DURATION_GROUPS)[number];

export const ANALYTICS_MESSAGE_LENGTH_GROUPS = [
  'empty',
  'short',
  'medium',
  'long',
] as const;

export type AnalyticsMessageLengthGroup =
  (typeof ANALYTICS_MESSAGE_LENGTH_GROUPS)[number];

export const ALLOWED_ANALYTICS_PARAMS = new Set<string>([
  'source',
  'page_path',
  'page_name',
  'method',
  'test_type',
  'question_count',
  'period',
  'practice_id',
  'practice_type',
  'duration_group',
  'trigger',
  'message_length_group',
  'entry_point',
  'debug_mode',
]);

export function getDurationGroup(
  seconds: number | null | undefined
): AnalyticsDurationGroup {
  if (!seconds || seconds <= 0) return 'unknown';
  if (seconds < 60) return 'under_1_min';
  if (seconds <= 180) return '1_3_min';
  if (seconds <= 300) return '3_5_min';
  return 'over_5_min';
}

export function getMessageLengthGroup(
  text: string | null | undefined
): AnalyticsMessageLengthGroup {
  const length = text?.trim().length ?? 0;

  if (length === 0) return 'empty';
  if (length <= 100) return 'short';
  if (length <= 500) return 'medium';
  return 'long';
}
