import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import {
  ANALYTICS_SOURCE,
  AnalyticsEvents,
  type AnalyticsPageName,
} from './analyticsEvents';
import { trackEvent } from './firebaseAnalytics';

const pageNameByPath: Record<string, AnalyticsPageName> = {
  '/': 'home',
  '/about': 'about',
  '/auth': 'auth',
  '/tests': 'tests',
  '/charts': 'analytics',
  '/ai-psychologist': 'ai_psychologist',
  '/relaxation': 'relaxation',
  '/profile': 'profile',
};

export function AnalyticsRouteTracker() {
  const location = useLocation();

  useEffect(() => {
    const normalizedPath = normalizePath(location.pathname);

    trackEvent(AnalyticsEvents.PAGE_VIEW, {
      source: ANALYTICS_SOURCE,
      page_path: normalizedPath,
      page_name: pageNameByPath[normalizedPath] ?? 'unknown',
    });
  }, [location.pathname]);

  return null;
}

function normalizePath(pathname: string) {
  if (pathname === '/') {
    return pathname;
  }

  return pathname.replace(/\/+$/, '') || '/';
}
