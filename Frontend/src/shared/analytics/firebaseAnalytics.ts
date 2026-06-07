import {
  getAnalytics,
  isSupported,
  logEvent,
  setUserId,
  type Analytics,
} from 'firebase/analytics';
import app from '../../firebase/config';
import {
  ALLOWED_ANALYTICS_PARAMS,
  ANALYTICS_SOURCE,
  type AnalyticsEventName,
} from './analyticsEvents';

type AnalyticsParamValue = string | number | boolean;
type AnalyticsParams = Record<string, unknown>;

interface PendingEvent {
  eventName: AnalyticsEventName | string;
  params: Record<string, AnalyticsParamValue>;
}

const analyticsEnabled = import.meta.env.VITE_ANALYTICS_ENABLED === 'true';
const analyticsDebugMode =
  import.meta.env.VITE_ANALYTICS_DEBUG_MODE === 'true';
const maxPendingEvents = 50;

let analyticsInstance: Analytics | null = null;
let analyticsInitPromise: Promise<Analytics | null> | null = null;
let analyticsInitialized = false;
let pendingUserId: string | null = null;

const pendingEvents: PendingEvent[] = [];

export function initAnalytics(): Promise<Analytics | null> {
  if (!analyticsEnabled || typeof window === 'undefined') {
    return Promise.resolve(null);
  }

  if (analyticsInitPromise) {
    return analyticsInitPromise;
  }

  analyticsInitPromise = initializeAnalytics();
  return analyticsInitPromise;
}

export function trackEvent(
  eventName: AnalyticsEventName | string,
  params: AnalyticsParams = {}
) {
  if (!analyticsEnabled || typeof window === 'undefined') {
    return;
  }

  const safeParams = sanitizeAnalyticsParams({
    source: ANALYTICS_SOURCE,
    ...params,
  });

  if (analyticsDebugMode) {
    safeParams.debug_mode = true;
  }

  if (!analyticsInitialized || !analyticsInstance) {
    enqueueEvent(eventName, safeParams);
    void initAnalytics();
    return;
  }

  sendAnalyticsEvent(eventName, safeParams);
}

export function identifyAnalyticsUser(userId: string | number | null) {
  if (!analyticsEnabled || typeof window === 'undefined') {
    return;
  }

  const safeUserId = sanitizeUserId(userId);
  if (!safeUserId) {
    return;
  }

  if (!analyticsInitialized || !analyticsInstance) {
    pendingUserId = safeUserId;
    void initAnalytics();
    return;
  }

  setAnalyticsUserId(safeUserId);
}

async function initializeAnalytics(): Promise<Analytics | null> {
  try {
    const supported = await isSupported();

    if (!supported) {
      logAnalyticsDebug('warn', 'Firebase Analytics is not supported here');
      return null;
    }

    analyticsInstance = getAnalytics(app);
    analyticsInitialized = true;
    flushPendingUserId();
    flushPendingEvents();
    logAnalyticsDebug('info', 'Firebase Analytics initialized');

    return analyticsInstance;
  } catch (error) {
    logAnalyticsDebug('error', 'Failed to initialize Firebase Analytics', error);
    return null;
  }
}

function enqueueEvent(
  eventName: AnalyticsEventName | string,
  params: Record<string, AnalyticsParamValue>
) {
  if (pendingEvents.length >= maxPendingEvents) {
    pendingEvents.shift();
  }

  pendingEvents.push({ eventName, params });
}

function flushPendingEvents() {
  if (!analyticsInstance) {
    return;
  }

  while (pendingEvents.length > 0) {
    const nextEvent = pendingEvents.shift();
    if (nextEvent) {
      sendAnalyticsEvent(nextEvent.eventName, nextEvent.params);
    }
  }
}

function flushPendingUserId() {
  if (!pendingUserId || !analyticsInstance) {
    return;
  }

  setAnalyticsUserId(pendingUserId);
  pendingUserId = null;
}

function sendAnalyticsEvent(
  eventName: AnalyticsEventName | string,
  params: Record<string, AnalyticsParamValue>
) {
  if (!analyticsInstance) {
    return;
  }

  try {
    logEvent(analyticsInstance, eventName, params);
    logAnalyticsDebug('info', `Event: ${eventName}`, params);
  } catch (error) {
    logAnalyticsDebug('error', `Failed to log event: ${eventName}`, error);
  }
}

function setAnalyticsUserId(userId: string) {
  if (!analyticsInstance) {
    return;
  }

  try {
    setUserId(analyticsInstance, userId);
  } catch (error) {
    logAnalyticsDebug('error', 'Failed to set analytics user id', error);
  }
}

function sanitizeAnalyticsParams(
  params: AnalyticsParams
): Record<string, AnalyticsParamValue> {
  const result: Record<string, AnalyticsParamValue> = {};

  Object.entries(params).forEach(([key, value]) => {
    if (!ALLOWED_ANALYTICS_PARAMS.has(key)) {
      return;
    }

    if (value === null || value === undefined) {
      return;
    }

    if (typeof value === 'string') {
      const trimmedValue = value.trim();
      if (trimmedValue.length > 0) {
        result[key] = trimmedValue.slice(0, 100);
      }
      return;
    }

    if (typeof value === 'number') {
      if (Number.isFinite(value)) {
        result[key] = value;
      }
      return;
    }

    if (typeof value === 'boolean') {
      result[key] = value;
    }
  });

  return result;
}

function sanitizeUserId(userId: string | number | null): string | null {
  if (userId === null) {
    return null;
  }

  const value = String(userId).trim();

  if (!value || value.includes('@')) {
    return null;
  }

  return value.slice(0, 100);
}

function logAnalyticsDebug(
  level: 'info' | 'warn' | 'error',
  message: string,
  data?: unknown
) {
  if (!import.meta.env.DEV) {
    return;
  }

  const prefix = '[Analytics]';

  if (data === undefined) {
    console[level](prefix, message);
    return;
  }

  console[level](prefix, message, data);
}
