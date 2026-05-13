import * as Sentry from "@sentry/node";

const DSN = process.env["SENTRY_DSN"] ?? "https://60bdf7076e5f97dcb54c374a9c309c08@o143364.ingest.us.sentry.io/4511380657143808";

let initialized = false;

export function initSentry(extensionVersion: string): void {
  if (!DSN || initialized) return;
  Sentry.init({
    dsn: DSN,
    release: `flcn-sec@${extensionVersion}`,
    environment: "production",
    tracesSampleRate: 0,
    integrations: [],
  });
  initialized = true;
}

export function captureException(err: unknown, context?: Record<string, unknown>): void {
  if (!initialized) return;
  Sentry.captureException(err, context ? { extra: context } : undefined);
}
