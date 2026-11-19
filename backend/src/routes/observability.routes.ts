import { Router } from 'express';
import type { Request, Response } from 'express';
import { authenticate, requirePermission } from '../middleware/access-control';
import { metrics, TelemetryConfigError } from '../observability/telemetry';
import { sendFailure, sendSuccess } from '../types/api';
import { createInvoiceHandlers, InvoiceHandlerOptions } from './invoice.handlers';

/**
 * Observability & Telemetry routes. Mount under `/api`.
 *
 * Exposes:
 *   GET /observability/metrics
 *   GET /metrics
 *   GET /observability/sampling
 *   PUT /observability/sampling
 */
export function createObservabilityRouter(options: InvoiceHandlerOptions): Router {
  const handlers = createInvoiceHandlers(options);
  const router = Router();

  router.get('/observability/metrics', handlers.getObservabilityMetrics);
  router.get('/metrics', handlers.getPrometheusMetrics);

  router.get(
    '/observability/sampling',
    authenticate(),
    requirePermission('analytics:read'),
    (_req: Request, res: Response) => {
      const summary = metrics.getMetricsSummary();
      sendSuccess(res, 200, summary.telemetry_sampling);
    }
  );

  router.put(
    '/observability/sampling',
    authenticate(),
    requirePermission('analytics:clear'),
    (req: Request, res: Response) => {
      try {
        const updated = metrics.setSamplingPolicy({
          successSampleRate: req.body?.successSampleRate,
          failureSampleRate: req.body?.failureSampleRate,
          maxLogsPerWindow: req.body?.maxLogsPerWindow,
          windowMs: req.body?.windowMs,
        });
        sendSuccess(res, 200, { policy: updated });
      } catch (err) {
        if (err instanceof TelemetryConfigError) {
          return sendFailure(res, err.httpStatus, err.message, err.code);
        }
        throw err;
      }
    }
  );

  return router;
}

export default createObservabilityRouter;
