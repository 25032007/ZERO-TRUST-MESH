/**
 * Live event stream for the dashboard.
 *
 * The pipeline publishes every result to an in-process EventBus. A WebSocket
 * server forwards those events to connected dashboards so threats show up
 * instantly, with no polling.
 */
import { EventEmitter } from 'node:events';
import type { Server as HttpServer } from 'node:http';
import { WebSocketServer } from 'ws';
import type { FindingSummary } from '../threat/presenter.js';
import type { PipelineResult } from '../types.js';

export class EventBus extends EventEmitter {
  publishDecision(result: PipelineResult): void {
    this.emit('decision', result);
  }
  /** Additive threat update; never replaces the pipeline decision event. */
  publishThreatFinding(summary: FindingSummary): void {
    this.emit('threat-finding', summary);
  }
}

/**
 * Attach a WebSocket endpoint at /ws.
 * `authorize` lets the caller require the admin key when the dashboard is private.
 */
export function attachWebSocket(
  server: HttpServer,
  bus: EventBus,
  authorize: (url: URL) => boolean,
): WebSocketServer {
  const wss = new WebSocketServer({ server, path: '/ws' });

  wss.on('connection', (socket, req) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (!authorize(url)) {
      socket.close(4401, 'unauthorized');
      return;
    }
    const onDecision = (r: PipelineResult) => {
      if (socket.readyState === socket.OPEN) socket.send(JSON.stringify({ type: 'decision', data: r }));
    };
    // Versioned additive threat events ride the SAME connection; no second socket.
    const onThreatFinding = (summary: FindingSummary) => {
      if (socket.readyState === socket.OPEN) socket.send(JSON.stringify({ type: 'threat.finding.v1', data: summary }));
    };
    bus.on('decision', onDecision);
    bus.on('threat-finding', onThreatFinding);
    const detach = () => {
      bus.off('decision', onDecision); // avoid listener leaks
      bus.off('threat-finding', onThreatFinding);
    };
    socket.on('close', detach);
    socket.on('error', detach);
  });

  return wss;
}
