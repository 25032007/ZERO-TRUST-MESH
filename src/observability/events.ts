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
import type { PipelineResult } from '../types.js';

export class EventBus extends EventEmitter {
  publishDecision(result: PipelineResult): void {
    this.emit('decision', result);
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
    bus.on('decision', onDecision);
    socket.on('close', () => bus.off('decision', onDecision)); // avoid listener leaks
    socket.on('error', () => bus.off('decision', onDecision));
  });

  return wss;
}
