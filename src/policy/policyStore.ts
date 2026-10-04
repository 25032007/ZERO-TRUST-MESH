/**
 * PolicyStore — loads policies from a JSON file and keeps the engine in sync.
 *
 * Safety properties (the whole point of this class):
 *   1. ATOMIC: a new policy set is validated completely first; only if it is
 *      valid is it swapped in with a single assignment (PolicyEngine.replaceAll).
 *   2. FAIL-SAFE ON RELOAD: if the edited file is invalid (typo, half-saved,
 *      bad JSON) the PREVIOUS good policies stay active, the error is recorded
 *      and surfaced via status() — a bad edit can never open or close the mesh.
 *   3. FAIL-FAST ON STARTUP: if the very first load is invalid there is nothing
 *      safe to fall back to, so startup throws instead of running unprotected.
 *   4. VERSIONED: every loaded set gets a short content hash so you can tell
 *      exactly which policies were active when a decision was made.
 */
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { readFileSync, watch, type FSWatcher } from 'node:fs';
import path from 'node:path';
import { parsePolicyDocument } from './policyFile.js';
import type { Policy, PolicyEngine } from './policyEngine.js';

export interface PolicyStatus {
  file?: string;
  /** First 12 hex chars of the SHA-256 of the active policy source. */
  version: string;
  policyCount: number;
  workflowCount: number;
  dryRun: boolean;
  loadedAt: number;
  reloads: number;
  rejectedReloads: number;
  lastError?: { at: number; errors: string[] };
}

export interface ReloadEvent {
  ok: boolean;
  version?: string;
  errors?: string[];
}

export class PolicyStore extends EventEmitter {
  private version = 'none';
  private loadedAt = 0;
  private reloads = 0;
  private rejectedReloads = 0;
  private lastError?: { at: number; errors: string[] };
  private watcher?: FSWatcher;
  private debounce?: NodeJS.Timeout;

  constructor(
    private readonly engine: PolicyEngine,
    private readonly filePath: string | undefined,
    /** Forces global dry-run on regardless of the file (DRY_RUN=true). */
    private readonly forceDryRun = false,
    private readonly clock: () => number = Date.now,
  ) {
    super();
  }

  get hasFile(): boolean {
    return this.filePath !== undefined;
  }

  /** Use an in-code policy list (no file). Used by tests and as the built-in fallback. */
  useInline(policies: Policy[], workflows: string[][] = []): void {
    this.engine.replaceAll(policies);
    this.engine.setAllowedWorkflows(workflows);
    this.engine.setDryRun(this.forceDryRun);
    this.version = hashOf(JSON.stringify({ policies, workflows }));
    this.loadedAt = this.clock();
  }

  /** First load. Throws if the file is missing or invalid (fail fast, see class comment). */
  loadInitial(): void {
    if (!this.filePath) throw new Error('PolicyStore has no file configured');
    const result = this.readAndApply();
    if (!result.ok) throw new Error(`Invalid policy file ${this.filePath}:\n  - ${result.errors!.join('\n  - ')}`);
  }

  /** Re-read the file. On any problem the previous policies stay active. */
  reload(): ReloadEvent {
    if (!this.filePath) return { ok: false, errors: ['no policy file configured'] };
    const result = this.readAndApply();
    if (result.ok) {
      this.reloads++;
      this.lastError = undefined;
    } else {
      this.rejectedReloads++;
      this.lastError = { at: this.clock(), errors: result.errors! };
    }
    this.emit('reload', result);
    return result;
  }

  /**
   * Watch for edits and reload automatically (hot reload).
   * We watch the DIRECTORY and filter by file name because many editors save by
   * writing a temp file and renaming it, which detaches a watcher on the file itself.
   * Events are debounced because one save usually fires several fs events.
   */
  watch(debounceMs = 150): void {
    if (!this.filePath || this.watcher) return;
    const dir = path.dirname(this.filePath);
    const base = path.basename(this.filePath);
    this.watcher = watch(dir, (_event, name) => {
      if (name && name !== base) return;
      clearTimeout(this.debounce);
      this.debounce = setTimeout(() => this.reload(), debounceMs);
      this.debounce.unref();
    });
    this.watcher.unref(); // never keep the process alive just for this
  }

  close(): void {
    clearTimeout(this.debounce);
    this.watcher?.close();
    this.watcher = undefined;
  }

  status(): PolicyStatus {
    return {
      file: this.filePath,
      version: this.version,
      policyCount: this.engine.list().length,
      workflowCount: this.engine.allowedWorkflows().length,
      dryRun: this.engine.dryRun,
      loadedAt: this.loadedAt,
      reloads: this.reloads,
      rejectedReloads: this.rejectedReloads,
      lastError: this.lastError,
    };
  }

  private readAndApply(): ReloadEvent {
    let text: string;
    try {
      text = readFileSync(this.filePath!, 'utf8');
    } catch (err) {
      return { ok: false, errors: [`cannot read file: ${(err as Error).message}`] };
    }
    const parsed = parsePolicyDocument(text);
    if (!parsed.ok) return { ok: false, errors: parsed.errors };

    // Everything validated: apply as one synchronous step.
    this.engine.replaceAll(parsed.doc.policies);
    this.engine.setAllowedWorkflows(parsed.doc.allowedWorkflows);
    this.engine.setDryRun(parsed.doc.dryRun || this.forceDryRun);
    this.version = hashOf(text);
    this.loadedAt = this.clock();
    return { ok: true, version: this.version };
  }
}

function hashOf(text: string): string {
  return createHash('sha256').update(text).digest('hex').slice(0, 12);
}
