import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { generateTraffic } from '../src/eval/trafficGenerator.js';
import { runDetector, type DetectorConfig } from '../src/eval/runner.js';
import { computeMetrics, meanStd } from '../src/eval/metrics.js';
import { createDemoMesh } from '../src/demoMesh.js';
import { loadConfig } from '../src/config.js';
import { createMesh } from '../src/mesh.js';
import path from 'node:path';

async function evaluateMultiple(
  seeds: number[],
  config: DetectorConfig,
  durationMs: number,
  loadScale: number
) {
  const f1s: number[] = [];
  const fprs: number[] = [];
  
  // Dummy mesh to get clients
  const dummyMesh = createMesh(loadConfig());
  const clients = await createDemoMesh(dummyMesh);

  for (const seed of seeds) {
    const traffic = generateTraffic({ seed, durationMs, loadScale });
    const res = await runDetector(config, traffic, clients);
    const metrics = computeMetrics(res.outcomes, res.episodes);
    f1s.push(metrics.behavioral.f1);
    fprs.push(metrics.fpr);
  }
  
  return {
    f1: meanStd(f1s),
    fpr: meanStd(fprs),
  };
}

async function main() {
  console.log('Starting Evaluation Harness...');
  const valSeeds = [101, 102];
  const testSeeds = [201, 202, 203, 204, 205];
  const durationMs = 600_000; // 10 minutes

  // 1. Tuning
  console.log('Tuning baseline detector on validation seeds...');
  const alphas = [0.1, 0.2, 0.3];
  const zWarns = [2, 3, 4];
  const spikeHighPoints = [15, 20, 25];
  const zScorePoints = [10, 15, 20];
  
  let bestF1 = -1;
  let bestParams = { alpha: 0.2, zWarn: 3, spikeHighPoints: 20, zScorePoints: 15 };
  
  for (const alpha of alphas) {
    for (const zWarn of zWarns) {
      for (const sp of spikeHighPoints) {
        for (const zp of zScorePoints) {
          const cfg: DetectorConfig = {
            name: 'tuning',
            rate: 'baseline',
            payloadZ: true,
            workflows: true,
            params: { alpha, zWarn, spikeHighPoints: sp, zScorePoints: zp }
          };
          const res = await evaluateMultiple(valSeeds, cfg, durationMs, 1.0);
          if (res.fpr.mean <= 0.01 && res.f1.mean > bestF1) {
            bestF1 = res.f1.mean;
            bestParams = { alpha, zWarn, spikeHighPoints: sp, zScorePoints: zp };
          }
        }
      }
    }
  }
  
  console.log(`Best parameters found: ${JSON.stringify(bestParams)} (F1: ${bestF1.toFixed(3)})`);

  // 2. Evaluation
  console.log('Evaluating on test seeds...');
  
  const configs: Record<string, DetectorConfig> = {
    'Fixed Thresholds': { name: 'Fixed', rate: 'fixed', payloadZ: true, workflows: true },
    'Baseline Default': { name: 'Baseline Default', rate: 'baseline', payloadZ: true, workflows: true },
    'Baseline Tuned': { name: 'Baseline Tuned', rate: 'baseline', payloadZ: true, workflows: true, params: bestParams },
    'Ablation: No Payload Z': { name: 'No Payload Z', rate: 'baseline', payloadZ: false, workflows: true, params: bestParams },
    'Ablation: No Workflows': { name: 'No Workflows', rate: 'baseline', payloadZ: true, workflows: false, params: bestParams },
    'Ablation: Baseline -> Fixed': { name: 'Baseline -> Fixed', rate: 'fixed', payloadZ: true, workflows: true, params: bestParams },
  };

  const results1x: Record<string, { f1: ReturnType<typeof meanStd>, fpr: ReturnType<typeof meanStd> }> = {};
  for (const [name, cfg] of Object.entries(configs)) {
    console.log(`Running ${name} at 1x load...`);
    results1x[name] = await evaluateMultiple(testSeeds, cfg, durationMs, 1.0);
  }

  const resultsLoad: Record<string, any> = {};
  for (const scale of [1, 2, 4]) {
    console.log(`Running Baseline Tuned at ${scale}x load...`);
    resultsLoad[`${scale}x`] = await evaluateMultiple(testSeeds, configs['Baseline Tuned'], durationMs, scale);
  }

  // 3. Write Report
  const format = (ms: ReturnType<typeof meanStd>, pct = false) => {
    const mult = pct ? 100 : 1;
    return `${(ms.mean * mult).toFixed(3)} ± ${(ms.std * mult).toFixed(3)}${pct ? '%' : ''}`;
  };

  let md = `# Detector Evaluation Report

Generated on: ${new Date().toUTCString()}
Command: \`npm run evaluate\`
Validation seeds: ${valSeeds.join(', ')}
Test seeds: ${testSeeds.join(', ')}

## Tuning Results
Best parameters found maximizing F1 (subject to FPR <= 1%):
\`\`\`json
${JSON.stringify(bestParams, null, 2)}
\`\`\`

## Variant Comparison (1x Load)
| Variant | Behavioral F1 | FPR |
|---------|---------------|-----|
`;

  for (const name of ['Fixed Thresholds', 'Baseline Default', 'Baseline Tuned']) {
    md += `| ${name} | ${format(results1x[name].f1)} | ${format(results1x[name].fpr, true)} |\n`;
  }

  md += `
## Ablation Study (1x Load, Tuned Params)
| Variant | Behavioral F1 | FPR |
|---------|---------------|-----|
`;
  for (const name of ['Baseline Tuned', 'Ablation: No Payload Z', 'Ablation: No Workflows', 'Ablation: Baseline -> Fixed']) {
    md += `| ${name} | ${format(results1x[name].f1)} | ${format(results1x[name].fpr, true)} |\n`;
  }

  md += `
## Load Scaling (Baseline Tuned)
| Load Scale | Behavioral F1 | FPR |
|------------|---------------|-----|
`;
  for (const scale of [1, 2, 4]) {
    const r = resultsLoad[`${scale}x`];
    md += `| ${scale}x | ${format(r.f1)} | ${format(r.fpr, true)} |\n`;
  }

  md += `
## Threats to Validity
1. **Synthetic Data**: The traffic is generated synthetically by the same author who wrote the detector, meaning the scenarios perfectly match the detector's assumptions.
2. **Tuned on Synthetic Data**: The parameters were optimized on this specific synthetic generator, which may not generalize to real-world noise.
3. **Known Misses**: The \`lateral-slow\` attack class (spreading traversal over 8s) is intentionally designed to bypass the 1s time window and is a known miss not reflected as a penalty if excluded from behavioral target sets (though it is included, capping maximum possible recall).
`;

  const outDir = path.resolve(process.cwd(), 'docs');
  if (!existsSync(outDir)) mkdirSync(outDir);
  writeFileSync(path.join(outDir, 'EVALUATION.md'), md);
  console.log('Wrote docs/EVALUATION.md');
}

main().catch(console.error);
