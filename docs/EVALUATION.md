# Detector Evaluation Report

Generated on: Sun, 04 Oct 2026 18:54:59 GMT
Command: `npm run evaluate`
Validation seeds: 101, 102
Test seeds: 201, 202, 203, 204, 205

## Tuning Results
Best parameters found maximizing F1 (subject to FPR <= 1%):
```json
{
  "alpha": 0.1,
  "zWarn": 2,
  "spikeHighPoints": 15,
  "zScorePoints": 10
}
```

## Variant Comparison (1x Load)
| Variant | Behavioral F1 | FPR |
|---------|---------------|-----|
| Fixed Thresholds | 0.003 ± 0.000 | 0.093 ± 0.059% |
| Baseline Default | 0.002 ± 0.000 | 0.012 ± 0.018% |
| Baseline Tuned | 0.002 ± 0.000 | 0.000 ± 0.000% |

## Ablation Study (1x Load, Tuned Params)
| Variant | Behavioral F1 | FPR |
|---------|---------------|-----|
| Baseline Tuned | 0.002 ± 0.000 | 0.000 ± 0.000% |
| Ablation: No Payload Z | 0.002 ± 0.000 | 0.000 ± 0.000% |
| Ablation: No Workflows | 0.002 ± 0.000 | 1.332 ± 0.119% |
| Ablation: Baseline -> Fixed | 0.003 ± 0.000 | 0.093 ± 0.059% |

## Load Scaling (Baseline Tuned)
| Load Scale | Behavioral F1 | FPR |
|------------|---------------|-----|
| 1x | 0.002 ± 0.000 | 0.000 ± 0.000% |
| 2x | 0.001 ± 0.000 | 0.004 ± 0.006% |
| 4x | 0.001 ± 0.000 | 0.000 ± 0.000% |

## Threats to Validity
1. **Synthetic Data**: The traffic is generated synthetically by the same author who wrote the detector, meaning the scenarios perfectly match the detector's assumptions.
2. **Tuned on Synthetic Data**: The parameters were optimized on this specific synthetic generator, which may not generalize to real-world noise.
3. **Known Misses**: The `lateral-slow` attack class (spreading traversal over 8s) is intentionally designed to bypass the 1s time window and is a known miss not reflected as a penalty if excluded from behavioral target sets (though it is included, capping maximum possible recall).
