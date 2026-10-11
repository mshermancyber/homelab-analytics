import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService, CoverageTechnique } from '../../services/api.service';

interface MatrixCell {
  technique_id: string;
  tactic: string;
  count: number;
  covered_by_detectors: string[];
  intensity: number; // 0-1 based on count
}

interface TacticColumn {
  tactic: string;
  techniques: MatrixCell[];
}

const MITRE_TACTICS = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

@Component({
  selector: 'app-coverage',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="page-header">
      <h1>🎯 MITRE ATT&CK Coverage</h1>
      <span class="period-badge" *ngIf="periodDays">Last {{ periodDays }} days</span>
    </div>

    <div class="error-msg" *ngIf="error">{{ error }}</div>

    <div class="summary-row-stats" *ngIf="techniques.length > 0">
      <div class="stat-card">
        <div class="stat-value">{{ techniques.length }}</div>
        <div class="stat-label">Techniques Covered</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{{ totalAlerts }}</div>
        <div class="stat-label">Total Alerts</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{{ tacticsWithCoverage }}</div>
        <div class="stat-label">Tactics Active</div>
      </div>
    </div>

    <!-- Matrix Grid -->
    <div class="matrix-wrap" *ngIf="tacticColumns.length > 0">
      <div class="matrix-scroll">
        <div class="matrix-grid" [style.grid-template-columns]="'repeat(' + tacticColumns.length + ', 1fr)'">
          <!-- Headers -->
          <div *ngFor="let col of tacticColumns" class="tactic-header">
            <div class="tactic-title">{{ col.tactic }}</div>
            <div class="tactic-count">{{ col.techniques.length }} techniques</div>
          </div>
          <!-- Cells - each row has one cell per tactic -->
          <ng-container *ngFor="let rowIdx of maxRowsArray">
            <ng-container *ngFor="let col of tacticColumns">
              <div
                *ngIf="col.techniques[rowIdx] as cell; else emptyCell"
                class="matrix-cell"
                [style.background]="cellBg(cell.intensity)"
                [style.color]="cell.count > 0 ? '#fff' : '#8b9cb5'"
                [title]="tooltip(cell)"
              >
                <div class="cell-tech">{{ cell.technique_id }}</div>
                <div class="cell-count" *ngIf="cell.count > 0">{{ cell.count }}</div>
                <div class="cell-detectors" *ngIf="cell.covered_by_detectors.length > 0">
                  <span class="detector-chip" *ngFor="let d of cell.covered_by_detectors.slice(0, 2)">{{ d }}</span>
                  <span class="detector-more" *ngIf="cell.covered_by_detectors.length > 2">+{{ cell.covered_by_detectors.length - 2 }}</span>
                </div>
              </div>
              <ng-template #emptyCell>
                <div class="matrix-cell empty"></div>
              </ng-template>
            </ng-container>
          </ng-container>
        </div>
      </div>
    </div>

    <div class="empty-state" *ngIf="techniques.length === 0 && !loading && !error">
      <p>No MITRE ATT&CK coverage data available.</p>
      <p class="hint">Coverage is calculated from alert attack_technique fields.</p>
    </div>

    <div class="empty-state" *ngIf="loading">
      <p>Loading coverage data...</p>
    </div>

    <!-- Legend -->
    <div class="legend" *ngIf="techniques.length > 0">
      <span class="legend-label">Alert Intensity:</span>
      <span class="legend-step" *ngFor="let s of legendSteps" [style.background]="s.color">{{ s.label }}</span>
    </div>
  `,
  styles: [`
    .page-header {
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }
    .page-header h1 { margin: 0; font-size: 1.4rem; }
    .period-badge {
      background: #1a3a5a;
      color: #4fc3f7;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 0.75rem;
    }

    .error-msg { color: #ef5350; margin-bottom: 16px; }

    /* Summary */
    .summary-row-stats {
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }
    .stat-card {
      background: #1a1a2e;
      border: 1px solid #2a2a4e;
      border-radius: 8px;
      padding: 14px 20px;
      min-width: 140px;
      text-align: center;
    }
    .stat-value {
      font-size: 1.5rem;
      font-weight: 700;
      color: #4fc3f7;
    }
    .stat-label {
      font-size: 0.7rem;
      color: #8b9cb5;
      text-transform: uppercase;
      margin-top: 4px;
    }

    /* Matrix */
    .matrix-wrap {
      background: #1a1a2e;
      border: 1px solid #2a2a4e;
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 16px;
    }
    .matrix-scroll {
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
    }
    .matrix-grid {
      display: grid;
      min-width: 900px;
      gap: 1px;
      background: #0a0e17;
    }
    .tactic-header {
      background: #111927;
      padding: 10px 6px;
      text-align: center;
      border-bottom: 2px solid #2a2a4e;
      position: sticky;
      top: 0;
      z-index: 2;
    }
    .tactic-title {
      font-size: 0.68rem;
      font-weight: 700;
      color: #4fc3f7;
      text-transform: uppercase;
      letter-spacing: 0.3px;
      line-height: 1.2;
      word-break: break-word;
    }
    .tactic-count {
      font-size: 0.6rem;
      color: #5a6a7a;
      margin-top: 2px;
    }

    .matrix-cell {
      padding: 6px 4px;
      min-height: 64px;
      text-align: center;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 2px;
      border: 1px solid #0a0e17;
      transition: transform 0.15s, box-shadow 0.15s;
      cursor: default;
    }
    .matrix-cell:hover {
      transform: scale(1.05);
      box-shadow: 0 0 12px rgba(79,195,247,0.3);
      z-index: 1;
      position: relative;
    }
    .matrix-cell.empty {
      background: #0d1520 !important;
      min-height: 64px;
    }
    .cell-tech {
      font-size: 0.55rem;
      font-family: monospace;
      font-weight: 600;
      line-height: 1.1;
      word-break: break-all;
    }
    .cell-count {
      font-size: 0.7rem;
      font-weight: 700;
      font-family: monospace;
    }
    .cell-detectors {
      display: flex;
      flex-wrap: wrap;
      gap: 2px;
      justify-content: center;
    }
    .detector-chip {
      font-size: 0.5rem;
      background: rgba(255,255,255,0.15);
      padding: 1px 4px;
      border-radius: 3px;
      white-space: nowrap;
    }
    .detector-more {
      font-size: 0.5rem;
      color: rgba(255,255,255,0.5);
    }

    .empty-state {
      text-align: center;
      padding: 60px 20px;
      color: #8b9cb5;
      font-size: 0.85rem;
    }
    .hint { font-size: 0.78rem; margin-top: 8px; color: #5a6a7a; }

    /* Legend */
    .legend {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      padding: 10px 0;
    }
    .legend-label {
      font-size: 0.7rem;
      color: #8b9cb5;
      text-transform: uppercase;
      margin-right: 4px;
    }
    .legend-step {
      padding: 3px 10px;
      border-radius: 10px;
      font-size: 0.65rem;
      color: #fff;
    }
  `]
})
export class CoverageComponent implements OnInit {
  techniques: CoverageTechnique[] = [];
  tacticColumns: TacticColumn[] = [];
  periodDays = 0;
  loading = false;
  error = '';
  totalAlerts = 0;
  tacticsWithCoverage = 0;
  maxRows = 0;
  maxRowsArray: number[] = [];

  legendSteps = [
    { label: '0', color: '#0d2137' },
    { label: '1-2', color: '#1a3a5a' },
    { label: '3-5', color: '#1565c0' },
    { label: '6-10', color: '#e65100' },
    { label: '10+', color: '#b71c1c' },
  ];

  constructor(private api: ApiService) {}

  ngOnInit() {
    this.load();
  }

  load() {
    this.loading = true;
    this.error = '';
    this.api.getCoverage().subscribe({
      next: (data) => {
        this.techniques = data.techniques || [];
        this.periodDays = data.period_days;
        this.loading = false;
        this.buildMatrix();
      },
      error: (err) => {
        this.error = err.error?.detail || 'Failed to load coverage data';
        this.loading = false;
      }
    });
  }

  buildMatrix() {
    // Determine max count for intensity calculation
    const maxCount = this.techniques.reduce((max, t) => Math.max(max, t.count), 0);

    // Group techniques by tactic
    const tacticMap = new Map<string, CoverageTechnique[]>();
    for (const tech of this.techniques) {
      const tactic = tech.tactic || 'Unknown';
      if (!tacticMap.has(tactic)) tacticMap.set(tactic, []);
      tacticMap.get(tactic)!.push(tech);
    }

    // Build columns in MITRE order
    this.tacticColumns = MITRE_TACTICS
      .filter(t => tacticMap.has(t))
      .map(tactic => {
        const techs = tacticMap.get(tactic)!;
        // Sort by technique_id
        techs.sort((a, b) => a.technique_id.localeCompare(b.technique_id));
        const cells: MatrixCell[] = techs.map(t => ({
          technique_id: t.technique_id,
          tactic: t.tactic,
          count: t.count,
          covered_by_detectors: t.covered_by_detectors || [],
          intensity: maxCount > 0 ? t.count / maxCount : 0,
        }));
        return { tactic, techniques: cells };
      });

    // Add any tactics not in MITRE_ORDER
    for (const [tactic, techs] of tacticMap) {
      if (!MITRE_TACTICS.includes(tactic)) {
        techs.sort((a, b) => a.technique_id.localeCompare(b.technique_id));
        this.tacticColumns.push({
          tactic,
          techniques: techs.map(t => ({
            technique_id: t.technique_id,
            tactic: t.tactic,
            count: t.count,
            covered_by_detectors: t.covered_by_detectors || [],
            intensity: maxCount > 0 ? t.count / maxCount : 0,
          })),
        });
      }
    }

    this.maxRows = Math.max(...this.tacticColumns.map(c => c.techniques.length), 0);
    this.maxRowsArray = Array.from({ length: this.maxRows }, (_, i) => i);
    this.totalAlerts = this.techniques.reduce((sum, t) => sum + t.count, 0);
    this.tacticsWithCoverage = this.tacticColumns.length;
  }

  cellBg(intensity: number): string {
    if (intensity <= 0) return '#0d1520';
    if (intensity < 0.15) return '#0d2137';
    if (intensity < 0.3) return '#1a3a5a';
    if (intensity < 0.5) return '#1565c0';
    if (intensity < 0.7) return '#e65100';
    return '#b71c1c';
  }

  tooltip(cell: MatrixCell): string {
    const parts = [
      `${cell.technique_id} (${cell.tactic})`,
      `Alerts: ${cell.count}`,
      cell.covered_by_detectors.length > 0
        ? `Detectors: ${cell.covered_by_detectors.join(', ')}`
        : '',
    ];
    return parts.filter(Boolean).join('\n');
  }
}
