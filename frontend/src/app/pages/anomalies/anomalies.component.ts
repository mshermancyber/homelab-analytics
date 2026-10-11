import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService, AnomalyHost, ShadowResult, ModelRun } from '../../services/api.service';

interface Suppression {
  ip: string;
  detector_name: string;
  created_at?: string;
}

type AnomalyTab = 'production' | 'shadow';

@Component({
  selector: 'app-anomalies',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="page-header">
      <h1>🔬 Anomaly Detection</h1>
      <button class="btn btn-secondary" (click)="refresh()" [disabled]="loading">
        {{ loading ? 'Loading...' : 'Refresh' }}
      </button>
    </div>

    <!-- Tab Switcher -->
    <div class="tab-bar">
      <button class="tab-btn" [class.active]="activeTab === 'production'" (click)="switchTab('production')">
        Production
      </button>
      <button class="tab-btn" [class.active]="activeTab === 'shadow'" (click)="switchTab('shadow')">
        Shadow Mode
        <span class="tab-badge" *ngIf="shadowResults.length">{{ shadowResults.length }}</span>
      </button>
    </div>

    <div class="error-msg" *ngIf="error">{{ error }}</div>

    <!-- === PRODUCTION TAB === -->
    <ng-container *ngIf="activeTab === 'production'">
      <div class="section">
        <h2 class="section-title">
          Detected Anomalies
          <span class="meta-text" *ngIf="lastRun">(last run: {{ formatTime(lastRun) }})</span>
        </h2>

        <div class="table-wrap" *ngIf="anomalies.length > 0">
          <table class="data-table">
            <thead>
              <tr>
                <th>Host IP</th>
                <th>Detector</th>
                <th>Score</th>
                <th>Details</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let a of anomalies" class="data-row">
                <td class="cell-ip">{{ a.ip }}</td>
                <td>
                  <span class="detector-tag">{{ a.detector_name || 'isolation_forest' }}</span>
                </td>
                <td>
                  <span class="score-bar">
                    <span class="score-fill"
                          [style.width.%]="scorePercent(a.anomaly_score)"></span>
                  </span>
                  <span class="score-val">{{ a.anomaly_score?.toFixed(3) || 'N/A' }}</span>
                </td>
                <td class="cell-details">
                  <span *ngIf="a.unique_destinations != null">Dests: {{ a.unique_destinations }}</span>
                  <span *ngIf="a.unique_ports != null">Ports: {{ a.unique_ports }}</span>
                  <span *ngIf="a.total_connections != null">Conns: {{ a.total_connections }}</span>
                  <span *ngIf="a.blocked_ratio != null">Blocked: {{ (a.blocked_ratio * 100).toFixed(0) }}%</span>
                </td>
                <td>
                  <button class="btn btn-suppress"
                          (click)="suppress(a.ip, a.detector_name || 'isolation_forest')"
                          [disabled]="suppressing === a.ip"
                          title="Suppress this anomaly">
                    <span class="btn-label">Suppress</span>
                    <span class="btn-icon">🚫</span>
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="empty-state" *ngIf="anomalies.length === 0 && !loading">
          ✅ No anomalies detected. The detector runs every 30 minutes.
        </div>
      </div>

      <!-- Suppressions Section -->
      <div class="section">
        <h2 class="section-title">
          Active Suppressions
          <span class="meta-text">({{ suppressions.length }} total)</span>
        </h2>

        <div class="table-wrap" *ngIf="suppressions.length > 0">
          <table class="data-table">
            <thead>
              <tr>
                <th>IP</th>
                <th>Detector</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let s of suppressions" class="data-row">
                <td class="cell-ip">{{ s.ip }}</td>
                <td><span class="detector-tag">{{ s.detector_name }}</span></td>
                <td>{{ formatTime(s.created_at) }}</td>
                <td>
                  <button class="btn btn-delete"
                          (click)="deleteSuppression(s.ip, s.detector_name)"
                          [disabled]="deletingSuppression === s.ip + s.detector_name"
                          title="Remove suppression">
                    <span class="btn-label">Remove</span>
                    <span class="btn-icon">🗑️</span>
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="empty-state small" *ngIf="suppressions.length === 0 && !loading">
          No active suppressions.
        </div>
      </div>

      <div class="empty-state" *ngIf="loading && anomalies.length === 0">
        <p>Loading anomaly data...</p>
      </div>
    </ng-container>

    <!-- === SHADOW MODE TAB === -->
    <ng-container *ngIf="activeTab === 'shadow'">
      <div class="section">
        <h2 class="section-title">
          Shadow Detection Results
          <span class="meta-text" *ngIf="shadowResults.length">({{ shadowResults.length }} entries)</span>
        </h2>
        <p class="section-desc">
          Experimental detector outputs running alongside production detectors. These do not generate alerts.
        </p>

        <div class="table-wrap" *ngIf="shadowResults.length > 0">
          <table class="data-table">
            <thead>
              <tr>
                <th>Detector</th>
                <th>Host IP</th>
                <th>Score</th>
                <th>Details</th>
                <th>Last Run</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let s of shadowResults" class="data-row">
                <td>
                  <span class="detector-tag shadow">{{ s.detector_name }}</span>
                </td>
                <td class="cell-ip">{{ s.ip }}</td>
                <td>
                  <span class="score-bar shadow-bar">
                    <span class="score-fill shadow-fill"
                          [style.width.%]="scorePercent(s.score)"></span>
                  </span>
                  <span class="score-val shadow-val">{{ s.score?.toFixed(3) || 'N/A' }}</span>
                </td>
                <td class="cell-details">
                  <span>{{ s.details || '-' }}</span>
                </td>
                <td>{{ formatTime(s.created_at) }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="empty-state" *ngIf="shadowResults.length === 0 && !shadowLoading">
          No shadow detection results available.
        </div>

        <div class="empty-state" *ngIf="shadowLoading && shadowResults.length === 0">
          <p>Loading shadow results...</p>
        </div>
      </div>
    </ng-container>

    <!-- Model History (always visible) -->
    <div class="section">
      <h2 class="section-title">
        Model History
        <span class="meta-text" *ngIf="modelHistory.length > 0">({{ modelHistory.length }} runs)</span>
      </h2>

      <div class="table-wrap" *ngIf="modelHistory.length > 0">
        <table class="data-table">
          <thead>
            <tr>
              <th>Detector</th>
              <th>Trained At</th>
              <th>Samples</th>
              <th>Anomalies</th>
              <th>Training Time</th>
              <th>Score Stats</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let m of modelHistory" class="data-row">
              <td>
                <span class="detector-tag">{{ m.detector_name }}</span>
              </td>
              <td>
                <span class="spark-label">{{ formatTime(m.trained_at) }}</span>
              </td>
              <td>
                <span class="spark-val">{{ m.sample_count || '-' }}</span>
              </td>
              <td>
                <span class="spark-val" [class.anomaly-high]="(m.anomaly_count || 0) > 0">
                  {{ m.anomaly_count || 0 }}
                </span>
              </td>
              <td>
                <span class="spark-val">{{ m.training_time_ms ? (m.training_time_ms / 1000).toFixed(1) + 's' : '-' }}</span>
              </td>
              <td>
                <div class="sparkline-wrap" *ngIf="parseScoreStats(m.score_stats_json) as stats">
                  <div class="sparkline">
                    <span class="spark-min" [style.left.%]="0">{{ stats.min?.toFixed(2) }}</span>
                    <span class="spark-bar"
                          [style.left.%]="statsPct(stats.min, stats)"
                          [style.width.%]="statsPct(stats.max, stats) - statsPct(stats.min, stats)"></span>
                    <span class="spark-mean-dot"
                          [style.left.%]="statsPct(stats.mean, stats)"></span>
                    <span class="spark-max" [style.left.%]="statsPct(stats.max, stats) - 1">{{ stats.max?.toFixed(2) }}</span>
                  </div>
                  <div class="spark-labels">
                    <span>μ={{ stats.mean?.toFixed(3) }}</span>
                    <span>σ={{ stats.std?.toFixed(3) }}</span>
                  </div>
                </div>
                <span *ngIf="!parseScoreStats(m.score_stats_json)">-</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="empty-state small" *ngIf="modelHistory.length === 0 && !loading">
        No model training history available.
      </div>
    </div>

    <div class="empty-state" *ngIf="loading && anomalies.length === 0">
      <p>Loading anomaly data...</p>
    </div>

    <!-- Success toast -->
    <div class="toast" *ngIf="successMsg" (click)="successMsg = ''">
      {{ successMsg }}
    </div>
  `,
  styles: [`
    .page-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }
    .page-header h1 {
      margin: 0;
      font-size: 1.4rem;
    }

    .btn {
      padding: 8px 16px;
      border: none;
      border-radius: 6px;
      cursor: pointer;
      font-size: 0.85rem;
      transition: background 0.2s;
    }
    .btn:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
    .btn-secondary {
      background: #1e2d3d;
      color: #b0bec5;
    }
    .btn-secondary:hover:not(:disabled) {
      background: #2a3f5a;
    }
    .btn-suppress {
      background: #e65100;
      color: white;
    }
    .btn-suppress:hover:not(:disabled) {
      background: #f57c00;
    }
    .btn-delete {
      background: #b71c1c;
      color: white;
    }
    .btn-delete:hover:not(:disabled) {
      background: #d32f2f;
    }

    .btn-label {
      display: inline;
    }
    .btn-icon {
      display: none;
    }
    @media (max-width: 768px) {
      .btn-label { display: none; }
      .btn-icon { display: inline; font-size: 1.1rem; }
      .btn {
        padding: 6px 10px;
      }
    }

    .section {
      margin-bottom: 28px;
    }
    .section-title {
      font-size: 1rem;
      color: #4fc3f7;
      margin: 0 0 12px;
    }
    .meta-text {
      font-size: 0.75rem;
      color: #5a6a7a;
      font-weight: 400;
    }

    .table-wrap {
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
    }
    .data-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
      min-width: 600px;
    }
    .data-table th {
      text-align: left;
      padding: 8px 12px;
      color: #5a6a7a;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.68rem;
      letter-spacing: .3px;
      border-bottom: 1px solid #1e2d3d;
      white-space: nowrap;
    }
    .data-table td {
      padding: 8px 12px;
      border-bottom: 1px solid #0d1520;
      color: #b0bec5;
      white-space: nowrap;
    }
    .data-row:hover {
      background: #0d1520;
    }
    .cell-ip {
      font-family: monospace;
      color: #e0e6ed;
    }
    .cell-details {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    .cell-details span {
      background: #111927;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.72rem;
      color: #8b9cb5;
    }

    .detector-tag {
      display: inline-block;
      background: #0d2137;
      color: #64b5f6;
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 0.72rem;
      font-family: monospace;
    }

    .score-bar {
      display: inline-block;
      width: 50px;
      height: 8px;
      background: #0d1520;
      border-radius: 3px;
      overflow: hidden;
      vertical-align: middle;
      margin-right: 6px;
    }
    .score-fill {
      display: block;
      height: 100%;
      background: #e65100;
      border-radius: 3px;
    }
    .score-val {
      font-family: monospace;
      font-size: 0.78rem;
      color: #ff9800;
    }

    /* Sparkline */
    .sparkline-wrap {
      width: 120px;
    }
    .sparkline {
      position: relative;
      height: 24px;
      background: #0d1520;
      border-radius: 3px;
      overflow: hidden;
      margin-bottom: 2px;
    }
    .spark-bar {
      position: absolute;
      top: 4px;
      bottom: 4px;
      background: linear-gradient(90deg, #1565c0, #4fc3f7);
      border-radius: 2px;
    }
    .spark-mean-dot {
      position: absolute;
      top: 6px;
      width: 6px;
      height: 12px;
      background: #ffa726;
      border-radius: 2px;
      transform: translateX(-50%);
    }
    .spark-min, .spark-max {
      position: absolute;
      font-size: 0.55rem;
      color: #5a6a7a;
      font-family: monospace;
      bottom: 2px;
    }
    .spark-labels {
      display: flex;
      gap: 8px;
      font-size: 0.6rem;
      color: #8b9cb5;
      font-family: monospace;
    }
    .spark-label { font-size: 0.78rem; color: #b0bec5; }
    .spark-val { font-family: monospace; font-size: 0.78rem; color: #b0bec5; }
    .anomaly-high { color: #ef5350; font-weight: 600; }

    .empty-state {
      text-align: center;
      padding: 30px 20px;
      color: #8b9cb5;
      font-size: 0.85rem;
    }
    .empty-state.small {
      padding: 20px;
    }
    .error-msg {
      color: #ef5350;
      margin-bottom: 16px;
    }

    /* Tab bar */
    .tab-bar {
      display: flex;
      gap: 0;
      margin-bottom: 20px;
      border-bottom: 2px solid #1e2d3d;
    }
    .tab-btn {
      padding: 10px 20px;
      background: none;
      border: none;
      border-bottom: 2px solid transparent;
      margin-bottom: -2px;
      color: #8b9cb5;
      font-size: 0.85rem;
      cursor: pointer;
      transition: color 0.2s, border-color 0.2s;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .tab-btn:hover {
      color: #b0bec5;
    }
    .tab-btn.active {
      color: #4fc3f7;
      border-bottom-color: #4fc3f7;
    }
    .tab-badge {
      background: #1565c0;
      color: #e0e6ed;
      font-size: 0.68rem;
      padding: 1px 7px;
      border-radius: 10px;
      font-weight: 600;
    }

    .section-desc {
      color: #8b9cb5;
      font-size: 0.8rem;
      margin: -8px 0 14px;
      line-height: 1.4;
    }

    .detector-tag.shadow {
      background: #1a0a2e;
      color: #b39ddb;
    }

    .score-bar.shadow-bar {
      background: #1a0a2e;
    }
    .score-fill.shadow-fill {
      background: #7c4dff;
    }
    .score-val.shadow-val {
      color: #b39ddb;
    }

    .toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #1b5e20;
      color: #a5d6a7;
      padding: 12px 24px;
      border-radius: 8px;
      font-size: 0.85rem;
      cursor: pointer;
      z-index: 1000;
      box-shadow: 0 4px 12px rgba(0,0,0,.4);
    }
  `]
})
export class AnomaliesComponent implements OnInit {
  anomalies: AnomalyHost[] = [];
  suppressions: Suppression[] = [];
  shadowResults: ShadowResult[] = [];
  modelHistory: ModelRun[] = [];
  lastRun: string | null = null;
  loading = false;
  shadowLoading = false;
  error = '';
  successMsg = '';
  suppressing: string = '';
  deletingSuppression: string = '';
  activeTab: AnomalyTab = 'production';

  constructor(private api: ApiService) {}

  ngOnInit() {
    this.refresh();
  }

  switchTab(tab: AnomalyTab) {
    this.activeTab = tab;
    if (tab === 'shadow' && this.shadowResults.length === 0) {
      this.loadShadowResults();
    }
  }

  refresh() {
    this.loading = true;
    this.error = '';

    this.api.getAnomalies().subscribe({
      next: (data) => {
        this.anomalies = (data.anomalies || []).map((a: any) => ({
          ...(a.details || {}),
          ...a,
          anomaly_score: a.anomaly_score ?? a.score ?? a.details?.anomaly_score,
        }));
        this.lastRun = data.last_run;
        this.loading = false;
      },
      error: (err) => {
        this.error = err.error?.detail || 'Failed to load anomalies';
        this.loading = false;
        this.anomalies = [];
      }
    });

    this.api.getSuppressions().subscribe({
      next: (data) => {
        this.suppressions = data || [];
      },
      error: () => {
        this.suppressions = [];
      }
    });

    if (this.activeTab === 'shadow') {
      this.loadShadowResults();
    }

    this.api.getModelHistory().subscribe({
      next: (data) => {
        this.modelHistory = data || [];
      },
      error: () => {
        this.modelHistory = [];
      }
    });
  }

  loadShadowResults() {
    this.shadowLoading = true;
    this.api.getShadowResults().subscribe({
      next: (data) => {
        this.shadowResults = data || [];
        this.shadowLoading = false;
      },
      error: () => {
        this.shadowResults = [];
        this.shadowLoading = false;
      }
    });
  }

  suppress(ip: string, detectorName: string) {
    this.suppressing = ip;
    this.api.suppressAnomaly(ip, detectorName).subscribe({
      next: () => {
        this.suppressing = '';
        this.successMsg = `Suppressed ${ip} / ${detectorName}`;
        setTimeout(() => { this.successMsg = ''; }, 3000);
        this.refresh();
      },
      error: (err) => {
        this.suppressing = '';
        this.error = err.error?.detail || 'Failed to suppress anomaly';
      }
    });
  }

  deleteSuppression(ip: string, detectorName: string) {
    this.deletingSuppression = ip + detectorName;
    this.api.deleteSuppression(ip, detectorName).subscribe({
      next: () => {
        this.deletingSuppression = '';
        this.successMsg = `Removed suppression for ${ip} / ${detectorName}`;
        setTimeout(() => { this.successMsg = ''; }, 3000);
        this.refresh();
      },
      error: (err) => {
        this.deletingSuppression = '';
        this.error = err.error?.detail || 'Failed to remove suppression';
      }
    });
  }

  scorePercent(score: number): number {
    if (score == null || isNaN(score)) return 0;
    return Math.min(score / 0.5 * 100, 100);
  }

  formatTime(ts: string | null | undefined): string {
    if (!ts) return '-';
    try {
      // Tolerate malformed stamps like "+00:00Z" (offset plus Z suffix)
      const clean = /[+-]\d{2}:\d{2}Z$/.test(ts) ? ts.slice(0, -1) : ts;
      const d = new Date(clean);
      return isNaN(d.getTime()) ? ts : d.toLocaleString();
    } catch {
      return ts;
    }
  }

  parseScoreStats(json: string | undefined): { min: number; max: number; mean: number; std: number } | null {
    if (!json) return null;
    try {
      return JSON.parse(json);
    } catch {
      return null;
    }
  }

  statsPct(value: number, stats: { min: number; max: number }): number {
    if (stats.max === stats.min) return 50;
    return ((value - stats.min) / (stats.max - stats.min)) * 100;
  }
}
