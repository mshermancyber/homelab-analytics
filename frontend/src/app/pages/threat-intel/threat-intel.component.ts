import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService, ThreatIntelStatus } from '../../services/api.service';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-threat-intel',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="page-header">
      <h1>🔍 Threat Intelligence</h1>
      <button *ngIf="isAdmin" class="btn btn-primary" (click)="refresh()" [disabled]="loading">
        {{ loading ? 'Refreshing...' : 'Refresh Feeds' }}
      </button>
    </div>

    <div class="summary-bar" *ngIf="status">
      <div class="summary-card">
        <div class="summary-value">{{ status.total_iocs | number }}</div>
        <div class="summary-label">Total IOCs</div>
      </div>
      <div class="summary-card loaded">
        <div class="summary-value">{{ status.feeds_loaded }}</div>
        <div class="summary-label">Feeds Loaded</div>
      </div>
      <div class="summary-card failed" *ngIf="status.feeds_failed > 0">
        <div class="summary-value">{{ status.feeds_failed }}</div>
        <div class="summary-label">Feeds Failed</div>
      </div>
      <div class="summary-card">
        <div class="summary-value">{{ status.feeds_total }}</div>
        <div class="summary-label">Total Feeds</div>
      </div>
    </div>

    <div class="error-msg" *ngIf="error">{{ error }}</div>

    <div class="feed-grid" *ngIf="status">
      <div *ngFor="let feed of status.feeds" class="feed-card" [class.failed]="feed.status === 'failed'" [class.stale]="feed.status === 'stale'">
        <div class="feed-header">
          <span class="feed-name">{{ feed.name }}</span>
          <span class="feed-status" [class.active]="feed.status === 'active'" [class.bad]="feed.status === 'failed' || feed.status === 'stale'">
            {{ feed.status }}
          </span>
        </div>
        <div class="feed-body">
          <div class="feed-info">
            <span class="feed-category">{{ feed.category }}</span>
            <span class="feed-count">{{ feed.ioc_count || 0 }} IOCs</span>
          </div>
          <div class="feed-refresh">
            Last refresh: {{ formatDate(feed.last_refresh) }}
          </div>
          <div class="feed-error" *ngIf="feed.error">
            ⚠️ {{ feed.error }}
          </div>
        </div>
      </div>
    </div>

    <div class="empty-state" *ngIf="!status && !error">
      <p>Loading threat intelligence status...</p>
    </div>
  `,
  styles: [`
    .page-header { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }
    .page-header h1 { margin: 0; font-size: 1.4rem; }
    .btn { padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.85rem; }
    .btn-primary { background: #1565c0; color: white; }
    .btn-primary:disabled { background: #0d3b6e; cursor: not-allowed; }
    .btn-primary:hover:not(:disabled) { background: #1976d2; }

    .summary-bar { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 20px; }
    .summary-card { background: #111927; border: 1px solid #1e2d3d; border-radius: 8px; padding: 16px; text-align: center; }
    .summary-card.loaded { border-left: 3px solid #4caf50; }
    .summary-card.failed { border-left: 3px solid #ef5350; }
    .summary-value { font-size: 1.6rem; font-weight: 700; color: #4fc3f7; }
    .summary-label { font-size: 0.75rem; color: #8b9cb5; margin-top: 4px; text-transform: uppercase; }

    .feed-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }
    @media (max-width: 600px) { .feed-grid { grid-template-columns: 1fr; } .summary-bar { grid-template-columns: repeat(2, 1fr); } }

    .feed-card { background: #111927; border: 1px solid #1e2d3d; border-radius: 8px; overflow: hidden; transition: border-color 0.2s; }
    .feed-card.failed { border-left: 3px solid #ef5350; }
    .feed-card.stale { border-left: 3px solid #ffa726; }
    .feed-card:hover { border-color: #2a3f5a; }
    .feed-header { display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; background: #0d1520; border-bottom: 1px solid #1e2d3d; }
    .feed-name { font-size: 0.9rem; font-weight: 600; font-family: monospace; }
    .feed-status { padding: 2px 8px; border-radius: 10px; font-size: 0.65rem; text-transform: uppercase; font-weight: 600; }
    .feed-status.active { background: #1b5e20; color: #a5d6a7; }
    .feed-status.bad { background: #b71c1c; color: #ef9a9a; }
    .feed-body { padding: 10px 14px; }
    .feed-info { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
    .feed-category { font-size: 0.75rem; color: #64b5f6; background: #0d2137; padding: 2px 8px; border-radius: 4px; }
    .feed-count { font-size: 0.85rem; color: #b0bec5; font-family: monospace; }
    .feed-refresh { font-size: 0.7rem; color: #8b9cb5; }
    .feed-error { font-size: 0.75rem; color: #ef5350; margin-top: 6px; word-break: break-all; }

    .empty-state { text-align: center; padding: 60px 20px; color: #8b9cb5; }
    .error-msg { color: #ef5350; margin-bottom: 16px; }
  `]
})
export class ThreatIntelComponent implements OnInit {
  status: ThreatIntelStatus | null = null;
  loading = false;
  error = '';

  constructor(private api: ApiService, public auth: AuthService) {}

  get isAdmin(): boolean {
    return this.auth.hasRole('admin');
  }

  ngOnInit() {
    this.load();
  }

  load() {
    this.api.getThreatIntelStatus().subscribe({
      next: (data) => { this.status = data; this.error = ''; },
      error: (err) => { this.error = err.error?.detail || 'Failed to load threat intel status'; }
    });
  }

  refresh() {
    this.loading = true;
    this.api.refreshThreatIntel().subscribe({
      next: () => {
        this.loading = false;
        setTimeout(() => this.load(), 500);
      },
      error: (err) => {
        this.loading = false;
        this.error = err.error?.detail || 'Failed to refresh feeds';
      }
    });
  }

  formatDate(ts: string | undefined): string {
    if (!ts) return 'never';
    try { return new Date(ts).toLocaleString(); } catch { return ts; }
  }
}
