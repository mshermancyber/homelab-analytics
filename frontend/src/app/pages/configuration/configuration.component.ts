import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../services/api.service';

@Component({
  selector: 'app-configuration',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="page-header">
      <h1>⚙️ Configuration</h1>
    </div>

    <div class="error-msg" *ngIf="error">{{ error }}</div>
    <div class="success-msg" *ngIf="success">{{ success }}</div>

    <div class="config-container" *ngIf="config">
      <section class="config-section">
        <h2>🔍 Threat Intelligence Feeds</h2>
        <div class="form-group">
          <label>Refresh Interval (seconds)</label>
          <input type="number" [(ngModel)]="config.feeds.refresh_interval_seconds" class="form-input" />
        </div>
        <div class="form-group">
          <label>Feed URLs</label>
          <div class="feed-url-list">
            <div *ngFor="let key of feedKeys" class="feed-url-row">
              <span class="feed-key">{{ key }}</span>
              <input [(ngModel)]="config.feeds.urls[key]" class="form-input" />
            </div>
          </div>
        </div>
      </section>

      <section class="config-section">
        <h2>📊 Analytics Thresholds</h2>
        <div class="form-grid">
          <div class="form-group">
            <label>Outbound Volume (bytes/min)</label>
            <input type="number" [(ngModel)]="config.analytics.thresholds.outbound_volume_bytes_per_minute" class="form-input" />
          </div>
          <div class="form-group">
            <label>Entropy Shannon Threshold</label>
            <input type="number" step="0.1" [(ngModel)]="config.analytics.thresholds.high_entropy_shannon_threshold" class="form-input" />
          </div>
          <div class="form-group">
            <label>Blocked Query Repeat Threshold</label>
            <input type="number" [(ngModel)]="config.analytics.thresholds.blocked_query_repeat_threshold" class="form-input" />
          </div>
          <div class="form-group">
            <label>Port Scan Distinct Ports</label>
            <input type="number" [(ngModel)]="config.analytics.thresholds.port_scan_distinct_ports" class="form-input" />
          </div>
          <div class="form-group">
            <label>Beaconing Interval Tolerance (sec)</label>
            <input type="number" [(ngModel)]="config.analytics.thresholds.beaconing_interval_tolerance_seconds" class="form-input" />
          </div>
          <div class="form-group">
            <label>Beaconing Min Repetitions</label>
            <input type="number" [(ngModel)]="config.analytics.thresholds.beaconing_min_repetitions" class="form-input" />
          </div>
        </div>
      </section>

      <section class="config-section">
        <h2>🤖 LLM Triage</h2>
        <div class="form-grid">
          <div class="form-group">
            <label>Model</label>
            <input [(ngModel)]="config.llm.model" class="form-input" />
          </div>
          <div class="form-group">
            <label>Temperature</label>
            <input type="number" step="0.1" [(ngModel)]="config.llm.temperature" class="form-input" />
          </div>
          <div class="form-group">
            <label>Max Tokens</label>
            <input type="number" [(ngModel)]="config.llm.max_tokens" class="form-input" />
          </div>
        </div>
      </section>

      <section class="config-section">
        <h2>📡 Listeners</h2>
        <div class="form-grid">
          <div class="form-group">
            <label>Syslog Port</label>
            <input type="number" [(ngModel)]="config.listeners.syslog_port" class="form-input" />
          </div>
          <div class="form-group">
            <label>API Port</label>
            <input type="number" [(ngModel)]="config.listeners.api_port" class="form-input" />
          </div>
        </div>
      </section>

      <button class="btn btn-primary save-btn" (click)="save()" [disabled]="saving">
        {{ saving ? 'Saving...' : 'Save Configuration' }}
      </button>
      <p class="note">Note: Some changes may require a restart to take effect.</p>
    </div>

    <div class="empty-state" *ngIf="!config && !error">
      <p>Loading configuration...</p>
    </div>
  `,
  styles: [`
    .page-header { display: flex; align-items: center; gap: 16px; margin-bottom: 20px; }
    .page-header h1 { margin: 0; font-size: 1.4rem; }

    .config-container { display: flex; flex-direction: column; gap: 20px; }

    .config-section {
      background: #111927;
      border: 1px solid #1e2d3d;
      border-radius: 8px;
      padding: 20px;
    }
    .config-section h2 { margin: 0 0 16px; font-size: 1rem; color: #4fc3f7; }

    .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
    @media (max-width: 600px) { .form-grid { grid-template-columns: 1fr; } }

    .form-group { display: flex; flex-direction: column; gap: 4px; margin-bottom: 12px; }
    .form-group label { font-size: 0.75rem; color: #8b9cb5; text-transform: uppercase; }
    .form-input {
      padding: 8px 12px;
      background: #0d1520;
      border: 1px solid #1e2d3d;
      border-radius: 6px;
      color: #e0e6ed;
      font-size: 0.85rem;
    }
    .form-input:focus { outline: none; border-color: #4fc3f7; }

    .feed-url-list { display: flex; flex-direction: column; gap: 8px; }
    .feed-url-row { display: flex; align-items: center; gap: 8px; }
    .feed-key {
      font-family: monospace;
      font-size: 0.75rem;
      color: #64b5f6;
      min-width: 90px;
    }
    .feed-url-row .form-input { flex: 1; }

    .btn { padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.9rem; }
    .btn-primary { background: #1565c0; color: white; }
    .btn-primary:disabled { background: #0d3b6e; cursor: not-allowed; }
    .btn-primary:hover:not(:disabled) { background: #1976d2; }
    .save-btn { align-self: flex-start; }
    .note { font-size: 0.75rem; color: #8b9cb5; margin: 0; }

    .error-msg { color: #ef5350; margin-bottom: 16px; }
    .success-msg { color: #4caf50; margin-bottom: 16px; }
    .empty-state { text-align: center; padding: 60px 20px; color: #8b9cb5; }
  `]
})
export class ConfigurationComponent implements OnInit {
  config: any = null;
  error = '';
  success = '';
  saving = false;

  constructor(private api: ApiService) {}

  get feedKeys(): string[] {
    return this.config?.feeds?.urls ? Object.keys(this.config.feeds.urls) : [];
  }

  ngOnInit() {
    this.load();
  }

  load() {
    this.api.getConfig().subscribe({
      next: (data) => { this.config = data; this.error = ''; },
      error: (err) => { this.error = err.error?.detail || 'Failed to load configuration'; }
    });
  }

  save() {
    this.saving = true;
    this.error = '';
    this.success = '';

    // Ensure numeric types
    const body: any = {
      feeds: {
        refresh_interval_seconds: Number(this.config.feeds.refresh_interval_seconds),
      },
      analytics: {
        thresholds: {
          outbound_volume_bytes_per_minute: Number(this.config.analytics.thresholds.outbound_volume_bytes_per_minute),
          high_entropy_shannon_threshold: Number(this.config.analytics.thresholds.high_entropy_shannon_threshold),
          blocked_query_repeat_threshold: Number(this.config.analytics.thresholds.blocked_query_repeat_threshold),
          port_scan_distinct_ports: Number(this.config.analytics.thresholds.port_scan_distinct_ports),
          beaconing_interval_tolerance_seconds: Number(this.config.analytics.thresholds.beaconing_interval_tolerance_seconds),
          beaconing_min_repetitions: Number(this.config.analytics.thresholds.beaconing_min_repetitions),
        },
      },
    };

    this.api.updateConfig(body).subscribe({
      next: () => {
        this.saving = false;
        this.success = 'Configuration saved successfully. Some changes may require a restart.';
      },
      error: (err) => {
        this.saving = false;
        this.error = err.error?.detail || 'Failed to save configuration';
      }
    });
  }
}
