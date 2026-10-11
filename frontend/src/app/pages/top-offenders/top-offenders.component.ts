import { Component, OnInit, OnDestroy, AfterViewInit, ViewChild, ElementRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService, TopOffenders } from '../../services/api.service';
import { Chart, registerables } from 'chart.js';
import { formatIpShort } from '../../config/network.config';

Chart.register(...registerables);

@Component({
  selector: 'app-top-offenders',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="page-header">
      <h1>Top Offenders</h1>
      <div class="period-select">
        <label>Period:</label>
        <select [(ngModel)]="days" (change)="load()" class="filter-input">
          <option [value]="7">Last 7 days</option>
          <option [value]="14">Last 14 days</option>
          <option [value]="30">Last 30 days</option>
          <option [value]="90">Last 90 days</option>
        </select>
      </div>
    </div>

    <div class="error-msg" *ngIf="error">{{ error }}</div>

    <div *ngIf="data">
      <!-- Summary stats -->
      <div class="summary-bar">
        <div class="stat">
          <span class="stat-value">{{ data.period_days }}</span>
          <span class="stat-label">Day Period</span>
        </div>
        <div class="stat">
          <span class="stat-value">{{ data.top_sources?.length || 0 }}</span>
          <span class="stat-label">Unique Sources</span>
        </div>
        <div class="stat">
          <span class="stat-value">{{ data.top_destinations?.length || 0 }}</span>
          <span class="stat-label">Unique Destinations</span>
        </div>
        <div class="stat">
          <span class="stat-value">{{ totalAlerts }}</span>
          <span class="stat-label">Total Alerts</span>
        </div>
      </div>

      <div class="charts-grid">
        <!-- Top Sources chart -->
        <div class="chart-card">
          <h2>Top Source IPs</h2>
          <div class="chart-container">
            <canvas #topSourcesChart></canvas>
          </div>
          <div class="chart-empty" *ngIf="!data.top_sources?.length">
            No data available for this period.
          </div>
        </div>

        <!-- Severity + Classification charts -->
        <div class="chart-card">
          <div class="dual-chart">
            <div class="dual-left">
              <h2>Severity</h2>
              <div class="chart-container chart-pie">
                <canvas #severityChart></canvas>
              </div>
              <div class="chart-empty" *ngIf="!hasSeverityData()">No severity data.</div>
            </div>
            <div class="dual-right" *ngIf="data.top_classifications?.length">
              <h2>Top Classifications</h2>
              <div class="class-list">
                <div class="class-row" *ngFor="let c of data.top_classifications; let i = index">
                  <span class="class-label">{{ c.classification }}</span>
                  <span class="class-bar-track">
                    <span class="class-bar-fill"
                          [style.width.%]="classPercent(c.count)"
                          [style.background]="classColor(i)"></span>
                  </span>
                  <span class="class-count">{{ c.count }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Top Destinations with enrichment -->
      <div class="chart-card dest-card">
        <h2>Top Destination IPs</h2>
        <div class="chart-container">
          <canvas #topDestChart></canvas>
        </div>
        <div class="chart-empty" *ngIf="!data.top_destinations?.length">
          No data available for this period.
        </div>
        <div class="dest-table-wrap" *ngIf="data.top_destinations?.length">
          <table class="dest-table">
            <thead>
              <tr>
                <th>IP</th>
                <th>Alerts</th>
                <th>Country</th>
                <th>Org / ISP</th>
                <th>ASN</th>
                <th>rDNS</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let d of data.top_destinations">
                <td class="mono">{{ d.dst_ip }}</td>
                <td class="alert-num">{{ d.alert_count }}</td>
                <td>
                  <span class="cflag" *ngIf="d.country_code">{{ countryFlag(d.country_code) }}</span>
                  {{ d.country || '-' }}
                </td>
                <td class="org-cell">{{ d.org || '-' }}</td>
                <td class="mono asn-cell">{{ d.asn || '-' }}</td>
                <td class="rdns-cell mono">{{ d.reverse_dns || '-' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="empty-state" *ngIf="!data && !error">
      <p>Loading top offenders data...</p>
    </div>
  `,
  styles: [`
    .page-header { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }
    .page-header h1 { margin: 0; font-size: 1.4rem; }
    .period-select { display: flex; align-items: center; gap: 8px; }
    .period-select label { font-size: 0.8rem; color: #8b9cb5; }
    .filter-input { padding: 6px 10px; background: #0d1520; border: 1px solid #1e2d3d; border-radius: 4px; color: #e0e6ed; font-size: 0.85rem; }
    .filter-input:focus { outline: none; border-color: #4fc3f7; }

    .summary-bar { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px; }
    .stat { text-align: center; padding: 14px; background: #111927; border: 1px solid #1e2d3d; border-radius: 8px; }
    .stat-value { display: block; font-size: 1.6rem; font-weight: 700; color: #4fc3f7; }
    .stat-label { display: block; font-size: 0.7rem; color: #8b9cb5; margin-top: 4px; text-transform: uppercase; }

    .charts-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
    .chart-card { background: #111927; border: 1px solid #1e2d3d; border-radius: 8px; padding: 20px; }
    .chart-card h2 { margin: 0 0 14px; font-size: 0.95rem; color: #4fc3f7; }
    .chart-container { position: relative; width: 100%; height: 280px; }
    .chart-container.chart-pie { max-width: 200px; height: 200px; margin: 0 auto; }
    .chart-empty { text-align: center; padding: 40px; color: #8b9cb5; font-size: 0.85rem; }

    .dual-chart { display: flex; gap: 16px; }
    .dual-left { flex: 0 0 220px; }
    .dual-right { flex: 1; min-width: 0; }
    .dual-right h2 { margin: 0 0 10px; font-size: 0.85rem; color: #4fc3f7; }

    .class-list { display: flex; flex-direction: column; gap: 5px; }
    .class-row { display: flex; align-items: center; gap: 6px; font-size: 0.78rem; }
    .class-label { width: 100px; text-align: right; color: #b0bec5; text-transform: capitalize; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .class-bar-track { flex: 1; height: 14px; background: #0d1520; border-radius: 3px; overflow: hidden; }
    .class-bar-fill { display: block; height: 100%; border-radius: 3px; min-width: 2px; }
    .class-count { width: 30px; text-align: right; color: #8b9cb5; font-family: monospace; font-size: 0.75rem; }

    .dest-card { margin-top: 0; }
    .dest-table-wrap { overflow-x: auto; margin-top: 16px; border-top: 1px solid #1e2d3d; padding-top: 12px; }
    .dest-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
    .dest-table th { text-align: left; padding: 6px 8px; color: #5a6a7a; font-weight: 600; text-transform: uppercase; font-size: 0.65rem; letter-spacing: .3px; border-bottom: 1px solid #1e2d3d; }
    .dest-table td { padding: 6px 8px; border-bottom: 1px solid #0d1520; color: #b0bec5; white-space: nowrap; }
    .dest-table tbody tr:hover { background: #0d1520; }
    .mono { font-family: monospace; color: #e0e6ed; }
    .alert-num { color: #ef5350; font-weight: 600; }
    .org-cell { max-width: 180px; overflow: hidden; text-overflow: ellipsis; color: #8b9cb5; }
    .asn-cell { font-size: 0.72rem; color: #8b9cb5; }
    .rdns-cell { font-size: 0.72rem; max-width: 200px; overflow: hidden; text-overflow: ellipsis; color: #8b9cb5; }
    .cflag { font-size: 0.9rem; margin-right: 4px; }

    .empty-state { text-align: center; padding: 60px 20px; color: #8b9cb5; }
    .error-msg { color: #ef5350; margin-bottom: 16px; }

    @media (max-width: 900px) {
      .charts-grid { grid-template-columns: 1fr; }
      .summary-bar { grid-template-columns: repeat(2, 1fr); }
      .dual-chart { flex-direction: column; }
      .dual-left { flex: none; }
    }
    @media (max-width: 500px) {
      .summary-bar { grid-template-columns: 1fr 1fr; }
      .class-label { width: 70px; }
    }
  `]
})
export class TopOffendersComponent implements OnInit, OnDestroy, AfterViewInit {
  @ViewChild('topSourcesChart') topSourcesCanvas!: ElementRef<HTMLCanvasElement>;
  @ViewChild('topDestChart') topDestCanvas!: ElementRef<HTMLCanvasElement>;
  @ViewChild('severityChart') severityCanvas!: ElementRef<HTMLCanvasElement>;

  data: TopOffenders | null = null;
  days = 7;
  error = '';

  private sourcesChart: Chart | null = null;
  private destChart: Chart | null = null;
  private sevChart: Chart | null = null;

  constructor(private api: ApiService) {}

  ngOnInit() { this.load(); }
  ngAfterViewInit() { if (this.data) this.renderCharts(); }

  ngOnDestroy() {
    this.sourcesChart?.destroy();
    this.destChart?.destroy();
    this.sevChart?.destroy();
  }

  load() {
    this.error = '';
    this.api.getTopOffenders(this.days).subscribe({
      next: (data) => {
        this.data = data;
        setTimeout(() => this.renderCharts(), 100);
      },
      error: (err) => {
        this.error = err.error?.detail || 'Failed to load top offenders';
      }
    });
  }

  get totalAlerts(): number {
    if (!this.data?.severity_breakdown) return 0;
    return Object.values(this.data.severity_breakdown).reduce((a, b) => a + b, 0);
  }

  get maxClassCount(): number {
    if (!this.data?.top_classifications?.length) return 1;
    return Math.max(...this.data.top_classifications.map(c => c.count));
  }

  classPercent(count: number): number {
    return this.maxClassCount > 0 ? (count / this.maxClassCount) * 100 : 0;
  }

  classColor(index: number): string {
    const colors = ['#d32f2f', '#e65100', '#f9a825', '#1565c0', '#2e7d32', '#6a1b9a', '#00695c', '#4e342e', '#1565c0', '#c62828'];
    return colors[index % colors.length];
  }

  hasSeverityData(): boolean {
    if (!this.data?.severity_breakdown) return false;
    return Object.keys(this.data.severity_breakdown).length > 0;
  }

  countryFlag(code: string): string {
    if (!code || code.length !== 2) return '';
    const upper = code.toUpperCase();
    const offset = 0x1F1E6;
    const a = upper.charCodeAt(0) - 65 + offset;
    const b = upper.charCodeAt(1) - 65 + offset;
    if (a < offset || b < offset) return '';
    return String.fromCodePoint(a, b);
  }

  renderCharts() {
    if (!this.data) return;

    this.sourcesChart?.destroy();
    this.destChart?.destroy();
    this.sevChart?.destroy();

    if (this.topSourcesCanvas && this.data.top_sources?.length > 0) {
      const labels = this.data.top_sources.map(s => formatIpShort(s.src_ip));
      this.sourcesChart = new Chart(this.topSourcesCanvas.nativeElement, {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label: 'Alert Count',
            data: this.data.top_sources.map(s => s.alert_count),
            backgroundColor: '#1565c0',
            borderColor: '#1976d2',
            borderWidth: 1,
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: '#8b9cb5', font: { size: 10 } }, grid: { color: '#1e2d3d' } },
            y: { ticks: { color: '#8b9cb5' }, grid: { color: '#1e2d3d' }, beginAtZero: true }
          }
        }
      });
    }

    if (this.topDestCanvas && this.data.top_destinations?.length > 0) {
      const labels = this.data.top_destinations.map(d => {
        if (d.reverse_dns) return d.reverse_dns.length > 20 ? d.reverse_dns.slice(0, 18) + '..' : d.reverse_dns;
        return d.dst_ip;
      });
      this.destChart = new Chart(this.topDestCanvas.nativeElement, {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label: 'Alert Count',
            data: this.data.top_destinations.map(d => d.alert_count),
            backgroundColor: '#c62828',
            borderColor: '#d32f2f',
            borderWidth: 1,
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: '#8b9cb5', font: { size: 10 } }, grid: { color: '#1e2d3d' } },
            y: { ticks: { color: '#8b9cb5' }, grid: { color: '#1e2d3d' }, beginAtZero: true }
          }
        }
      });
    }

    if (this.severityCanvas && this.hasSeverityData()) {
      const severityColors: Record<string, string> = {
        critical: '#d32f2f', high: '#e65100', medium: '#f9a825', low: '#33691e', info: '#1565c0',
      };
      const entries = Object.entries(this.data.severity_breakdown);
      this.sevChart = new Chart(this.severityCanvas.nativeElement, {
        type: 'doughnut',
        data: {
          labels: entries.map(e => e[0]),
          datasets: [{
            data: entries.map(e => e[1]),
            backgroundColor: entries.map(e => severityColors[e[0]] || '#8b9cb5'),
            borderColor: '#111927',
            borderWidth: 2,
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: {
            legend: { position: 'bottom', labels: { color: '#8b9cb5', font: { size: 11 } } }
          }
        }
      });
    }
  }
}
