import { Component, OnInit, OnDestroy, AfterViewInit, ViewChild, ElementRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService, NetworkOverview, AnomalyHost, DeviceRole } from '../../services/api.service';
import { Chart, registerables } from 'chart.js';

Chart.register(...registerables);

@Component({
  selector: 'app-network-overview',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="page-header">
      <h1>🌐 Network Overview</h1>
      <div class="period-select">
        <label>Time window:</label>
        <select [(ngModel)]="hours" (change)="load()" class="filter-input">
          <option [value]="1">Last hour</option>
          <option [value]="6">Last 6 hours</option>
          <option [value]="12">Last 12 hours</option>
          <option [value]="24">Last 24 hours</option>
          <option [value]="48">Last 2 days</option>
          <option [value]="72">Last 3 days</option>
          <option [value]="168">Last week</option>
        </select>
      </div>
    </div>

    <div class="error-msg" *ngIf="error">{{ error }}</div>

    <div *ngIf="data">
      <div class="summary-bar">
        <div class="summary-card">
          <div class="summary-value">{{ data.total_events | number }}</div>
          <div class="summary-label">Total Events</div>
        </div>
        <div class="summary-card">
          <div class="summary-value">{{ data.active_hosts?.length || 0 }}</div>
          <div class="summary-label">Active Hosts</div>
        </div>
        <div class="summary-card flagged">
          <div class="summary-value">{{ data.flagged_hosts?.length || 0 }}</div>
          <div class="summary-label">Flagged Hosts</div>
        </div>
      </div>

      <div class="panels-grid">
        <div class="panel">
          <h2>Active Hosts</h2>
          <div class="host-list" *ngIf="data.active_hosts && data.active_hosts.length > 0">
            <div *ngFor="let host of data.active_hosts" class="host-row" [class.flagged]="isFlagged(host.ip)">
              <span class="host-ip">{{ host.ip }}</span>
              <span class="host-role" *ngIf="getDeviceRole(host.ip) as role">{{ role }}</span>
              <span class="host-events">{{ host.event_count | number }} events</span>
              <span class="host-flag" *ngIf="isFlagged(host.ip)">⚠️</span>
            </div>
          </div>
          <div class="panel-empty" *ngIf="!data.active_hosts || data.active_hosts.length === 0">
            No active hosts in this period.
          </div>
        </div>

        <div class="panel">
          <h2>Flagged Hosts</h2>
          <div class="host-list" *ngIf="data.flagged_hosts && data.flagged_hosts.length > 0">
            <div *ngFor="let host of data.flagged_hosts" class="host-row flagged-row">
              <span class="host-ip">{{ host.ip }}</span>
              <span class="host-alerts">{{ host.alert_count }} alerts</span>
            </div>
          </div>
          <div class="panel-empty" *ngIf="!data.flagged_hosts || data.flagged_hosts.length === 0">
            ✅ No flagged hosts — network looks clean!
          </div>
        </div>

        <div class="panel">
          <h2>Event Types</h2>
          <div class="chart-container" *ngIf="hasEventTypes()">
            <canvas #typeChart></canvas>
          </div>
          <div class="panel-empty" *ngIf="!hasEventTypes()">
            No event type data available.
          </div>
        </div>
      </div>

      <!-- Anomaly Detection -->
      <div class="anomaly-section">
        <h2 class="section-title">Statistical Anomalies (IsolationForest)</h2>
        <div class="anomaly-meta" *ngIf="anomalyLastRun">
          Last run: {{ formatTime(anomalyLastRun) }}
        </div>
        <div class="panel" *ngIf="anomalies.length > 0">
          <table class="anomaly-table">
            <thead>
              <tr>
                <th>Host IP</th>
                <th>Anomaly Score</th>
                <th>Connections</th>
                <th>Unique Dests</th>
                <th>Unique Ports</th>
                <th>Blocked Ratio</th>
                <th>Protocols</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let a of anomalies" class="anomaly-row">
                <td class="host-ip">{{ a.ip }}</td>
                <td>
                  <span class="anomaly-score-bar">
                    <span class="anomaly-score-fill"
                          [style.width.%]="anomalyBarWidth(a.anomaly_score)"></span>
                  </span>
                  <span class="anomaly-score-val">{{ a.anomaly_score != null ? a.anomaly_score.toFixed(3) : '—' }}</span>
                </td>
                <td>{{ a.total_connections ?? '—' }}</td>
                <td>{{ a.unique_destinations ?? '—' }}</td>
                <td>{{ a.unique_ports ?? '—' }}</td>
                <td>{{ a.blocked_ratio != null ? (a.blocked_ratio * 100).toFixed(1) + '%' : '—' }}</td>
                <td>{{ a.unique_protocols }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="panel-empty" *ngIf="anomalies.length === 0">
          No anomalies detected. The detector runs every 30 minutes.
        </div>
      </div>
    </div>

    <!-- Device Roles -->
    <div class="device-roles-section">
      <h2 class="section-title">🏷️ Device Roles</h2>
      <div class="panel">
        <div class="dr-add-form">
          <input [(ngModel)]="newDeviceRole.ip" placeholder="IP address..." class="filter-input" />
          <input [(ngModel)]="newDeviceRole.role" placeholder="Role (e.g., router, server)..." class="filter-input" />
          <input [(ngModel)]="newDeviceRole.label" placeholder="Label (optional)..." class="filter-input" />
          <button class="btn btn-primary btn-sm" (click)="addDeviceRole()" [disabled]="!newDeviceRole.ip || !newDeviceRole.role || savingRole">
            {{ savingRole ? 'Adding...' : '+ Add' }}
          </button>
        </div>

        <div class="table-wrap" *ngIf="deviceRoles.length > 0">
          <table class="anomaly-table">
            <thead>
              <tr>
                <th>IP</th>
                <th>Role</th>
                <th>Label</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr *ngFor="let dr of deviceRoles" class="anomaly-row">
                <td class="host-ip">{{ dr.ip }}</td>
                <td>
                  <ng-container *ngIf="editingRoleId !== dr.id">
                    <span class="role-badge" [class.role-router]="dr.role === 'router'" [class.role-server]="dr.role === 'server'" [class.role-workstation]="dr.role === 'workstation'">{{ dr.role }}</span>
                  </ng-container>
                  <ng-container *ngIf="editingRoleId === dr.id">
                    <input [(ngModel)]="editRoleForm.role" class="filter-input" style="width:120px" />
                  </ng-container>
                </td>
                <td>
                  <ng-container *ngIf="editingRoleId !== dr.id">{{ dr.label || '-' }}</ng-container>
                  <ng-container *ngIf="editingRoleId === dr.id">
                    <input [(ngModel)]="editRoleForm.label" class="filter-input" style="width:140px" />
                  </ng-container>
                </td>
                <td>{{ formatTime(dr.created_at) }}</td>
                <td class="td-actions">
                  <ng-container *ngIf="editingRoleId !== dr.id">
                    <button class="btn btn-secondary btn-sm" (click)="startEditRole(dr)">Edit</button>
                    <button class="btn btn-delete btn-sm" (click)="deleteDeviceRole(dr.id)">×</button>
                  </ng-container>
                  <ng-container *ngIf="editingRoleId === dr.id">
                    <button class="btn btn-primary btn-sm" (click)="saveRoleEdit(dr)">Save</button>
                    <button class="btn btn-secondary btn-sm" (click)="editingRoleId = null">Cancel</button>
                  </ng-container>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="panel-empty" *ngIf="deviceRoles.length === 0 && deviceRolesLoaded">
          No device roles defined. Add roles to label your network devices.
        </div>
        <div class="panel-empty" *ngIf="!deviceRolesLoaded">
          Loading device roles...
        </div>
      </div>
    </div>

    <div class="empty-state" *ngIf="!data && !error">
      <p>Loading network overview...</p>
    </div>
  `,
  styles: [`
    .page-header { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }
    .page-header h1 { margin: 0; font-size: 1.4rem; }
    .period-select { display: flex; align-items: center; gap: 8px; }
    .period-select label { font-size: 0.8rem; color: #8b9cb5; }
    .filter-input { padding: 6px 10px; background: #0d1520; border: 1px solid #1e2d3d; border-radius: 4px; color: #e0e6ed; font-size: 0.85rem; }
    .filter-input:focus { outline: none; border-color: #4fc3f7; }

    .summary-bar { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 20px; }
    @media (max-width: 600px) { .summary-bar { grid-template-columns: 1fr; } }
    .summary-card { background: #111927; border: 1px solid #1e2d3d; border-radius: 8px; padding: 16px; text-align: center; }
    .summary-card.flagged { border-left: 3px solid #ef5350; }
    .summary-value { font-size: 1.6rem; font-weight: 700; color: #4fc3f7; }
    .summary-label { font-size: 0.75rem; color: #8b9cb5; margin-top: 4px; text-transform: uppercase; }

    .panels-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    @media (max-width: 900px) { .panels-grid { grid-template-columns: 1fr; } }

    .panel { background: #111927; border: 1px solid #1e2d3d; border-radius: 8px; padding: 20px; }
    .panel h2 { margin: 0 0 14px; font-size: 0.95rem; color: #4fc3f7; }

    .host-list { display: flex; flex-direction: column; gap: 6px; max-height: 400px; overflow-y: auto; }
    .host-row { display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; background: #0d1520; border-radius: 6px; border-left: 3px solid transparent; }
    .host-row.flagged { border-left-color: #ef5350; }
    .host-row.flagged-row { border-left-color: #ef5350; background: #1a0a0a; }
    .host-ip { font-family: monospace; font-size: 0.85rem; flex: 1; }
    .host-role { font-size: 0.68rem; padding: 2px 8px; border-radius: 8px; background: #1e2d3d; color: #81d4fa; text-transform: uppercase; font-weight: 600; letter-spacing: .3px; white-space: nowrap; }
    .host-events, .host-alerts { font-size: 0.8rem; color: #8b9cb5; }
    .host-alerts { color: #ef5350; }
    .host-flag { margin-left: 8px; }

    .chart-container { position: relative; width: 100%; max-width: 300px; margin: 0 auto; height: 250px; }

    .panel-empty { text-align: center; padding: 30px; color: #8b9cb5; font-size: 0.85rem; }
    .empty-state { text-align: center; padding: 60px 20px; color: #8b9cb5; }
    .error-msg { color: #ef5350; margin-bottom: 16px; }

    .anomaly-section { margin-top: 20px; }
    .section-title { font-size: 1rem; color: #4fc3f7; margin: 0 0 8px; }
    .anomaly-meta { font-size: 0.75rem; color: #5a6a7a; margin-bottom: 10px; }
    .anomaly-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
    .anomaly-table th { text-align: left; padding: 8px 10px; color: #5a6a7a; font-weight: 600; text-transform: uppercase; font-size: 0.68rem; letter-spacing: .3px; border-bottom: 1px solid #1e2d3d; }
    .anomaly-table td { padding: 8px 10px; border-bottom: 1px solid #0d1520; color: #b0bec5; }
    .anomaly-row:hover { background: #0d1520; }
    .anomaly-score-bar { display: inline-block; width: 60px; height: 10px; background: #0d1520; border-radius: 3px; overflow: hidden; vertical-align: middle; margin-right: 6px; }
    .anomaly-score-fill { display: block; height: 100%; background: #e65100; border-radius: 3px; }
    .anomaly-score-val { font-family: monospace; font-size: 0.78rem; color: #ff9800; }

    /* Device Roles */
    .device-roles-section { margin-top: 20px; }
    .device-roles-section .section-title { font-size: 1rem; color: #4fc3f7; margin: 0 0 8px; }
    .dr-add-form {
      display: flex;
      gap: 8px;
      margin-bottom: 14px;
      flex-wrap: wrap;
      align-items: center;
    }
    .dr-add-form .filter-input {
      flex: 1;
      min-width: 130px;
      max-width: 250px;
      padding: 6px 10px;
      background: #0d1520;
      border: 1px solid #1e2d3d;
      border-radius: 4px;
      color: #e0e6ed;
      font-size: 0.8rem;
    }
    .dr-add-form .filter-input:focus { outline: none; border-color: #4fc3f7; }
    .btn { padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.85rem; transition: background 0.2s; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-primary { background: #1565c0; color: white; }
    .btn-primary:hover:not(:disabled) { background: #1976d2; }
    .btn-secondary { background: #1e2d3d; color: #b0bec5; }
    .btn-secondary:hover:not(:disabled) { background: #2a3f5a; }
    .btn-delete { background: #b71c1c; color: white; }
    .btn-delete:hover:not(:disabled) { background: #d32f2f; }
    .btn-sm { padding: 4px 10px; font-size: 0.72rem; }
    .role-badge {
      padding: 3px 10px;
      border-radius: 10px;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      background: #1e2d3d;
      color: #b0bec5;
    }
    .role-router { background: #01579b; color: #81d4fa; }
    .role-server { background: #1b5e20; color: #a5d6a7; }
    .role-workstation { background: #311b92; color: #b39ddb; }
    .td-actions { white-space: nowrap; }
  `]
})
export class NetworkOverviewComponent implements OnInit, OnDestroy, AfterViewInit {
  @ViewChild('typeChart') typeCanvas!: ElementRef<HTMLCanvasElement>;

  data: NetworkOverview | null = null;
  hours = 24;
  error = '';
  anomalies: AnomalyHost[] = [];
  anomalyLastRun: string | null = null;
  deviceRoles: DeviceRole[] = [];
  deviceRolesLoaded = false;
  newDeviceRole = { ip: '', role: '', label: '' };
  savingRole = false;
  editingRoleId: number | null = null;
  editRoleForm = { role: '', label: '' };

  private typeChart: Chart | null = null;

  constructor(private api: ApiService) {}

  ngOnInit() {
    this.load();
  }

  ngAfterViewInit() {
    if (this.data) {
      this.renderChart();
    }
  }

  ngOnDestroy() {
    this.typeChart?.destroy();
  }

  load() {
    this.error = '';
    this.api.getNetworkOverview(this.hours).subscribe({
      next: (data) => {
        this.data = data;
        setTimeout(() => this.renderChart(), 100);
      },
      error: (err) => {
        this.error = err.error?.detail || 'Failed to load network overview';
      }
    });

    this.api.getAnomalies().subscribe({
      next: (data) => {
        this.anomalies = (data.anomalies || []).map((a: any) => ({
          ...(a.details || {}),
          ...a,
          anomaly_score: a.anomaly_score ?? a.score ?? a.details?.anomaly_score,
        }));
        this.anomalyLastRun = data.last_run;
      },
      error: () => {
        this.anomalies = [];
      }
    });

    this.api.getDeviceRoles().subscribe({
      next: (data) => {
        this.deviceRoles = data || [];
        this.deviceRolesLoaded = true;
      },
      error: () => { this.deviceRolesLoaded = true; }
    });
  }

  anomalyBarWidth(score: number): number {
    if (score == null || isNaN(score)) return 0;
    return Math.min(score / 0.5 * 100, 100);
  }

  formatTime(ts: string): string {
    if (!ts) return '-';
    try { const d = new Date(ts); return d.toLocaleString(); } catch { return ts; }
  }

  isFlagged(ip: string): boolean {
    if (!this.data?.flagged_hosts) return false;
    return this.data.flagged_hosts.some(h => h.ip === ip);
  }

  getDeviceRole(ip: string): string | null {
    const dr = this.deviceRoles.find(r => r.ip === ip);
    if (!dr) return null;
    return dr.label ? `${dr.role} — ${dr.label}` : dr.role;
  }

  hasEventTypes(): boolean {
    if (!this.data?.event_type_breakdown) return false;
    return Object.keys(this.data.event_type_breakdown).length > 0;
  }

  addDeviceRole() {
    if (!this.newDeviceRole.ip || !this.newDeviceRole.role) return;
    this.savingRole = true;
    this.api.createDeviceRole({
      ip: this.newDeviceRole.ip,
      role: this.newDeviceRole.role,
      label: this.newDeviceRole.label || '',
    }).subscribe({
      next: (role) => {
        this.savingRole = false;
        this.deviceRoles.push(role);
        this.deviceRolesLoaded = true;
        this.newDeviceRole = { ip: '', role: '', label: '' };
      },
      error: (err) => {
        this.savingRole = false;
        this.error = err.error?.detail || 'Failed to add device role';
      }
    });
  }

  startEditRole(dr: DeviceRole) {
    this.editingRoleId = dr.id;
    this.editRoleForm = { role: dr.role, label: dr.label || '' };
  }

  saveRoleEdit(dr: DeviceRole) {
    if (!this.editingRoleId) return;
    this.api.updateDeviceRole(dr.id, this.editRoleForm).subscribe({
      next: (updated) => {
        const idx = this.deviceRoles.findIndex(r => r.id === dr.id);
        if (idx >= 0) this.deviceRoles[idx] = updated;
        this.editingRoleId = null;
      },
      error: (err) => {
        this.error = err.error?.detail || 'Failed to update device role';
      }
    });
  }

  deleteDeviceRole(id: number) {
    this.api.deleteDeviceRole(id).subscribe({
      next: () => {
        this.deviceRoles = this.deviceRoles.filter(r => r.id !== id);
      },
      error: (err) => {
        this.error = err.error?.detail || 'Failed to delete device role';
      }
    });
  }

  renderChart() {
    if (!this.data || !this.typeCanvas) return;

    this.typeChart?.destroy();

    if (!this.hasEventTypes()) return;

    const entries = Object.entries(this.data.event_type_breakdown);
    const colors: Record<string, string> = {
      opnsense: '#4caf50', pihole: '#42a5f5', generic: '#ffa726',
    };

    this.typeChart = new Chart(this.typeCanvas.nativeElement, {
      type: 'doughnut',
      data: {
        labels: entries.map(e => e[0]),
        datasets: [{
          data: entries.map(e => e[1]),
          backgroundColor: entries.map(e => colors[e[0]] || '#8b9cb5'),
          borderColor: '#111927',
          borderWidth: 2,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { color: '#8b9cb5', font: { size: 11 } } }
        }
      }
    });
  }
}
