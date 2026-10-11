import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { ApiService, DashboardSummary, DeviceActivity, HostRiskScore, TimelineBucket, RecentCriticalAlert } from '../../services/api.service';
import { interval, Subscription } from 'rxjs';
import { formatIpShort } from '../../config/network.config';

@Component({
  selector: 'app-live-feed',
  standalone: true,
  imports: [CommonModule, RouterModule],
  template: `
    <div class="dashboard">
      <div class="page-header">
        <h1>Security Dashboard</h1>
        <span class="refreshed" *ngIf="lastRefreshed">
          Updated {{ lastRefreshed | date:'mediumTime' }}
        </span>
        <span class="refresh-indicator" [class.spinning]="refreshing" (click)="refresh()">&#x21bb;</span>
      </div>

      <div class="loading-overlay" *ngIf="loading && !summary">
        <div class="spinner"></div>
        <p>Loading dashboard data...</p>
      </div>

      <div class="error-banner" *ngIf="error">
        <span>&#x26A0; {{ error }}</span>
        <button (click)="refresh()">Retry</button>
      </div>

      <ng-container *ngIf="summary">

        <!-- ROW 1: Stat Cards -->
        <div class="stat-cards">
          <div class="stat-card">
            <div class="stat-label">Total Alerts (24h)</div>
            <div class="stat-value" [class.critical]="(summary.severity_breakdown.critical || 0) > 0">
              {{ summary.total_alerts_24h || 0 }}
            </div>
            <div class="stat-sub" *ngIf="totalTrend as t">
              <span class="trend" [class.trend-up]="t.dir > 0" [class.trend-down]="t.dir < 0">
                {{ t.dir > 0 ? '&#x25B2;' : (t.dir < 0 ? '&#x25BC;' : '&#x2500;') }} {{ t.text }}
              </span> vs prior 24h
            </div>
          </div>
          <div class="stat-card critical-high">
            <div class="stat-label">Critical / High</div>
            <div class="stat-value">
              {{ (summary.severity_breakdown.critical || 0) + (summary.severity_breakdown.high || 0) }}
            </div>
            <div class="stat-sub" *ngIf="critHighTrend as t">
              <span class="trend" [class.trend-up]="t.dir > 0" [class.trend-down]="t.dir < 0">
                {{ t.dir > 0 ? '&#x25B2;' : (t.dir < 0 ? '&#x25BC;' : '&#x2500;') }} {{ t.text }}
              </span> vs prior 24h
            </div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Active Threat Feeds</div>
            <div class="stat-value">
              {{ summary.threat_intel_status.feeds_loaded || 0 }}
            </div>
            <div class="stat-sub">{{ summary.threat_intel_status.total_iocs || 0 }} IOCs loaded</div>
          </div>
          <div class="stat-card">
            <div class="stat-label">Events Ingested (24h)</div>
            <div class="stat-value">
              {{ formatNumber(summary.ingestion_status.events_24h || 0) }}
            </div>
            <div class="stat-sub">
              <span class="dot" [class.live]="summary.ingestion_status.syslog_active"
                    [class.dead]="!summary.ingestion_status.syslog_active"></span>
              {{ summary.ingestion_status.syslog_active ? 'Syslog Active' : 'Syslog Idle' }}
            </div>
          </div>
        </div>

        <!-- ROW 1.5: Alert Timeline -->
        <div class="panel timeline-panel" *ngIf="hasTimeline">
          <h3 class="panel-title">
            Alert Timeline (24h)
            <span class="timeline-peak" *ngIf="timelinePeak > 0">Peak: {{ timelinePeak }}/hr</span>
          </h3>
          <div class="panel-body">
            <div class="timeline-chart">
              <div class="timeline-bars">
                <div class="tl-bar-col" *ngFor="let b of summary.alert_timeline; let i = index"
                     [title]="timelineTooltip(b)">
                  <div class="tl-bar-stack" [style.height.px]="timelineBarHeight(b.total)">
                    <div class="tl-seg tl-crit" *ngIf="b.critical" [style.flex-grow]="b.critical"></div>
                    <div class="tl-seg tl-high" *ngIf="b.high" [style.flex-grow]="b.high"></div>
                    <div class="tl-seg tl-med" *ngIf="b.medium" [style.flex-grow]="b.medium"></div>
                    <div class="tl-seg tl-low" *ngIf="b.low" [style.flex-grow]="b.low"></div>
                  </div>
                  <div class="tl-bar-empty" *ngIf="!b.total" [style.height.px]="2"></div>
                  <span class="tl-label" *ngIf="i % timelineLabelStep === 0">{{ timelineLabel(b.hour) }}</span>
                </div>
              </div>
              <div class="timeline-legend">
                <span class="tl-legend-item"><span class="tl-dot tl-crit"></span>Critical</span>
                <span class="tl-legend-item"><span class="tl-dot tl-high"></span>High</span>
                <span class="tl-legend-item"><span class="tl-dot tl-med"></span>Medium</span>
                <span class="tl-legend-item"><span class="tl-dot tl-low"></span>Low</span>
              </div>
            </div>
          </div>
        </div>

        <!-- ROW 2: Recent Critical Alerts + Host Risk Scores -->
        <div class="panel-row two-col">
          <!-- Recent Critical/High Alerts -->
          <div class="panel crit-panel">
            <h3 class="panel-title">
              Recent Critical/High Alerts
              <span class="panel-badge" *ngIf="summary.recent_critical?.length">{{ summary.recent_critical.length }}</span>
            </h3>
            <div class="panel-body">
              <div class="empty-hint" *ngIf="!summary.recent_critical?.length">
                No critical/high alerts in the last 24h.
              </div>
              <div class="crit-list" *ngIf="summary.recent_critical?.length">
                <a *ngFor="let ca of summary.recent_critical"
                   class="crit-row" [routerLink]="['/alerts', ca.id]">
                  <span class="crit-sev" [class.sev-critical]="ca.severity === 'critical'"
                        [class.sev-high]="ca.severity === 'high'">{{ ca.severity }}</span>
                  <span class="crit-class">{{ ca.classification }}</span>
                  <span class="crit-flow mono">{{ formatIp(ca.src_ip) }} &#x2192; {{ formatIp(ca.dst_ip) }}</span>
                  <span class="crit-meta" *ngIf="ca.dst_country || ca.dst_org">
                    {{ ca.dst_country || '' }} {{ ca.dst_org ? '(' + ca.dst_org + ')' : '' }}
                  </span>
                  <span class="crit-time">{{ formatTimeAgo(ca.created_at) }}</span>
                  <span class="crit-status tag" [class.tag-open]="ca.status === 'open'">{{ ca.status }}</span>
                </a>
              </div>
            </div>
          </div>

          <!-- Host Risk Scores -->
          <div class="panel risk-panel" *ngIf="hostRisks.length > 0">
            <h3 class="panel-title">
              Host Risk Scores (24h)
              <span class="panel-badge">{{ hostRisks.length }}</span>
            </h3>
            <div class="panel-body">
              <div class="risk-grid">
                <div class="risk-row" *ngFor="let h of hostRisks">
                  <span class="risk-ip mono">{{ formatIp(h.ip) }}</span>
                  <span class="risk-bar-track">
                    <span class="risk-bar-fill"
                          [style.width.%]="h.risk_score"
                          [class.risk-red]="h.risk_score > 75"
                          [class.risk-orange]="h.risk_score > 50 && h.risk_score <= 75"
                          [class.risk-yellow]="h.risk_score > 25 && h.risk_score <= 50"
                          [class.risk-green]="h.risk_score <= 25"></span>
                  </span>
                  <span class="risk-score" [class.risk-red-text]="h.risk_score > 75"
                        [class.risk-orange-text]="h.risk_score > 50 && h.risk_score <= 75"
                        [class.risk-yellow-text]="h.risk_score > 25 && h.risk_score <= 50"
                        [class.risk-green-text]="h.risk_score <= 25">{{ h.risk_score }}</span>
                  <span class="risk-alerts">{{ h.alert_count }} alerts</span>
                  <span class="risk-sev tag" [class.sev-critical]="h.top_severity === 'critical'"
                        [class.sev-high]="h.top_severity === 'high'"
                        [class.sev-medium]="h.top_severity === 'medium'"
                        [class.sev-low]="h.top_severity === 'low'">{{ h.top_severity }}</span>
                </div>
              </div>
            </div>
          </div>
          <div class="panel risk-panel" *ngIf="hostRisks.length === 0">
            <h3 class="panel-title">Host Risk Scores (24h)</h3>
            <div class="panel-body">
              <div class="empty-hint safe">No hosts with elevated risk scores.</div>
            </div>
          </div>
        </div>

        <!-- ROW 3: Top Alert Types + Destination Countries -->
        <div class="panel-row two-col">
          <div class="panel">
            <h3 class="panel-title">Top Alert Types</h3>
            <div class="panel-body">
              <div class="empty-hint" *ngIf="!summary.top_alert_types?.length">
                No alerts recorded yet.
              </div>
              <div class="bar-chart" *ngIf="summary.top_alert_types?.length">
                <div class="bar-row" *ngFor="let t of summary.top_alert_types; let i = index">
                  <span class="bar-label">{{ t.classification || 'unknown' }}</span>
                  <span class="bar-track">
                    <span class="bar-fill"
                          [style.width.%]="barPercent(t.count, maxAlertTypeCount)"
                          [style.background]="barColor(i)"></span>
                  </span>
                  <span class="bar-count">{{ t.count }}</span>
                </div>
              </div>
            </div>
          </div>
          <div class="panel">
            <h3 class="panel-title">Top Destination Countries</h3>
            <div class="panel-body">
              <div class="empty-hint" *ngIf="!summary.top_destination_countries?.length">
                No country data available.
              </div>
              <div class="country-list" *ngIf="summary.top_destination_countries?.length">
                <div class="country-row" *ngFor="let c of summary.top_destination_countries; let i = index">
                  <span class="country-flag">{{ countryFlag(c.country_code) }}</span>
                  <span class="country-name">{{ c.country || c.country_code || 'Unknown' }}</span>
                  <span class="country-bar-track">
                    <span class="country-bar-fill"
                          [style.width.%]="barPercent(c.alert_count, maxCountryCount)"></span>
                  </span>
                  <span class="country-count">{{ c.alert_count }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- ROW 4: Suspicious Destinations + Device Activity -->
        <div class="panel-row two-col">
          <div class="panel">
            <h3 class="panel-title">Suspicious Destinations</h3>
            <div class="panel-body scrollable">
              <div class="empty-hint" *ngIf="!summary.top_suspicious_destinations?.length">
                No suspicious destinations flagged.
              </div>
              <table class="data-table" *ngIf="summary.top_suspicious_destinations?.length">
                <thead>
                  <tr>
                    <th>IP</th>
                    <th>Country</th>
                    <th>Org / ISP</th>
                    <th>Alerts</th>
                    <th>Classification</th>
                  </tr>
                </thead>
                <tbody>
                  <tr *ngFor="let d of summary.top_suspicious_destinations">
                    <td class="mono">{{ d.ip }}</td>
                    <td>
                      <span class="country-flag small">{{ countryFlag(d.country) }}</span>
                      {{ d.country || '-' }}
                    </td>
                    <td class="org-cell">{{ d.org || '-' }}</td>
                    <td class="alert-num">{{ d.alert_count }}</td>
                    <td>
                      <span class="tag" *ngFor="let c of (d.classifications || [])">{{ c }}</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
          <div class="panel">
            <h3 class="panel-title">Device Activity</h3>
            <div class="panel-body scrollable">
              <div class="empty-hint" *ngIf="!devices?.length">
                Loading device activity...
              </div>
              <table class="data-table" *ngIf="devices?.length">
                <thead>
                  <tr>
                    <th>Internal IP</th>
                    <th>Alerts</th>
                    <th>Unique Dsts</th>
                    <th>Top Classification</th>
                    <th>Last Alert</th>
                  </tr>
                </thead>
                <tbody>
                  <tr *ngFor="let dev of devices">
                    <td class="mono">{{ formatIp(dev.ip) }}</td>
                    <td class="alert-num">{{ dev.alert_count }}</td>
                    <td>{{ dev.unique_destinations }}</td>
                    <td>
                      <span class="tag" *ngFor="let c of (dev.classifications || []) | slice:0:2">{{ c }}</span>
                    </td>
                    <td class="time-cell">{{ formatTime(dev.last_alert) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <!-- ROW 5: IoT Concerns -->
        <div class="panel iot-panel" *ngIf="summary.iot_concerns?.length">
          <h3 class="panel-title">
            IoT Concerns
            <span class="panel-badge">{{ summary.iot_concerns.length }}</span>
          </h3>
          <div class="panel-body scrollable">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Internal IP</th>
                  <th>&#x2192;</th>
                  <th>External IP</th>
                  <th>Country</th>
                  <th>Org</th>
                  <th>Classification</th>
                  <th>Count</th>
                </tr>
              </thead>
              <tbody>
                <tr *ngFor="let iot of summary.iot_concerns">
                  <td class="mono">{{ formatIp(iot.src_ip) }}</td>
                  <td class="arrow-cell">&#x2192;</td>
                  <td class="mono">{{ iot.dst_ip }}</td>
                  <td>
                    <span class="country-flag small">{{ countryFlag(iot.country) }}</span>
                    {{ iot.country || '-' }}
                  </td>
                  <td class="org-cell">{{ iot.org || '-' }}</td>
                  <td><span class="tag alert">{{ iot.classification }}</span></td>
                  <td class="alert-num">{{ iot.count }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

      </ng-container>
    </div>
  `,
  styles: [`
    .dashboard{display:flex;flex-direction:column;gap:16px}
    .page-header{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
    .page-header h1{margin:0;font-size:1.4rem;color:#e0e6ed}
    .refreshed{color:#5a6a7a;font-size:.78rem}
    .refresh-indicator{font-size:1.2rem;color:#4fc3f7;cursor:pointer;transition:transform .5s;user-select:none}
    .refresh-indicator.spinning{animation:spin 1s linear infinite}
    @keyframes spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}
    .loading-overlay{display:flex;flex-direction:column;align-items:center;padding:60px 20px;color:#8b9cb5;gap:16px}
    .spinner{width:36px;height:36px;border:3px solid #1e2d3d;border-top-color:#4fc3f7;border-radius:50%;animation:spin .8s linear infinite}
    .error-banner{display:flex;align-items:center;justify-content:space-between;background:#3e1a1a;border:1px solid #b71c1c;border-radius:6px;padding:10px 16px;color:#ef9a9a;font-size:.85rem}
    .error-banner button{background:#b71c1c;color:#ffcdd2;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:.8rem}

    /* Stat cards */
    .stat-cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
    .stat-card{background:#111927;border:1px solid #1e2d3d;border-radius:8px;padding:16px;display:flex;flex-direction:column;gap:4px}
    .stat-card.critical-high{border-left:3px solid #d32f2f}
    .stat-label{font-size:.72rem;color:#8b9cb5;text-transform:uppercase;letter-spacing:.5px}
    .stat-value{font-size:2rem;font-weight:700;color:#e0e6ed}
    .stat-value.critical{color:#ef5350}
    .stat-sub{font-size:.75rem;color:#5a6a7a;margin-top:2px}
    .dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:4px}
    .dot.live{background:#4caf50}
    .dot.dead{background:#b71c1c}
    .trend{font-weight:600}
    .trend-up{color:#ef5350}
    .trend-down{color:#66bb6a}

    /* Panels */
    .panel-row{display:grid;gap:12px}
    .panel-row.two-col{grid-template-columns:1fr 1fr}
    .panel{background:#111927;border:1px solid #1e2d3d;border-radius:8px;overflow:hidden}
    .panel.timeline-panel{border-left:3px solid #4fc3f7}
    .panel.crit-panel{border-left:3px solid #d32f2f}
    .panel.iot-panel{border-left:3px solid #e65100}
    .panel.risk-panel{border-left:3px solid #1565c0}
    .panel-title{margin:0;padding:12px 16px;font-size:.82rem;color:#b0bec5;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid #1e2d3d;background:#0d1520;display:flex;align-items:center;gap:8px}
    .panel-badge{background:#b71c1c;color:#ffcdd2;padding:1px 8px;border-radius:10px;font-size:.65rem;font-weight:600}
    .panel-body{padding:12px 16px}
    .panel-body.scrollable{max-height:340px;overflow-y:auto}
    .empty-hint{color:#5a6a7a;font-size:.82rem;text-align:center;padding:24px 0}
    .empty-hint.safe{color:#66bb6a}

    /* Alert Timeline */
    .timeline-peak{font-size:.7rem;color:#4fc3f7;font-weight:400;margin-left:auto;text-transform:none;letter-spacing:0}
    .timeline-chart{display:flex;flex-direction:column;gap:8px}
    .timeline-bars{display:flex;align-items:flex-end;gap:1px;height:80px;overflow-x:auto}
    .tl-bar-col{display:flex;flex-direction:column;align-items:center;flex:1;min-width:8px;position:relative}
    .tl-bar-stack{display:flex;flex-direction:column;border-radius:2px 2px 0 0;overflow:hidden;min-width:6px;width:100%;max-width:20px}
    .tl-bar-empty{background:#1e2d3d;border-radius:1px;min-width:6px;width:100%;max-width:20px}
    .tl-seg{min-height:1px}
    .tl-crit{background:#d32f2f}
    .tl-high{background:#e65100}
    .tl-med{background:#f9a825}
    .tl-low{background:#1565c0}
    .tl-label{font-size:.55rem;color:#5a6a7a;position:absolute;bottom:-14px;white-space:nowrap}
    .timeline-legend{display:flex;gap:12px;justify-content:center;padding-top:16px}
    .tl-legend-item{display:flex;align-items:center;gap:4px;font-size:.65rem;color:#8b9cb5}
    .tl-dot{width:8px;height:8px;border-radius:2px;display:inline-block}
    .tl-dot.tl-crit{background:#d32f2f}
    .tl-dot.tl-high{background:#e65100}
    .tl-dot.tl-med{background:#f9a825}
    .tl-dot.tl-low{background:#1565c0}

    /* Recent Critical Alerts */
    .crit-list{display:flex;flex-direction:column;gap:6px}
    .crit-row{display:flex;align-items:center;gap:8px;padding:8px 10px;background:#0d1520;border-radius:6px;border-left:3px solid transparent;text-decoration:none;color:inherit;cursor:pointer;transition:background .15s;flex-wrap:wrap}
    .crit-row:hover{background:#1a2a3a}
    .crit-sev{padding:2px 8px;border-radius:10px;font-size:.65rem;font-weight:700;text-transform:uppercase}
    .crit-class{font-size:.8rem;color:#e0e6ed;font-weight:500;min-width:80px}
    .crit-flow{font-size:.72rem;color:#8b9cb5;flex:1;min-width:140px}
    .crit-meta{font-size:.68rem;color:#5a6a7a;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .crit-time{font-size:.68rem;color:#5a6a7a;margin-left:auto}
    .crit-status{margin-left:4px}
    .tag-open{background:#3e1a1a;color:#ef9a9a}

    /* Bar charts */
    .bar-chart{display:flex;flex-direction:column;gap:6px}
    .bar-row{display:flex;align-items:center;gap:8px;font-size:.8rem}
    .bar-label{width:110px;text-align:right;color:#b0bec5;text-transform:capitalize;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .bar-track{flex:1;height:16px;background:#0d1520;border-radius:3px;overflow:hidden}
    .bar-fill{display:block;height:100%;border-radius:3px;transition:width .4s;min-width:2px}
    .bar-count{width:36px;text-align:right;color:#8b9cb5;font-family:monospace;font-size:.78rem}

    /* Country list */
    .country-list{display:flex;flex-direction:column;gap:6px}
    .country-row{display:flex;align-items:center;gap:8px;font-size:.82rem}
    .country-flag{font-size:1.1rem}
    .country-flag.small{font-size:.9rem}
    .country-name{width:100px;color:#b0bec5;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .country-bar-track{flex:1;height:12px;background:#0d1520;border-radius:3px;overflow:hidden}
    .country-bar-fill{display:block;height:100%;background:#1565c0;border-radius:3px;transition:width .4s}
    .country-count{color:#8b9cb5;font-family:monospace;font-size:.78rem;width:30px;text-align:right}

    /* Data tables */
    .data-table{width:100%;border-collapse:collapse;font-size:.78rem}
    .data-table th{text-align:left;padding:6px 8px;color:#5a6a7a;font-weight:600;text-transform:uppercase;font-size:.65rem;letter-spacing:.3px;border-bottom:1px solid #1e2d3d}
    .data-table td{padding:6px 8px;border-bottom:1px solid #0d1520;color:#b0bec5;white-space:nowrap}
    .data-table tbody tr:hover{background:#0d1520}
    .mono{font-family:monospace;color:#e0e6ed}
    .org-cell{max-width:140px;overflow:hidden;text-overflow:ellipsis;color:#8b9cb5}
    .alert-num{color:#ef5350;font-weight:600}
    .arrow-cell{color:#5a6a7a}
    .time-cell{color:#8b9cb5;font-size:.75rem}
    .tag{display:inline-block;padding:1px 6px;margin:1px;background:#1a2a3a;color:#90caf9;border-radius:3px;font-size:.65rem;text-transform:uppercase;letter-spacing:.3px}
    .tag.alert{background:#3e1a1a;color:#ef9a9a}

    /* Host risk */
    .risk-grid{display:flex;flex-direction:column;gap:6px}
    .risk-row{display:flex;align-items:center;gap:8px;font-size:.8rem;padding:4px 0}
    .risk-ip{width:120px;color:#e0e6ed}
    .risk-bar-track{flex:1;height:14px;background:#0d1520;border-radius:3px;overflow:hidden;min-width:60px}
    .risk-bar-fill{display:block;height:100%;border-radius:3px;transition:width .4s;min-width:2px}
    .risk-red{background:#d32f2f}
    .risk-orange{background:#e65100}
    .risk-yellow{background:#f9a825}
    .risk-green{background:#2e7d32}
    .risk-score{width:30px;text-align:right;font-weight:700;font-family:monospace;font-size:.85rem}
    .risk-red-text{color:#ef5350}
    .risk-orange-text{color:#ff9800}
    .risk-yellow-text{color:#fdd835}
    .risk-green-text{color:#66bb6a}
    .risk-alerts{color:#8b9cb5;font-size:.72rem;width:60px;text-align:right}
    .risk-sev{font-size:.6rem}
    .risk-class{font-size:.6rem}

    /* Severity badges */
    .sev-critical{background:#b71c1c;color:#ffcdd2}
    .sev-high{background:#e65100;color:#ffe0b2}
    .sev-medium{background:#f9a825;color:#1a1a1a}
    .sev-low{background:#1a2a3a;color:#90caf9}

    @media(max-width:900px){
      .stat-cards{grid-template-columns:repeat(2,1fr)}
      .panel-row.two-col{grid-template-columns:1fr}
      .bar-label{width:80px}
      .country-name{width:70px}
      .crit-flow{min-width:auto}
      .crit-meta{display:none}
    }
    @media(max-width:500px){
      .stat-cards{grid-template-columns:1fr}
      .bar-label{width:60px}
      .data-table{font-size:.7rem}
    }
  `]
})
export class LiveFeedComponent implements OnInit, OnDestroy {
  summary: DashboardSummary | null = null;
  devices: DeviceActivity['devices'] | null = null;
  hostRisks: HostRiskScore[] = [];
  loading = true;
  refreshing = false;
  error: string | null = null;
  lastRefreshed: Date | null = null;

  private refreshSub?: Subscription;

  constructor(private api: ApiService) {}

  ngOnInit() {
    this.loadAll();
    this.refreshSub = interval(60000).subscribe(() => this.refresh());
  }

  ngOnDestroy() {
    this.refreshSub?.unsubscribe();
  }

  refresh() {
    this.refreshing = true;
    this.loadAll();
  }

  private loadAll() {
    this.error = null;

    this.api.getDashboardSummary().subscribe({
      next: (data) => {
        this.summary = data;
        this.lastRefreshed = new Date();
        this.loading = false;
        this.refreshing = false;
      },
      error: (err) => {
        this.error = 'Failed to load dashboard: ' + (err?.message || err?.statusText || 'unknown');
        this.loading = false;
        this.refreshing = false;
      }
    });

    this.api.getDeviceActivity().subscribe({
      next: (data) => { this.devices = data.devices || []; },
      error: () => { this.devices = []; }
    });

    this.api.getHostRiskScores().subscribe({
      next: (data) => { this.hostRisks = data.hosts || []; },
      error: () => { this.hostRisks = []; }
    });
  }

  // --- Trend helpers ---

  private trendOf(current: number, prev: number | undefined): { dir: number; text: string } | null {
    if (prev == null) return null;
    const delta = current - prev;
    if (delta === 0) return { dir: 0, text: 'no change' };
    const pct = prev > 0 ? Math.round(Math.abs(delta) / prev * 100) : null;
    const sign = delta > 0 ? '+' : '-';
    return { dir: Math.sign(delta), text: pct != null ? `${sign}${Math.abs(delta)} (${pct}%)` : `${sign}${Math.abs(delta)}` };
  }

  get totalTrend(): { dir: number; text: string } | null {
    if (!this.summary) return null;
    return this.trendOf(this.summary.total_alerts_24h || 0, this.summary.prev_total_alerts);
  }

  get critHighTrend(): { dir: number; text: string } | null {
    if (!this.summary?.prev_severity_breakdown) return null;
    const cur = (this.summary.severity_breakdown.critical || 0) + (this.summary.severity_breakdown.high || 0);
    const prev = (this.summary.prev_severity_breakdown.critical || 0) + (this.summary.prev_severity_breakdown.high || 0);
    return this.trendOf(cur, prev);
  }

  // --- Timeline helpers ---

  get hasTimeline(): boolean {
    return !!(this.summary?.alert_timeline && this.summary.alert_timeline.length > 0);
  }

  get timelinePeak(): number {
    if (!this.summary?.alert_timeline) return 0;
    return Math.max(...this.summary.alert_timeline.map(b => b.total), 0);
  }

  get timelineLabelStep(): number {
    const len = this.summary?.alert_timeline?.length || 24;
    if (len <= 12) return 1;
    if (len <= 24) return 4;
    return 6;
  }

  timelineBarHeight(total: number): number {
    const peak = this.timelinePeak;
    if (!peak || !total) return 0;
    return Math.max(2, (total / peak) * 64);
  }

  timelineLabel(hour: string): string {
    try {
      const d = new Date(hour);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
    } catch {
      return '';
    }
  }

  timelineTooltip(b: TimelineBucket): string {
    const parts = [this.timelineLabel(b.hour)];
    if (b.critical) parts.push(`Critical: ${b.critical}`);
    if (b.high) parts.push(`High: ${b.high}`);
    if (b.medium) parts.push(`Medium: ${b.medium}`);
    if (b.low) parts.push(`Low: ${b.low}`);
    parts.push(`Total: ${b.total}`);
    return parts.join('\n');
  }

  // --- General helpers ---

  get maxAlertTypeCount(): number {
    const types = this.summary?.top_alert_types || [];
    if (!types.length) return 1;
    return Math.max(...types.map(t => t.count));
  }

  get maxCountryCount(): number {
    const countries = this.summary?.top_destination_countries || [];
    if (!countries.length) return 1;
    return Math.max(...countries.map(c => c.alert_count));
  }

  barPercent(count: number, max: number): number {
    if (!max || max <= 0) return 0;
    return (count / max) * 100;
  }

  barColor(index: number): string {
    const colors = ['#d32f2f', '#e65100', '#f9a825', '#1565c0', '#2e7d32', '#6a1b9a', '#00695c', '#4e342e'];
    return colors[index % colors.length];
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

  formatIp(ip: string): string {
    if (!ip) return '-';
    return formatIpShort(ip);
  }

  formatNumber(n: number): string {
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
    if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
    return n.toString();
  }

  formatTime(ts: string): string {
    if (!ts) return '-';
    try { return new Date(ts).toLocaleString(); } catch { return ts; }
  }

  formatTimeAgo(ts: string): string {
    if (!ts) return '';
    try {
      const diff = Date.now() - new Date(ts).getTime();
      const mins = Math.floor(diff / 60000);
      if (mins < 1) return 'just now';
      if (mins < 60) return `${mins}m ago`;
      const hrs = Math.floor(mins / 60);
      if (hrs < 24) return `${hrs}h ago`;
      return `${Math.floor(hrs / 24)}d ago`;
    } catch {
      return '';
    }
  }
}
