import { Component, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { ApiService, Alert } from '../../services/api.service';
import { NETWORK_CONFIG, formatIpLabel, formatIpShort, isOwnIp } from '../../config/network.config';

interface FpPattern {
  id: number;
  detector_name: string;
  src_pattern?: string;
  dst_pattern?: string;
  domain_pattern?: string;
  classification?: string;
  reason?: string;
  times_matched: number;
  created_at?: string;
  created_by?: string;
}

interface AlertGroup {
  key: string;
  count: number;
  alerts: Alert[];
  representative: Alert;
  expanded: boolean;
}

interface SeverityCount {
  severity: string;
  count: number;
}

interface ClassCount {
  classification: string;
  count: number;
}

@Component({
  selector: 'app-alert-history',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule],
  template: `
    <div class="page-header">
      <h1>🚨 Alert History</h1>
    </div>

    <!-- Alert Summary -->
    <div class="summary-section" *ngIf="totalLoaded > 0">
      <div class="summary-row">
        <span class="summary-label">Severity</span>
        <span
          *ngFor="let sc of severityCounts"
          class="sev-summary-badge"
          [class.active]="filters.severity === sc.severity"
          [class.sev-sum-critical]="sc.severity === 'critical'"
          [class.sev-sum-high]="sc.severity === 'high'"
          [class.sev-sum-medium]="sc.severity === 'medium'"
          [class.sev-sum-low]="sc.severity === 'low'"
          [class.sev-sum-info]="sc.severity === 'info'"
          (click)="filterBySeverity(sc.severity)"
        >
          {{ sc.severity }}: {{ sc.count }}
        </span>
      </div>
      <div class="summary-row" *ngIf="topClassifications.length > 0">
        <span class="summary-label">Top Classes</span>
        <span
          *ngFor="let cc of topClassifications"
          class="class-summary-tag"
          [class.active]="filters.classification === cc.classification"
          (click)="filterByClassification(cc.classification)"
        >
          {{ cc.classification }} <em>{{ cc.count }}</em>
        </span>
      </div>
    </div>

    <div class="filters-bar">
      <div class="filter-group">
        <label>Classification</label>
        <input [(ngModel)]="filters.classification" (keyup.enter)="applyFilters()" placeholder="Search..." class="filter-input" />
      </div>
      <div class="filter-group">
        <label>Source IP</label>
        <input [(ngModel)]="filters.source_ip" (keyup.enter)="applyFilters()" placeholder="IP address..." class="filter-input" />
      </div>
      <div class="filter-group">
        <label>Action</label>
        <select [(ngModel)]="filters.action" (change)="applyFilters()" class="filter-input">
          <option value="">All</option>
          <option value="pass">Allowed</option>
          <option value="block">Blocked</option>
        </select>
      </div>
      <div class="filter-group">
        <label>Escalated</label>
        <select [(ngModel)]="filters.escalate" (change)="applyFilters()" class="filter-input">
          <option value="">All</option>
          <option value="true">Yes</option>
          <option value="false">No</option>
        </select>
      </div>
      <div class="filter-group">
        <label>Since</label>
        <input type="date" [(ngModel)]="filters.since" (change)="applyFilters()" class="filter-input" />
      </div>
      <div class="filter-group">
        <label>Until</label>
        <input type="date" [(ngModel)]="filters.until" (change)="applyFilters()" class="filter-input" />
      </div>
      <button class="btn btn-secondary" (click)="clearFilters()">Clear</button>
      <button class="btn btn-primary" (click)="applyFilters()">Search</button>
    </div>

    <div class="error-msg" *ngIf="error">{{ error }}</div>

    <!-- Cards (mobile) -->
    <div class="alert-cards" *ngIf="groups.length > 0">
      <div
        *ngFor="let group of groups"
        class="alert-card"
        [class.critical]="group.representative.severity === 'critical'"
        [class.high]="group.representative.severity === 'high'"
        [class.medium]="group.representative.severity === 'medium'"
        [class.expanded]="group.expanded"
      >
        <div class="alert-card-header" (click)="toggleGroup(group)">
          <span class="alert-severity" [class.sev-critical]="group.representative.severity === 'critical'" [class.sev-high]="group.representative.severity === 'high'" [class.sev-medium]="group.representative.severity === 'medium'" [class.sev-low]="group.representative.severity === 'low'">{{ group.representative.severity }}</span>
          <span class="alert-classification">{{ group.representative.classification }}</span>
          <span class="mitre-badge" *ngIf="group.representative.attack_technique" [title]="group.representative.attack_tactic || ''">
            {{ group.representative.attack_technique }}
          </span>
          <span class="alert-count-badge" *ngIf="group.count > 1">×{{ group.count }}</span>
          <span class="alert-escalated" *ngIf="group.representative.escalate">🔔 Escalated</span>
          <span class="expand-arrow">{{ group.expanded ? '▼' : '▶' }}</span>
        </div>

        <!-- Enrichment & flags row -->
        <div class="alert-enrich-row">
          <span class="action-badge" *ngIf="getFirewallAction(group.representative) as act"
            [class.action-block]="act === 'block'"
            [class.action-pass]="act === 'pass'"
          >{{ act }}</span>
          <span class="proto-tag" *ngIf="getProtocol(group.representative)">{{ getProtocol(group.representative) }}</span>
          <span class="domain-tag" *ngIf="getDstDomain(group.representative) as dom">{{ dom }}</span>
          <ng-container *ngIf="getEnrichment(group.representative) as enr">
            <span class="enrich-flag">{{ countryEmoji(enr.country_code) }}</span>
            <span class="enrich-country">{{ enr.country || enr.country_code || '' }}</span>
            <span class="enrich-org" *ngIf="enr.org || enr.isp">{{ enr.org || enr.isp }}</span>
            <span class="enrich-rdns" *ngIf="enr.reverse_dns && !enr.country">{{ enr.reverse_dns }}</span>
            <span class="enrich-asn" *ngIf="enr.asn">{{ enr.asn }}</span>
          </ng-container>
        </div>
        <div class="alert-flags-row" *ngIf="getBehavioralFlags(group.representative).length > 0">
          <span *ngFor="let flag of getBehavioralFlags(group.representative)" class="bf-tag">{{ flag }}</span>
        </div>

        <div class="alert-card-body">
          <div class="alert-ips">
            <span class="alert-src">{{ formatIpLabel(group.representative.src_ip) }}</span>
            <span class="alert-arrow">→</span>
            <span class="alert-dst">{{ formatIpLabel(group.representative.dst_ip) }}</span>
          </div>
          <div class="alert-meta">
            <span>Confidence: {{ group.representative.confidence }}%</span>
            <span class="alert-time">{{ formatDate(group.representative.created_at) }}</span>
          </div>

          <!-- Expanded timestamps -->
          <div class="expanded-timestamps" *ngIf="group.expanded && group.count > 1">
            <div class="ts-header">Individual alerts in group:</div>
            <div *ngFor="let a of group.alerts" class="ts-row">
              <span class="ts-time">{{ formatDate(a.created_at) }}</span>
              <span class="ts-meta">Conf: {{ a.confidence }}%</span>
              <a class="ts-link" [routerLink]="['/alerts', a.id]">View</a>
            </div>
          </div>

          <div class="alert-card-footer">
            <a class="view-link" [routerLink]="['/alerts', group.representative.id]">View Detail →</a>
            <button class="btn-fp"
                    *ngIf="group.representative.status !== 'false_positive'"
                    (click)="markFalsePositive(group.representative); $event.stopPropagation()">
              Flag FP
            </button>
            <span class="fp-badge" *ngIf="group.representative.status === 'false_positive'">False Positive</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Desktop table -->
    <div class="alert-table-wrap" *ngIf="groups.length > 0">
      <table class="alert-table">
        <thead>
          <tr>
            <th>Sev</th>
            <th>Classification</th>
            <th>Flow</th>
            <th>Enrichment</th>
            <th>Flags</th>
            <th>Time</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <ng-container *ngFor="let group of groups">
            <tr
              class="alert-row"
              [class.row-critical]="group.representative.severity === 'critical'"
              [class.row-high]="group.representative.severity === 'high'"
              [class.row-expanded]="group.expanded"
            >
              <td>
                <span class="sev-badge"
                  [class.sev-critical]="group.representative.severity === 'critical'"
                  [class.sev-high]="group.representative.severity === 'high'"
                  [class.sev-medium]="group.representative.severity === 'medium'"
                  [class.sev-low]="group.representative.severity === 'low'"
                  [class.sev-info]="group.representative.severity === 'info'"
                >{{ group.representative.severity | uppercase }}</span>
              </td>
              <td>
                <span class="class-cell">{{ group.representative.classification }}</span>
                <span class="mitre-badge" *ngIf="group.representative.attack_technique" [title]="group.representative.attack_tactic || ''">
                  {{ group.representative.attack_technique }}
                </span>
              </td>
              <td class="flow-cell">
                <span class="action-badge" *ngIf="getFirewallAction(group.representative) as act"
                  [class.action-block]="act === 'block'"
                  [class.action-pass]="act === 'pass'"
                >{{ act }}</span>
                <span class="flow-ips">
                  <span class="mono flow-src">{{ formatIpShort(group.representative.src_ip) }}</span>
                  <span class="flow-arrow">&#x2192;</span>
                  <span class="mono flow-dst">{{ formatIpShort(group.representative.dst_ip) }}</span>
                </span>
                <span class="proto-tag" *ngIf="getProtocol(group.representative)">{{ getProtocol(group.representative) }}</span>
              </td>
              <td class="enrich-cell">
                <span class="domain-tag" *ngIf="getDstDomain(group.representative) as dom">{{ dom }}</span>
                <ng-container *ngIf="getEnrichment(group.representative) as enr">
                  <span class="enrich-flag">{{ countryEmoji(enr.country_code) }}</span>
                  <span class="enrich-country">{{ enr.country || enr.country_code || '' }}</span>
                  <span class="enrich-org" *ngIf="enr.org || enr.isp"> {{ enr.org || enr.isp }}</span>
                </ng-container>
                <span class="no-enrich" *ngIf="!getEnrichment(group.representative) && !getDstDomain(group.representative)">&#x2014;</span>
              </td>
              <td>
                <span *ngFor="let flag of getBehavioralFlags(group.representative)" class="bf-tag bf-tag-sm">{{ flag }}</span>
                <span *ngIf="getBehavioralFlags(group.representative).length === 0" class="no-enrich">&#x2014;</span>
              </td>
              <td class="td-time">{{ formatTimeShort(group.representative.created_at) }}</td>
              <td class="td-actions">
                <span class="count-badge" *ngIf="group.count > 1" (click)="toggleGroup(group); $event.stopPropagation()">&#xD7;{{ group.count }}</span>
                <a class="view-link-inline" [routerLink]="['/alerts', group.representative.id]">&#x25B6;</a>
                <button class="btn-fp-sm"
                        *ngIf="group.representative.status !== 'false_positive'"
                        (click)="markFalsePositive(group.representative); $event.stopPropagation()"
                        title="Mark as False Positive">FP</button>
                <span class="fp-badge-sm" *ngIf="group.representative.status === 'false_positive'" title="False Positive">FP</span>
              </td>
            </tr>
            <!-- Expanded detail rows -->
            <tr *ngIf="group.expanded && group.count > 1" class="expanded-detail-row">
              <td colspan="7">
                <div class="expanded-detail-wrap">
                  <div class="expanded-header">Individual Alerts ({{ group.count }} total)</div>
                  <div *ngFor="let a of group.alerts" class="expanded-sub-row">
                    <span class="expanded-time">{{ formatTimeShort(a.created_at) }}</span>
                    <span class="expanded-conf">Conf: {{ a.confidence }}%</span>
                    <span class="expanded-dst" *ngIf="a.dst_ip !== group.representative.dst_ip">&#x2192; {{ a.dst_ip }}</span>
                    <a class="expanded-link" [routerLink]="['/alerts', a.id]">View</a>
                  </div>
                </div>
              </td>
            </tr>
          </ng-container>
        </tbody>
      </table>
    </div>

    <div class="empty-state" *ngIf="groups.length === 0 && !error && !loading">
      <p>No alerts found matching your filters.</p>
    </div>

    <div class="pagination" *ngIf="groups.length > 0">
      <button class="btn btn-secondary" (click)="loadMore()" [disabled]="loading">
        {{ loading ? 'Loading...' : 'Load More' }}
      </button>
      <span class="count-info">Showing {{ totalLoaded }} alerts in {{ groups.length }} groups</span>
    </div>

    <!-- FP Patterns Section -->
    <div class="fp-patterns-section" *ngIf="fpPatterns.length > 0 || fpPatternsLoaded">
      <h2 class="section-title">🧬 False Positive Patterns</h2>
      <div class="empty-sub" *ngIf="fpPatterns.length === 0">
        <p>No false positive patterns defined.</p>
      </div>
      <div class="fp-patterns-grid" *ngIf="fpPatterns.length > 0">
        <div *ngFor="let fp of fpPatterns" class="fp-pattern-card">
          <div class="fp-card-header">
            <span class="fp-detector">{{ fp.detector_name }}</span>
            <span class="fp-classification" *ngIf="fp.classification">{{ fp.classification }}</span>
            <span class="fp-count">×{{ fp.times_matched }}</span>
            <button class="btn-delete-pattern"
                    (click)="deleteFpPattern(fp)"
                    title="Delete pattern">×</button>
          </div>
          <div class="fp-card-body">
            <div class="fp-rule" *ngIf="fp.src_pattern">
              <span class="fp-label">Src:</span>
              <span class="mono">{{ fp.src_pattern }}</span>
            </div>
            <div class="fp-rule" *ngIf="fp.dst_pattern">
              <span class="fp-label">Dst:</span>
              <span class="mono">{{ fp.dst_pattern }}</span>
            </div>
            <div class="fp-rule" *ngIf="fp.domain_pattern">
              <span class="fp-label">Domain:</span>
              <span class="mono">{{ fp.domain_pattern }}</span>
            </div>
            <div class="fp-reason" *ngIf="fp.reason">{{ fp.reason }}</div>
          </div>
          <div class="fp-card-footer">
            <span class="fp-created">Created: {{ formatDate(fp.created_at) }}</span>
            <span class="fp-by" *ngIf="fp.created_by">by {{ fp.created_by }}</span>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .page-header { display: flex; align-items: center; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }
    .page-header h1 { margin: 0; font-size: 1.4rem; }

    /* Summary */
    .summary-section {
      background: #111927;
      border: 1px solid #1e2d3d;
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 16px;
    }
    .summary-row {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      margin-bottom: 6px;
    }
    .summary-row:last-child { margin-bottom: 0; }
    .summary-label {
      font-size: 0.65rem;
      text-transform: uppercase;
      color: #8b9cb5;
      margin-right: 4px;
      letter-spacing: 0.5px;
    }
    .sev-summary-badge {
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s;
      border: 2px solid transparent;
      color: #b0bec5;
      background: #1e2d3d;
    }
    .sev-summary-badge:hover { border-color: #4fc3f7; }
    .sev-summary-badge.active { border-color: #4fc3f7; box-shadow: 0 0 6px rgba(79,195,247,0.3); }
    .sev-sum-critical { background: #b71c1c; color: #ffcdd2; }
    .sev-sum-high { background: #bf360c; color: #ffccbc; }
    .sev-sum-medium { background: #e65100; color: #ffe0b2; }
    .sev-sum-low { background: #33691e; color: #c8e6c9; }
    .sev-sum-info { background: #1e2d3d; color: #90caf9; }

    .class-summary-tag {
      padding: 3px 10px;
      border-radius: 10px;
      font-size: 0.7rem;
      cursor: pointer;
      transition: all 0.15s;
      border: 1px solid #1e2d3d;
      color: #b0bec5;
      background: #0d1520;
    }
    .class-summary-tag em {
      font-style: normal;
      color: #8b9cb5;
      margin-left: 3px;
      font-size: 0.65rem;
    }
    .class-summary-tag:hover { border-color: #4fc3f7; color: #e0e6ed; }
    .class-summary-tag.active { border-color: #4fc3f7; color: #4fc3f7; }

    /* Filters */
    .filters-bar { display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; margin-bottom: 20px; padding: 14px; background: #111927; border: 1px solid #1e2d3d; border-radius: 8px; }
    .filter-group { display: flex; flex-direction: column; gap: 4px; }
    .filter-group label { font-size: 0.7rem; color: #8b9cb5; text-transform: uppercase; }
    .filter-input { padding: 6px 10px; background: #0d1520; border: 1px solid #1e2d3d; border-radius: 4px; color: #e0e6ed; font-size: 0.85rem; min-width: 120px; }
    .filter-input:focus { outline: none; border-color: #4fc3f7; }
    select.filter-input { cursor: pointer; }

    .btn { padding: 6px 14px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.8rem; white-space: nowrap; }
    .btn-primary { background: #1565c0; color: white; }
    .btn-primary:disabled { background: #0d3b6e; cursor: not-allowed; }
    .btn-secondary { background: #1e2d3d; color: #b0bec5; }
    .btn-secondary:hover { background: #2a3f5a; }

    /* Cards (mobile) */
    .alert-cards { display: none; flex-direction: column; gap: 10px; margin-bottom: 16px; }
    .alert-table-wrap { overflow-x: auto; border: 1px solid #1e2d3d; border-radius: 8px; margin-bottom: 16px; }

    @media (max-width: 768px) {
      .alert-cards { display: flex; }
      .alert-table-wrap { display: none; }
    }

    .alert-card { background: #111927; border: 1px solid #1e2d3d; border-radius: 8px; overflow: hidden; }
    .alert-card.critical { border-left: 3px solid #d32f2f; }
    .alert-card.high { border-left: 3px solid #e65100; }
    .alert-card.medium { border-left: 3px solid #f9a825; }
    .alert-card-header {
      display: flex; align-items: center; gap: 10px; padding: 10px 14px;
      background: #0d1520; border-bottom: 1px solid #1e2d3d; flex-wrap: wrap;
      cursor: pointer; user-select: none;
    }
    .alert-card-header:hover { background: #111927; }
    .alert-severity { padding: 2px 8px; border-radius: 10px; font-size: 0.65rem; text-transform: uppercase; font-weight: 700; background: #1e2d3d; color: #b0bec5; }
    .sev-critical { background: #b71c1c; color: #ffcdd2; }
    .sev-high { background: #bf360c; color: #ffccbc; }
    .sev-medium { background: #e65100; color: #ffe0b2; }
    .sev-low { background: #33691e; color: #c8e6c9; }
    .alert-classification { font-size: 0.85rem; flex: 1; }
    .alert-count-badge {
      background: #1a3a5a; color: #4fc3f7; padding: 2px 8px; border-radius: 10px;
      font-size: 0.75rem; font-weight: 700; font-family: monospace;
    }
    .alert-escalated { font-size: 0.75rem; color: #ffa726; }
    .expand-arrow { font-size: 0.7rem; color: #8b9cb5; margin-left: auto; }

    /* Enrichment row in card */
    .alert-enrich-row {
      display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
      padding: 6px 14px; background: #0a1018; border-bottom: 1px solid #1e2d3d;
      font-size: 0.75rem; color: #b0bec5;
    }
    .enrich-flag { font-size: 1rem; }
    .enrich-country { color: #e0e6ed; font-weight: 500; }
    .enrich-org { color: #8b9cb5; }
    .enrich-asn { color: #64b5f6; font-family: monospace; font-size: 0.7rem; }

    /* Behavioral flags row in card */
    .alert-flags-row {
      display: flex; flex-wrap: wrap; gap: 4px;
      padding: 4px 14px; background: #0a1018; border-bottom: 1px solid #1e2d3d;
    }
    .bf-tag {
      padding: 1px 7px; border-radius: 8px; font-size: 0.6rem; font-weight: 600;
      text-transform: uppercase; letter-spacing: 0.3px;
      background: #1a2a3a; color: #90caf9;
    }
    .bf-tag-sm { font-size: 0.55rem; padding: 1px 5px; }

    .mitre-badge {
      display: inline-block;
      padding: 1px 7px;
      border-radius: 8px;
      font-size: 0.6rem;
      font-weight: 700;
      font-family: monospace;
      background: #311b92;
      color: #b39ddb;
      cursor: help;
      white-space: nowrap;
    }

    .alert-card-body { padding: 10px 14px; }
    .alert-ips { font-family: monospace; font-size: 0.9rem; margin-bottom: 6px; }
    .alert-arrow { margin: 0 8px; color: #8b9cb5; }
    .alert-meta { font-size: 0.75rem; color: #8b9cb5; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 6px; }
    .alert-card-footer { margin-top: 8px; }
    .view-link { color: #4fc3f7; text-decoration: none; font-size: 0.85rem; }
    .view-link:hover { text-decoration: underline; }

    /* Engine tag */
    .engine-tag {
      padding: 1px 7px; border-radius: 8px; font-size: 0.6rem; font-weight: 600;
      text-transform: uppercase; letter-spacing: 0.3px;
    }
    .engine-ai { background: #0d47a1; color: #90caf9; }
    .engine-local { background: #37474f; color: #b0bec5; }

    /* Expanded timestamps in cards */
    .expanded-timestamps {
      margin-top: 8px; padding: 8px; background: #0a1018; border-radius: 6px;
      border: 1px solid #1e2d3d; max-height: 200px; overflow-y: auto;
    }
    .ts-header { font-size: 0.7rem; color: #8b9cb5; text-transform: uppercase; margin-bottom: 6px; }
    .ts-row { display: flex; align-items: center; gap: 12px; padding: 4px 0; border-bottom: 1px solid #0d1520; font-size: 0.75rem; }
    .ts-row:last-child { border-bottom: none; }
    .ts-time { color: #b0bec5; font-family: monospace; }
    .ts-meta { color: #8b9cb5; font-size: 0.7rem; }
    .ts-link { color: #4fc3f7; text-decoration: none; font-size: 0.75rem; margin-left: auto; }
    .ts-link:hover { text-decoration: underline; }

    /* Table */
    .alert-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; table-layout: auto; }
    .alert-table th { text-align: left; padding: 6px 8px; background: #0d1520; border-bottom: 2px solid #1e2d3d; color: #8b9cb5; font-size: 0.62rem; text-transform: uppercase; white-space: nowrap; }
    .alert-table td { padding: 6px 8px; border-bottom: 1px solid #1e2d3d; color: #b0bec5; vertical-align: middle; }
    .alert-row { cursor: pointer; }
    .alert-row:hover { background: #0d1520; }
    .alert-row.row-critical { border-left: 3px solid #d32f2f; }
    .alert-row.row-high { border-left: 3px solid #e65100; }
    .alert-row.row-expanded { background: #0d1520; }
    .mono { font-family: monospace; font-size: 0.78rem; color: #e0e6ed; }
    .td-time { white-space: nowrap; font-size: 0.72rem; color: #8b9cb5; }
    .class-cell { font-size: 0.76rem; }
    .count-badge {
      background: #1a3a5a; color: #4fc3f7; padding: 2px 6px; border-radius: 10px;
      font-size: 0.7rem; font-weight: 700; font-family: monospace; cursor: pointer;
    }
    .view-link-inline { color: #4fc3f7; text-decoration: none; font-size: 0.85rem; margin: 0 4px; }
    .view-link-inline:hover { opacity: 0.8; }
    .no-enrich { color: #4a5568; font-size: 0.72rem; }

    .flow-cell { white-space: nowrap; }
    .flow-ips { display: inline-flex; align-items: center; gap: 3px; }
    .flow-src, .flow-dst { font-size: 0.76rem; }
    .flow-arrow { color: #4a5568; font-size: 0.7rem; }

    .enrich-cell { font-size: 0.73rem; line-height: 1.3; max-width: 220px; overflow: hidden; text-overflow: ellipsis; }
    .enrich-cell .enrich-flag { font-size: 0.85rem; }
    .enrich-cell .enrich-country { color: #e0e6ed; font-weight: 500; }
    .enrich-cell .enrich-org { color: #8b9cb5; font-size: 0.68rem; }
    .enrich-rdns { color: #80cbc4; font-size: 0.68rem; font-family: monospace; }

    .action-badge { padding: 2px 8px; border-radius: 8px; font-size: 0.62rem; text-transform: uppercase; font-weight: 700; }
    .action-block { background: #b71c1c; color: #ffcdd2; }
    .action-pass { background: #1b5e20; color: #c8e6c9; }
    .domain-tag { color: #80cbc4; font-size: 0.72rem; font-family: monospace; font-weight: 500; }
    .proto-cell { font-size: 0.72rem; color: #8b9cb5; }
    .proto-tag { font-size: 0.68rem; color: #8b9cb5; font-family: monospace; }

    /* Expanded detail rows in table */
    .expanded-detail-row td {
      padding: 0;
      background: #0a1018;
      border-bottom: 2px solid #1e2d3d;
    }
    .expanded-detail-wrap {
      padding: 10px 14px; max-height: 240px; overflow-y: auto;
    }
    .expanded-header { font-size: 0.7rem; color: #8b9cb5; text-transform: uppercase; margin-bottom: 6px; }
    .expanded-sub-row {
      display: flex; align-items: center; gap: 16px; padding: 5px 0;
      border-bottom: 1px solid #0d1520; font-size: 0.78rem;
    }
    .expanded-sub-row:last-child { border-bottom: none; }
    .expanded-time { color: #b0bec5; font-family: monospace; min-width: 170px; }
    .expanded-conf { color: #8b9cb5; font-size: 0.72rem; }
    .expanded-dst { color: #8b9cb5; font-size: 0.72rem; font-family: monospace; }
    .expanded-link { color: #4fc3f7; text-decoration: none; font-size: 0.78rem; margin-left: auto; }
    .expanded-link:hover { text-decoration: underline; }

    .sev-badge { padding: 2px 8px; border-radius: 10px; font-size: 0.62rem; text-transform: uppercase; font-weight: 700; background: #1e2d3d; color: #b0bec5; white-space: nowrap; }
    .sev-critical { background: #b71c1c; color: #ffcdd2; }
    .sev-high { background: #bf360c; color: #ffccbc; }
    .sev-medium { background: #e65100; color: #ffe0b2; }
    .sev-low { background: #33691e; color: #c8e6c9; }
    .sev-info { background: #1e2d3d; color: #90caf9; }

    .pagination { display: flex; align-items: center; gap: 16px; }
    .count-info { font-size: 0.8rem; color: #8b9cb5; }

    .empty-state { text-align: center; padding: 60px 20px; color: #8b9cb5; }
    .error-msg { color: #ef5350; margin-bottom: 16px; }

    .btn-fp {
      background: transparent;
      border: 1px solid #ef5350;
      color: #ef5350;
      padding: 3px 10px;
      border-radius: 4px;
      font-size: 0.72rem;
      cursor: pointer;
      transition: all 0.15s;
    }
    .btn-fp:hover { background: #ef5350; color: #111927; }

    .btn-fp-sm {
      background: transparent;
      border: 1px solid #ef5350;
      color: #ef5350;
      padding: 1px 6px;
      border-radius: 3px;
      font-size: 0.65rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s;
      margin-left: 4px;
    }
    .btn-fp-sm:hover { background: #ef5350; color: #111927; }

    .fp-badge, .fp-badge-sm {
      background: #1b5e20;
      color: #a5d6a7;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.65rem;
      font-weight: 600;
    }
    .fp-badge-sm { padding: 1px 5px; font-size: 0.6rem; margin-left: 4px; }

    /* FP Patterns Section */
    .fp-patterns-section {
      background: #111927;
      border: 1px solid #1e2d3d;
      border-radius: 8px;
      padding: 20px;
      margin-top: 20px;
    }
    .fp-patterns-section .section-title {
      font-size: 1rem;
      color: #4fc3f7;
      margin: 0 0 14px;
    }
    .fp-patterns-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 12px;
    }
    .fp-pattern-card {
      background: #0d1520;
      border: 1px solid #1e2d3d;
      border-radius: 8px;
      overflow: hidden;
      transition: border-color 0.2s;
    }
    .fp-pattern-card:hover { border-color: #2a3f5a; }
    .fp-card-header {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 14px;
      background: #0a1018;
      border-bottom: 1px solid #1e2d3d;
      flex-wrap: wrap;
    }
    .fp-detector {
      font-size: 0.78rem;
      font-weight: 600;
      color: #64b5f6;
      font-family: monospace;
    }
    .fp-classification {
      font-size: 0.68rem;
      color: #8b9cb5;
      background: #1e2d3d;
      padding: 2px 8px;
      border-radius: 4px;
    }
    .fp-count {
      font-size: 0.72rem;
      color: #ffa726;
      font-weight: 700;
      margin-left: auto;
    }
    .btn-delete-pattern {
      background: transparent;
      border: 1px solid #ef5350;
      color: #ef5350;
      border-radius: 50%;
      width: 22px;
      height: 22px;
      font-size: 0.8rem;
      cursor: pointer;
      line-height: 1;
      padding: 0;
      transition: all 0.15s;
    }
    .btn-delete-pattern:hover { background: #ef5350; color: #111927; }
    .fp-card-body {
      padding: 10px 14px;
    }
    .fp-rule {
      display: flex;
      align-items: center;
      gap: 6px;
      margin-bottom: 4px;
    }
    .fp-label {
      font-size: 0.62rem;
      text-transform: uppercase;
      color: #5a6a7a;
      font-weight: 600;
      min-width: 50px;
    }
    .fp-rule .mono {
      font-size: 0.78rem;
      color: #e0e6ed;
    }
    .fp-reason {
      font-size: 0.75rem;
      color: #8b9cb5;
      margin-top: 6px;
      font-style: italic;
    }
    .fp-card-footer {
      padding: 8px 14px;
      border-top: 1px solid #1e2d3d;
      display: flex;
      gap: 8px;
    }
    .fp-created { font-size: 0.65rem; color: #5a6a7a; }
    .fp-by { font-size: 0.65rem; color: #8b9cb5; }

    .empty-sub { padding: 20px; text-align: center; color: #8b9cb5; font-size: 0.85rem; }

    .td-actions { white-space: nowrap; }
  `]
})
export class AlertHistoryComponent implements OnInit {
  alerts: Alert[] = [];
  groups: AlertGroup[] = [];
  loading = false;
  error = '';
  offset = 0;
  limit = 50;

  filters: any = {
    severity: '',
    classification: '',
    source_ip: '',
    action: '',
    escalate: '',
    since: '',
    until: '',
  };

  // Summary data
  severityCounts: SeverityCount[] = [];
  topClassifications: ClassCount[] = [];
  totalLoaded = 0;

  // FP Patterns
  fpPatterns: FpPattern[] = [];
  fpPatternsLoaded = false;

  // All known severity levels in order
  private allSeverities = ['critical', 'high', 'medium', 'low', 'info'];

  constructor(private api: ApiService) {}

  ngOnInit() {
    this.applyFilters();
    this.loadFpPatterns();
  }

  applyFilters() {
    this.offset = 0;
    this.alerts = [];
    this.groups = [];
    this.totalLoaded = 0;
    this.severityCounts = [];
    this.topClassifications = [];
    this.loadMore();
  }

  loadMore() {
    this.loading = true;
    this.error = '';

    const params: any = { limit: this.limit, offset: this.offset };
    if (this.filters.severity) params.severity = this.filters.severity;
    if (this.filters.classification) params.classification = this.filters.classification;
    if (this.filters.source_ip) params.source_ip = this.filters.source_ip;
    if (this.filters.action) params.action = this.filters.action;
    if (this.filters.escalate !== '') params.escalate = this.filters.escalate;
    if (this.filters.since) params.since = this.filters.since + 'T00:00:00';
    if (this.filters.until) params.until = this.filters.until + 'T23:59:59';

    this.api.getAlerts(params).subscribe({
      next: (data) => {
        this.alerts = this.alerts.concat(data);
        this.offset += data.length;
        this.totalLoaded = this.alerts.length;
        this.loading = false;
        this.rebuildGroups();
        this.rebuildSummary();
      },
      error: (err) => {
        this.error = err.error?.detail || 'Failed to load alerts';
        this.loading = false;
      }
    });
  }

  clearFilters() {
    this.filters = { severity: '', classification: '', source_ip: '', action: '', escalate: '', since: '', until: '' };
    this.applyFilters();
  }

  /* ---------- Summary helpers ---------- */

  filterBySeverity(sev: string) {
    if (this.filters.severity === sev) {
      this.filters.severity = '';
    } else {
      this.filters.severity = sev;
    }
    this.applyFilters();
  }

  filterByClassification(cls: string) {
    if (this.filters.classification === cls) {
      this.filters.classification = '';
    } else {
      this.filters.classification = cls;
    }
    this.applyFilters();
  }

  private rebuildSummary() {
    // Severity counts
    const sevMap = new Map<string, number>();
    for (const a of this.alerts) {
      const s = a.severity || 'info';
      sevMap.set(s, (sevMap.get(s) || 0) + 1);
    }
    this.severityCounts = this.allSeverities.map(s => ({
      severity: s,
      count: sevMap.get(s) || 0
    }));

    // Top 5 classifications
    const clsMap = new Map<string, number>();
    for (const a of this.alerts) {
      const c = a.classification || 'unknown';
      clsMap.set(c, (clsMap.get(c) || 0) + 1);
    }
    this.topClassifications = Array.from(clsMap.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([classification, count]) => ({ classification, count }));
  }

  /* ---------- Grouping ---------- */

  private rebuildGroups() {
    const result: AlertGroup[] = [];
    for (const alert of this.alerts) {
      const key = alert.src_ip + '|' + alert.classification;
      const last = result[result.length - 1];
      if (last && last.key === key) {
        last.alerts.push(alert);
        last.count = last.alerts.length;
      } else {
        result.push({
          key,
          count: 1,
          alerts: [alert],
          representative: alert,
          expanded: false
        });
      }
    }
    this.groups = result;
  }

  toggleGroup(group: AlertGroup) {
    group.expanded = !group.expanded;
  }

  /* ---------- Enrichment helpers ---------- */

  getEnrichment(alert: Alert): any | null {
    const da = alert.llm_analysis;
    if (!da || typeof da !== 'object') return null;
    const enr = da.enrichment;
    if (!enr || typeof enr !== 'object') return null;
    // Pick the external (remote) IP for enrichment — not one of ours
    const remoteIp = isOwnIp(alert.src_ip) ? alert.dst_ip : alert.src_ip;
    if (enr[remoteIp]) return enr[remoteIp];
    // Fallback: return first entry with actual geo/org data
    for (const key of Object.keys(enr)) {
      const e = enr[key];
      if (e && (e.country || e.org || e.isp || e.reverse_dns) && e.org !== NETWORK_CONFIG.name) return e;
    }
    return null;
  }

  getFirewallAction(alert: Alert): string {
    return (alert as any).firewall_action || alert.llm_analysis?.firewall_action || '';
  }

  getDstDomain(alert: Alert): string {
    return (alert as any).dst_domain || alert.llm_analysis?.dst_domain || '';
  }

  getProtocol(alert: Alert): string {
    const da = alert.llm_analysis;
    if (!da) return '';
    const proto = da.protocol || '';
    const port = da.dst_port;
    return port ? `${proto}/${port}` : proto;
  }

  countryEmoji(code: string | undefined): string {
    if (!code || code.length !== 2) return '🌐';
    const a = code.toUpperCase().charCodeAt(0) - 0x41 + 0x1F1E6;
    const b = code.toUpperCase().charCodeAt(1) - 0x41 + 0x1F1E6;
    if (a < 0x1F1E6 || a > 0x1F1FF || b < 0x1F1E6 || b > 0x1F1FF) return '🌐';
    return String.fromCodePoint(a, b);
  }

  getBehavioralFlags(alert: Alert): string[] {
    const flags = alert.behavioral_flags || [];
    if (!Array.isArray(flags)) return [];
    const seen = new Set<string>();
    const result: string[] = [];
    for (const f of flags) {
      const name = typeof f === 'string' ? f : (f.flag_type || f.type || f.name || '');
      if (name && !seen.has(name)) {
        seen.add(name);
        result.push(name);
      }
    }
    return result;
  }

  getAnalysisSource(alert: Alert): 'ai' | 'local' {
    const da = alert.llm_analysis;
    if (!da || typeof da !== 'object') return 'local';
    if (da.source === 'local_rules') return 'local';
    return 'ai';
  }

  /* ---------- Utilities ---------- */

  formatIpLabel(ip: string | undefined): string {
    return formatIpLabel(ip);
  }

  formatIpShort(ip: string | undefined): string {
    return formatIpShort(ip);
  }

  formatTimeShort(ts: string | undefined): string {
    if (!ts) return '';
    try {
      const d = new Date(ts);
      const now = new Date();
      const diffMs = now.getTime() - d.getTime();
      if (diffMs < 86400000) {
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      }
      return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' +
        d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch { return ts; }
  }

  markFalsePositive(alert: Alert) {
    this.api.updateAlertStatus(alert.id, 'false_positive').subscribe({
      next: () => {
        alert.status = 'false_positive';
      },
      error: (err) => {
        this.error = err.error?.detail || 'Failed to mark as false positive';
      }
    });
  }

  formatDate(ts: string | undefined): string {
    if (!ts) return '';
    try { return new Date(ts).toLocaleString(); } catch { return ts; }
  }

  loadFpPatterns() {
    this.api.getFpPatterns().subscribe({
      next: (data) => {
        this.fpPatterns = data || [];
        this.fpPatternsLoaded = true;
      },
      error: () => { this.fpPatternsLoaded = true; }
    });
  }

  deleteFpPattern(pattern: FpPattern) {
    this.api.deleteFpPattern(pattern.id).subscribe({
      next: () => {
        this.fpPatterns = this.fpPatterns.filter(p => p.id !== pattern.id);
      },
      error: (err) => {
        this.error = err.error?.detail || 'Failed to delete FP pattern';
      }
    });
  }
}
