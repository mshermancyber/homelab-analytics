import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { ApiService, EventDetail, RelatedAlert } from '../../services/api.service';
import { formatIpLabel } from '../../config/network.config';

@Component({
  selector: 'app-event-detail',
  standalone: true,
  imports: [CommonModule, RouterModule],
  template: `
    <div class="page-header">
      <a class="back-link" [routerLink]="isAlertView ? '/alerts' : '/live-feed'">← Back</a>
      <h1>{{ isAlertView ? 'Alert Detail' : 'Event Detail' }}</h1>
    </div>

    <div class="error-msg" *ngIf="error">{{ error }}</div>

    <!-- Alert view: shows alert data first, then linked event -->
    <div class="detail-container" *ngIf="isAlertView && alertDetail">
      <section class="detail-section">
        <h2>Alert Info</h2>
        <div class="event-grid">
          <div class="kv"><strong>Alert ID:</strong> {{ alertDetail.alert.id }}</div>
          <div class="kv"><strong>Severity:</strong> <span class="sev-badge" [class.sev-critical]="alertDetail.alert.severity === 'critical'" [class.sev-high]="alertDetail.alert.severity === 'high'" [class.sev-medium]="alertDetail.alert.severity === 'medium'" [class.sev-low]="alertDetail.alert.severity === 'low'">{{ alertDetail.alert.severity }}</span></div>
          <div class="kv"><strong>Classification:</strong> {{ alertDetail.alert.classification }}</div>
          <div class="kv"><strong>Confidence:</strong> {{ alertDetail.alert.confidence | number:'1.0-0' }}%</div>
          <div class="kv"><strong>Source IP:</strong> <span class="mono">{{ formatIpLabel(alertDetail.alert.src_ip) }}</span></div>
          <div class="kv"><strong>Dest IP:</strong> <span class="mono">{{ formatIpLabel(alertDetail.alert.dst_ip) }}</span></div>
          <div class="kv"><strong>Status:</strong> {{ alertDetail.alert.status }}</div>
          <div class="kv"><strong>Created:</strong> {{ formatDate(alertDetail.alert.created_at) }}</div>
          <div class="kv" *ngIf="alertDetail.alert.escalate"><strong>Escalated:</strong> Yes</div>
        </div>
      </section>

      <!-- Enrichment -->
      <section class="detail-section" *ngIf="getAlertEnrichment() as enrichKeys">
        <h2>Enrichment</h2>
        <div class="enrich-grid" *ngIf="enrichKeys.length > 0">
          <div *ngFor="let key of enrichKeys" class="enrich-card">
            <div class="enrich-card-hdr">{{ key }}</div>
            <div class="enrich-card-body">
              <ng-container *ngIf="alertDetail.alert.llm_analysis.enrichment[key] as enr">
                <div class="kv" *ngIf="enr.country"><strong>Country:</strong> {{ countryEmoji(enr.country_code) }} {{ enr.country }}</div>
                <div class="kv" *ngIf="enr.city"><strong>City:</strong> {{ enr.city }}<span *ngIf="enr.region">, {{ enr.region }}</span></div>
                <div class="kv" *ngIf="enr.org"><strong>Org:</strong> {{ enr.org }}</div>
                <div class="kv" *ngIf="enr.isp && enr.isp !== enr.org"><strong>ISP:</strong> {{ enr.isp }}</div>
                <div class="kv" *ngIf="enr.asn"><strong>ASN:</strong> {{ enr.asn }}</div>
                <div class="kv" *ngIf="enr.reverse_dns"><strong>rDNS:</strong> <span class="mono">{{ enr.reverse_dns }}</span></div>
                <div class="kv" *ngIf="realResolvedIps(enr.resolved_ips) as rips"><strong>Resolved IPs:</strong> <span class="mono">{{ rips.join(', ') }}</span></div>
              </ng-container>
            </div>
          </div>
        </div>
      </section>

      <!-- Behavioral flags from alert -->
      <section class="detail-section" *ngIf="alertDetail.alert.behavioral_flags?.length > 0">
        <h2>Behavioral Flags</h2>
        <div class="flag-list">
          <div *ngFor="let bf of alertDetail.alert.behavioral_flags" class="flag-card">
            <div class="flag-header">
              <span class="flag-type">{{ formatFlagType(bf.flag_type) }}</span>
              <span class="flag-mitre" *ngIf="bf.details?.mitre_attack">{{ bf.details.mitre_attack[0] }}</span>
              <span class="flag-time" *ngIf="bf.timestamp">{{ formatDate(bf.timestamp) }}</span>
            </div>
            <div class="flag-desc" *ngIf="bf.details?.description">{{ bf.details.description }}</div>
            <div class="flag-kv" *ngIf="bf.details">
              <span class="flag-kv-item" *ngIf="bf.details.src_ip"><strong>Src:</strong> {{ bf.details.src_ip }}</span>
              <span class="flag-kv-item" *ngIf="bf.details.dst_ip"><strong>Dst:</strong> {{ bf.details.dst_ip }}</span>
              <span class="flag-kv-item" *ngIf="bf.details.count"><strong>Count:</strong> {{ bf.details.count }}</span>
              <span class="flag-kv-item" *ngIf="bf.details.interval"><strong>Interval:</strong> {{ bf.details.interval }}s</span>
              <span class="flag-kv-item" *ngIf="bf.details.stddev"><strong>StdDev:</strong> {{ bf.details.stddev | number:'1.1-1' }}s</span>
              <span class="flag-kv-item" *ngIf="bf.details.entropy"><strong>Entropy:</strong> {{ bf.details.entropy | number:'1.2-2' }}</span>
              <span class="flag-kv-item" *ngIf="bf.details.ports?.length"><strong>Ports:</strong> {{ bf.details.ports.slice(0, 10).join(', ') }}<span *ngIf="bf.details.ports.length > 10"> +{{ bf.details.ports.length - 10 }}</span></span>
              <span class="flag-kv-item" *ngIf="bf.details.domain"><strong>Domain:</strong> {{ bf.details.domain }}</span>
              <span class="flag-kv-item" *ngIf="bf.details.feed"><strong>Feed:</strong> {{ bf.details.feed }}</span>
            </div>
          </div>
        </div>
      </section>

      <!-- Threat matches from alert -->
      <section class="detail-section" *ngIf="alertDetail.alert.threat_matches?.length > 0">
        <h2>Threat Intelligence Matches</h2>
        <div class="match-grid">
          <div *ngFor="let tm of alertDetail.alert.threat_matches" class="match-card">
            <div class="match-header">
              <span class="match-category">{{ tm.threat_category }}</span>
              <span class="match-severity" [class.sev-critical]="tm.severity_hint === 'critical'" [class.sev-high]="tm.severity_hint === 'high'" [class.sev-medium]="tm.severity_hint === 'medium'">{{ tm.severity_hint }}</span>
            </div>
            <div class="match-body">
              <div class="mono">{{ tm.ioc_value }}</div>
              <div class="match-feed" *ngIf="tm.feed">Feed: {{ tm.feed }}</div>
            </div>
          </div>
        </div>
      </section>

      <!-- Triage Analysis -->
      <section class="detail-section" *ngIf="hasAnalysis()">
        <h2>Analysis</h2>

        <!-- Connection Details -->
        <div class="analysis-sub" *ngIf="getConnectionDetails() as conn">
          <h3>Connection Details</h3>
          <div class="conn-row">
            <div class="conn-chip" *ngIf="conn.firewall_action">
              <span class="conn-label">Action</span>
              <span class="conn-value" [class.action-pass]="conn.firewall_action === 'pass'" [class.action-block]="conn.firewall_action === 'block'">{{ conn.firewall_action }}</span>
            </div>
            <div class="conn-chip" *ngIf="conn.protocol">
              <span class="conn-label">Protocol</span>
              <span class="conn-value">{{ conn.protocol | uppercase }}</span>
            </div>
            <div class="conn-chip" *ngIf="conn.dst_port">
              <span class="conn-label">Dest Port</span>
              <span class="conn-value mono">{{ conn.dst_port }}</span>
            </div>
            <div class="conn-chip" *ngIf="conn.dst_domain">
              <span class="conn-label">Domain</span>
              <span class="conn-value mono">{{ conn.dst_domain }}</span>
            </div>
          </div>
        </div>

        <!-- ML Ensemble Score -->
        <div class="analysis-sub" *ngIf="getEnsembleScore() !== null">
          <h3>ML Ensemble Score</h3>
          <div class="score-bar-container">
            <div class="score-bar-track">
              <div class="score-bar-fill" [style.width.%]="(getEnsembleScore() ?? 0) * 100" [style.background]="scoreColor(getEnsembleScore() ?? 0)"></div>
            </div>
            <span class="score-value" [style.color]="scoreColor(getEnsembleScore() ?? 0)">{{ ((getEnsembleScore() ?? 0) * 100).toFixed(1) }}%</span>
          </div>
        </div>

        <!-- Policy Scores -->
        <div class="analysis-sub" *ngIf="getPolicyScores() as ps">
          <h3>Policy Scores</h3>
          <div class="policy-composite">
            <span class="policy-composite-label">Composite Score</span>
            <span class="policy-composite-value" [style.background]="scoreColor(ps.composite_score ?? 0)">{{ ((ps.composite_score ?? 0) * 100).toFixed(1) }}%</span>
          </div>
          <div class="policy-meta" *ngIf="ps.active_policies != null">Active policies: {{ ps.active_policies }}</div>
          <div class="policy-grid" *ngIf="getPolicyIndividual(ps) as policies">
            <div *ngFor="let p of policies" class="policy-card">
              <div class="policy-name">{{ p.name }}</div>
              <div class="policy-score" [style.color]="scoreColor(p.score)">{{ (p.score * 100).toFixed(0) }}%</div>
            </div>
          </div>
        </div>

        <!-- MITRE ATT&CK -->
        <div class="analysis-sub" *ngIf="alertDetail.alert.attack_technique || alertDetail.alert.attack_tactic">
          <h3>MITRE ATT&CK</h3>
          <div class="mitre-row">
            <div class="mitre-chip" *ngIf="alertDetail.alert.attack_tactic">
              <span class="mitre-label">Tactic</span>
              <span class="mitre-value">{{ alertDetail.alert.attack_tactic }}</span>
            </div>
            <div class="mitre-chip" *ngIf="alertDetail.alert.attack_technique">
              <span class="mitre-label">Technique</span>
              <span class="mitre-value">{{ alertDetail.alert.attack_technique }}</span>
            </div>
          </div>
        </div>

        <!-- Remaining fields -->
        <div class="analysis-sub" *ngIf="getAnalysisRemainder() as rem">
          <h3 *ngIf="rem.length > 0">Additional Details</h3>
          <div class="remainder-grid" *ngIf="rem.length > 0">
            <div *ngFor="let kv of rem" class="remainder-item">
              <span class="remainder-key">{{ kv.key }}</span>
              <span class="remainder-val" *ngIf="!isObject(kv.value)">{{ kv.value }}</span>
              <pre class="remainder-val-obj" *ngIf="isObject(kv.value)">{{ kv.value | json }}</pre>
            </div>
          </div>
        </div>
      </section>

      <!-- Investigation Playbook -->
      <section class="detail-section" *ngIf="alertDetail.alert.investigation_guide">
        <h2>🕵️ Investigation Playbook</h2>
        <div class="playbook-body">
          <div class="playbook-section" *ngIf="alertDetail.alert.investigation_guide.summary">
            <h3>Summary</h3>
            <p>{{ alertDetail.alert.investigation_guide.summary }}</p>
          </div>
          <div class="playbook-section" *ngIf="alertDetail.alert.investigation_guide.steps?.length > 0">
            <h3>Steps</h3>
            <ol class="playbook-steps">
              <li *ngFor="let step of alertDetail.alert.investigation_guide.steps">{{ step }}</li>
            </ol>
          </div>
          <div class="playbook-section" *ngIf="alertDetail.alert.investigation_guide.references?.length > 0">
            <h3>References</h3>
            <ul class="playbook-refs">
              <li *ngFor="let ref of alertDetail.alert.investigation_guide.references">
                <a [href]="ref" target="_blank" rel="noopener">{{ ref }}</a>
              </li>
            </ul>
          </div>
        </div>
      </section>

      <!-- Linked raw event -->
      <section class="detail-section" *ngIf="alertDetail.linked_events?.length > 0">
        <h2>Linked Events</h2>
        <div *ngFor="let ev of alertDetail.linked_events" class="linked-event">
          <div class="event-grid">
            <div class="kv"><strong>Event ID:</strong> {{ ev.id }}</div>
            <div class="kv"><strong>Type:</strong> {{ ev.event_type?.toUpperCase() }}</div>
            <div class="kv"><strong>Source IP:</strong> <span class="mono">{{ ev.source_ip }}</span></div>
            <div class="kv"><strong>Timestamp:</strong> {{ formatDate(ev.timestamp) }}</div>
          </div>
          <div class="raw-block" *ngIf="ev.raw_message">
            <h3>Raw Message</h3>
            <pre>{{ ev.raw_message }}</pre>
          </div>
          <div class="parsed-block" *ngIf="ev.parsed_fields && keys(ev.parsed_fields).length > 0">
            <h3>Parsed Fields</h3>
            <pre>{{ ev.parsed_fields | json }}</pre>
          </div>
        </div>
      </section>

      <!-- Related Alerts Timeline (from API) -->
      <section class="detail-section">
        <h2>🕒 Alert Timeline</h2>
        <div class="empty-sub" *ngIf="!relatedAlertsLoaded">
          <p>Loading timeline...</p>
        </div>
        <div class="empty-sub" *ngIf="relatedAlertsLoaded && relatedAlerts.length === 0">
          <p>No related alerts found.</p>
        </div>
        <div class="timeline-cap" *ngIf="relatedAlertsLoaded && relatedAlerts.length > 10">
          <p>Showing 10 of {{ relatedAlerts.length }} related alerts</p>
        </div>
        <div class="timeline" *ngIf="relatedAlertsLoaded && relatedAlerts.length > 0">
          <div *ngFor="let ra of cappedRelatedAlerts()" class="timeline-item">
            <div class="timeline-dot" [class.dot-critical]="ra.severity === 'critical'" [class.dot-high]="ra.severity === 'high'"></div>
            <div class="timeline-content">
              <div class="timeline-hdr">
                <span class="sev-badge" [class.sev-critical]="ra.severity === 'critical'" [class.sev-high]="ra.severity === 'high'" [class.sev-medium]="ra.severity === 'medium'" [class.sev-low]="ra.severity === 'low'">{{ ra.severity }}</span>
                <span class="timeline-class">{{ ra.classification }}</span>
              </div>
              <div class="timeline-body">
                <span class="mono">{{ ra.src_ip }} → {{ ra.dst_ip }}</span>
              </div>
              <div class="timeline-time">{{ formatDate(ra.created_at) }}</div>
              <div class="timeline-link">
                <a [routerLink]="['/alerts', ra.id]">View Alert →</a>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>

    <!-- Event view (from /events/:id route) -->
    <div class="detail-container" *ngIf="!isAlertView && detail">
      <section class="detail-section">
        <h2>Event Info</h2>
        <div class="event-grid">
          <div class="kv"><strong>Event ID:</strong> {{ detail.event.id }}</div>
          <div class="kv"><strong>Type:</strong> {{ detail.event.event_type?.toUpperCase() }}</div>
          <div class="kv"><strong>Source IP:</strong> <span class="mono">{{ detail.event.source_ip }}</span></div>
          <div class="kv"><strong>Device:</strong> {{ detail.event.source_device }}</div>
          <div class="kv"><strong>Timestamp:</strong> {{ detail.event.timestamp }}</div>
          <div class="kv"><strong>Received:</strong> {{ detail.event.received_at }}</div>
        </div>

        <div class="raw-block" *ngIf="detail.event.raw_message">
          <h3>Raw Message</h3>
          <pre>{{ detail.event.raw_message }}</pre>
        </div>

        <div class="parsed-block" *ngIf="detail.event.parsed_fields && keys(detail.event.parsed_fields).length > 0">
          <h3>Parsed Fields</h3>
          <pre>{{ detail.event.parsed_fields | json }}</pre>
        </div>
      </section>

      <section class="detail-section">
        <h2>Threat Intelligence Matches</h2>
        <div class="empty-sub" *ngIf="!detail.threat_matches || detail.threat_matches.length === 0">
          <p>No threat intelligence matches found.</p>
        </div>
        <div class="match-grid" *ngIf="detail.threat_matches && detail.threat_matches.length > 0">
          <div *ngFor="let tm of detail.threat_matches" class="match-card">
            <div class="match-header">
              <span class="match-category">{{ tm.threat_category }}</span>
              <span class="match-severity" [class.sev-critical]="tm.severity_hint === 'critical'" [class.sev-high]="tm.severity_hint === 'high'">{{ tm.severity_hint }}</span>
            </div>
            <div class="match-body">
              <div class="mono">{{ tm.ioc_value }}</div>
              <div class="match-feed">Feed ID: {{ tm.feed_id }} | First Seen: {{ tm.first_seen }}</div>
            </div>
          </div>
        </div>
      </section>

      <section class="detail-section">
        <h2>Behavioral Flags</h2>
        <div class="empty-sub" *ngIf="!detail.behavioral_flags || detail.behavioral_flags.length === 0">
          <p>No behavioral flags detected.</p>
        </div>
        <div class="flag-list" *ngIf="detail.behavioral_flags && detail.behavioral_flags.length > 0">
          <div *ngFor="let bf of detail.behavioral_flags" class="flag-card">
            <span class="flag-type">{{ bf.flag_type }}</span>
            <span class="flag-time">{{ bf.timestamp }}</span>
            <pre class="flag-details" *ngIf="bf.details">{{ bf.details | json }}</pre>
          </div>
        </div>
      </section>

      <section class="detail-section">
        <h2>Related Alerts</h2>
        <div class="empty-sub" *ngIf="!detail.alerts || detail.alerts.length === 0">
          <p>No related alerts.</p>
        </div>
        <div class="alert-list" *ngIf="detail.alerts && detail.alerts.length > 0">
          <div *ngFor="let alert of detail.alerts" class="alert-detail-card" [class.alert-escalated]="alert.escalate">
            <div class="alert-card-hdr">
              <span class="alert-sev" [class.sev-critical]="alert.severity === 'critical'" [class.sev-high]="alert.severity === 'high'">{{ alert.severity }}</span>
              <span class="alert-class">{{ alert.classification }}</span>
              <span class="alert-conf">Confidence: {{ alert.confidence }}%</span>
              <span class="alert-esc" *ngIf="alert.escalate">Escalated</span>
            </div>
            <div class="alert-time">Created: {{ alert.created_at }}</div>
          </div>
        </div>
        </section>

        <!-- Related Alerts Timeline (from API) -->
        <section class="detail-section">
          <h2>🕒 Alert Timeline</h2>
          <div class="empty-sub" *ngIf="!relatedAlertsLoaded">
            <p>Loading timeline...</p>
          </div>
          <div class="empty-sub" *ngIf="relatedAlertsLoaded && relatedAlerts.length === 0">
            <p>No related alerts found for this event.</p>
          </div>
          <div class="timeline-cap" *ngIf="relatedAlertsLoaded && relatedAlerts.length > 10">
            <p>Showing 10 of {{ relatedAlerts.length }} related alerts</p>
          </div>
          <div class="timeline" *ngIf="relatedAlertsLoaded && relatedAlerts.length > 0">
            <div *ngFor="let ra of cappedRelatedAlerts()" class="timeline-item">
              <div class="timeline-dot" [class.dot-critical]="ra.severity === 'critical'" [class.dot-high]="ra.severity === 'high'"></div>
              <div class="timeline-content">
                <div class="timeline-hdr">
                  <span class="sev-badge" [class.sev-critical]="ra.severity === 'critical'" [class.sev-high]="ra.severity === 'high'" [class.sev-medium]="ra.severity === 'medium'" [class.sev-low]="ra.severity === 'low'">{{ ra.severity }}</span>
                  <span class="timeline-class">{{ ra.classification }}</span>
                  <span class="timeline-meta" *ngIf="ra.attack_technique">{{ ra.attack_technique }}</span>
                </div>
                <div class="timeline-body">
                  <span class="mono">{{ ra.src_ip }} → {{ ra.dst_ip }}</span>
                </div>
                <div class="timeline-time">{{ formatDate(ra.created_at) }}</div>
                <div class="timeline-link">
                  <a [routerLink]="['/alerts', ra.id]">View Alert →</a>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>

      <div class="empty-state" *ngIf="!detail && !alertDetail && !error">
        <p>Loading details...</p>
    </div>
  `,
  styles: [`
    .page-header { display: flex; align-items: center; gap: 16px; margin-bottom: 20px; }
    .page-header h1 { margin: 0; font-size: 1.4rem; }
    .back-link { color: #4fc3f7; text-decoration: none; font-size: 1rem; }
    .back-link:hover { text-decoration: underline; }

    .detail-container { display: flex; flex-direction: column; gap: 20px; }

    .detail-section { background: #111927; border: 1px solid #1e2d3d; border-radius: 8px; padding: 20px; }
    .detail-section h2 { margin: 0 0 14px; font-size: 1rem; color: #4fc3f7; }
    .detail-section h3 { margin: 12px 0 6px; font-size: 0.85rem; color: #8b9cb5; }
    .detail-section h4 { margin: 8px 0 6px; font-size: 0.8rem; color: #8b9cb5; }

    .event-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    @media (max-width: 600px) { .event-grid { grid-template-columns: 1fr; } }

    .kv { font-size: 0.85rem; color: #b0bec5; }
    .kv strong { color: #8b9cb5; }
    .mono { font-family: monospace; font-size: 0.85rem; color: #e0e6ed; }

    pre { background: #0d1520; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 0.8rem; color: #b0bec5; max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }

    .raw-block, .parsed-block { margin-top: 12px; }

    .match-grid { display: flex; flex-direction: column; gap: 8px; }
    .match-card { background: #0d1520; border: 1px solid #1e2d3d; border-radius: 6px; overflow: hidden; }
    .match-header { display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: #111927; border-bottom: 1px solid #1e2d3d; }
    .match-category { font-size: 0.75rem; color: #64b5f6; background: #0d2137; padding: 2px 8px; border-radius: 4px; }
    .match-severity { padding: 2px 8px; border-radius: 10px; font-size: 0.65rem; text-transform: uppercase; font-weight: 600; }
    .sev-critical { background: #b71c1c; color: #ffcdd2; }
    .sev-high { background: #bf360c; color: #ffccbc; }
    .match-body { padding: 8px 12px; }
    .match-feed { font-size: 0.7rem; color: #8b9cb5; margin-top: 4px; }

    .flag-list { display: flex; flex-direction: column; gap: 8px; }
    .flag-card { background: #0d1520; border: 1px solid #1e2d3d; border-left: 3px solid #ffa726; border-radius: 6px; padding: 10px 14px; }
    .flag-header { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 4px; }
    .flag-type { font-weight: 600; font-size: 0.85rem; color: #ffa726; letter-spacing: 0.3px; }
    .flag-mitre { font-size: 0.65rem; color: #ce93d8; background: #1a0a2e; padding: 2px 8px; border-radius: 10px; font-family: monospace; }
    .flag-time { font-size: 0.7rem; color: #8b9cb5; margin-left: auto; }
    .flag-desc { font-size: 0.8rem; color: #b0bec5; margin-bottom: 6px; line-height: 1.4; }
    .flag-kv { display: flex; flex-wrap: wrap; gap: 6px; }
    .flag-kv-item { font-size: 0.72rem; color: #8b9cb5; background: #111927; padding: 2px 8px; border-radius: 4px; }
    .flag-kv-item strong { color: #5a6a7a; margin-right: 4px; }
    .flag-details { margin-top: 6px; font-size: 0.75rem; max-height: 150px; }

    .alert-list { display: flex; flex-direction: column; gap: 12px; }
    .alert-detail-card { background: #0d1520; border: 1px solid #1e2d3d; border-radius: 8px; overflow: hidden; }
    .alert-detail-card.alert-escalated { border-left: 3px solid #ffa726; }
    .alert-card-hdr { display: flex; align-items: center; gap: 12px; padding: 10px 14px; background: #111927; border-bottom: 1px solid #1e2d3d; flex-wrap: wrap; }
    .alert-sev { padding: 3px 10px; border-radius: 10px; font-size: 0.7rem; text-transform: uppercase; font-weight: 700; background: #1e2d3d; color: #b0bec5; }
    .sev-critical { background: #b71c1c; color: #ffcdd2; }
    .sev-high { background: #bf360c; color: #ffccbc; }
    .alert-class { font-size: 0.85rem; font-weight: 500; flex: 1; }
    .alert-conf { font-size: 0.75rem; color: #8b9cb5; }
    .alert-esc { font-size: 0.75rem; color: #ffa726; }
    .alert-analysis { padding: 10px 14px; }
    .alert-time { padding: 8px 14px; font-size: 0.7rem; color: #8b9cb5; border-top: 1px solid #1e2d3d; }

    .enrich-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }
    .enrich-card { background: #0d1520; border: 1px solid #1e2d3d; border-radius: 6px; overflow: hidden; }
    .enrich-card-hdr { padding: 8px 12px; background: #111927; border-bottom: 1px solid #1e2d3d; font-family: monospace; font-size: 0.85rem; color: #4fc3f7; word-break: break-all; }
    .enrich-card-body { padding: 10px 12px; word-break: break-word; }
    .enrich-card-body .kv { margin-bottom: 4px; }

    .linked-event { background: #0d1520; border: 1px solid #1e2d3d; border-radius: 6px; padding: 14px; margin-bottom: 10px; }
    .linked-event .event-grid { margin-bottom: 8px; }

    /* Investigation Playbook */
    .playbook-body { color: #b0bec5; }
    .playbook-section { margin-bottom: 16px; }
    .playbook-section h3 { color: #ffa726; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.3px; }
    .playbook-section p { font-size: 0.85rem; line-height: 1.5; margin: 0; }
    .playbook-steps { margin: 4px 0 0; padding-left: 20px; }
    .playbook-steps li { font-size: 0.85rem; margin-bottom: 6px; line-height: 1.4; }
    .playbook-refs { margin: 4px 0 0; padding-left: 20px; }
    .playbook-refs li { font-size: 0.8rem; margin-bottom: 3px; word-break: break-all; }
    .playbook-refs a { color: #4fc3f7; }

    /* Timeline */
    .timeline { position: relative; padding-left: 20px; }
    .timeline::before { content: ''; position: absolute; left: 6px; top: 0; bottom: 0; width: 2px; background: #1e2d3d; }
    .timeline-item { position: relative; padding-left: 16px; margin-bottom: 16px; }
    .timeline-item:last-child { margin-bottom: 0; }
    .timeline-dot { position: absolute; left: -18px; top: 6px; width: 12px; height: 12px; border-radius: 50%; background: #546e7a; border: 2px solid #111927; z-index: 1; }
    .dot-critical { background: #ef5350; }
    .dot-high { background: #ff9800; }
    .timeline-content { background: #0d1520; border: 1px solid #1e2d3d; border-radius: 6px; padding: 10px 14px; }
    .timeline-hdr { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 6px; }
    .timeline-class { font-size: 0.8rem; font-weight: 500; color: #e0e6ed; }
    .timeline-meta { font-size: 0.7rem; color: #8b9cb5; }
    .timeline-body { margin-bottom: 4px; }
    .timeline-body .mono { font-size: 0.78rem; }
    .timeline-time { font-size: 0.68rem; color: #5a6a7a; }
    .timeline-link { margin-top: 4px; }
    .timeline-link a { font-size: 0.75rem; color: #4fc3f7; text-decoration: none; }
    .timeline-link a:hover { text-decoration: underline; }

    .sev-badge { padding: 2px 8px; border-radius: 10px; font-size: 0.7rem; text-transform: uppercase; font-weight: 700; background: #1e2d3d; color: #b0bec5; }
    .sev-critical { background: #b71c1c; color: #ffcdd2; }
    .sev-high { background: #bf360c; color: #ffccbc; }
    .sev-medium { background: #e65100; color: #ffe0b2; }
    .sev-low { background: #33691e; color: #c8e6c9; }

    .empty-sub { padding: 20px; text-align: center; color: #8b9cb5; font-size: 0.85rem; }
    .empty-state { text-align: center; padding: 60px 20px; color: #8b9cb5; }
    .error-msg { color: #ef5350; margin-bottom: 16px; }

    /* Timeline cap */
    .timeline-cap { padding: 6px 14px; text-align: center; }
    .timeline-cap p { font-size: 0.75rem; color: #8b9cb5; margin: 0; }

    /* Analysis section */
    .analysis-sub { margin-bottom: 16px; }
    .analysis-sub:last-child { margin-bottom: 0; }

    /* Connection details */
    .conn-row { display: flex; flex-wrap: wrap; gap: 10px; }
    .conn-chip { background: #0d1520; border: 1px solid #1e2d3d; border-radius: 6px; padding: 8px 14px; display: flex; flex-direction: column; gap: 2px; min-width: 90px; }
    .conn-label { font-size: 0.65rem; color: #8b9cb5; text-transform: uppercase; letter-spacing: 0.5px; }
    .conn-value { font-size: 0.85rem; color: #e0e6ed; font-weight: 500; }
    .action-pass { color: #66bb6a; }
    .action-block { color: #ef5350; }

    /* Ensemble score bar */
    .score-bar-container { display: flex; align-items: center; gap: 12px; }
    .score-bar-track { flex: 1; max-width: 300px; height: 10px; background: #0d1520; border-radius: 5px; overflow: hidden; border: 1px solid #1e2d3d; }
    .score-bar-fill { height: 100%; border-radius: 5px; transition: width 0.3s; }
    .score-value { font-size: 0.9rem; font-weight: 700; font-family: monospace; }

    /* Policy scores */
    .policy-composite { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
    .policy-composite-label { font-size: 0.8rem; color: #b0bec5; }
    .policy-composite-value { padding: 3px 12px; border-radius: 10px; font-size: 0.8rem; font-weight: 700; color: #fff; font-family: monospace; }
    .policy-meta { font-size: 0.75rem; color: #8b9cb5; margin-bottom: 8px; }
    .policy-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 8px; }
    @media (max-width: 600px) { .policy-grid { grid-template-columns: 1fr 1fr; } }
    .policy-card { background: #0d1520; border: 1px solid #1e2d3d; border-radius: 6px; padding: 8px 12px; display: flex; justify-content: space-between; align-items: center; }
    .policy-name { font-size: 0.75rem; color: #b0bec5; word-break: break-word; }
    .policy-score { font-size: 0.85rem; font-weight: 700; font-family: monospace; }

    /* MITRE ATT&CK */
    .mitre-row { display: flex; flex-wrap: wrap; gap: 10px; }
    .mitre-chip { background: #0d1520; border: 1px solid #1e2d3d; border-left: 3px solid #7e57c2; border-radius: 6px; padding: 8px 14px; display: flex; flex-direction: column; gap: 2px; }
    .mitre-label { font-size: 0.65rem; color: #8b9cb5; text-transform: uppercase; letter-spacing: 0.5px; }
    .mitre-value { font-size: 0.85rem; color: #ce93d8; font-weight: 500; }

    /* Remainder key-value */
    .remainder-grid { display: grid; grid-template-columns: 1fr; gap: 6px; }
    .remainder-item { display: flex; gap: 8px; font-size: 0.8rem; padding: 4px 0; border-bottom: 1px solid #1a2636; }
    .remainder-item:last-child { border-bottom: none; }
    .remainder-key { color: #8b9cb5; font-weight: 500; min-width: 120px; flex-shrink: 0; }
    .remainder-val { color: #e0e6ed; word-break: break-word; }
    .remainder-val-obj { margin: 0; padding: 6px 8px; font-size: 0.75rem; max-height: 120px; }
  `]
})
export class EventDetailComponent implements OnInit {
  detail: EventDetail | null = null;
  alertDetail: any = null;
  isAlertView = false;
  error = '';
  relatedAlerts: RelatedAlert[] = [];
  relatedAlertsLoaded = false;

  constructor(private route: ActivatedRoute, private api: ApiService) {}

  ngOnInit() {
    const id = this.route.snapshot.paramMap.get('id');
    const url = this.route.snapshot.url.map(s => s.path);
    this.isAlertView = url[0] === 'alerts';

    if (id && this.isAlertView) {
      this.api.getAlertDetail(+id).subscribe({
        next: (data) => { this.alertDetail = data; },
        error: (err) => { this.error = err.error?.detail || 'Failed to load alert detail'; }
      });
      this.api.getRelatedAlerts(+id).subscribe({
        next: (data) => {
          this.relatedAlerts = (data as any).related || [];
          this.relatedAlertsLoaded = true;
        },
        error: () => { this.relatedAlertsLoaded = true; }
      });
    } else if (id) {
      this.api.getEventDetail(+id).subscribe({
        next: (data) => { this.detail = data; },
        error: (err) => { this.error = err.error?.detail || 'Failed to load event detail'; }
      });
      this.api.getRelatedAlerts(+id).subscribe({
        next: (data) => {
          this.relatedAlerts = (data as any).related || [];
          this.relatedAlertsLoaded = true;
        },
        error: () => { this.relatedAlertsLoaded = true; }
      });
    }
  }

  keys(obj: any): string[] {
    return obj ? Object.keys(obj) : [];
  }

  formatIpLabel(ip: string | undefined): string {
    return formatIpLabel(ip);
  }

  formatDate(ts: string | undefined): string {
    if (!ts) return '';
    try { return new Date(ts).toLocaleString(); } catch { return ts || ''; }
  }

  countryEmoji(code: string | undefined): string {
    if (!code || code.length !== 2) return '';
    const a = code.toUpperCase().charCodeAt(0) - 0x41 + 0x1F1E6;
    const b = code.toUpperCase().charCodeAt(1) - 0x41 + 0x1F1E6;
    return String.fromCodePoint(a, b);
  }

  getAlertEnrichment(): string[] {
    const da = this.alertDetail?.alert?.llm_analysis;
    if (!da?.enrichment) return [];
    return Object.keys(da.enrichment);
  }

  private readonly _skipKeys = new Set([
    'source', 'enrichment', 'firewall_action', 'protocol', 'dst_port',
    'dst_domain', 'ensemble_score', 'policy_scores'
  ]);

  hasAnalysis(): boolean {
    const da = this.alertDetail?.alert?.llm_analysis;
    if (!da || typeof da !== 'object') return false;
    return this.getConnectionDetails() !== null
      || this.getEnsembleScore() !== null
      || this.getPolicyScores() !== null
      || Object.keys(da).some(k => k !== 'source' && k !== 'enrichment');
  }

  getConnectionDetails(): { firewall_action?: string; protocol?: string; dst_port?: number; dst_domain?: string } | null {
    const da = this.alertDetail?.alert?.llm_analysis;
    if (!da) return null;
    const conn: any = {};
    if (da.firewall_action) conn.firewall_action = da.firewall_action;
    if (da.protocol) conn.protocol = da.protocol;
    if (da.dst_port) conn.dst_port = da.dst_port;
    if (da.dst_domain) conn.dst_domain = da.dst_domain;
    return Object.keys(conn).length > 0 ? conn : null;
  }

  getEnsembleScore(): number | null {
    const da = this.alertDetail?.alert?.llm_analysis;
    if (!da || da.ensemble_score == null) return null;
    return da.ensemble_score;
  }

  getPolicyScores(): any | null {
    const da = this.alertDetail?.alert?.llm_analysis;
    if (!da?.policy_scores || typeof da.policy_scores !== 'object') return null;
    return da.policy_scores;
  }

  realResolvedIps(ips: string[] | undefined): string[] | null {
    if (!ips?.length) return null;
    // 0.0.0.0 / :: are Pi-hole block responses, not real resolutions
    const real = ips.filter(ip => ip && ip !== '0.0.0.0' && ip !== '::');
    return real.length > 0 ? real : null;
  }

  getPolicyIndividual(ps: any): { name: string; score: number }[] | null {
    if (!ps) return null;
    const skip = new Set(['composite_score', 'active_policies', 'consensus_count']);
    const items = Object.keys(ps)
      // Only 0-1 ratios are policy scores; counts/metadata are not percentages
      .filter(k => !skip.has(k) && typeof ps[k] === 'number' && ps[k] >= 0 && ps[k] <= 1)
      .map(k => ({ name: k.replace(/_/g, ' '), score: ps[k] }));
    return items.length > 0 ? items : null;
  }

  getAnalysisRemainder(): { key: string; value: any }[] {
    const da = this.alertDetail?.alert?.llm_analysis;
    if (!da) return [];
    return Object.keys(da)
      .filter(k => !this._skipKeys.has(k) && k !== 'source' && k !== 'enrichment')
      .map(k => ({ key: k.replace(/_/g, ' '), value: da[k] }));
  }

  isObject(val: any): boolean {
    return val !== null && typeof val === 'object';
  }

  formatFlagType(flagType: string): string {
    const labels: Record<string, string> = {
      'beaconing': 'Beaconing',
      'port_scan': 'Port Scan',
      'dga': 'DGA (Domain Generation)',
      'dga_classifier': 'DGA Classifier',
      'volume': 'High Volume',
      'dns_query_burst': 'DNS Query Burst',
      'dns_unknown_burst': 'DNS Unknown Burst',
      'unknown_source': 'Unknown Source',
      'dest_fanout': 'Destination Fanout',
      'haddrscan': 'Horizontal Address Scan',
      'sigma_dns': 'Sigma DNS Rule',
      'sigma_firewall': 'Sigma Firewall Rule',
      'brute_force': 'Brute Force',
      'dns_tunnel': 'DNS Tunnel',
      'first_seen': 'First Seen',
      'ddos_flood': 'DDoS Flood',
      'dns_amplification': 'DNS Amplification',
      'connection_without_dns': 'Connection Without DNS',
      'dns_flow_mismatch': 'DNS Flow Mismatch',
      'outbound_blocked_ratio': 'High Blocked Ratio',
      'lateral_movement': 'Lateral Movement',
    };
    return labels[flagType] || flagType.replace(/_/g, ' ');
  }

  scoreColor(score: number): string {
    if (score < 0.3) return '#66bb6a';
    if (score < 0.5) return '#ffca28';
    if (score < 0.7) return '#ffa726';
    return '#ef5350';
  }

  cappedRelatedAlerts(): RelatedAlert[] {
    return this.relatedAlerts.slice(0, 10);
  }
}
