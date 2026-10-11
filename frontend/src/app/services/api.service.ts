import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface SyslogEvent {
  id: number;
  timestamp: string;
  source_ip: string;
  source_device: string;
  raw_message: string;
  parsed_fields: any;
  event_type: string;
  received_at: string;
}

export interface Alert {
  id: number;
  src_ip: string;
  dst_ip: string;
  severity: string;
  classification: string;
  escalate: boolean;
  confidence: number;
  threat_matches: any[];
  behavioral_flags: any[];
  llm_analysis: any;
  firewall_action: string;
  dst_domain: string;
  created_at: string;
  status: string;
  attack_technique?: string;
  attack_tactic?: string;
}

export interface FeedStatus {
  name: string;
  category: string;
  status: string;
  ioc_count: number;
  last_refresh: string;
  error?: string;
}

export interface ThreatIntelStatus {
  total_iocs: number;
  feeds: FeedStatus[];
  feeds_loaded: number;
  feeds_failed: number;
  feeds_total: number;
}

export interface TopOffenders {
  top_sources: { src_ip: string; alert_count: number }[];
  top_destinations: { dst_ip: string; alert_count: number; country?: string; country_code?: string; org?: string; asn?: string; reverse_dns?: string }[];
  severity_breakdown: { [key: string]: number };
  top_classifications: { classification: string; count: number }[];
  period_days: number;
}

export interface NetworkOverview {
  active_hosts: { ip: string; event_count: number }[];
  flagged_hosts: { ip: string; alert_count: number }[];
  event_type_breakdown: { [key: string]: number };
  period_hours: number;
  total_events: number;
}

export interface EventDetail {
  event: SyslogEvent;
  threat_matches: any[];
  behavioral_flags: any[];
  alerts: any[];
}

export interface TimelineBucket {
  hour: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface RecentCriticalAlert {
  id: number;
  severity: string;
  classification: string;
  src_ip: string;
  dst_ip: string;
  dst_country: string | null;
  dst_org: string | null;
  created_at: string;
  status: string;
}

export interface DashboardSummary {
  total_alerts_24h: number;
  severity_breakdown: { critical: number; high: number; medium: number; low: number };
  prev_total_alerts?: number;
  prev_severity_breakdown?: { critical: number; high: number; medium: number; low: number };
  top_alert_types: { classification: string; count: number }[];
  top_destination_countries: { country: string; country_code: string; alert_count: number }[];
  top_suspicious_destinations: { ip: string; alert_count: number; country: string; org: string; classifications: string[] }[];
  top_talkers: { ip: string; alert_count: number; top_classification: string }[];
  iot_concerns: { src_ip: string; dst_ip: string; country: string; org: string; classification: string; count: number }[];
  threat_intel_status: { feeds_loaded: number; total_iocs: number };
  ingestion_status: { events_24h: number; syslog_active: boolean };
  alert_timeline: TimelineBucket[];
  recent_critical: RecentCriticalAlert[];
}

export interface GeoBreakdown {
  countries: { country: string; code: string; alert_count: number; unique_ips: number }[];
}

export interface DeviceActivity {
  devices: { ip: string; alert_count: number; unique_destinations: number; top_destinations: { ip: string; country: string; org: string }[]; classifications: string[]; last_alert: string }[];
}

export interface HostRiskScore {
  ip: string;
  risk_score: number;
  alert_count: number;
  top_severity: string;
  top_classification: string;
}

export interface HostRiskResponse {
  hosts: HostRiskScore[];
  period_hours: number;
}

export interface AnomalyHost {
  ip: string;
  detector_name?: string;
  anomaly_score: number;
  unique_destinations: number;
  unique_ports: number;
  total_connections: number;
  blocked_ratio: number;
  unique_protocols: number;
}

export interface AnomalyResponse {
  anomalies: AnomalyHost[];
  last_run: string | null;
}

export interface EnsembleHost {
  ip: string;
  composite_score: number;
  consensus_count: number;
  detectors: { name: string; score: number; details: any }[];
}

export interface EnsembleResponse {
  hosts: EnsembleHost[];
  last_run: string | null;
  detectors_run: number;
}

export interface FpPattern {
  id: number;
  detector_name: string;
  src_pattern?: string;
  dst_pattern?: string;
  domain_pattern?: string;
  classification: string;
  reason?: string;
  times_matched: number;
  created_at: string;
  created_by?: string;
}

export interface ShadowResult {
  id: number;
  detector_name: string;
  ip: string;
  score: number;
  details: string;
  created_at: string;
}

export interface RelatedAlert {
  id: number;
  src_ip: string;
  dst_ip: string;
  severity: string;
  classification: string;
  created_at: string;
  attack_technique?: string;
  attack_tactic?: string;
}

export interface RelatedAlertsResponse {
  alert: Alert;
  related: RelatedAlert[];
  timeline_groups: { [tactic: string]: number[] };
}

export interface CoverageTechnique {
  technique_id: string;
  tactic: string;
  count: number;
  covered_by_detectors: string[];
}

export interface CoverageResponse {
  techniques: CoverageTechnique[];
  period_days: number;
}

export interface RuleTestResult {
  would_generate_alerts: number;
  sample_matches: { event_id: number; src_ip: string; dst_ip: string; match_detail: string }[];
  total_events_tested: number;
}

export interface DeviceRole {
  id: number;
  ip: string;
  role: string;
  label?: string;
  created_at: string;
}

export interface ModelRun {
  id: number;
  detector_name: string;
  data_hash?: string;
  trained_at: string;
  training_time_ms?: number;
  sample_count?: number;
  anomaly_count?: number;
  score_stats_json?: string;
}

export interface ShadowModeConfig {
  [detectorName: string]: boolean;
}

@Injectable({ providedIn: 'root' })
export class ApiService {
  constructor(private http: HttpClient) {}

  getEvents(params?: any): Observable<SyslogEvent[]> {
    let httpParams = new HttpParams();
    if (params) {
      Object.keys(params).forEach(key => {
        if (params[key] !== null && params[key] !== undefined) {
          httpParams = httpParams.set(key, params[key]);
        }
      });
    }
    return this.http.get<SyslogEvent[]>('/api/events', { params: httpParams });
  }

  getEventDetail(id: number): Observable<EventDetail> {
    return this.http.get<EventDetail>(`/api/events/${id}`);
  }

  getAlertDetail(id: number): Observable<any> {
    return this.http.get(`/api/alerts/${id}`);
  }

  getAlerts(params?: any): Observable<Alert[]> {
    let httpParams = new HttpParams();
    if (params) {
      Object.keys(params).forEach(key => {
        if (params[key] !== null && params[key] !== undefined) {
          httpParams = httpParams.set(key, params[key]);
        }
      });
    }
    return this.http.get<Alert[]>('/api/alerts', { params: httpParams });
  }

  getTopOffenders(days: number = 7): Observable<TopOffenders> {
    return this.http.get<TopOffenders>('/api/alerts/top-offenders', {
      params: { days: days.toString() }
    });
  }

  getThreatIntelStatus(): Observable<ThreatIntelStatus> {
    return this.http.get<ThreatIntelStatus>('/api/threat-intel/status');
  }

  refreshThreatIntel(): Observable<any> {
    return this.http.post('/api/threat-intel/refresh', {});
  }

  getNetworkOverview(hours: number = 24): Observable<NetworkOverview> {
    return this.http.get<NetworkOverview>('/api/network/overview', {
      params: { hours: hours.toString() }
    });
  }

  getConfig(): Observable<any> {
    return this.http.get('/api/config');
  }

  updateConfig(body: any): Observable<any> {
    return this.http.put('/api/config', body);
  }

  getDashboardSummary(): Observable<DashboardSummary> {
    return this.http.get<DashboardSummary>('/api/dashboard/summary');
  }

  getGeoBreakdown(): Observable<GeoBreakdown> {
    return this.http.get<GeoBreakdown>('/api/dashboard/geo-breakdown');
  }

  getDeviceActivity(): Observable<DeviceActivity> {
    return this.http.get<DeviceActivity>('/api/dashboard/device-activity');
  }

  updateAlertStatus(alertId: number, status: string): Observable<any> {
    return this.http.patch(`/api/alerts/${alertId}/status`, { status });
  }

  getHealth(): Observable<any> {
    return this.http.get('/api/health');
  }

  getHostRiskScores(hours: number = 24): Observable<HostRiskResponse> {
    return this.http.get<HostRiskResponse>('/api/dashboard/host-risk', {
      params: { hours: hours.toString() }
    });
  }

  getAnomalies(): Observable<AnomalyResponse> {
    return this.http.get<AnomalyResponse>('/api/analytics/anomalies');
  }

  getEnsembleScores(): Observable<EnsembleResponse> {
    return this.http.get<EnsembleResponse>('/api/analytics/ensemble');
  }

  // Anomaly suppression
  suppressAnomaly(ip: string, detectorName: string): Observable<any> {
    return this.http.post('/api/analytics/anomalies/suppress', { ip, detector_name: detectorName });
  }

  getSuppressions(): Observable<any[]> {
    return this.http.get<any[]>('/api/analytics/anomalies/suppressions');
  }

  deleteSuppression(ip: string, detectorName: string): Observable<any> {
    return this.http.delete('/api/analytics/anomalies/suppress', {
      body: { ip, detector_name: detectorName }
    });
  }

  // Custom rules
  getRules(): Observable<any[]> {
    return this.http.get<any[]>('/api/rules');
  }

  createRule(rule: any): Observable<any> {
    return this.http.post('/api/rules', rule);
  }

  updateRule(id: number, rule: any): Observable<any> {
    return this.http.put(`/api/rules/${id}`, rule);
  }

  deleteRule(id: number): Observable<any> {
    return this.http.delete(`/api/rules/${id}`);
  }

  // False positive patterns
  getFpPatterns(): Observable<FpPattern[]> {
    return this.http.get<FpPattern[]>('/api/fp-patterns');
  }

  createFpPattern(pattern: any): Observable<FpPattern> {
    return this.http.post<FpPattern>('/api/fp-patterns', pattern);
  }

  deleteFpPattern(id: number): Observable<any> {
    return this.http.delete(`/api/fp-patterns/${id}`);
  }

  // Shadow mode
  getShadowResults(): Observable<ShadowResult[]> {
    return this.http.get<ShadowResult[]>('/api/analytics/shadow-results');
  }

  updateShadowMode(shadowMode: any): Observable<any> {
    return this.http.put('/api/config', { shadow_mode: shadowMode });
  }

  // Related alerts
  getRelatedAlerts(alertId: number): Observable<RelatedAlertsResponse> {
    return this.http.get<RelatedAlertsResponse>(`/api/alerts/${alertId}/related`);
  }

  // MITRE ATT&CK coverage
  getCoverage(): Observable<CoverageResponse> {
    return this.http.get<CoverageResponse>('/api/analytics/coverage');
  }

  // Rule testing
  testRule(rule: { rule_json: string; name: string; severity: string }): Observable<RuleTestResult> {
    return this.http.post<RuleTestResult>('/api/rules/test', rule);
  }

  promoteRule(id: number): Observable<any> {
    return this.http.patch(`/api/rules/${id}/promote`, {});
  }

  deprecateRule(id: number, reason: string): Observable<any> {
    return this.http.patch(`/api/rules/${id}/deprecate`, { reason });
  }

  // Device roles
  getDeviceRoles(): Observable<DeviceRole[]> {
    return this.http.get<DeviceRole[]>('/api/devices/roles');
  }

  createDeviceRole(role: any): Observable<DeviceRole> {
    return this.http.post<DeviceRole>('/api/devices/roles', role);
  }

  updateDeviceRole(id: number, role: any): Observable<DeviceRole> {
    return this.http.put<DeviceRole>(`/api/devices/roles/${id}`, role);
  }

  deleteDeviceRole(id: number): Observable<any> {
    return this.http.delete(`/api/devices/roles/${id}`);
  }

  // Model history
  getModelHistory(): Observable<ModelRun[]> {
    return this.http.get<ModelRun[]>('/api/analytics/model-history');
  }
}
