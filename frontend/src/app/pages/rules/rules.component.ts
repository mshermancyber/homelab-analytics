import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../services/api.service';

interface Rule {
  id?: number;
  name: string;
  description?: string;
  rule_json?: any;
  severity: string;
  enabled: boolean;
  maturity?: string;
  created_at?: string;
  updated_at?: string;
}

interface RuleForm {
  name: string;
  description: string;
  field: string;
  operator: string;
  value: string;
  aggregate_field: string;
  aggregate_operator: string;
  aggregate_window: string;
  threshold: number | null;
  severity: string;
  enabled: boolean;
}

const FIELD_OPTIONS = [
  { value: 'src_ip', label: 'Source IP' },
  { value: 'dst_ip', label: 'Destination IP' },
  { value: 'dst_port', label: 'Destination Port' },
  { value: 'protocol', label: 'Protocol' },
  { value: 'action', label: 'Action' },
  { value: 'dst_country', label: 'Destination Country' },
  { value: 'dst_org', label: 'Destination Organization' },
  { value: 'domain', label: 'Domain' },
];

const OPERATOR_OPTIONS = [
  { value: 'eq', label: 'equals' },
  { value: 'neq', label: 'not equals' },
  { value: 'contains', label: 'contains' },
  { value: 'startswith', label: 'starts with' },
  { value: 'gt', label: 'greater than' },
  { value: 'lt', label: 'less than' },
];

const AGGREGATE_WINDOWS = [
  { value: '1m', label: '1 minute' },
  { value: '5m', label: '5 minutes' },
  { value: '15m', label: '15 minutes' },
  { value: '1h', label: '1 hour' },
];

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info'];

@Component({
  selector: 'app-rules',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="page-header">
      <h1>📏 Custom Rules</h1>
      <button class="btn btn-primary" (click)="startCreate()" *ngIf="!showForm">
        + Create Rule
      </button>
    </div>

    <div class="error-msg" *ngIf="error">{{ error }}</div>

    <!-- Create/Edit Form -->
    <div class="form-panel" *ngIf="showForm">
      <h2>{{ editingRule ? 'Edit Rule' : 'Create Rule' }}</h2>

      <div class="form-grid">
        <div class="form-group full-width">
          <label>Name <span class="required">*</span></label>
          <input [(ngModel)]="form.name" placeholder="Rule name..." class="form-input" />
        </div>

        <div class="form-group full-width">
          <label>Description</label>
          <textarea [(ngModel)]="form.description" placeholder="Optional description..." class="form-input" rows="2"></textarea>
        </div>

        <div class="form-group">
          <label>Field <span class="required">*</span></label>
          <select [(ngModel)]="form.field" class="form-input">
            <option value="">Select field...</option>
            <option *ngFor="let f of fieldOptions" [value]="f.value">{{ f.label }}</option>
          </select>
        </div>

        <div class="form-group">
          <label>Operator <span class="required">*</span></label>
          <select [(ngModel)]="form.operator" class="form-input">
            <option value="">Select operator...</option>
            <option *ngFor="let o of operatorOptions" [value]="o.value">{{ o.label }}</option>
          </select>
        </div>

        <div class="form-group">
          <label>Value <span class="required">*</span></label>
          <input [(ngModel)]="form.value" placeholder="Value..." class="form-input" />
        </div>

        <div class="form-group">
          <label>Severity <span class="required">*</span></label>
          <select [(ngModel)]="form.severity" class="form-input">
            <option value="">Select severity...</option>
            <option *ngFor="let s of severityOptions" [value]="s">{{ s }}</option>
          </select>
        </div>

        <div class="form-group">
          <label>Enabled</label>
          <label class="toggle-wrap">
            <input type="checkbox" [(ngModel)]="form.enabled" />
            <span class="toggle-slider"></span>
            <span class="toggle-label">{{ form.enabled ? 'On' : 'Off' }}</span>
          </label>
        </div>

        <!-- Aggregate section -->
        <div class="form-group full-width">
          <button class="btn btn-link" (click)="showAggregate = !showAggregate">
            {{ showAggregate ? '▾' : '▸' }} Aggregation (optional)
          </button>
        </div>

        <ng-container *ngIf="showAggregate">
          <div class="form-group">
            <label>Aggregate Field</label>
            <select [(ngModel)]="form.aggregate_field" class="form-input">
              <option value="">Same as field</option>
              <option *ngFor="let f of fieldOptions" [value]="f.value">{{ f.label }}</option>
            </select>
          </div>

          <div class="form-group">
            <label>Aggregate Operator</label>
            <select [(ngModel)]="form.aggregate_operator" class="form-input">
              <option value="">None</option>
              <option value="count">Count</option>
              <option value="count_distinct">Count Distinct</option>
            </select>
          </div>

          <div class="form-group">
            <label>Window</label>
            <select [(ngModel)]="form.aggregate_window" class="form-input">
              <option value="">None</option>
              <option *ngFor="let w of windowOptions" [value]="w.value">{{ w.label }}</option>
            </select>
          </div>

          <div class="form-group">
            <label>Threshold</label>
            <input type="number" [(ngModel)]="form.threshold" placeholder="0" class="form-input" />
          </div>
        </ng-container>
      </div>

      <div class="form-actions">
        <button class="btn btn-secondary" (click)="cancelForm()">Cancel</button>
        <button class="btn btn-primary" (click)="saveRule()" [disabled]="saving">
          {{ saving ? 'Saving...' : (editingRule ? 'Update Rule' : 'Create Rule') }}
        </button>
      </div>
    </div>

    <!-- Rules Table -->
    <div class="table-wrap" *ngIf="rules.length > 0 && !showForm">
      <table class="data-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Severity</th>
            <th>Maturity</th>
            <th>Enabled</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr *ngFor="let rule of rules" class="data-row">
            <td class="cell-name">
              <div class="rule-name">{{ rule.name }}</div>
              <div class="rule-desc" *ngIf="rule.description">{{ rule.description }}</div>
            </td>
            <td>
              <span class="sev-badge"
                    [class.sev-critical]="rule.severity === 'critical'"
                    [class.sev-high]="rule.severity === 'high'"
                    [class.sev-medium]="rule.severity === 'medium'"
                    [class.sev-low]="rule.severity === 'low'"
                    [class.sev-info]="rule.severity === 'info'">
                {{ rule.severity }}
              </span>
            </td>
            <td>
              <span class="maturity-badge"
                    [class.mat-experimental]="(rule.maturity || 'active') === 'experimental'"
                    [class.mat-active]="(rule.maturity || 'active') === 'active'"
                    [class.mat-stable]="rule.maturity === 'stable'"
                    [class.mat-deprecated]="rule.maturity === 'deprecated'">
                {{ rule.maturity || 'active' }}
              </span>
            </td>
            <td>
              <label class="toggle-wrap" (click)="toggleRule(rule); $event.stopPropagation()">
                <input type="checkbox" [checked]="rule.enabled" (change)="toggleRule(rule)" />
                <span class="toggle-slider"></span>
              </label>
            </td>
            <td>{{ formatTime(rule.created_at) }}</td>
            <td class="cell-actions">
              <button class="btn btn-sm btn-test" (click)="testRule(rule)" [disabled]="testingRuleId === rule.id">
                <span class="btn-label">{{ testingRuleId === rule.id ? 'Testing...' : 'Test' }}</span>
                <span class="btn-icon">🧪</span>
              </button>
              <button class="btn btn-sm btn-secondary" (click)="startEdit(rule)">
                <span class="btn-label">Edit</span>
                <span class="btn-icon">✏️</span>
              </button>
              <button class="btn btn-sm btn-delete" (click)="deleteRule(rule)">
                <span class="btn-label">Delete</span>
                <span class="btn-icon">🗑️</span>
              </button>
              <div class="maturity-actions">
                <button class="btn btn-sm btn-promote"
                        *ngIf="(rule.maturity || 'active') !== 'stable'"
                        (click)="promoteRule(rule)"
                        [disabled]="promotingRuleId === rule.id">
                  ⬆ Promote
                </button>
                <button class="btn btn-sm btn-deprecate"
                        *ngIf="(rule.maturity || 'active') !== 'deprecated'"
                        (click)="deprecateRule(rule)"
                        [disabled]="deprecatingRuleId === rule.id">
                  ⬇ Deprecate
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="empty-state" *ngIf="rules.length === 0 && !showForm && !loading">
      <p>No custom rules defined.</p>
      <p class="hint">Create a rule to start flagging or suppressing specific traffic patterns.</p>
    </div>

    <div class="empty-state" *ngIf="loading && !showForm">
      <p>Loading rules...</p>
    </div>

    <!-- Test Results -->
    <div class="test-results-panel" *ngIf="testResult">
      <h2>🧪 Test Results: {{ testResult.would_generate_alerts }} potential alerts</h2>
      <p class="test-meta">Tested against {{ testResult.total_events_tested }} events</p>
      <div class="test-matches" *ngIf="testResult.sample_matches?.length > 0">
        <h3>Sample Matches (up to 5)</h3>
        <div *ngFor="let m of testResult.sample_matches" class="test-match-row">
          <span class="mono">{{ m.src_ip }} → {{ m.dst_ip }}</span>
          <span class="test-match-detail">{{ m.match_detail }}</span>
        </div>
      </div>
    </div>

    <!-- Confirm Delete Modal -->
    <div class="modal-overlay" *ngIf="deleteTarget" (click)="deleteTarget = null">
      <div class="modal-box" (click)="$event.stopPropagation()">
        <h2>Delete Rule</h2>
        <p>Are you sure you want to delete <strong>{{ deleteTarget.name }}</strong>?</p>
        <div class="modal-actions">
          <button class="btn btn-secondary" (click)="deleteTarget = null">Cancel</button>
          <button class="btn btn-delete" (click)="confirmDelete()" [disabled]="saving">
            {{ saving ? 'Deleting...' : 'Delete' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Deprecate Reason Modal -->
    <div class="modal-overlay" *ngIf="deprecateTarget" (click)="deprecateTarget = null">
      <div class="modal-box" (click)="$event.stopPropagation()">
        <h2>Deprecate Rule</h2>
        <p>Deprecate <strong>{{ deprecateTarget.name }}</strong>?</p>
        <div class="form-group">
          <label>Reason</label>
          <input [(ngModel)]="deprecateReason" placeholder="Why is this rule being deprecated?" class="form-input" />
        </div>
        <div class="modal-actions">
          <button class="btn btn-secondary" (click)="deprecateTarget = null">Cancel</button>
          <button class="btn btn-deprecate" (click)="confirmDeprecate()" [disabled]="saving">
            {{ saving ? 'Deprecating...' : 'Deprecate' }}
          </button>
        </div>
      </div>
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
    .btn-primary {
      background: #1565c0;
      color: white;
    }
    .btn-primary:hover:not(:disabled) {
      background: #1976d2;
    }
    .btn-secondary {
      background: #1e2d3d;
      color: #b0bec5;
    }
    .btn-secondary:hover:not(:disabled) {
      background: #2a3f5a;
    }
    .btn-delete {
      background: #b71c1c;
      color: white;
    }
    .btn-delete:hover:not(:disabled) {
      background: #d32f2f;
    }
    .btn-sm {
      padding: 4px 10px;
      font-size: 0.78rem;
      margin-right: 4px;
    }
    .btn-link {
      background: none;
      color: #4fc3f7;
      padding: 4px 0;
      font-size: 0.85rem;
    }
    .btn-link:hover {
      color: #81d4fa;
    }

    .btn-label { display: inline; }
    .btn-icon { display: none; }
    @media (max-width: 768px) {
      .btn-label { display: none; }
      .btn-icon { display: inline; font-size: 1.1rem; }
      .btn-sm { padding: 6px 8px; }
    }

    .error-msg {
      color: #ef5350;
      margin-bottom: 16px;
    }

    /* Form */
    .form-panel {
      background: #111927;
      border: 1px solid #1e2d3d;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .form-panel h2 {
      margin: 0 0 16px;
      font-size: 1rem;
      color: #4fc3f7;
    }
    .form-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }
    @media (max-width: 600px) {
      .form-grid {
        grid-template-columns: 1fr;
      }
    }
    .form-group {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .form-group.full-width {
      grid-column: 1 / -1;
    }
    .form-group label {
      font-size: 0.78rem;
      color: #8b9cb5;
      text-transform: uppercase;
      letter-spacing: .3px;
    }
    .required {
      color: #ef5350;
    }
    .form-input {
      padding: 8px 12px;
      background: #0d1520;
      border: 1px solid #1e2d3d;
      border-radius: 4px;
      color: #e0e6ed;
      font-size: 0.85rem;
      font-family: inherit;
    }
    .form-input:focus {
      outline: none;
      border-color: #4fc3f7;
    }
    select.form-input {
      cursor: pointer;
    }
    textarea.form-input {
      resize: vertical;
    }

    .form-actions {
      display: flex;
      justify-content: flex-end;
      gap: 8px;
      margin-top: 16px;
      padding-top: 16px;
      border-top: 1px solid #1e2d3d;
    }

    /* Toggle */
    .toggle-wrap {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      cursor: pointer;
    }
    .toggle-wrap input[type="checkbox"] {
      display: none;
    }
    .toggle-slider {
      position: relative;
      width: 36px;
      height: 20px;
      background: #1e2d3d;
      border-radius: 10px;
      transition: background 0.2s;
    }
    .toggle-slider::after {
      content: '';
      position: absolute;
      top: 2px;
      left: 2px;
      width: 16px;
      height: 16px;
      background: #8b9cb5;
      border-radius: 50%;
      transition: transform 0.2s;
    }
    input:checked + .toggle-slider {
      background: #1565c0;
    }
    input:checked + .toggle-slider::after {
      transform: translateX(16px);
      background: #e0e6ed;
    }
    .toggle-label {
      font-size: 0.8rem;
      color: #8b9cb5;
    }

    /* Table */
    .table-wrap {
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
    }
    .data-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
      min-width: 700px;
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
    }
    .data-row:hover {
      background: #0d1520;
    }
    .cell-name {
      max-width: 250px;
    }
    .rule-name {
      font-weight: 600;
      color: #e0e6ed;
    }
    .rule-desc {
      font-size: 0.72rem;
      color: #8b9cb5;
      margin-top: 2px;
      white-space: normal;
      word-break: break-word;
    }
    .cell-actions {
      white-space: nowrap;
    }

    /* Severity badges */
    .sev-badge {
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
    }
    .sev-critical { background: #b71c1c; color: #ef9a9a; }
    .sev-high { background: #e65100; color: #ffcc80; }
    .sev-medium { background: #e65100; color: #ffe0b2; }
    .sev-low { background: #f9a825; color: #fff9c4; }
    .sev-info { background: #1565c0; color: #90caf9; }

    /* Maturity badges */
    .maturity-badge {
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 0.65rem;
      font-weight: 600;
      text-transform: uppercase;
      background: #1e2d3d;
      color: #b0bec5;
    }
    .mat-experimental { background: #311b92; color: #b39ddb; }
    .mat-active { background: #1b5e20; color: #a5d6a7; }
    .mat-stable { background: #01579b; color: #81d4fa; }
    .mat-deprecated { background: #b71c1c; color: #ef9a9a; }

    /* Test button */
    .btn-test {
      background: #4a148c;
      color: #e1bee7;
    }
    .btn-test:hover:not(:disabled) {
      background: #6a1b9a;
    }

    /* Promote/Deprecate */
    .btn-promote {
      background: #1b5e20;
      color: #c8e6c9;
      font-size: 0.65rem;
    }
    .btn-promote:hover:not(:disabled) {
      background: #2e7d32;
    }
    .btn-deprecate {
      background: #bf360c;
      color: #ffccbc;
      font-size: 0.65rem;
    }
    .btn-deprecate:hover:not(:disabled) {
      background: #dd2c00;
    }
    .maturity-actions {
      display: flex;
      gap: 4px;
      margin-top: 4px;
    }

    /* Test results */
    .test-results-panel {
      background: #111927;
      border: 1px solid #4a148c;
      border-radius: 8px;
      padding: 16px;
      margin-top: 16px;
    }
    .test-results-panel h2 {
      margin: 0 0 6px;
      font-size: 0.95rem;
      color: #ce93d8;
    }
    .test-meta {
      font-size: 0.7rem;
      color: #8b9cb5;
      margin: 0 0 12px;
    }
    .test-matches h3 {
      font-size: 0.75rem;
      color: #8b9cb5;
      margin: 0 0 8px;
    }
    .test-match-row {
      background: #0d1520;
      border: 1px solid #1e2d3d;
      border-radius: 4px;
      padding: 8px 12px;
      margin-bottom: 6px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
    }
    .test-match-row .mono {
      font-size: 0.78rem;
      color: #e0e6ed;
    }
    .test-match-detail {
      font-size: 0.7rem;
      color: #8b9cb5;
    }

    .empty-state {
      text-align: center;
      padding: 40px 20px;
      color: #8b9cb5;
      font-size: 0.85rem;
    }
    .hint {
      font-size: 0.78rem;
      margin-top: 8px;
    }

    /* Modal */
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,.6);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
    }
    .modal-box {
      background: #111927;
      border: 1px solid #1e2d3d;
      border-radius: 8px;
      padding: 24px;
      max-width: 400px;
      width: 90%;
    }
    .modal-box h2 {
      margin: 0 0 12px;
      color: #ef5350;
      font-size: 1.1rem;
    }
    .modal-box p {
      color: #b0bec5;
      font-size: 0.9rem;
      margin: 0 0 16px;
    }
    .modal-actions {
      display: flex;
      justify-content: flex-end;
      gap: 8px;
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
export class RulesComponent implements OnInit {
  rules: Rule[] = [];
  loading = false;
  error = '';
  successMsg = '';
  saving = false;

  showForm = false;
  showAggregate = false;
  editingRule: Rule | null = null;
  deleteTarget: Rule | null = null;
  deprecateTarget: Rule | null = null;
  deprecateReason = '';
  testingRuleId: number | null = null;
  promotingRuleId: number | null = null;
  deprecatingRuleId: number | null = null;
  testResult: any = null;

  form: RuleForm = this.emptyForm();

  fieldOptions = FIELD_OPTIONS;
  operatorOptions = OPERATOR_OPTIONS;
  windowOptions = AGGREGATE_WINDOWS;
  severityOptions = SEVERITY_OPTIONS;

  constructor(private api: ApiService) {}

  ngOnInit() {
    this.loadRules();
  }

  emptyForm(): RuleForm {
    return {
      name: '',
      description: '',
      field: '',
      operator: '',
      value: '',
      aggregate_field: '',
      aggregate_operator: '',
      aggregate_window: '',
      threshold: null,
      severity: '',
      enabled: true,
    };
  }

  loadRules() {
    this.loading = true;
    this.error = '';
    this.api.getRules().subscribe({
      next: (data) => {
        this.rules = data || [];
        this.loading = false;
      },
      error: (err) => {
        this.error = err.error?.detail || 'Failed to load rules';
        this.loading = false;
      }
    });
  }

  startCreate() {
    this.editingRule = null;
    this.form = this.emptyForm();
    this.showAggregate = false;
    this.showForm = true;
  }

  startEdit(rule: Rule) {
    this.editingRule = rule;
    this.showAggregate = false;

    if (rule.rule_json) {
      const rj = rule.rule_json;
      this.form = {
        name: rule.name || '',
        description: rule.description || '',
        field: rj.field || '',
        operator: rj.operator || '',
        value: rj.value || '',
        aggregate_field: rj.aggregate_field || '',
        aggregate_operator: rj.aggregate_operator || '',
        aggregate_window: rj.aggregate_window || '',
        threshold: rj.threshold ?? null,
        severity: rule.severity || '',
        enabled: rule.enabled,
      };
      if (rj.aggregate_operator) {
        this.showAggregate = true;
      }
    } else {
      this.form = {
        ...this.emptyForm(),
        name: rule.name || '',
        description: rule.description || '',
        severity: rule.severity || '',
        enabled: rule.enabled,
      };
    }

    this.showForm = true;
  }

  cancelForm() {
    this.showForm = false;
    this.editingRule = null;
    this.form = this.emptyForm();
    this.showAggregate = false;
  }

  buildRuleJson(): any {
    const rj: any = {
      field: this.form.field,
      operator: this.form.operator,
      value: this.form.value,
    };
    if (this.form.aggregate_operator) {
      rj.aggregate_field = this.form.aggregate_field || this.form.field;
      rj.aggregate_operator = this.form.aggregate_operator;
      rj.aggregate_window = this.form.aggregate_window;
      rj.threshold = this.form.threshold;
    }
    return rj;
  }

  saveRule() {
    if (!this.form.name || !this.form.field || !this.form.operator || !this.form.value || !this.form.severity) {
      this.error = 'Please fill in all required fields (Name, Field, Operator, Value, Severity).';
      return;
    }

    this.saving = true;
    this.error = '';

    const ruleData: any = {
      name: this.form.name,
      description: this.form.description,
      rule_json: this.buildRuleJson(),
      severity: this.form.severity,
      enabled: this.form.enabled,
    };

    const request = this.editingRule
      ? this.api.updateRule(this.editingRule.id!, ruleData)
      : this.api.createRule(ruleData);

    request.subscribe({
      next: () => {
        this.saving = false;
        this.successMsg = this.editingRule ? 'Rule updated!' : 'Rule created!';
        setTimeout(() => { this.successMsg = ''; }, 3000);
        this.cancelForm();
        this.loadRules();
      },
      error: (err) => {
        this.saving = false;
        this.error = err.error?.detail || 'Failed to save rule';
      }
    });
  }

  toggleRule(rule: Rule) {
    this.api.updateRule(rule.id!, { ...rule, enabled: !rule.enabled }).subscribe({
      next: () => {
        rule.enabled = !rule.enabled;
      },
      error: (err) => {
        this.error = err.error?.detail || 'Failed to toggle rule';
      }
    });
  }

  deleteRule(rule: Rule) {
    this.deleteTarget = rule;
  }

  confirmDelete() {
    if (!this.deleteTarget) return;
    this.saving = true;
    this.api.deleteRule(this.deleteTarget.id!).subscribe({
      next: () => {
        this.saving = false;
        this.successMsg = 'Rule deleted!';
        setTimeout(() => { this.successMsg = ''; }, 3000);
        this.deleteTarget = null;
        this.loadRules();
      },
      error: (err) => {
        this.saving = false;
        this.deleteTarget = null;
        this.error = err.error?.detail || 'Failed to delete rule';
      }
    });
  }

  testRule(rule: Rule) {
    this.testingRuleId = rule.id || null;
    this.testResult = null;
    const payload = {
      rule_json: JSON.stringify(rule.rule_json || {}),
      name: rule.name,
      severity: rule.severity,
    };
    this.api.testRule(payload).subscribe({
      next: (data) => {
        this.testingRuleId = null;
        this.testResult = data;
      },
      error: (err) => {
        this.testingRuleId = null;
        this.error = err.error?.detail || 'Failed to test rule';
      }
    });
  }

  promoteRule(rule: Rule) {
    this.promotingRuleId = rule.id || null;
    this.api.promoteRule(rule.id!).subscribe({
      next: () => {
        this.promotingRuleId = null;
        rule.maturity = rule.maturity === 'stable' ? 'stable' : (
          rule.maturity === 'experimental' ? 'active' : 'stable'
        );
        this.successMsg = `Rule "${rule.name}" promoted!`;
        setTimeout(() => { this.successMsg = ''; }, 3000);
        this.loadRules();
      },
      error: (err) => {
        this.promotingRuleId = null;
        this.error = err.error?.detail || 'Failed to promote rule';
      }
    });
  }

  deprecateRule(rule: Rule) {
    this.deprecateTarget = rule;
    this.deprecateReason = '';
  }

  confirmDeprecate() {
    if (!this.deprecateTarget) return;
    this.saving = true;
    this.api.deprecateRule(this.deprecateTarget.id!, this.deprecateReason || 'No reason given').subscribe({
      next: () => {
        this.saving = false;
        this.successMsg = `Rule "${this.deprecateTarget!.name}" deprecated!`;
        setTimeout(() => { this.successMsg = ''; }, 3000);
        this.deprecateTarget = null;
        this.loadRules();
      },
      error: (err) => {
        this.saving = false;
        this.deprecateTarget = null;
        this.error = err.error?.detail || 'Failed to deprecate rule';
      }
    });
  }

  formatTime(ts: string | undefined): string {
    if (!ts) return '-';
    try {
      return new Date(ts).toLocaleString();
    } catch {
      return ts;
    }
  }
}
