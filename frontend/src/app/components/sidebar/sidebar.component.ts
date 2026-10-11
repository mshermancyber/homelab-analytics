import { Component, Output, EventEmitter, Input } from '@angular/core';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [RouterModule, CommonModule],
  template: `
    <nav class="sidebar" [class.open]="mobileOpen" [class.collapsed]="collapsed">
      <div class="sidebar-header">
        <h2 *ngIf="!collapsed">UEBA Platform</h2>
        <span class="role-badge" *ngIf="!collapsed">{{ roleLabel }}</span>
        <button class="collapse-btn" (click)="toggleCollapse()" [title]="collapsed ? 'Expand' : 'Collapse'">
          {{ collapsed ? '»' : '«' }}
        </button>
      </div>

      <ul class="nav-list">
        <li><a routerLink="/live-feed" routerLinkActive="active" (click)="closeMobile()" [title]="collapsed ? 'Dashboard' : ''">
          <span class="icon">&#x1F6E1;</span><span class="label" *ngIf="!collapsed"> Dashboard</span>
        </a></li>
        <li><a routerLink="/alerts" routerLinkActive="active" (click)="closeMobile()" [title]="collapsed ? 'Alerts' : ''">
          <span class="icon">&#x1F6A8;</span><span class="label" *ngIf="!collapsed"> Alert History</span>
        </a></li>
        <li><a routerLink="/top-offenders" routerLinkActive="active" (click)="closeMobile()" [title]="collapsed ? 'Top Offenders' : ''">
          <span class="icon">&#x1F4CA;</span><span class="label" *ngIf="!collapsed"> Top Offenders</span>
        </a></li>
        <li><a routerLink="/threat-intel" routerLinkActive="active" (click)="closeMobile()" [title]="collapsed ? 'Threat Intel' : ''">
          <span class="icon">&#x1F50D;</span><span class="label" *ngIf="!collapsed"> Threat Intel</span>
        </a></li>
        <li><a routerLink="/network" routerLinkActive="active" (click)="closeMobile()" [title]="collapsed ? 'Network' : ''">
          <span class="icon">&#x1F310;</span><span class="label" *ngIf="!collapsed"> Network</span>
        </a></li>
        <li *ngIf="canManageRules"><a routerLink="/rules" routerLinkActive="active" (click)="closeMobile()" [title]="collapsed ? 'Rules' : ''">
          <span class="icon">&#x1F4CF;</span><span class="label" *ngIf="!collapsed"> Rules</span>
        </a></li>
        <li *ngIf="canManageRules"><a routerLink="/coverage" routerLinkActive="active" (click)="closeMobile()" [title]="collapsed ? 'Coverage' : ''">
          <span class="icon">&#x1F3AF;</span><span class="label" *ngIf="!collapsed"> Coverage</span>
        </a></li>
        <li><a routerLink="/anomalies" routerLinkActive="active" (click)="closeMobile()" [title]="collapsed ? 'Anomalies' : ''">
          <span class="icon">&#x1F52C;</span><span class="label" *ngIf="!collapsed"> Anomalies</span>
        </a></li>
        <li><a routerLink="/chat" routerLinkActive="active" (click)="closeMobile()" [title]="collapsed ? 'AI Chat' : ''">
          <span class="icon">&#x1F4AC;</span><span class="label" *ngIf="!collapsed"> AI Chat</span>
        </a></li>
        <li *ngIf="isAdmin"><a routerLink="/config" routerLinkActive="active" (click)="closeMobile()" [title]="collapsed ? 'Config' : ''">
          <span class="icon">&#x2699;</span><span class="label" *ngIf="!collapsed"> Configuration</span>
        </a></li>
      </ul>

      <div class="sidebar-footer">
        <span class="user-info" *ngIf="!collapsed">{{ username }}</span>
        <button class="logout-btn" (click)="logout()" [title]="collapsed ? 'Logout' : ''">
          {{ collapsed ? '&#x23FB;' : 'Logout' }}
        </button>
      </div>
    </nav>

    <!-- Mobile hamburger -->
    <button class="hamburger" (click)="onToggleMobile()">
      <span></span><span></span><span></span>
    </button>
  `,
  styles: [`
    .hamburger {
      display: none;
      position: fixed;
      top: 12px;
      left: 12px;
      z-index: 1000;
      background: #1a2332;
      border: none;
      border-radius: 6px;
      padding: 8px;
      cursor: pointer;
      flex-direction: column;
      gap: 4px;
    }
    .hamburger span {
      display: block;
      width: 22px;
      height: 2px;
      background: #e0e6ed;
    }
    @media (max-width: 768px) {
      .hamburger { display: flex; }
    }

    .sidebar {
      position: fixed;
      top: 0;
      left: 0;
      width: 220px;
      height: 100vh;
      background: #111927;
      border-right: 1px solid #1e2d3d;
      display: flex;
      flex-direction: column;
      z-index: 900;
      overflow-y: auto;
      overflow-x: hidden;
      transition: width 0.2s ease;
    }
    .sidebar.collapsed {
      width: 52px;
    }
    .sidebar-header {
      padding: 16px 12px 10px;
      border-bottom: 1px solid #1e2d3d;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 6px;
      min-height: 52px;
    }
    .sidebar-header h2 {
      margin: 0;
      font-size: 1rem;
      color: #4fc3f7;
      white-space: nowrap;
    }
    .role-badge {
      display: inline-block;
      padding: 2px 8px;
      background: #1e3a5f;
      border-radius: 10px;
      font-size: 0.65rem;
      text-transform: uppercase;
      color: #64b5f6;
    }
    .collapse-btn {
      background: none;
      border: 1px solid #1e2d3d;
      color: #8b9cb5;
      cursor: pointer;
      font-size: 0.9rem;
      padding: 2px 6px;
      border-radius: 4px;
      margin-left: auto;
      line-height: 1;
    }
    .collapse-btn:hover { color: #4fc3f7; border-color: #4fc3f7; }
    .collapsed .collapse-btn { margin: 0 auto; }

    .nav-list {
      list-style: none;
      padding: 6px 0;
      margin: 0;
      flex: 1;
    }
    .nav-list li a {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 9px 14px;
      color: #8b9cb5;
      text-decoration: none;
      font-size: 0.85rem;
      transition: background 0.2s;
      white-space: nowrap;
      overflow: hidden;
    }
    .nav-list li a:hover { background: #1a2a3a; color: #e0e6ed; }
    .nav-list li a.active { background: #1a3a5a; color: #4fc3f7; border-left: 3px solid #4fc3f7; }
    .collapsed .nav-list li a { justify-content: center; padding: 9px 0; }
    .collapsed .nav-list li a.active { border-left: none; border-bottom: 2px solid #4fc3f7; }
    .icon { font-size: 1rem; flex-shrink: 0; }
    .label { overflow: hidden; text-overflow: ellipsis; }

    .sidebar-footer {
      padding: 10px 12px;
      border-top: 1px solid #1e2d3d;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 6px;
    }
    .collapsed .sidebar-footer { justify-content: center; }
    .user-info { font-size: 0.8rem; color: #8b9cb5; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .logout-btn {
      background: #c62828;
      color: white;
      border: none;
      padding: 5px 10px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.75rem;
      white-space: nowrap;
    }
    .logout-btn:hover { background: #d32f2f; }
    .collapsed .logout-btn { padding: 5px 8px; font-size: 0.8rem; }

    @media (max-width: 768px) {
      .sidebar {
        transform: translateX(-100%);
        transition: transform 0.3s ease, width 0.2s ease;
        width: 220px;
      }
      .sidebar.open { transform: translateX(0); }
      .sidebar.collapsed { width: 220px; }
    }
  `]
})
export class SidebarComponent {
  @Output() sidebarToggle = new EventEmitter<boolean>();
  @Input() collapsed = false;
  mobileOpen = false;

  constructor(public authService: AuthService) {
    const saved = localStorage.getItem('sidebar_collapsed');
    if (saved === 'true') this.collapsed = true;
  }

  get username(): string {
    return this.authService.getCurrentUser()?.username || 'User';
  }

  get roleLabel(): string {
    return this.authService.getCurrentUser()?.role || '';
  }

  get isAdmin(): boolean {
    return this.authService.hasRole('admin');
  }

  get canManageRules(): boolean {
    return this.authService.hasRole('analyst') || this.authService.hasRole('admin');
  }

  toggleCollapse() {
    this.collapsed = !this.collapsed;
    localStorage.setItem('sidebar_collapsed', String(this.collapsed));
    this.sidebarToggle.emit(this.collapsed);
  }

  onToggleMobile() {
    this.mobileOpen = !this.mobileOpen;
  }

  closeMobile() {
    if (this.mobileOpen) {
      this.mobileOpen = false;
    }
  }

  logout() {
    this.authService.logout();
  }
}
