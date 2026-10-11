import { Component, OnInit, HostListener } from '@angular/core';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { SidebarComponent } from './components/sidebar/sidebar.component';
import { AuthService } from './services/auth.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterModule, CommonModule, SidebarComponent],
  template: `
    <div class="app-container" [class.mobile]="isMobile">
      <ng-container *ngIf="authService.isLoggedIn()">
        <app-sidebar [collapsed]="sidebarCollapsed" (sidebarToggle)="onSidebarToggle($event)"></app-sidebar>
      </ng-container>
      <main class="main-content"
        [class.full-width]="!authService.isLoggedIn()"
        [class.sidebar-collapsed]="sidebarCollapsed && authService.isLoggedIn()">
        <router-outlet></router-outlet>
      </main>
    </div>
  `,
  styles: [`
    .app-container {
      display: flex;
      min-height: 100vh;
      background: #0a0e17;
      color: #e0e6ed;
    }
    .main-content {
      flex: 1;
      padding: 20px;
      overflow-x: auto;
      margin-left: 220px;
      transition: margin-left 0.2s ease;
    }
    .main-content.sidebar-collapsed {
      margin-left: 52px;
    }
    .main-content.full-width {
      margin-left: 0;
    }
    .app-container.mobile .main-content {
      margin-left: 0;
    }
    @media (max-width: 768px) {
      .main-content {
        margin-left: 0;
        padding: 12px;
      }
      .main-content.sidebar-collapsed {
        margin-left: 0;
      }
    }
  `]
})
export class AppComponent implements OnInit {
  isMobile = false;
  sidebarCollapsed = false;

  constructor(public authService: AuthService) {
    const saved = localStorage.getItem('sidebar_collapsed');
    if (saved === 'true') this.sidebarCollapsed = true;
  }

  ngOnInit() {
    this.checkScreenSize();
  }

  @HostListener('window:resize')
  checkScreenSize() {
    this.isMobile = window.innerWidth < 768;
  }

  onSidebarToggle(collapsed: boolean) {
    this.sidebarCollapsed = collapsed;
  }
}
