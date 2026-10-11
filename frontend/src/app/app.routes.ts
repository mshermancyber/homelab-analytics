import { Routes } from '@angular/router';
import { authGuard } from './guards/auth.guard';

export const routes: Routes = [
  { path: 'login', loadComponent: () => import('./pages/login/login.component').then(m => m.LoginComponent) },
  { path: 'register', loadComponent: () => import('./pages/register/register.component').then(m => m.RegisterComponent) },
  {
    path: '',
    canActivate: [authGuard],
    children: [
      { path: '', redirectTo: 'live-feed', pathMatch: 'full' },
      { path: 'live-feed', loadComponent: () => import('./pages/live-feed/live-feed.component').then(m => m.LiveFeedComponent) },
      { path: 'threat-intel', loadComponent: () => import('./pages/threat-intel/threat-intel.component').then(m => m.ThreatIntelComponent) },
      { path: 'alerts', loadComponent: () => import('./pages/alert-history/alert-history.component').then(m => m.AlertHistoryComponent) },
      { path: 'alerts/:id', loadComponent: () => import('./pages/event-detail/event-detail.component').then(m => m.EventDetailComponent) },
      { path: 'top-offenders', loadComponent: () => import('./pages/top-offenders/top-offenders.component').then(m => m.TopOffendersComponent) },
      { path: 'events/:id', loadComponent: () => import('./pages/event-detail/event-detail.component').then(m => m.EventDetailComponent) },
      { path: 'network', loadComponent: () => import('./pages/network-overview/network-overview.component').then(m => m.NetworkOverviewComponent) },
      { path: 'anomalies', loadComponent: () => import('./pages/anomalies/anomalies.component').then(m => m.AnomaliesComponent) },
      { path: 'rules', loadComponent: () => import('./pages/rules/rules.component').then(m => m.RulesComponent) },
      { path: 'chat', loadComponent: () => import('./pages/chat/chat.component').then(m => m.ChatComponent) },
      { path: 'coverage', loadComponent: () => import('./pages/coverage/coverage.component').then(m => m.CoverageComponent) },
      { path: 'config', loadComponent: () => import('./pages/configuration/configuration.component').then(m => m.ConfigurationComponent) },
    ]
  },
  { path: '**', redirectTo: 'live-feed' }
];
