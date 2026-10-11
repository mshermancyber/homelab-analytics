import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [FormsModule, RouterModule, CommonModule],
  template: `
    <div class="auth-container">
      <div class="auth-card">
        <h1>UEBA Platform</h1>
        <h3>Create Account</h3>
        <form (ngSubmit)="register()">
          <div class="form-group">
            <label>Username</label>
            <input [(ngModel)]="username" name="username" required placeholder="Choose a username" class="form-input" />
          </div>
          <div class="form-group">
            <label>Password</label>
            <input [(ngModel)]="password" name="password" type="password" required placeholder="Choose a password" class="form-input" />
          </div>
          <div class="form-group">
            <label>Role</label>
            <select [(ngModel)]="role" name="role" class="form-input">
              <option value="viewer">Viewer</option>
              <option value="analyst">Analyst</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div class="error" *ngIf="error">{{ error }}</div>
          <button type="submit" class="btn btn-primary" [disabled]="loading">
            {{ loading ? 'Creating...' : 'Register' }}
          </button>
        </form>
        <p class="register-link">
          Already have an account? <a routerLink="/login">Sign In</a>
        </p>
      </div>
    </div>
  `,
  styles: [`
    .auth-container { display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #0a0e17; }
    .auth-card { background: #111927; border: 1px solid #1e2d3d; border-radius: 12px; padding: 40px; width: 100%; max-width: 400px; box-shadow: 0 4px 24px rgba(0,0,0,0.3); }
    .auth-card h1 { margin: 0 0 8px; color: #4fc3f7; font-size: 1.4rem; text-align: center; }
    .auth-card h3 { margin: 0 0 24px; color: #8b9cb5; font-weight: 400; text-align: center; }
    .form-group { margin-bottom: 16px; }
    .form-group label { display: block; margin-bottom: 4px; color: #8b9cb5; font-size: 0.85rem; }
    .form-input { width: 100%; padding: 10px 12px; background: #0d1520; border: 1px solid #1e2d3d; border-radius: 6px; color: #e0e6ed; font-size: 0.95rem; box-sizing: border-box; }
    .form-input:focus { outline: none; border-color: #4fc3f7; }
    select.form-input { cursor: pointer; }
    .btn { width: 100%; padding: 10px; border: none; border-radius: 6px; cursor: pointer; font-size: 0.95rem; margin-top: 8px; }
    .btn-primary { background: #1565c0; color: white; }
    .btn-primary:disabled { background: #0d3b6e; cursor: not-allowed; }
    .btn-primary:hover:not(:disabled) { background: #1976d2; }
    .error { color: #ef5350; font-size: 0.85rem; margin-bottom: 8px; }
    .register-link { text-align: center; margin-top: 16px; color: #8b9cb5; font-size: 0.85rem; }
    .register-link a { color: #4fc3f7; text-decoration: none; }
  `]
})
export class RegisterComponent {
  username = '';
  password = '';
  role = 'viewer';
  error = '';
  loading = false;

  constructor(private authService: AuthService, private router: Router) {}

  register() {
    if (!this.username || !this.password) {
      this.error = 'Username and password are required';
      return;
    }
    if (this.password.length < 6) {
      this.error = 'Password must be at least 6 characters';
      return;
    }
    this.loading = true;
    this.error = '';
    this.authService.register(this.username, this.password, this.role).subscribe({
      next: () => {
        this.router.navigate(['/live-feed']);
      },
      error: (err) => {
        this.error = err.error?.detail || 'Registration failed';
        this.loading = false;
      }
    });
  }
}
