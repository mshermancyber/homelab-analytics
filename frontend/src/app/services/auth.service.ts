import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { BehaviorSubject, Observable, tap, catchError, of, map } from 'rxjs';

export interface User {
  user_id: number;
  username: string;
  role: string;
  permissions: string[];
}

interface JwtPayload {
  sub: string;
  user_id: number;
  role: string;
  iat: number;
  exp: number;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private apiBase = '/api/auth';
  private currentUserSubject = new BehaviorSubject<User | null>(null);
  currentUser$ = this.currentUserSubject.asObservable();

  constructor(private http: HttpClient, private router: Router) {
    this.loadUser();
  }

  private loadUser() {
    const stored = localStorage.getItem('user');
    if (stored) {
      try {
        this.currentUserSubject.next(JSON.parse(stored));
      } catch { /* ignore corrupt data */ }
    }
  }

  /** Decode JWT payload without verification (for expiry check only). */
  private decodeToken(token: string): JwtPayload | null {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      const payload = JSON.parse(atob(parts[1]));
      return payload;
    } catch {
      return null;
    }
  }

  /** Check if token exists and is not expired. */
  isLoggedIn(): boolean {
    const token = localStorage.getItem('access_token');
    if (!token) return false;
    const payload = this.decodeToken(token);
    if (!payload) return false;
    // Check expiration with 30-second buffer
    const now = Math.floor(Date.now() / 1000);
    return payload.exp > now + 30;
  }

  getCurrentUser(): User | null {
    return this.currentUserSubject.value;
  }

  /** Return the raw JWT token for non-HttpClient requests (e.g., SSE fetch). */
  getToken(): string | null {
    return localStorage.getItem('access_token');
  }

  hasRole(...roles: string[]): boolean {
    const user = this.getCurrentUser();
    return user ? roles.includes(user.role) : false;
  }

  register(username: string, password: string, role: string = 'viewer'): Observable<any> {
    return this.http.post(`${this.apiBase}/register`, { username, password, role }).pipe(
      tap((res: any) => {
        this.handleAuthResponse(res);
      })
    );
  }

  login(username: string, password: string): Observable<any> {
    return this.http.post(`${this.apiBase}/login`, { username, password }).pipe(
      tap((res: any) => {
        this.handleAuthResponse(res);
      })
    );
  }

  private handleAuthResponse(res: any) {
    localStorage.setItem('access_token', res.access_token);
    const user: User = {
      user_id: res.user_id,
      username: res.username,
      role: res.role,
      permissions: res.permissions || [],
    };
    localStorage.setItem('user', JSON.stringify(user));
    this.currentUserSubject.next(user);
  }

  /** Validate token with the backend and refresh user info. */
  validateToken(): Observable<boolean> {
    return this.http.get<User>(`${this.apiBase}/me`).pipe(
      tap((user) => {
        localStorage.setItem('user', JSON.stringify(user));
        this.currentUserSubject.next(user);
      }),
      map(() => true),
      catchError(() => {
        // Token invalid — clear auth state
        localStorage.removeItem('access_token');
        localStorage.removeItem('user');
        this.currentUserSubject.next(null);
        return of(false);
      }),
    );
  }

  fetchMe(): Observable<User> {
    return this.http.get<User>(`${this.apiBase}/me`).pipe(
      tap((user) => {
        localStorage.setItem('user', JSON.stringify(user));
        this.currentUserSubject.next(user);
      })
    );
  }

  logout() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
    this.currentUserSubject.next(null);
    this.router.navigate(['/login']);
  }
}
