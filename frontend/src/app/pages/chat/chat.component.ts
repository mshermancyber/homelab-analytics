import { Component, ViewChild, ElementRef, AfterViewChecked } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { AuthService } from '../../services/auth.service';

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

@Component({
  selector: 'app-chat',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="page-layout">
      <div class="chat-container">
        <div class="chat-header">
          <h1>💬 AI Investigation Chat</h1>
          <span class="rate-info">10 queries/min</span>
        </div>

        <div class="alert-context" *ngIf="alertContext">
          <span class="context-label">Context: Alert #{{ alertId }}</span>
          <button class="clear-btn" (click)="clearContext()">✕</button>
        </div>

        <div class="error-banner" *ngIf="error">{{ error }}</div>

        <div class="messages" #messagesContainer>
          <div *ngFor="let msg of messages" class="message" [class.user]="msg.role === 'user'" [class.assistant]="msg.role === 'assistant'">
            <div class="msg-role">{{ msg.role === 'user' ? 'You' : 'AI' }}</div>
            <div class="msg-content">{{ msg.content }}</div>
          </div>
          <div *ngIf="streaming" class="message assistant">
            <div class="msg-role">AI</div>
            <div class="msg-content">{{ streamingContent }}<span class="cursor">▊</span></div>
          </div>
        </div>

        <div class="input-area">
          <input type="number" [(ngModel)]="alertId" placeholder="Alert ID (optional)" class="alert-id-input" />
          <textarea
            [(ngModel)]="inputMessage"
            (keydown.enter)="send()"
            placeholder="Ask about alerts, threats, or security patterns..."
            rows="2"
            class="chat-input"
          ></textarea>
          <button (click)="send()" [disabled]="!inputMessage.trim() || streaming" class="send-btn">
            {{ streaming ? '...' : 'Send' }}
          </button>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .page-layout {
      padding: 0;
      background: #1a1a2e;
      min-height: calc(100vh - 60px);
      display: flex;
      justify-content: center;
    }

    .chat-container {
      max-width: 800px;
      width: 100%;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      height: calc(100vh - 60px);
    }

    .chat-header {
      padding: 16px 20px;
      border-bottom: 1px solid #1e2d3d;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-shrink: 0;
    }

    .chat-header h1 {
      margin: 0;
      font-size: 1.2rem;
      color: #e0e6ed;
    }

    .rate-info {
      font-size: 0.7rem;
      color: #8b9cb5;
      background: #111927;
      padding: 4px 10px;
      border-radius: 12px;
      border: 1px solid #1e2d3d;
    }

    .alert-context {
      padding: 6px 16px;
      background: #1a3a5a;
      border-bottom: 1px solid #1e2d3d;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-shrink: 0;
    }

    .context-label {
      font-size: 0.8rem;
      color: #4fc3f7;
    }

    .clear-btn {
      background: none;
      border: none;
      color: #8b9cb5;
      cursor: pointer;
      font-size: 1rem;
      padding: 2px 6px;
    }

    .clear-btn:hover {
      color: #e0e6ed;
    }

    .error-banner {
      padding: 8px 16px;
      background: #3e1a1a;
      color: #ef5350;
      font-size: 0.85rem;
      border-bottom: 1px solid #5c2a2a;
      flex-shrink: 0;
    }

    .messages {
      flex: 1;
      overflow-y: auto;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .message {
      max-width: 80%;
      padding: 12px 16px;
      border-radius: 12px;
      word-wrap: break-word;
      white-space: pre-wrap;
    }

    .message.user {
      align-self: flex-end;
      background: #1565c0;
      color: white;
    }

    .message.assistant {
      align-self: flex-start;
      background: #1a2332;
      border: 1px solid #1e2d3d;
      color: #e0e0e0;
    }

    .msg-role {
      font-size: 0.65rem;
      text-transform: uppercase;
      margin-bottom: 4px;
      opacity: 0.7;
      letter-spacing: 0.5px;
    }

    .msg-content {
      font-size: 0.9rem;
      line-height: 1.5;
    }

    .cursor {
      animation: blink 1s step-end infinite;
      color: #4fc3f7;
    }

    @keyframes blink {
      50% { opacity: 0; }
    }

    .input-area {
      display: flex;
      gap: 8px;
      padding: 12px;
      background: #111927;
      border-top: 1px solid #1e2d3d;
      flex-wrap: wrap;
      flex-shrink: 0;
    }

    .chat-input {
      flex: 1;
      min-width: 200px;
      background: #0d1520;
      border: 1px solid #1e2d3d;
      color: #e0e6ed;
      border-radius: 6px;
      padding: 8px 12px;
      resize: none;
      font-family: inherit;
      font-size: 0.9rem;
    }

    .chat-input::placeholder {
      color: #5a6a7e;
    }

    .chat-input:focus {
      outline: none;
      border-color: #4fc3f7;
    }

    .alert-id-input {
      width: 130px;
      background: #0d1520;
      border: 1px solid #1e2d3d;
      color: #e0e6ed;
      border-radius: 6px;
      padding: 8px;
      font-family: inherit;
      font-size: 0.85rem;
    }

    .alert-id-input::placeholder {
      color: #5a6a7e;
    }

    .alert-id-input:focus {
      outline: none;
      border-color: #4fc3f7;
    }

    .send-btn {
      background: #1565c0;
      color: white;
      border: none;
      border-radius: 6px;
      padding: 8px 20px;
      cursor: pointer;
      font-size: 0.9rem;
      font-weight: 500;
      transition: background 0.2s;
      white-space: nowrap;
    }

    .send-btn:hover:not(:disabled) {
      background: #1976d2;
    }

    .send-btn:disabled {
      background: #0d3b6e;
      cursor: not-allowed;
      opacity: 0.7;
    }

    /* Hide number input arrows */
    .alert-id-input::-webkit-inner-spin-button,
    .alert-id-input::-webkit-outer-spin-button {
      -webkit-appearance: none;
      margin: 0;
    }
    .alert-id-input[type=number] {
      -moz-appearance: textfield;
    }

    @media (max-width: 768px) {
      .chat-container {
        height: calc(100vh - 50px);
      }
      .message {
        max-width: 90%;
      }
      .input-area {
        padding: 8px;
        gap: 6px;
      }
      .alert-id-input {
        width: 100%;
      }
    }
  `]
})
export class ChatComponent implements AfterViewChecked {
  messages: ChatMessage[] = [];
  inputMessage = '';
  alertId: number | null = null;
  alertContext = false;
  streaming = false;
  streamingContent = '';
  error = '';

  @ViewChild('messagesContainer') private messagesContainer!: ElementRef;

  constructor(private authService: AuthService) {}

  ngAfterViewChecked() {
    this.scrollToBottom();
  }

  send() {
    if (!this.inputMessage.trim() || this.streaming) return;

    this.error = '';

    // Don't send on shift+enter (allow newlines)
    const msg = this.inputMessage.trim();
    this.messages.push({ role: 'user', content: msg });
    this.inputMessage = '';
    this.streaming = true;
    this.streamingContent = '';

    const body: any = { message: msg };
    if (this.alertId) {
      body.alert_id = this.alertId;
      this.alertContext = true;
    }

    const token = this.authService.getToken();
    fetch('/api/chat', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    })
      .then(async (response) => {
        if (response.status === 429) {
          this.error = 'Rate limit exceeded. Max 10 queries per minute.';
          this.messages.push({ role: 'assistant', content: '⚠️ Rate limit exceeded. Max 10 queries per minute.' });
          this.streaming = false;
          this.streamingContent = '';
          return;
        }
        if (!response.ok) {
          const text = await response.text();
          this.error = `HTTP ${response.status}: ${text}`;
          this.messages.push({ role: 'assistant', content: `⚠️ Error: ${response.status} — ${text}` });
          this.streaming = false;
          this.streamingContent = '';
          return;
        }

        const reader = response.body?.getReader();
        if (!reader) {
          this.messages.push({ role: 'assistant', content: '⚠️ No response stream available.' });
          this.streaming = false;
          this.streamingContent = '';
          return;
        }

        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            if (line.startsWith('data: ')) {
              const data = line.slice(6);
              if (data === '[DONE]') {
                if (this.streamingContent) {
                  this.messages.push({ role: 'assistant', content: this.streamingContent });
                }
                this.streaming = false;
                this.streamingContent = '';
                return;
              }
              try {
                const parsed = JSON.parse(data);
                if (parsed.error) {
                  this.messages.push({ role: 'assistant', content: `⚠️ ${parsed.error}` });
                  this.streaming = false;
                  this.streamingContent = '';
                  return;
                }
                if (parsed.content) {
                  this.streamingContent += parsed.content;
                }
              } catch {
                // Ignore unparseable lines
              }
            }
          }
        }

        // Stream ended without [DONE]
        if (this.streamingContent) {
          this.messages.push({ role: 'assistant', content: this.streamingContent });
        }
        this.streaming = false;
        this.streamingContent = '';
      })
      .catch((err) => {
        this.streaming = false;
        const errMsg = err.message || 'Connection failed';
        this.error = errMsg;
        this.messages.push({ role: 'assistant', content: `⚠️ Error: ${errMsg}` });
        this.streamingContent = '';
      });
  }

  clearContext() {
    this.alertId = null;
    this.alertContext = false;
  }

  private scrollToBottom() {
    try {
      const el = this.messagesContainer.nativeElement;
      el.scrollTop = el.scrollHeight;
    } catch {
      // Ignore if element not yet rendered
    }
  }
}
