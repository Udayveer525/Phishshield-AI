import type { DownloadAssessment } from '../../engine/download.js';
import type { RiskAssessment } from '../../shared/types.js';
import type { DownloadRecord, TabState } from './state.js';

/** Messages accepted by the background service worker. Only extension pages and our own content script send these. */
export type BgRequest =
  | { type: 'get-tab-state'; tabId: number; url?: string }
  | { type: 'rescan-tab'; tabId: number; url: string }
  | { type: 'scan-url'; url: string; deep?: boolean }
  | { type: 'set-content-assessment'; tabId: number; assessment: RiskAssessment }
  | { type: 'bypass-and-continue'; tabId: number; url: string; trust: boolean }
  | { type: 'go-back-safe'; tabId: number }
  | { type: 'guard-check'; title: string }
  | { type: 'settings-changed' }
  | { type: 'list-downloads' }
  | { type: 'get-download'; id: number }
  | { type: 'download-action'; id: number; action: DownloadAction };

export type DownloadAction = 'cancel' | 'resume' | 'delete' | 'show';

export interface DownloadView {
  record: DownloadRecord;
  assessment: DownloadAssessment;
  /** Live state from chrome.downloads; absent when the item no longer exists. */
  live?: { state: string; paused: boolean; exists: boolean; bytesReceived: number; totalBytes: number; url: string };
}

export type BgResponse =
  | { ok: true; state?: TabState; assessment?: RiskAssessment; guard?: GuardInfo; downloads?: DownloadRecord[]; download?: DownloadView }
  | { ok: false; error: string };

export interface GuardInfo {
  warn: boolean;
  verdict?: RiskAssessment['verdict'];
  host: string;
  reason?: string;
  officialHint?: string;
}

export function sendBg(msg: BgRequest): Promise<BgResponse> {
  return chrome.runtime.sendMessage(msg) as Promise<BgResponse>;
}
