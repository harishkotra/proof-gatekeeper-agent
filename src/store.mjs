// Durable seen-set for PROOF_REUSED detection.
// Backends: "file" (default) or "github" (private repo JSON, for serverless hosts).
import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import path from 'node:path';

const FILE = process.env.SEEN_SET_FILE || './data/seen.json';
const MAX = 20000;

class FileStore {
  constructor() {
    this.set = new Set();
    this.loaded = false;
    this.writing = Promise.resolve();
  }
  async load() {
    if (this.loaded) return;
    try {
      const raw = JSON.parse(await readFile(FILE, 'utf8'));
      for (const k of raw.seen || []) this.set.add(k);
    } catch {
      await mkdir(path.dirname(FILE), { recursive: true }).catch(() => {});
    }
    this.loaded = true;
  }
  has(k) { return this.set.has(k); }
  async add(k) {
    await this.load();
    if (this.set.has(k)) return;
    this.set.add(k);
    if (this.set.size > MAX) this.set = new Set([...this.set].slice(-MAX));
    const snapshot = JSON.stringify({ seen: [...this.set], updated_at: new Date().toISOString() });
    this.writing = this.writing.then(async () => {
      const tmp = FILE + '.tmp';
      await mkdir(path.dirname(FILE), { recursive: true }).catch(() => {});
      await writeFile(tmp, snapshot, 'utf8');
      await rename(tmp, FILE); // atomic swap, survives a crash mid-write
    });
    await this.writing;
  }
  size() { return this.set.size; }
}

// Serverless adapter: keeps the seen-set in a private GitHub repo file.
// Env: GITHUB_TOKEN, SEEN_SET_REPO ("owner/name"), SEEN_SET_PATH ("seen.json"), SEEN_SET_BRANCH ("main")
class GithubStore {
  constructor() {
    this.repo = process.env.SEEN_SET_REPO;
    this.file = process.env.SEEN_SET_PATH || 'seen.json';
    this.branch = process.env.SEEN_SET_BRANCH || 'main';
    this.token = process.env.GITHUB_TOKEN;
    this.cache = new Set();
    this.sha = null;
    this.primed = false;
  }
  async api(p, init = {}) {
    const res = await fetch(`https://api.github.com/repos/${this.repo}/${p}`, {
      ...init,
      headers: {
        authorization: `Bearer ${this.token}`,
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
        ...(init.headers || {}),
      },
    });
    return res;
  }
  async load() {
    if (this.primed) return;
    const res = await this.api(`contents/${this.file}?ref=${this.branch}`);
    if (res.status === 200) {
      const body = await res.json();
      this.sha = body.sha;
      const text = Buffer.from(body.content || '', 'base64').toString('utf8');
      try {
        for (const k of JSON.parse(text).seen || []) this.cache.add(k);
      } catch { /* first write */ }
    }
    this.primed = true;
  }
  has(k) { return this.cache.has(k); }
  async add(k) {
    await this.load();
    if (this.cache.has(k)) return;
    this.cache.add(k);
    if (this.cache.size > MAX) this.cache = new Set([...this.cache].slice(-MAX));
    const payload = {
      message: `seen +${k.slice(0, 12)}`,
      content: Buffer.from(JSON.stringify({ seen: [...this.cache], updated_at: new Date().toISOString() })).toString('base64'),
      branch: this.branch,
      ...(this.sha ? { sha: this.sha } : {}),
    };
    const res = await this.api(`contents/${this.file}`, { method: 'PUT', body: JSON.stringify(payload) });
    if (res.ok) {
      const body = await res.json();
      this.sha = body.content?.sha || this.sha;
    }
  }
  size() { return this.cache.size; }
}

export function createStore() {
  if (process.env.SEEN_SET_BACKEND === 'github') return new GithubStore();
  return new FileStore();
}
