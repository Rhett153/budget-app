'use strict';

const DB_NAME = 'budget-app-private-vault';
const DB_VERSION = 2;
const VAULT_STORE = 'vault';
const DEVICE_STORE = 'device';
const KDF_ITERATIONS = 310000;
const MAX_STATEMENT_BYTES = 5 * 1024 * 1024;
const CATEGORIES = ['Housing', 'Utilities', 'Groceries', 'Dining', 'Transportation', 'Health', 'Debt', 'Subscriptions', 'Shopping', 'Personal care', 'Education', 'Travel', 'Income', 'Other'];
const DEFAULT_STATE = { transactions: [], statements: [], goals: [], plans: {}, settings: { monthlyIncome: 0, investmentPercent: 0 } };
const $ = function (selector) { return document.querySelector(selector); };
const $$ = function (selector) { return Array.from(document.querySelectorAll(selector)); };

let dbPromise;
let vaultRecord = null;
let vaultKey = null;
let appData = null;
let selectedMonth = monthKey(new Date());
let pendingImport = null;
let toastTimer = null;
let cloudSession = null;
let cloudRevision = 0;
let cloudMessage = '';

function id() {
  if (window.crypto && typeof window.crypto.randomUUID === 'function') return window.crypto.randomUUID();
  return 'id-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2);
}

function openDatabase() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise(function (resolve, reject) {
    if (!window.indexedDB) return reject(new Error('This browser does not support local vault storage.'));
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = function () {
      const db = request.result;
      if (!db.objectStoreNames.contains(VAULT_STORE)) db.createObjectStore(VAULT_STORE, { keyPath: 'id' });
      if (!db.objectStoreNames.contains(DEVICE_STORE)) db.createObjectStore(DEVICE_STORE, { keyPath: 'id' });
    };
    request.onsuccess = function () { resolve(request.result); };
    request.onerror = function () { reject(request.error || new Error('Could not open local vault storage.')); };
  });
  return dbPromise;
}

async function dbGet() {
  const db = await openDatabase();
  return new Promise(function (resolve, reject) {
    const request = db.transaction(VAULT_STORE, 'readonly').objectStore(VAULT_STORE).get('primary');
    request.onsuccess = function () { resolve(request.result || null); };
    request.onerror = function () { reject(request.error); };
  });
}

async function dbPut(record) {
  const db = await openDatabase();
  return new Promise(function (resolve, reject) {
    const request = db.transaction(VAULT_STORE, 'readwrite').objectStore(VAULT_STORE).put(record);
    request.onsuccess = function () { resolve(); };
    request.onerror = function () { reject(request.error || new Error('Could not save your encrypted vault.')); };
  });
}

async function dbDelete() {
  const db = await openDatabase();
  return new Promise(function (resolve, reject) {
    const request = db.transaction(VAULT_STORE, 'readwrite').objectStore(VAULT_STORE).delete('primary');
    request.onsuccess = function () { resolve(); };
    request.onerror = function () { reject(request.error); };
  });
}

async function deviceRecordGet(idValue) {
  const db = await openDatabase();
  return new Promise(function (resolve, reject) {
    const request = db.transaction(DEVICE_STORE, 'readonly').objectStore(DEVICE_STORE).get(idValue);
    request.onsuccess = function () { resolve(request.result || null); };
    request.onerror = function () { reject(request.error); };
  });
}

async function deviceRecordPut(record) {
  const db = await openDatabase();
  return new Promise(function (resolve, reject) {
    const request = db.transaction(DEVICE_STORE, 'readwrite').objectStore(DEVICE_STORE).put(record);
    request.onsuccess = function () { resolve(); };
    request.onerror = function () { reject(request.error || new Error('Could not save this device preference.')); };
  });
}

async function deviceRecordDelete(idValue) {
  const db = await openDatabase();
  return new Promise(function (resolve, reject) {
    const request = db.transaction(DEVICE_STORE, 'readwrite').objectStore(DEVICE_STORE).delete(idValue);
    request.onsuccess = function () { resolve(); };
    request.onerror = function () { reject(request.error); };
  });
}

async function saveRememberedKey(key, enabled) {
  if (enabled) await deviceRecordPut({ id: 'remembered-vault-key', key: key });
  else await deviceRecordDelete('remembered-vault-key');
}

function requireCrypto() {
  if (!window.crypto || !window.crypto.subtle) throw new Error('Secure browser encryption is unavailable. Open the site over HTTPS in a modern browser.');
}

function bytesToBase64(bytes) {
  let binary = '';
  const step = 0x8000;
  for (let i = 0; i < bytes.length; i += step) binary += String.fromCharCode.apply(null, bytes.subarray(i, i + step));
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function deriveVaultKey(passphrase, salt) {
  requireCrypto();
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: KDF_ITERATIONS, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptState(data, key, existingSalt) {
  requireCrypto();
  const salt = existingSalt || crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const derivedKey = existingSalt && key ? key : key;
  const plain = new TextEncoder().encode(JSON.stringify(data));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, derivedKey, plain);
  return { id: 'primary', version: 1, kdf: 'PBKDF2-SHA-256', iterations: KDF_ITERATIONS, salt: bytesToBase64(salt), iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(encrypted)), updatedAt: new Date().toISOString() };
}

async function decryptRecordWithKey(record, key) {
  requireCrypto();
  if (!record || !record.salt || !record.iv || !record.ciphertext) throw new Error('This backup is incomplete or not a Budget App vault.');
  const iv = base64ToBytes(record.iv);
  try {
    const clear = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, base64ToBytes(record.ciphertext));
    const parsed = JSON.parse(new TextDecoder().decode(clear));
    return { key: key, data: normalizeState(parsed) };
  } catch (error) {
    throw new Error('That passphrase did not unlock this vault. Check it and try again.');
  }
}

async function decryptRecord(record, passphrase) {
  requireCrypto();
  if (!record || !record.salt) throw new Error('This backup is incomplete or not a Budget App vault.');
  const key = await deriveVaultKey(passphrase, base64ToBytes(record.salt));
  return decryptRecordWithKey(record, key);
}

function normalizeState(value) {
  const data = value && typeof value === 'object' ? value : {};
  return {
    transactions: Array.isArray(data.transactions) ? data.transactions : [],
    statements: Array.isArray(data.statements) ? data.statements : [],
    goals: Array.isArray(data.goals) ? data.goals : [],
    plans: data.plans && typeof data.plans === 'object' ? data.plans : {},
    settings: Object.assign({ monthlyIncome: 0, investmentPercent: 0 }, data.settings || {})
  };
}

function showGate(createMode, errorMessage) {
  $('#appShell').hidden = true;
  $('#vaultGate').hidden = false;
  $('#createVaultPanel').hidden = !createMode;
  $('#unlockVaultPanel').hidden = createMode;
  $('#restoreBackupLink').hidden = false;
  // A fresh vault must never silently replace an existing encrypted vault.
  $('#switchVaultMode').hidden = Boolean(vaultRecord);
  $('#gateError').hidden = !errorMessage;
  $('#gateError').textContent = errorMessage || '';
  $('#newPassphrase').value = '';
  $('#confirmPassphrase').value = '';
  $('#unlockPassphrase').value = '';
  if (createMode) $('#newPassphrase').focus();
  else $('#unlockPassphrase').focus();
}

function showApp() {
  $('#vaultGate').hidden = true;
  $('#appShell').hidden = false;
  $('#monthPicker').value = selectedMonth;
  renderAll();
  refreshCloudControls();
}

function setCloudStatus(message) {
  cloudMessage = message || '';
  const status = document.getElementById('cloudSyncStatus');
  if (status) status.textContent = cloudMessage;
}

function refreshCloudControls() {
  const configured = window.BudgetCloud && window.BudgetCloud.isConfigured();
  const signedIn = Boolean(cloudSession);
  const enabled = Boolean(appData && appData.settings && appData.settings.cloudSyncEnabled);
  const setHidden = function (idValue, hidden) { const element = document.getElementById(idValue); if (element) element.hidden = hidden; };
  if (!configured) {
    setHidden('emailCloudLinkButton', true); setHidden('passkeySignInButton', true); setHidden('registerPasskeyButton', true);
    setHidden('enableCloudSyncButton', true); setHidden('syncNowButton', true); setHidden('cloudSignOutButton', true);
    const notice = document.getElementById('cloudSyncSetupNotice');
    if (notice) notice.textContent = 'Cloud sync is not configured yet. Create a Supabase project and add its project URL and publishable key to supabase-config.js. No data is sent until sync is enabled.';
    setCloudStatus('Your vault remains local until cloud setup is complete.');
    return;
  }
  const notice = document.getElementById('cloudSyncSetupNotice');
  if (notice) notice.textContent = 'Passkey sign-in uses Supabase Auth. The server receives only the encrypted vault record after you enable sync.';
  setHidden('emailCloudLinkButton', signedIn); setHidden('passkeySignInButton', signedIn); setHidden('registerPasskeyButton', !signedIn);
  setHidden('enableCloudSyncButton', !signedIn || !appData || enabled); setHidden('syncNowButton', !signedIn || !appData || !enabled);
  setHidden('cloudSignOutButton', !signedIn);
  if (signedIn && !cloudMessage) setCloudStatus('Signed in' + (cloudSession.user && cloudSession.user.email ? ' as ' + cloudSession.user.email : '') + (enabled ? ' · encrypted sync on' : ' · sync off'));
  if (!signedIn && !cloudMessage) setCloudStatus('Cloud account is not connected.');
}

async function saveCloudRevision(record, expectedRevision) {
  const revision = await window.BudgetCloud.saveEncryptedVault(record, expectedRevision);
  cloudRevision = revision;
  await deviceRecordPut({ id: 'cloud-sync-state', revision: revision, lastSyncedUpdatedAt: record.updatedAt });
  setCloudStatus('Encrypted vault synced. Cloud revision ' + revision + '.');
  return revision;
}

function isPristineVault(data) {
  const settings = data && data.settings || {};
  return Boolean(data && !settings.cloudSyncEnabled &&
    (!Array.isArray(data.transactions) || data.transactions.length === 0) &&
    (!Array.isArray(data.statements) || data.statements.length === 0) &&
    (!Array.isArray(data.goals) || data.goals.length === 0) &&
    (!data.plans || Object.keys(data.plans).length === 0) &&
    !(Number(settings.investmentPercent) > 0) &&
    !(Number(settings.monthlyIncome) > 0));
}

async function prepareCloudVault() {
  if (!cloudSession || !window.BudgetCloud || !window.BudgetCloud.isConfigured()) return;
  try {
    const remote = await window.BudgetCloud.getEncryptedVault();
    const local = await dbGet();
    const meta = await deviceRecordGet('cloud-sync-state');
    if (!remote) {
      cloudRevision = 0;
      if (!local) setCloudStatus('Signed in. Create or restore a vault, then enable encrypted sync.');
      else setCloudStatus('Signed in. Your existing vault is local; enable encrypted sync when you are ready.');
      return;
    }
    cloudRevision = Number(remote.revision) || 0;
    if (!local) {
      await dbPut(Object.assign({}, remote.record, { id: 'primary' }));
      vaultRecord = await dbGet();
      await deviceRecordPut({ id: 'cloud-sync-state', revision: cloudRevision, lastSyncedUpdatedAt: remote.record.updatedAt });
      setCloudStatus('Downloaded the encrypted vault. Enter its passphrase to unlock it on this device.');
      return 'downloaded';
    }
    if (meta && cloudRevision > Number(meta.revision || 0) && local.updatedAt === meta.lastSyncedUpdatedAt) {
      await dbPut(Object.assign({}, remote.record, { id: 'primary' }));
      vaultRecord = await dbGet();
      await deviceRecordPut({ id: 'cloud-sync-state', revision: cloudRevision, lastSyncedUpdatedAt: remote.record.updatedAt });
      if (vaultKey) {
        const unlocked = await decryptRecordWithKey(vaultRecord, vaultKey);
        appData = unlocked.data;
        renderAll();
      }
      setCloudStatus('Loaded the latest encrypted vault from your other device.');
      return;
    }
    if (meta && cloudRevision === Number(meta.revision || 0)) {
      setCloudStatus('Signed in. Cloud vault is up to date' + (appData && appData.settings.cloudSyncEnabled ? '.' : '; enable sync to start sharing this vault.') );
      return;
    }
    if (!meta && appData && isPristineVault(appData)) {
      await dbPut(Object.assign({}, remote.record, { id: 'primary' }));
      vaultRecord = await dbGet();
      cloudRevision = Number(remote.revision) || 0;
      await deviceRecordPut({ id: 'cloud-sync-state', revision: cloudRevision, lastSyncedUpdatedAt: remote.record.updatedAt });
      await deviceRecordDelete('remembered-vault-key');
      vaultKey = null;
      appData = null;
      setCloudStatus('Found your synced vault. Enter the passphrase you use on your other device to unlock it here.');
      showGate(false);
      return 'needs-unlock';
    }
    setCloudStatus('A cloud vault exists, but this device has changes that are not confirmed as synced. It was left untouched to prevent overwriting data.');
  } catch (error) {
    setCloudStatus('Cloud check failed: ' + (error.message || 'try again from Settings.'));
  }
}

async function persist() {
  if (!vaultKey || !appData) throw new Error('Unlock your vault before saving changes.');
  const record = await encryptState(appData, vaultKey, base64ToBytes(vaultRecord.salt));
  await dbPut(record);
  vaultRecord = record;
  if (appData.settings.cloudSyncEnabled && cloudSession && window.BudgetCloud && window.BudgetCloud.isConfigured()) {
    try {
      const meta = await deviceRecordGet('cloud-sync-state');
      await saveCloudRevision(record, Number(meta && meta.revision || 0));
    } catch (error) {
      setCloudStatus(error.message && error.message.includes('VAULT_REVISION_CONFLICT') ? 'Sync conflict: the cloud copy changed on another device. This device’s encrypted copy is still saved locally.' : 'Saved on this device; cloud sync failed: ' + (error.message || 'try again later.'));
    }
  }
}

function showToast(message, isError) {
  $('#toastMessage').textContent = message;
  $('#toast').classList.toggle('error', Boolean(isError));
  $('#toast').classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(function () { $('#toast').classList.remove('show'); }, 3100);
}

function escapeHtml(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, function (character) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character];
  });
}

function monthKey(date) {
  return date.getFullYear() + '-' + String(date.getMonth() + 1).padStart(2, '0');
}

function currentMonthDate() {
  const pieces = selectedMonth.split('-');
  return new Date(Number(pieces[0]), Number(pieces[1]) - 1, 1);
}

function dateKey(date) {
  return date.getFullYear() + '-' + String(date.getMonth() + 1).padStart(2, '0') + '-' + String(date.getDate()).padStart(2, '0');
}

function formatMoney(value, compact) {
  const amount = Number(value) || 0;
  return new Intl.NumberFormat('en-CA', { style: 'currency', currency: 'CAD', maximumFractionDigits: compact && Math.abs(amount) >= 1000 ? 0 : 2, minimumFractionDigits: compact && Math.abs(amount) >= 1000 ? 0 : 2 }).format(amount);
}

function formatShortDate(dateValue) {
  const date = parseLocalDate(dateValue);
  if (!date) return 'No date';
  return new Intl.DateTimeFormat('en-CA', { month: 'short', day: 'numeric', year: 'numeric' }).format(date);
}

function parseLocalDate(value) {
  if (!value) return null;
  const input = String(value).trim();
  let match = input.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})/);
  if (match) return new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  match = input.match(/^(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})/);
  if (match) {
    let year = Number(match[3]);
    if (year < 100) year += year < 50 ? 2000 : 1900;
    return new Date(year, Number(match[1]) - 1, Number(match[2]));
  }
  const fallback = new Date(input);
  return Number.isNaN(fallback.getTime()) ? null : new Date(fallback.getFullYear(), fallback.getMonth(), fallback.getDate());
}

function iconForCategory(category) {
  const value = String(category || '').toLowerCase();
  if (/housing|rent|mortgage/.test(value)) return ['⌂', ''];
  if (/food|grocer|dining|restaurant/.test(value)) return ['⌁', 'orange'];
  if (/transport|transit|car|gas/.test(value)) return ['↗', 'bluecat'];
  if (/health|personal/.test(value)) return ['✚', 'purplecat'];
  if (/income|salary|payroll/.test(value)) return ['↙', ''];
  return ['✳', ''];
}

function inferCategory(description, amount) {
  const text = String(description || '').toLowerCase();
  if (amount > 0 || /payroll|salary|deposit|refund/.test(text)) return 'Income';
  if (/rent|mortgage|property/.test(text)) return 'Housing';
  if (/electric|power|water|internet|utility|enmax|telus|rogers/.test(text)) return 'Utilities';
  if (/grocery|market|superstore|costco|safeway|walmart/.test(text)) return 'Groceries';
  if (/restaurant|cafe|coffee|skip|uber eats|doordash|dining/.test(text)) return 'Dining';
  if (/uber|lyft|transit|parking|petro|esso|shell|gas station/.test(text)) return 'Transportation';
  if (/pharmacy|clinic|medical|dental|health/.test(text)) return 'Health';
  if (/loan|student loan|credit card payment/.test(text)) return 'Debt';
  if (/netflix|spotify|subscription|icloud/.test(text)) return 'Subscriptions';
  if (/amazon|shopping|clothing|store/.test(text)) return 'Shopping';
  return 'Other';
}

function monthTransactions(key) {
  return appData.transactions.filter(function (transaction) { return String(transaction.date || '').slice(0, 7) === key; });
}

function totalsFor(transactions) {
  return transactions.reduce(function (result, transaction) {
    const amount = Number(transaction.amount) || 0;
    if (amount > 0) result.income += amount;
    else result.spending += Math.abs(amount);
    return result;
  }, { income: 0, spending: 0 });
}

function renderAll() {
  if (!appData) return;
  renderOverview();
  renderTransactions();
  renderBudget();
  renderStatements();
  renderGoals();
  renderMarkets();
  renderPageTitle();
}

function investmentIncomeBasis() {
  const selected = currentMonthDate();
  const monthKeys = [];
  for (let offset = 2; offset >= 0; offset -= 1) monthKeys.push(monthKey(new Date(selected.getFullYear(), selected.getMonth() - offset, 1)));
  const recentIncome = appData.transactions.filter(function (transaction) {
    return Number(transaction.amount) > 0 && monthKeys.includes(String(transaction.date || '').slice(0, 7));
  });
  const monthsWithIncome = new Set(recentIncome.map(function (transaction) { return String(transaction.date).slice(0, 7); }));
  if (recentIncome.length) return recentIncome.reduce(function (sum, transaction) { return sum + Number(transaction.amount); }, 0) / Math.max(1, monthsWithIncome.size);
  return Number(appData.settings.monthlyIncome) || 0;
}

function renderMarkets() {
  if (!appData || !$('#investPercentInput')) return;
  const percentage = Math.min(20, Math.max(0, Number(appData.settings.investmentPercent) || 0));
  const income = investmentIncomeBasis();
  const contribution = income * percentage / 100;
  $('#investPercentInput').value = String(percentage);
  $('#investPercentLabel').textContent = String(percentage);
  $('#marketIncomeBasis').textContent = formatMoney(income);
  $('#marketInvestAmount').textContent = formatMoney(contribution);
  $('#marketTipAmount').textContent = 'At ' + percentage + '%, that is ' + formatMoney(contribution) + ' per month, based on ' + formatMoney(income) + ' monthly income.';
  $('#investIncomeBasisLabel').textContent = income > 0 ? 'Average monthly income from your recent 3-month history, or saved income' : 'Add income transactions or set income in Budget plan to estimate this amount.';

  const tips = [
    ['Keep a long-term view', 'A single market session can be noisy. Consider your time horizon and cash needs before changing a long-term investing plan.'],
    ['A down day is not a deadline', 'Broad markets rise and fall. If you invest, a repeatable amount you can afford may help reduce pressure to time every move.'],
    ['Avoid chasing a rally', 'Strong market days can tempt people to buy based on excitement. Revisit your goals, diversification, and risk comfort before making changes.'],
    ['Protect near-term cash', 'Money needed soon for bills or emergencies may not belong in volatile investments, even when markets are rising.'],
    ['Spread risk thoughtfully', 'One index does not represent every company or region. Learn how diversification and fees affect the investments you are considering.'],
    ['Choose a sustainable amount', 'A contribution should fit after essentials, debt obligations, and emergency savings. You can set this app’s optional estimate to 0% at any time.'],
    ['Review the plan, not every tick', 'Daily price changes are one part of the picture. A regular review schedule can help keep short-term headlines in perspective.']
  ];
  const now = new Date();
  const localDay = Date.UTC(now.getFullYear(), now.getMonth(), now.getDate());
  const tip = tips[Math.floor(localDay / 86400000) % tips.length];
  $('#marketTipTitle').textContent = tip[0];
  $('#marketTipText').textContent = tip[1];
}

function loadMarketWidget() {
  const container = $('#tradingViewMarketWidget');
  if (!container || container.dataset.loaded) return;
  container.dataset.loaded = 'true';
  const script = document.createElement('script');
  script.src = 'https://s3.tradingview.com/external-embedding/embed-widget-market-overview.js';
  script.async = true;
  script.textContent = JSON.stringify({
    colorTheme: 'light', dateRange: '1D', locale: 'en', largeChartUrl: '',
    isTransparent: true, showFloatingTooltip: false, width: '100%', height: '420',
    showSymbolLogo: false, showChart: false, displayMode: 'regular',
    tabs: [
      { title: 'North America', symbols: [
      { s: 'FOREXCOM:SPXUSD', d: 'S&P 500' },
      { s: 'FOREXCOM:NSXUSD', d: 'Nasdaq 100' },
      { s: 'FOREXCOM:DJI', d: 'Dow Jones' },
      { s: 'TSX:TSX', d: 'S&P/TSX Composite' }
      ] },
      { title: 'Companies', symbols: [
        { s: 'NASDAQ:AAPL', d: 'Apple' },
        { s: 'NASDAQ:MSFT', d: 'Microsoft' }
      ] }
    ]
  });
  script.onerror = function () {
    container.dataset.loaded = '';
    const note = $('#marketWidgetStatus');
    if (note) { note.textContent = 'Market quotes could not load. Check your connection and reopen the Markets tab.'; note.hidden = false; }
  };
  container.appendChild(script);
}

function renderPageTitle() {
  const active = $('.nav-link.active');
  if (!active) return;
  const page = active.dataset.page;
  const title = page === 'settings' ? 'Settings' : page.charAt(0).toUpperCase() + page.slice(1);
  $('#breadcrumbPage').textContent = title;
}

function showPage(page) {
  $$('.nav-link[data-page]').forEach(function (button) { button.classList.toggle('active', button.dataset.page === page); });
  $$('.page-view').forEach(function (view) { view.hidden = view.id !== 'view-' + page; });
  renderPageTitle();
  if (page === 'markets') { renderMarkets(); loadMarketWidget(); }
  if (window.innerWidth <= 560) window.scrollTo(0, 0);
}

function renderOverview() {
  const transactions = monthTransactions(selectedMonth);
  const totals = totalsFor(transactions);
  const hasData = transactions.length > 0 || appData.statements.length > 0;
  $('#overviewEmpty').hidden = hasData;
  $('#overviewData').hidden = !hasData;
  $('#dateEyebrow').textContent = new Intl.DateTimeFormat('en-CA', { month: 'long', year: 'numeric' }).format(currentMonthDate()).toUpperCase() + ' · YOUR MONTH AT A GLANCE';
  $('#statIncome').textContent = formatMoney(totals.income);
  $('#statSpending').textContent = formatMoney(totals.spending);
  $('#statLeft').textContent = formatMoney(totals.income - totals.spending);
  $('#statLeftHint').firstChild.textContent = totals.income - totals.spending >= 0 ? 'Income minus expenses' : 'Spending exceeds income';
  $('#statCount').textContent = String(transactions.length);
  renderCashflowChart();
  renderPlanOverview(totals);
  renderRecentTransactions(transactions);
  renderRecentStatements();
  renderGoalStrip();
}

function renderCashflowChart() {
  const base = currentMonthDate();
  const months = [];
  for (let i = 5; i >= 0; i -= 1) {
    const date = new Date(base.getFullYear(), base.getMonth() - i, 1);
    const key = monthKey(date);
    months.push({ key: key, label: new Intl.DateTimeFormat('en-CA', { month: 'short' }).format(date), totals: totalsFor(monthTransactions(key)) });
  }
  const maximum = Math.max(1, ...months.map(function (month) { return Math.max(month.totals.income, month.totals.spending); }));
  const chart = $('#cashflowChart');
  if (!months.some(function (month) { return month.totals.income || month.totals.spending; })) {
    chart.innerHTML = '<div class="chart-empty">Add transactions to see your cash flow.</div>';
    return;
  }
  chart.innerHTML = months.map(function (month) {
    const incomeHeight = month.totals.income ? Math.max(5, Math.round(month.totals.income / maximum * 94)) : 0;
    const spendHeight = month.totals.spending ? Math.max(5, Math.round(month.totals.spending / maximum * 94)) : 0;
    return '<div class="bar-group ' + (month.key === selectedMonth ? 'current' : '') + '"><div class="bars"><i class="bar income" style="height:' + incomeHeight + '%" aria-label="Income ' + escapeHtml(formatMoney(month.totals.income)) + '"></i><i class="bar spending" style="height:' + spendHeight + '%" aria-label="Spending ' + escapeHtml(formatMoney(month.totals.spending)) + '"></i></div><span>' + escapeHtml(month.label) + '</span></div>';
  }).join('');
}

function renderPlanOverview(totals) {
  const plan = appData.plans[selectedMonth];
  const planEmpty = !plan;
  $('#planOverviewEmpty').hidden = !planEmpty;
  $('#planOverviewContent').hidden = planEmpty;
  if (planEmpty) {
    $('#planOverviewSubtitle').textContent = 'Generate a plan from your entries';
    return;
  }
  $('#planOverviewSubtitle').textContent = new Intl.DateTimeFormat('en-CA', { month: 'long', year: 'numeric' }).format(currentMonthDate()) + ' · ' + formatMoney(plan.income) + ' income';
  const spent = plan.categories.reduce(function (sum, category) { return sum + Number(category.spent || 0); }, 0);
  const planned = plan.categories.reduce(function (sum, category) { return sum + Number(category.budget || 0); }, 0);
  const percent = planned ? Math.min(100, Math.round(spent / planned * 100)) : 0;
  $('#planSpent').textContent = formatMoney(spent, true);
  $('#planPercent').textContent = percent + '%';
  $('#planDonut').style.background = 'conic-gradient(#527d5b 0 ' + percent + '%, #edf1ec ' + percent + '% 100%)';
  const categories = plan.categories.filter(function (category) { return Number(category.budget) > 0; }).slice(0, 4);
  $('#overviewCategories').innerHTML = categories.length ? categories.map(function (category) {
    const used = Math.min(100, Number(category.budget) ? Math.round(Number(category.spent || 0) / Number(category.budget) * 100) : 0);
    const icon = iconForCategory(category.name);
    return '<div class="category-row"><span class="cat-icon ' + icon[1] + '">' + icon[0] + '</span><span class="cat-name">' + escapeHtml(category.name) + '</span><span class="cat-progress"><i style="width:' + used + '%"></i></span><span class="cat-value">' + formatMoney(category.spent || 0, true) + ' <small>/ ' + formatMoney(category.budget, true) + '</small></span></div>';
  }).join('') : '<div class="mini-empty"><p>No category limits yet. Generate a plan from your transaction history.</p></div>';
}

function transactionMarkup(transaction, includeActions) {
  const positive = Number(transaction.amount) > 0;
  const icon = iconForCategory(transaction.category);
  const amount = (positive ? '+' : '−') + formatMoney(Math.abs(Number(transaction.amount) || 0));
  const category = escapeHtml(transaction.category || 'Other');
  const actions = includeActions ? '<span class="row-actions"><button class="row-action" data-edit-transaction="' + escapeHtml(transaction.id) + '">Edit</button><button class="row-action" data-delete-transaction="' + escapeHtml(transaction.id) + '">Delete</button></span>' : '<strong class="amount ' + (positive ? 'positive' : '') + '">' + amount + '</strong>';
  return '<div class="transaction-row"><span class="merchant"><span class="merchant-logo">' + icon[0] + '</span><span><strong>' + escapeHtml(transaction.merchant || 'Transaction') + '</strong><small>' + escapeHtml(transaction.notes || transaction.account || (positive ? 'Income' : 'Expense')) + '</small></span></span><span><i class="category-tag">' + category + '</i></span><span class="date">' + escapeHtml(formatShortDate(transaction.date)) + '</span><span class="account-cell">' + escapeHtml(transaction.account || '—') + '</span>' + actions + '</div>';
}

function renderRecentTransactions(transactions) {
  const recent = transactions.slice().sort(function (a, b) { return String(b.date).localeCompare(String(a.date)); }).slice(0, 5);
  const header = '<div class="table-header"><span>MERCHANT</span><span>CATEGORY</span><span>DATE</span><span>ACCOUNT</span><span class="align-right">AMOUNT</span></div>';
  $('#recentTransactions').innerHTML = recent.length ? header + recent.map(function (transaction) { return transactionMarkup(transaction, false); }).join('') : '<div class="table-empty">No transactions in this month yet.</div>';
}

function renderTransactions() {
  const search = ($('#transactionSearch').value || '').trim().toLowerCase();
  const type = $('#transactionTypeFilter').value;
  const category = $('#transactionCategoryFilter').value;
  const filtered = appData.transactions.filter(function (transaction) {
    const isIncome = Number(transaction.amount) > 0;
    const matchesType = type === 'all' || (type === 'income' && isIncome) || (type === 'expense' && !isIncome);
    const haystack = [transaction.merchant, transaction.notes, transaction.account, transaction.category].join(' ').toLowerCase();
    return matchesType && (category === 'all' || transaction.category === category) && (!search || haystack.includes(search));
  }).sort(function (a, b) { return String(b.date).localeCompare(String(a.date)); });
  const header = '<div class="table-header"><span>MERCHANT</span><span>CATEGORY</span><span>DATE</span><span>ACCOUNT</span><span class="align-right">ACTIONS</span></div>';
  $('#allTransactions').innerHTML = filtered.length ? header + filtered.map(function (transaction) { return transactionMarkup(transaction, true); }).join('') : '';
  $('#transactionsEmpty').hidden = filtered.length > 0;
  const current = $('#transactionCategoryFilter').value;
  const categories = Array.from(new Set(appData.transactions.map(function (transaction) { return transaction.category || 'Other'; }))).sort();
  $('#transactionCategoryFilter').innerHTML = '<option value="all">All categories</option>' + categories.map(function (item) { return '<option value="' + escapeHtml(item) + '">' + escapeHtml(item) + '</option>'; }).join('');
  if (categories.includes(current)) $('#transactionCategoryFilter').value = current;
}

function renderBudget() {
  const plan = appData.plans[selectedMonth];
  $('#budgetNoPlan').hidden = Boolean(plan);
  $('#budgetPlanContent').hidden = !plan;
  if (!plan) return;
  const budgetTotal = plan.categories.reduce(function (sum, item) { return sum + Number(item.budget || 0); }, 0);
  const remainder = Number(plan.income || 0) - budgetTotal;
  $('#planIncomeValue').textContent = formatMoney(plan.income);
  $('#planBudgetValue').textContent = formatMoney(budgetTotal);
  $('#planRemainderValue').textContent = formatMoney(remainder);
  $('#planPeriodLabel').textContent = new Intl.DateTimeFormat('en-CA', { month: 'long', year: 'numeric' }).format(currentMonthDate()) + ' · Generated from your recent history';
  $('#planCategories').innerHTML = plan.categories.map(function (category) {
    const used = Math.min(100, Number(category.budget) ? Math.round(Number(category.spent || 0) / Number(category.budget) * 100) : 0);
    return '<div class="plan-category-row"><span class="plan-category-name">' + escapeHtml(category.name) + '</span><span class="plan-category-actual">Recent average: ' + formatMoney(category.average || 0) + '</span><span class="plan-category-limit"><label class="sr-only" for="limit-' + escapeHtml(category.key) + '">' + escapeHtml(category.name) + ' monthly limit</label><input id="limit-' + escapeHtml(category.key) + '" data-plan-limit="' + escapeHtml(category.key) + '" type="number" min="0" step="5" value="' + Math.round(Number(category.budget || 0) * 100) / 100 + '"></span><span class="plan-category-progress"><i style="width:' + used + '%"></i></span></div>';
  }).join('');
  $('#planAssumptions').textContent = plan.assumptions || 'Limits are based on your recent transaction history. Edit any limit to change it.';
}

function statementMarkup(statement, detailed) {
  const isPdf = statement.kind === 'pdf';
  const isImage = statement.kind === 'image';
  const icon = isPdf ? '<span class="statement-logo pdf-logo">PDF</span>' : isImage ? '<span class="statement-logo">IMG</span>' : '<span class="statement-logo">CSV</span>';
  const fileType = isPdf ? 'PDF' : isImage ? 'image' : 'CSV';
  const detail = isPdf || isImage ? 'Encrypted ' + fileType + ' · ' + prettyBytes(statement.size || 0) + (statement.importedCount == null ? '' : ' · ' + Number(statement.importedCount) + ' transactions') : (statement.content ? 'Encrypted CSV · ' : 'CSV import · ') + Number(statement.importedCount || 0) + ' transactions';
  const actions = detailed ? '<span class="statement-ready">Encrypted</span>' + (statement.content && (isPdf || isImage) ? '<button class="row-action" data-process-statement="' + escapeHtml(statement.id) + '">' + (statement.importedCount == null ? 'Read transactions' : 'Read again') + '</button>' : '') + (statement.content ? '<button class="download-button" data-download-statement="' + escapeHtml(statement.id) + '" aria-label="Download ' + fileType + '">↓</button>' : '') + '<button class="download-button" data-delete-statement="' + escapeHtml(statement.id) + '" aria-label="Remove statement">×</button>' : '<span class="statement-ready">Saved here</span>';
  return '<div class="statement-item">' + icon + '<span class="statement-info"><strong>' + escapeHtml(statement.name || 'Statement') + '</strong><small>' + escapeHtml(detail) + ' · ' + escapeHtml(formatShortDate(statement.addedAt)) + '</small></span>' + actions + '</div>';
}

function prettyBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(0) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function renderRecentStatements() {
  const statements = appData.statements.slice().sort(function (a, b) { return String(b.addedAt).localeCompare(String(a.addedAt)); }).slice(0, 2);
  $('#recentStatements').innerHTML = statements.length ? statements.map(function (statement) { return statementMarkup(statement, false); }).join('') : '<div class="table-empty">No statements saved yet.</div>';
}

function renderStatements() {
  const statements = appData.statements.slice().sort(function (a, b) { return String(b.addedAt).localeCompare(String(a.addedAt)); });
  $('#allStatements').innerHTML = statements.map(function (statement) { return statementMarkup(statement, true); }).join('');
  $('#statementsEmpty').hidden = statements.length > 0;
}

function renderGoalStrip() {
  const goal = appData.goals.slice().sort(function (a, b) { return Number(b.target || 0) - Number(b.saved || 0) - (Number(a.target || 0) - Number(a.saved || 0)); })[0];
  const strip = $('#goalStrip');
  strip.hidden = !goal;
  if (!goal) return;
  const percent = Math.min(100, Math.round(Number(goal.target) ? Number(goal.saved) / Number(goal.target) * 100 : 0));
  strip.innerHTML = '<div class="goal-copy"><span class="goal-symbol">✳</span><div><strong>' + escapeHtml(goal.name) + '</strong><small>One step at a time</small></div></div><div class="goal-progress-wrap"><div class="goal-progress-label"><span>' + formatMoney(goal.saved, true) + ' saved</span><span>' + formatMoney(goal.target, true) + ' goal</span></div><div class="goal-track"><i style="width:' + percent + '%"></i></div></div><div class="goal-percent">' + percent + '%<span>there</span></div><button class="goal-arrow" data-page="goals" aria-label="Open savings goals">↗</button>';
}

function renderGoals() {
  const goals = appData.goals.slice().sort(function (a, b) { return String(a.name).localeCompare(String(b.name)); });
  $('#goalsEmpty').hidden = goals.length > 0;
  $('#goalsList').hidden = goals.length === 0;
  $('#goalsList').innerHTML = goals.map(function (goal) {
    const percent = Math.min(100, Math.round(Number(goal.target) ? Number(goal.saved) / Number(goal.target) * 100 : 0));
    const due = goal.targetDate ? 'Target ' + formatShortDate(goal.targetDate) : 'No target date';
    return '<article class="goal-card"><div class="goal-card-top"><span class="goal-symbol">✳</span><span class="goal-title-wrap"><strong>' + escapeHtml(goal.name) + '</strong><small>' + escapeHtml(due) + '</small></span><span class="goal-card-actions"><button class="row-action" data-edit-goal="' + escapeHtml(goal.id) + '">Edit</button><button class="row-action" data-delete-goal="' + escapeHtml(goal.id) + '">Delete</button></span></div><div class="goal-card-progress"><div class="goal-card-values"><span>' + formatMoney(goal.saved) + ' saved</span><strong>' + formatMoney(goal.target) + '</strong></div><div class="goal-track"><i style="width:' + percent + '%"></i></div></div><div class="goal-card-bottom"><small>' + percent + '% of your target</small><button data-contribute-goal="' + escapeHtml(goal.id) + '">＋ Add contribution</button></div></article>';
  }).join('');
}

function setDefaultMonthPicker() {
  const input = $('#monthPicker');
  input.value = selectedMonth;
  input.max = monthKey(new Date());
}

function showDialog(idValue) {
  const dialog = document.getElementById(idValue);
  if (dialog && typeof dialog.showModal === 'function') dialog.showModal();
}

function closeDialog(idValue) {
  const dialog = document.getElementById(idValue);
  if (dialog && dialog.open) dialog.close();
}

function openTransaction(transaction) {
  const item = transaction || null;
  $('#transactionForm').reset();
  $('#transactionId').value = item ? item.id : '';
  $('#transactionDialogTitle').textContent = item ? 'Edit transaction' : 'New transaction';
  $('#transactionType').value = item && Number(item.amount) > 0 ? 'income' : 'expense';
  $('#transactionAmount').value = item ? Math.abs(Number(item.amount)).toFixed(2) : '';
  $('#transactionMerchant').value = item ? item.merchant || '' : '';
  $('#transactionDate').value = item ? item.date : dateKey(new Date());
  $('#transactionCategory').value = item ? item.category || 'Other' : 'Other';
  $('#transactionAccount').value = item ? item.account || '' : '';
  $('#transactionNotes').value = item ? item.notes || '' : '';
  showDialog('transactionDialog');
  $('#transactionMerchant').focus();
}

function openGoal(goal) {
  const item = goal || null;
  $('#goalForm').reset();
  $('#goalId').value = item ? item.id : '';
  $('#goalDialogTitle').textContent = item ? 'Edit savings goal' : 'Create a goal';
  $('#goalName').value = item ? item.name : '';
  $('#goalTarget').value = item ? item.target : '';
  $('#goalSaved').value = item ? item.saved : 0;
  $('#goalDate').value = item ? item.targetDate || '' : '';
  showDialog('goalDialog');
}

function displayValue(value) {
  const number = Number(String(value).replace(/[$,\s]/g, '').replace(/^\((.*)\)$/, '-$1'));
  return Number.isFinite(number) ? number : NaN;
}

function parseDelimited(text) {
  const firstLine = String(text).split(/\r?\n/)[0] || '';
  const delimiters = [',', '\t', ';'];
  const delimiter = delimiters.sort(function (a, b) {
    return (firstLine.split(a).length - 1) - (firstLine.split(b).length - 1);
  }).pop() || ',';
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;
  const input = String(text).replace(/^\uFEFF/, '');
  for (let i = 0; i < input.length; i += 1) {
    const char = input[i];
    if (char === '"') {
      if (quoted && input[i + 1] === '"') { cell += '"'; i += 1; }
      else quoted = !quoted;
    } else if (char === delimiter && !quoted) {
      row.push(cell.trim()); cell = '';
    } else if ((char === '\n' || char === '\r') && !quoted) {
      if (char === '\r' && input[i + 1] === '\n') i += 1;
      row.push(cell.trim());
      if (row.some(function (field) { return field !== ''; })) rows.push(row);
      row = []; cell = '';
    } else cell += char;
  }
  row.push(cell.trim());
  if (row.some(function (field) { return field !== ''; })) rows.push(row);
  return rows;
}

function headerIndex(headers, options) {
  for (let i = 0; i < headers.length; i += 1) if (options.includes(headers[i])) return i;
  return -1;
}

function parseCsvTransactions(text, filename) {
  const rows = parseDelimited(text);
  if (rows.length < 2) throw new Error('This file does not contain a header and transaction rows.');
  const headers = rows[0].map(function (header) { return header.toLowerCase().replace(/[^a-z]/g, ''); });
  const dateIndex = headerIndex(headers, ['date', 'transactiondate', 'posteddate', 'postingdate', 'completeddate', 'transdate']);
  const merchantIndex = headerIndex(headers, ['description', 'merchant', 'name', 'payee', 'details', 'memo', 'transactiondescription', 'transaction']);
  const amountIndex = headerIndex(headers, ['amount', 'transactionamount', 'value']);
  const debitIndex = headerIndex(headers, ['debit', 'withdrawal', 'withdrawals', 'moneyout', 'outflow']);
  const creditIndex = headerIndex(headers, ['credit', 'deposit', 'deposits', 'moneyin', 'inflow']);
  const typeIndex = headerIndex(headers, ['type', 'transactiontype', 'drcr']);
  const categoryIndex = headerIndex(headers, ['category', 'transactioncategory']);
  const accountIndex = headerIndex(headers, ['account', 'accountname', 'accounttype']);
  if (dateIndex < 0 || (amountIndex < 0 && debitIndex < 0 && creditIndex < 0)) throw new Error('Could not find date and amount columns. Use a CSV with Date and Amount, or Date plus Debit and Credit columns.');
  const transactions = [];
  rows.slice(1).forEach(function (row, rowNumber) {
    const date = parseLocalDate(row[dateIndex]);
    if (!date || Number.isNaN(date.getTime())) return;
    let amount = 0;
    if (debitIndex >= 0 || creditIndex >= 0) {
      const debit = debitIndex >= 0 ? displayValue(row[debitIndex]) : 0;
      const credit = creditIndex >= 0 ? displayValue(row[creditIndex]) : 0;
      if (Number.isFinite(debit) && debit !== 0) amount -= Math.abs(debit);
      if (Number.isFinite(credit) && credit !== 0) amount += Math.abs(credit);
    } else {
      amount = displayValue(row[amountIndex]);
      if (!Number.isFinite(amount)) return;
      const type = typeIndex >= 0 ? String(row[typeIndex] || '').toLowerCase() : '';
      if (/debit|withdraw|purchase|expense/.test(type)) amount = -Math.abs(amount);
      if (/credit|deposit|income|refund/.test(type)) amount = Math.abs(amount);
    }
    if (!Number.isFinite(amount) || amount === 0) return;
    const description = merchantIndex >= 0 && row[merchantIndex] ? row[merchantIndex] : 'Imported transaction ' + (rowNumber + 1);
    const explicitCategory = categoryIndex >= 0 && row[categoryIndex] ? row[categoryIndex] : inferCategory(description, amount);
    transactions.push({ id: id(), date: dateKey(date), merchant: description.slice(0, 100), amount: Math.round(amount * 100) / 100, category: CATEGORIES.includes(explicitCategory) ? explicitCategory : String(explicitCategory).slice(0, 40), account: accountIndex >= 0 ? String(row[accountIndex] || '').slice(0, 60) : '', notes: '', source: filename });
  });
  if (!transactions.length) throw new Error('No transaction rows could be read. Check the date and amount columns in your CSV.');
  return transactions;
}

function parseStatementTransactions(text, filename) {
  const datePattern = /\b(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}(?:[-/.]\d{2,4})?|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2}(?:,?\s+\d{4})?)\b/i;
  const amountPattern = /(?:\(\s*)?-?\s*\$?\s*\d[\d,]*\.\d{2}\s*\)?-?/g;
  const allText = String(text || '').replace(/\u00a0/g, ' ');
  const yearMatch = allText.match(/\b(20\d{2})\b/);
  const statementYear = yearMatch ? Number(yearMatch[1]) : new Date().getFullYear();
  const transactions = [];
  const lines = allText.split(/\r?\n/).map(function (line) { return line.replace(/\s+/g, ' ').trim(); }).filter(Boolean);
  const rows = [];
  lines.forEach(function (line) {
    if (datePattern.test(line)) rows.push(line);
    else if (rows.length && !/^(?:date|description|details|transaction|withdrawal|deposit|debit|credit|balance|continued)\b/i.test(line)) rows[rows.length - 1] += ' ' + line;
    datePattern.lastIndex = 0;
  });
  rows.forEach(function (line, rowNumber) {
    const dateMatch = line.match(datePattern);
    if (!dateMatch) return;
    let dateText = dateMatch[0];
    if (!/\b\d{4}\b/.test(dateText)) {
      if (/^[A-Za-z]/.test(dateText)) dateText += ' ' + statementYear;
      else dateText += '/' + statementYear;
    }
    const parsedDate = parseLocalDate(dateText);
    if (!parsedDate || Number.isNaN(parsedDate.getTime())) return;
    const amounts = Array.from(line.matchAll(amountPattern));
    if (!amounts.length) return;
    const chosen = amounts[0];
    const amountToken = chosen[0];
    const rawAmount = displayValue(amountToken.replace(/-$/, ''));
    if (!Number.isFinite(rawAmount) || rawAmount === 0) return;
    const description = line.replace(dateMatch[0], ' ').replace(amountPattern, ' ').replace(/\b(?:CAD|USD|CR|DR|DEBIT|CREDIT)\b/gi, ' ').replace(/[|•·]+/g, ' ').replace(/\s+/g, ' ').trim();
    if (!description || /^(?:date|balance|opening balance|closing balance|total|subtotal|continued)$/i.test(description)) return;
    const explicitlyNegative = /^\s*\(/.test(amountToken) || /^\s*-/.test(amountToken) || /-\s*$/.test(amountToken) || /\bDR\b|\bDEBIT\b/i.test(line);
    const explicitlyPositive = /\bCR\b|\bCREDIT\b/i.test(line);
    const incomeDescription = /payroll|salary|deposit|income|refund|received|interest earned|cashback|reversal/i.test(description);
    const amount = explicitlyNegative || rawAmount < 0 ? -Math.abs(rawAmount) : (explicitlyPositive || incomeDescription ? Math.abs(rawAmount) : -Math.abs(rawAmount));
    transactions.push({ id: id(), date: dateKey(parsedDate), merchant: description.slice(0, 100), amount: Math.round(amount * 100) / 100, category: inferCategory(description, amount), account: '', notes: 'Extracted from statement; verify against the original.', source: filename + ' · extracted row ' + (rowNumber + 1) });
  });
  if (!transactions.length) throw new Error('No transaction rows could be confidently identified. You can still save the original statement and add transactions manually.');
  return transactions;
}

function duplicateKey(transaction) {
  return [transaction.date, Number(transaction.amount).toFixed(2), String(transaction.merchant).trim().toLowerCase()].join('|');
}

function renderImportPreview() {
  const imported = pendingImport.transactions;
  const existing = new Set(appData.transactions.map(duplicateKey));
  const duplicateCount = imported.filter(function (transaction) { return existing.has(duplicateKey(transaction)); }).length;
  const preview = imported.slice(0, 6).map(function (transaction) {
    return '<div class="preview-row"><strong>' + escapeHtml(formatShortDate(transaction.date)) + '</strong><span>' + escapeHtml(transaction.merchant) + '</span><em>' + (Number(transaction.amount) > 0 ? '+' : '−') + formatMoney(Math.abs(Number(transaction.amount))) + '</em></div>';
  }).join('');
  const warning = duplicateCount ? '<div class="preview-warning">' + duplicateCount + ' possible duplicate' + (duplicateCount === 1 ? '' : 's') + ' will be skipped. Positive amounts are treated as income unless your CSV has a debit or type column.</div>' : '<div class="preview-warning">Positive amounts are treated as income unless your CSV has a debit or type column. You can change categories and transaction types after import.</div>';
  $('#importTitle').textContent = 'Review ' + imported.length + ' transaction' + (imported.length === 1 ? '' : 's');
  $('#importMessage').textContent = pendingImport.fileName + ' · ' + imported.length + ' rows found. Review a sample before adding them to your vault.';
  $('#importPreview').innerHTML = warning + preview + (imported.length > 6 ? '<div class="preview-warning">Showing 6 of ' + imported.length + ' rows.</div>' : '');
  $('#pdfNameField').hidden = true;
  $('#confirmImportButton').textContent = 'Import ' + imported.length + ' transactions';
  showDialog('importDialog');
}

function fileToBase64(file) {
  return new Promise(function (resolve, reject) {
    const reader = new FileReader();
    reader.onload = function () {
      const result = String(reader.result || '');
      resolve(result.slice(result.indexOf(',') + 1));
    };
    reader.onerror = function () { reject(new Error('Could not read the selected PDF.')); };
    reader.readAsDataURL(file);
  });
}

async function handleSelectedStatement(file) {
  if (!file) return;
  if (file.size > MAX_STATEMENT_BYTES) { showToast('Files must be 5 MB or smaller in this version.', true); return; }
  const extension = file.name.split('.').pop().toLowerCase();
  if (extension === 'csv' || file.type === 'text/csv') {
    try {
      const transactions = parseCsvTransactions(await file.text(), file.name);
      pendingImport = { kind: 'csv', sourceKind: 'csv', fileName: file.name.slice(0, 100), transactions: transactions, size: file.size, mimeType: 'text/csv', content: await fileToBase64(file) };
      renderImportPreview();
    } catch (error) { showToast(error.message || 'Could not read this CSV.', true); }
    return;
  }
  if (['pdf', 'png', 'jpg', 'jpeg'].includes(extension) || file.type === 'application/pdf' || file.type === 'image/png' || file.type === 'image/jpeg') {
    try {
      $('#importTitle').textContent = 'Reading your statement…';
      $('#importMessage').textContent = 'The file stays in this browser while text is extracted. OCR may take a moment on scanned pages.';
      $('#importPreview').innerHTML = '<div class="preview-warning" role="status">Preparing local document reader…</div>';
      $('#pdfNameField').hidden = true;
      $('#confirmImportButton').disabled = true;
      showDialog('importDialog');
      const extracted = await window.BudgetDocumentReader.extract(file, function (message) { $('#importMessage').textContent = message; });
      const transactions = parseStatementTransactions(extracted.text, file.name);
      const isPdf = extension === 'pdf' || file.type === 'application/pdf';
      const sourceKind = isPdf ? 'pdf' : 'image';
      const mimeType = file.type || (isPdf ? 'application/pdf' : 'image/' + (extension === 'jpg' ? 'jpeg' : extension));
      pendingImport = { kind: 'document-import', sourceKind: sourceKind, fileName: file.name.slice(0, 100), size: file.size, mimeType: mimeType, content: await fileToBase64(file), transactions: transactions, extractionMethod: extracted.method };
      $('#importTitle').textContent = 'Review extracted transactions';
      $('#importMessage').textContent = file.name + ' · ' + transactions.length + ' rows found with ' + extracted.method + '. The source file will be stored encrypted with the import.';
      const warning = '<div class="preview-warning">OCR can misread digits, dates, and balances. Check these sample rows against the statement; imported rows can be edited later.</div>';
      const sample = transactions.slice(0, 8).map(function (transaction) { return '<div class="preview-row"><strong>' + escapeHtml(formatShortDate(transaction.date)) + '</strong><span>' + escapeHtml(transaction.merchant) + '</span><em>' + (transaction.amount > 0 ? '+' : '−') + formatMoney(Math.abs(transaction.amount)) + '</em></div>'; }).join('');
      $('#importPreview').innerHTML = warning + sample + (transactions.length > 8 ? '<div class="preview-warning">Showing 8 of ' + transactions.length + ' extracted rows.</div>' : '');
      $('#confirmImportButton').textContent = 'Import and save statement';
      $('#confirmImportButton').disabled = false;
    } catch (error) {
      const isPdf = extension === 'pdf' || file.type === 'application/pdf';
      try {
        pendingImport = { kind: 'document-only', sourceKind: isPdf ? 'pdf' : 'image', fileName: file.name.slice(0, 100), size: file.size, mimeType: file.type || (isPdf ? 'application/pdf' : 'image/' + (extension === 'jpg' ? 'jpeg' : extension)), content: await fileToBase64(file) };
        $('#importTitle').textContent = 'Save the original statement';
        $('#importMessage').textContent = (error.message || 'Transactions could not be extracted.') + ' You can save the file encrypted and add transactions manually.';
        $('#importPreview').innerHTML = '<div class="preview-warning">' + escapeHtml(file.name) + ' · ' + prettyBytes(file.size) + '</div>';
        $('#confirmImportButton').textContent = 'Save without importing';
        $('#confirmImportButton').disabled = false;
      } catch (readError) {
        closeDialog('importDialog'); pendingImport = null; $('#confirmImportButton').disabled = false;
        showToast(readError.message || 'Could not read this statement.', true);
      }
    }
    return;
  }
  showToast('Choose a CSV, PDF, PNG, or JPEG statement.', true);
}

async function processSavedStatement(statementId) {
  const statement = appData.statements.find(function (item) { return item.id === statementId; });
  if (!statement || !statement.content) return;
  if (Number(statement.size || 0) > MAX_STATEMENT_BYTES) { showToast('This statement is over the 5 MB processing limit.', true); return; }
  try {
    const mimeType = statement.mimeType || (statement.kind === 'pdf' ? 'application/pdf' : 'image/jpeg');
    const file = new File([base64ToBytes(statement.content)], statement.name || 'statement', { type: mimeType });
    $('#importTitle').textContent = 'Reading your saved statement…';
    $('#importMessage').textContent = 'Extracting transaction rows from the encrypted statement on this device.';
    $('#importPreview').innerHTML = '<div class="preview-warning" role="status">Preparing local document reader…</div>';
    $('#pdfNameField').hidden = true;
    $('#confirmImportButton').disabled = true;
    showDialog('importDialog');
    const extracted = await window.BudgetDocumentReader.extract(file, function (message) { $('#importMessage').textContent = message; });
    const transactions = parseStatementTransactions(extracted.text, statement.name || 'Saved statement');
    pendingImport = { kind: 'document-import', existingStatementId: statement.id, sourceKind: statement.kind, fileName: statement.name, size: statement.size, mimeType: mimeType, content: statement.content, transactions: transactions, extractionMethod: extracted.method };
    $('#importTitle').textContent = 'Review extracted transactions';
    $('#importMessage').textContent = statement.name + ' · ' + transactions.length + ' rows found with ' + extracted.method + '. Review these rows before adding them to Transactions.';
    const sample = transactions.slice(0, 8).map(function (transaction) { return '<div class="preview-row"><strong>' + escapeHtml(formatShortDate(transaction.date)) + '</strong><span>' + escapeHtml(transaction.merchant) + '</span><em>' + (transaction.amount > 0 ? '+' : '−') + formatMoney(Math.abs(transaction.amount)) + '</em></div>'; }).join('');
    $('#importPreview').innerHTML = '<div class="preview-warning">Check the dates, amounts, and income/expense signs against the statement. Balances can look like transaction amounts in some statement layouts.</div>' + sample + (transactions.length > 8 ? '<div class="preview-warning">Showing 8 of ' + transactions.length + ' rows.</div>' : '');
    $('#confirmImportButton').textContent = 'Add transactions';
    $('#confirmImportButton').disabled = false;
  } catch (error) {
    pendingImport = null;
    closeDialog('importDialog');
    $('#confirmImportButton').disabled = false;
    showToast(error.message || 'Could not extract transactions from this statement.', true);
  }
}

async function confirmImport() {
  if (!pendingImport) return;
  if (pendingImport.kind === 'document-only') {
    appData.statements.push({ id: id(), kind: pendingImport.sourceKind, name: pendingImport.fileName, size: pendingImport.size, mimeType: pendingImport.mimeType, addedAt: new Date().toISOString(), content: pendingImport.content });
    await persist();
    pendingImport = null;
    closeDialog('importDialog');
    renderAll();
    showToast('Original statement encrypted and saved in this browser.');
    return;
  }
  if (pendingImport.kind === 'pdf') {
    appData.statements.push({ id: id(), kind: 'pdf', name: ($('#pdfDocumentName').value || pendingImport.fileName).slice(0, 100), size: pendingImport.size, addedAt: new Date().toISOString(), content: pendingImport.content });
    await persist();
    pendingImport = null;
    closeDialog('importDialog');
    renderAll();
    showToast('PDF encrypted and saved in this browser.');
    return;
  }
  const existing = new Set(appData.transactions.map(duplicateKey));
  const additions = pendingImport.transactions.filter(function (transaction) {
    const key = duplicateKey(transaction);
    if (existing.has(key)) return false;
    existing.add(key);
    return true;
  });
  appData.transactions.push.apply(appData.transactions, additions);
  const sourceKind = pendingImport.sourceKind || 'csv';
  if (pendingImport.existingStatementId) {
    const savedStatement = appData.statements.find(function (item) { return item.id === pendingImport.existingStatementId; });
    if (savedStatement) { savedStatement.importedCount = Number(savedStatement.importedCount || 0) + additions.length; savedStatement.lastProcessedAt = new Date().toISOString(); }
  } else {
    appData.statements.push({ id: id(), kind: sourceKind, name: pendingImport.fileName, importedCount: additions.length, size: pendingImport.size, mimeType: pendingImport.mimeType || 'text/csv', content: pendingImport.content, addedAt: new Date().toISOString() });
  }
  await persist();
  pendingImport = null;
  closeDialog('importDialog');
  renderAll();
  showPage('transactions');
  showToast(additions.length + ' transaction' + (additions.length === 1 ? '' : 's') + ' added to Transactions.');
}

function createPlan(income) {
  const selected = currentMonthDate();
  const monthKeys = [];
  for (let offset = 2; offset >= 0; offset -= 1) monthKeys.push(monthKey(new Date(selected.getFullYear(), selected.getMonth() - offset, 1)));
  const history = appData.transactions.filter(function (transaction) { return monthKeys.includes(String(transaction.date).slice(0, 7)); });
  const monthsWithEntries = new Set(history.map(function (transaction) { return String(transaction.date).slice(0, 7); }));
  const divisor = Math.max(1, monthsWithEntries.size);
  const spent = new Map();
  history.forEach(function (transaction) {
    if (Number(transaction.amount) >= 0) return;
    const category = transaction.category || 'Other';
    spent.set(category, (spent.get(category) || 0) + Math.abs(Number(transaction.amount)));
  });
  let categories = Array.from(spent.entries()).map(function (entry) {
    const average = entry[1] / divisor;
    return { key: id(), name: entry[0], average: average, spent: 0, budget: Math.ceil(average / 5) * 5 };
  }).sort(function (a, b) { return b.average - a.average; });
  let assumptions = 'Limits use your average spending in ' + divisor + ' month' + (divisor === 1 ? '' : 's') + ' of recent transaction history, rounded up to the nearest $5. Edit each limit to make the plan yours.';
  if (!categories.length) {
    categories = [
      { key: id(), name: 'Housing', average: 0, spent: 0, budget: income * 0.30 },
      { key: id(), name: 'Utilities', average: 0, spent: 0, budget: income * 0.05 },
      { key: id(), name: 'Groceries', average: 0, spent: 0, budget: income * 0.10 },
      { key: id(), name: 'Transportation', average: 0, spent: 0, budget: income * 0.05 },
      { key: id(), name: 'Dining', average: 0, spent: 0, budget: income * 0.05 },
      { key: id(), name: 'Other', average: 0, spent: 0, budget: income * 0.15 }
    ];
    assumptions = 'No recent expenses were found. This starter plan allocates 70% of the income you entered to spending categories and leaves 30% unallocated for saving or flexibility. Review the limits before using the plan.';
  }
  let planned = categories.reduce(function (sum, item) { return sum + item.budget; }, 0);
  if (planned > income && planned > 0) {
    const scale = income * 0.9 / planned;
    categories = categories.map(function (item) { return Object.assign({}, item, { budget: Math.floor(item.budget * scale / 5) * 5 }); });
    assumptions = 'Recent average spending was higher than the income used for this plan. Category limits were scaled to leave 10% unallocated. Review these assumptions and adjust the limits.';
  }
  categories.forEach(function (item) {
    item.spent = Math.abs(monthTransactions(selectedMonth).filter(function (transaction) { return transaction.category === item.name && Number(transaction.amount) < 0; }).reduce(function (sum, transaction) { return sum + Number(transaction.amount); }, 0));
  });
  return { monthKey: selectedMonth, income: Math.round(income * 100) / 100, categories: categories, assumptions: assumptions, generatedAt: new Date().toISOString() };
}

async function generatePlanWithIncome(income) {
  const amount = Number(income);
  if (!Number.isFinite(amount) || amount <= 0) { showToast('Enter a monthly income above zero.', true); return; }
  appData.settings.monthlyIncome = amount;
  appData.plans[selectedMonth] = createPlan(amount);
  await persist();
  closeDialog('incomeDialog');
  renderAll();
  showPage('budget');
  showToast('Your monthly plan is ready to review.');
}

async function requestPlan() {
  const plan = appData.plans[selectedMonth];
  const incomes = appData.transactions.filter(function (transaction) { return Number(transaction.amount) > 0; });
  let amount = 0;
  if (incomes.length) {
    const selected = currentMonthDate();
    const monthKeys = [];
    for (let offset = 2; offset >= 0; offset -= 1) monthKeys.push(monthKey(new Date(selected.getFullYear(), selected.getMonth() - offset, 1)));
    const recent = incomes.filter(function (transaction) { return monthKeys.includes(String(transaction.date).slice(0, 7)); });
    const months = new Set(recent.map(function (transaction) { return String(transaction.date).slice(0, 7); }));
    amount = recent.reduce(function (sum, transaction) { return sum + Number(transaction.amount); }, 0) / Math.max(1, months.size);
  }
  if (amount <= 0) amount = Number(appData.settings.monthlyIncome) || 0;
  if (amount > 0) { await generatePlanWithIncome(amount); return; }
  $('#planIncomeInput').value = '';
  showDialog('incomeDialog');
}

function renderContribution(idValue, amount) {
  const goal = appData.goals.find(function (item) { return item.id === idValue; });
  if (!goal) return;
  const contribution = Number(amount);
  if (!Number.isFinite(contribution) || contribution <= 0) { showToast('Enter a contribution above zero.', true); return; }
  goal.saved = Math.round((Number(goal.saved) + contribution) * 100) / 100;
  persist().then(function () { renderAll(); showToast('Contribution saved to your vault.'); }).catch(function () { showToast('Could not save your contribution.', true); });
}

async function downloadBackup() {
  if (!vaultRecord) return;
  const payload = JSON.stringify({ format: 'budget-app-encrypted-backup', version: 1, vault: vaultRecord }, null, 2);
  const url = URL.createObjectURL(new Blob([payload], { type: 'application/json' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'budget-app-encrypted-backup-' + dateKey(new Date()) + '.json';
  document.body.appendChild(anchor); anchor.click(); anchor.remove(); URL.revokeObjectURL(url);
  showToast('Encrypted backup downloaded. Keep it somewhere private.');
}

async function restoreBackup(file) {
  if (!file) return;
  try {
    const parsed = JSON.parse(await file.text());
    const record = parsed && parsed.format === 'budget-app-encrypted-backup' ? parsed.vault : parsed;
    if (!record || !record.ciphertext || !record.salt || !record.iv) throw new Error('This file is not a Budget App encrypted backup.');
    const existing = await dbGet();
    if (existing && !window.confirm('Restoring will replace the vault in this browser with the selected backup. Continue?')) return;
    await dbPut(Object.assign({}, record, { id: 'primary' }));
    await deviceRecordDelete('remembered-vault-key');
    vaultRecord = await dbGet();
    vaultKey = null; appData = null;
    showGate(false);
    showToast('Backup restored. Unlock it with the passphrase used when it was created.');
  } catch (error) {
    showToast(error.message || 'Could not restore this backup.', true);
  }
}

async function downloadStatement(idValue) {
  const statement = appData.statements.find(function (item) { return item.id === idValue; });
  if (!statement || !statement.content) return;
  const bytes = base64ToBytes(statement.content);
  const isPdf = statement.kind === 'pdf';
  const isImage = statement.kind === 'image';
  const originalExtension = String(statement.name || '').match(/\.(png|jpe?g|pdf|csv)$/i);
  const extension = isPdf ? '.pdf' : isImage ? (originalExtension ? '.' + originalExtension[1].toLowerCase() : statement.mimeType === 'image/png' ? '.png' : '.jpg') : '.csv';
  const mimeType = statement.mimeType || (isPdf ? 'application/pdf' : isImage ? 'image/jpeg' : 'text/csv;charset=utf-8');
  const url = URL.createObjectURL(new Blob([bytes], { type: mimeType }));
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = statement.name.toLowerCase().endsWith(extension) ? statement.name : statement.name + extension;
  document.body.appendChild(anchor); anchor.click(); anchor.remove(); URL.revokeObjectURL(url);
}

function fillCategorySelect(select, selected) {
  select.innerHTML = CATEGORIES.map(function (category) { return '<option value="' + escapeHtml(category) + '">' + escapeHtml(category) + '</option>'; }).join('');
  select.value = selected || 'Other';
}

function lockVault(message) {
  vaultKey = null;
  appData = null;
  Promise.all([dbGet(), deviceRecordDelete('remembered-vault-key')]).then(function (results) {
    const record = results[0];
    vaultRecord = record;
    showGate(!record, message || '');
  }).catch(function () { showGate(false, 'Could not read this browser vault. Refresh the page and try again.'); });
}

async function startApp() {
  $('#createVaultForm').addEventListener('submit', async function (event) {
    event.preventDefault();
    const passphrase = $('#newPassphrase').value;
    if (passphrase.length < 12) { showGate(true, 'Choose a passphrase with at least 12 characters.'); return; }
    if (passphrase !== $('#confirmPassphrase').value) { showGate(true, 'Those passphrases do not match.'); return; }
    try {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      vaultKey = await deriveVaultKey(passphrase, salt);
      appData = structuredClone(DEFAULT_STATE);
      vaultRecord = await encryptState(appData, vaultKey, salt);
      await dbPut(vaultRecord);
      await saveRememberedKey(vaultKey, $('#rememberCreateDevice').checked);
      selectedMonth = monthKey(new Date()); setDefaultMonthPicker(); showApp();
      showToast('Your encrypted vault is ready. Download a backup from Privacy & backups.');
    } catch (error) { showGate(true, error.message || 'Could not create your encrypted vault.'); }
  });

  $('#unlockVaultForm').addEventListener('submit', async function (event) {
    event.preventDefault();
    try {
      vaultRecord = await dbGet();
      const unlocked = await decryptRecord(vaultRecord, $('#unlockPassphrase').value);
      vaultKey = unlocked.key; appData = unlocked.data; selectedMonth = monthKey(new Date()); setDefaultMonthPicker();
      if (cloudSession && await prepareCloudVault() === 'needs-unlock') return;
      showApp();
      await saveRememberedKey(vaultKey, $('#rememberUnlockDevice').checked);
    } catch (error) { showGate(false, error.message || 'Could not unlock this vault.'); }
  });

  $('#switchVaultMode').addEventListener('click', function () { showGate(true); });
  $('#restoreBackupLink').addEventListener('click', function () { $('#backupInput').click(); });
  $('#backupInput').addEventListener('change', function (event) { restoreBackup(event.target.files && event.target.files[0]); event.target.value = ''; });
  $('#settingsBackupInput').addEventListener('change', function (event) { restoreBackup(event.target.files && event.target.files[0]); event.target.value = ''; });

  $('#lockVaultButton').addEventListener('click', function () { lockVault(); });
  $('#lockQuickButton').addEventListener('click', function () { lockVault(); });
  $('#monthPicker').addEventListener('change', function (event) { if (event.target.value) { selectedMonth = event.target.value; renderAll(); } });
  $('#investPercentInput').addEventListener('input', function (event) {
    appData.settings.investmentPercent = Number(event.target.value);
    renderMarkets();
  });
  $('#investPercentInput').addEventListener('change', function () {
    persist().then(function () { showToast('Investing estimate saved to your encrypted budget.'); }).catch(function () { showToast('Could not save the investing estimate.', true); });
  });
  $('#transactionSearch').addEventListener('input', renderTransactions);
  $('#transactionTypeFilter').addEventListener('change', renderTransactions);
  $('#transactionCategoryFilter').addEventListener('change', renderTransactions);

  document.addEventListener('click', function (event) {
    const pageButton = event.target.closest('[data-page]');
    if (pageButton) { showPage(pageButton.dataset.page); return; }
    const closeButton = event.target.closest('[data-close-dialog]');
    if (closeButton) { closeDialog(closeButton.dataset.closeDialog); return; }
    const editTransactionButton = event.target.closest('[data-edit-transaction]');
    if (editTransactionButton) { const item = appData.transactions.find(function (transaction) { return transaction.id === editTransactionButton.dataset.editTransaction; }); if (item) openTransaction(item); return; }
    const deleteTransactionButton = event.target.closest('[data-delete-transaction]');
    if (deleteTransactionButton) {
      const item = appData.transactions.find(function (transaction) { return transaction.id === deleteTransactionButton.dataset.deleteTransaction; });
      if (item && window.confirm('Delete this transaction from your encrypted vault?')) { appData.transactions = appData.transactions.filter(function (transaction) { return transaction.id !== item.id; }); persist().then(function () { renderAll(); showToast('Transaction deleted.'); }).catch(function () { showToast('Could not save the change.', true); }); }
      return;
    }
    const editGoalButton = event.target.closest('[data-edit-goal]');
    if (editGoalButton) { const item = appData.goals.find(function (goal) { return goal.id === editGoalButton.dataset.editGoal; }); if (item) openGoal(item); return; }
    const deleteGoalButton = event.target.closest('[data-delete-goal]');
    if (deleteGoalButton) {
      const item = appData.goals.find(function (goal) { return goal.id === deleteGoalButton.dataset.deleteGoal; });
      if (item && window.confirm('Delete the savings goal "' + item.name + '"?')) { appData.goals = appData.goals.filter(function (goal) { return goal.id !== item.id; }); persist().then(function () { renderAll(); showToast('Goal deleted.'); }).catch(function () { showToast('Could not save the change.', true); }); }
      return;
    }
    const contributeButton = event.target.closest('[data-contribute-goal]');
    if (contributeButton) { const amount = window.prompt('Contribution amount in CAD'); if (amount !== null) renderContribution(contributeButton.dataset.contributeGoal, amount); return; }
    const downloadStatementButton = event.target.closest('[data-download-statement]');
    if (downloadStatementButton) { downloadStatement(downloadStatementButton.dataset.downloadStatement); return; }
    const processStatementButton = event.target.closest('[data-process-statement]');
    if (processStatementButton) { processSavedStatement(processStatementButton.dataset.processStatement); return; }
    const deleteStatementButton = event.target.closest('[data-delete-statement]');
    if (deleteStatementButton) {
      const statement = appData.statements.find(function (item) { return item.id === deleteStatementButton.dataset.deleteStatement; });
      if (statement && window.confirm('Remove "' + statement.name + '" from this browser vault?')) { appData.statements = appData.statements.filter(function (item) { return item.id !== statement.id; }); persist().then(function () { renderAll(); showToast('Statement removed from this vault.'); }).catch(function () { showToast('Could not save the change.', true); }); }
      return;
    }
  });

  ['addTransactionSide', 'addTransactionTop', 'addTransactionPage', 'emptyAddTransaction'].forEach(function (buttonId) { $('#' + buttonId).addEventListener('click', function () { openTransaction(); }); });
  ['generatePlanTop', 'generatePlanMini', 'generatePlanPage', 'generatePlanEmpty'].forEach(function (buttonId) { $('#' + buttonId).addEventListener('click', requestPlan); });
  $('#regeneratePlanInline').addEventListener('click', requestPlan);
  $('#emptyImportStatement').addEventListener('click', function () { $('#statementInput').click(); });
  ['overviewUpload', 'uploadStatementPage', 'uploadStatementBanner'].forEach(function (buttonId) { $('#' + buttonId).addEventListener('click', function () { $('#statementInput').click(); }); });
  $('#statementInput').addEventListener('change', function (event) { handleSelectedStatement(event.target.files && event.target.files[0]); event.target.value = ''; });
  $('#transactionCategory').innerHTML = CATEGORIES.map(function (category) { return '<option value="' + escapeHtml(category) + '">' + escapeHtml(category) + '</option>'; }).join('');

  $('#transactionForm').addEventListener('submit', async function (event) {
    event.preventDefault();
    const transactionId = $('#transactionId').value;
    const amount = Math.abs(Number($('#transactionAmount').value));
    const sign = $('#transactionType').value === 'income' ? 1 : -1;
    if (!Number.isFinite(amount) || amount <= 0) { showToast('Enter an amount above zero.', true); return; }
    const value = { id: transactionId || id(), date: $('#transactionDate').value, merchant: $('#transactionMerchant').value.trim().slice(0, 100), amount: Math.round(amount * sign * 100) / 100, category: $('#transactionCategory').value, account: $('#transactionAccount').value.trim().slice(0, 60), notes: $('#transactionNotes').value.trim().slice(0, 160), source: 'manual' };
    if (transactionId) appData.transactions = appData.transactions.map(function (item) { return item.id === transactionId ? value : item; });
    else appData.transactions.push(value);
    try { await persist(); closeDialog('transactionDialog'); renderAll(); showToast(transactionId ? 'Transaction updated.' : 'Transaction saved to your vault.'); }
    catch (error) { showToast(error.message || 'Could not save your transaction.', true); }
  });

  $('#goalForm').addEventListener('submit', async function (event) {
    event.preventDefault();
    const goalId = $('#goalId').value;
    const value = { id: goalId || id(), name: $('#goalName').value.trim().slice(0, 80), target: Number($('#goalTarget').value), saved: Number($('#goalSaved').value), targetDate: $('#goalDate').value || '' };
    if (goalId) appData.goals = appData.goals.map(function (item) { return item.id === goalId ? value : item; }); else appData.goals.push(value);
    try { await persist(); closeDialog('goalDialog'); renderAll(); showToast('Savings goal saved.'); }
    catch (error) { showToast(error.message || 'Could not save this goal.', true); }
  });
  ['addGoalButton', 'addGoalEmpty'].forEach(function (buttonId) { $('#' + buttonId).addEventListener('click', function () { openGoal(); }); });

  $('#importForm').addEventListener('submit', async function (event) { event.preventDefault(); try { await confirmImport(); } catch (error) { showToast(error.message || 'Could not save this import.', true); } });
  $('#incomeForm').addEventListener('submit', function (event) { event.preventDefault(); generatePlanWithIncome($('#planIncomeInput').value); });
  $('#planCategories').addEventListener('change', function (event) {
    const input = event.target.closest('[data-plan-limit]');
    if (!input) return;
    const plan = appData.plans[selectedMonth];
    const category = plan && plan.categories.find(function (item) { return item.key === input.dataset.planLimit; });
    if (!category) return;
    category.budget = Math.max(0, Number(input.value) || 0);
    persist().then(function () { renderAll(); showToast('Budget limit updated.'); }).catch(function () { showToast('Could not save your limit.', true); });
  });

  $('#downloadBackupButton').addEventListener('click', downloadBackup);
  $('#backupQuickButton').addEventListener('click', downloadBackup);
  $('#restoreBackupButton').addEventListener('click', function () { $('#settingsBackupInput').click(); });
  $('#deleteVaultButton').addEventListener('click', async function () {
    if (!window.confirm('Delete all encrypted Budget App data from this browser? This cannot be undone without a backup.')) return;
    await dbDelete();
    await deviceRecordDelete('remembered-vault-key');
    vaultRecord = null; vaultKey = null; appData = null;
    showGate(true);
    showToast('The local vault was deleted.');
  });

  $('#changePassphraseForm').addEventListener('submit', async function (event) {
    event.preventDefault();
    const current = $('#currentPassphrase').value;
    const updated = $('#updatedPassphrase').value;
    if (updated.length < 12) { showToast('Choose at least 12 characters for the new passphrase.', true); return; }
    if (updated !== $('#updatedPassphraseConfirm').value) { showToast('The new passphrases do not match.', true); return; }
    try {
      const verified = await decryptRecord(vaultRecord, current);
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const nextKey = await deriveVaultKey(updated, salt);
      const nextRecord = await encryptState(verified.data, nextKey, salt);
      let nextRevision = null;
      const syncEnabled = Boolean(verified.data.settings.cloudSyncEnabled && cloudSession && window.BudgetCloud && window.BudgetCloud.isConfigured());
      if (syncEnabled) {
        const meta = await deviceRecordGet('cloud-sync-state');
        nextRevision = await window.BudgetCloud.saveEncryptedVault(nextRecord, Number(meta && meta.revision || 0));
      }
      await dbPut(nextRecord);
      vaultRecord = nextRecord; vaultKey = nextKey; appData = verified.data;
      if (syncEnabled) {
        await deviceRecordPut({ id: 'cloud-sync-state', revision: nextRevision, lastSyncedUpdatedAt: nextRecord.updatedAt });
        cloudRevision = nextRevision;
        setCloudStatus('Passphrase changed and encrypted vault synced.');
      }
      if (await deviceRecordGet('remembered-vault-key')) await saveRememberedKey(nextKey, true);
      $('#changePassphraseForm').reset();
      showToast('Vault re-encrypted with the new passphrase.');
    } catch (error) { showToast(error.message && error.message.includes('VAULT_REVISION_CONFLICT') ? 'The cloud copy changed on another device. Sync that copy before changing the passphrase.' : error.message || 'Could not change the passphrase.', true); }
  });

  $('#emailCloudLinkButton').addEventListener('click', async function () {
    const email = $('#cloudEmail').value.trim();
    if (!email) { setCloudStatus('Enter your email to start account setup.'); return; }
    try {
      await window.BudgetCloud.sendSignInLink(email);
      cloudMessage = 'Check your email for a secure sign-in link. After confirming the account, return here and add a passkey.';
      refreshCloudControls();
      setCloudStatus(cloudMessage);
    } catch (error) { setCloudStatus(error.message || 'Could not send the sign-in link.'); }
  });

  $('#passkeySignInButton').addEventListener('click', async function () {
    try {
      cloudSession = await window.BudgetCloud.signInWithPasskey();
      if (!cloudSession) cloudSession = await window.BudgetCloud.getSession();
      await prepareCloudVault();
      refreshCloudControls();
    } catch (error) { setCloudStatus(error.message || 'Passkey sign-in did not complete.'); }
  });

  $('#registerPasskeyButton').addEventListener('click', async function () {
    try {
      await window.BudgetCloud.registerPasskey();
      setCloudStatus('Passkey added. Use it to sign into this account on your other devices.');
      refreshCloudControls();
    } catch (error) { setCloudStatus(error.message || 'Could not add a passkey. Confirm your email account first.'); }
  });

  $('#cloudSignOutButton').addEventListener('click', async function () {
    try {
      await window.BudgetCloud.signOut();
      cloudSession = null; cloudRevision = 0; cloudMessage = '';
      refreshCloudControls();
      setCloudStatus('Signed out of the cloud account. This device’s local encrypted vault remains here.');
    } catch (error) { setCloudStatus(error.message || 'Could not sign out.'); }
  });

  $('#enableCloudSyncButton').addEventListener('click', async function () {
    if (!cloudSession || !appData || !vaultKey) { setCloudStatus('Unlock your vault and sign in before enabling sync.'); return; }
    if (!window.confirm('This uploads the encrypted vault record, including encrypted transaction and statement files, to your Supabase project. Supabase receives ciphertext, not your passphrase or readable records. Enable sync?')) return;
    const previous = Boolean(appData.settings.cloudSyncEnabled);
    appData.settings.cloudSyncEnabled = true;
    try {
      const record = await encryptState(appData, vaultKey, base64ToBytes(vaultRecord.salt));
      const meta = await deviceRecordGet('cloud-sync-state');
      const revision = await window.BudgetCloud.saveEncryptedVault(record, Number(meta && meta.revision || 0));
      await dbPut(record);
      vaultRecord = record;
      await deviceRecordPut({ id: 'cloud-sync-state', revision: revision, lastSyncedUpdatedAt: record.updatedAt });
      cloudRevision = revision;
      cloudMessage = 'Encrypted sync is on. Cloud revision ' + revision + '.';
      refreshCloudControls();
      setCloudStatus(cloudMessage);
      showToast('Encrypted vault synced to your account.');
    } catch (error) {
      appData.settings.cloudSyncEnabled = previous;
      setCloudStatus(error.message && error.message.includes('VAULT_REVISION_CONFLICT') ? 'A cloud vault already exists with different changes. No data was overwritten.' : error.message || 'Could not enable cloud sync.');
    }
  });

  $('#syncNowButton').addEventListener('click', async function () {
    if (!cloudSession || !appData || !vaultKey) return;
    try {
      const remote = await window.BudgetCloud.getEncryptedVault();
      if (!remote) { setCloudStatus('No cloud copy exists yet. Enable encrypted sync to create one.'); return; }
      const local = await dbGet();
      const meta = await deviceRecordGet('cloud-sync-state');
      if (meta && Number(remote.revision) > Number(meta.revision) && local.updatedAt === meta.lastSyncedUpdatedAt) {
        await dbPut(Object.assign({}, remote.record, { id: 'primary' }));
        vaultRecord = await dbGet();
        const unlocked = await decryptRecordWithKey(vaultRecord, vaultKey);
        appData = unlocked.data;
        cloudRevision = Number(remote.revision);
        await deviceRecordPut({ id: 'cloud-sync-state', revision: cloudRevision, lastSyncedUpdatedAt: remote.record.updatedAt });
        renderAll();
        setCloudStatus('Loaded the latest encrypted vault from your other device.');
        return;
      }
      if (meta && Number(remote.revision) === Number(meta.revision)) {
        if (local.updatedAt === meta.lastSyncedUpdatedAt) { setCloudStatus('Your devices are up to date.'); return; }
        await saveCloudRevision(local, Number(remote.revision));
        return;
      }
      setCloudStatus('Sync conflict: another device changed the cloud vault. Your local copy remains saved; no data was overwritten.');
    } catch (error) { setCloudStatus(error.message || 'Could not sync this device.'); }
  });

  $$('.app-dialog').forEach(function (dialog) { dialog.addEventListener('click', function (event) { if (event.target === dialog) dialog.close(); }); });

  try {
    requireCrypto();
    if (window.BudgetCloud && window.BudgetCloud.isConfigured()) {
      try {
        await window.BudgetCloud.init();
        cloudSession = await window.BudgetCloud.getSession();
        if (cloudSession) await prepareCloudVault();
        await window.BudgetCloud.onAuthStateChange(async function (session) {
          cloudSession = session;
          cloudMessage = '';
          if (cloudSession) await prepareCloudVault();
          refreshCloudControls();
        });
      } catch (cloudError) { setCloudStatus(cloudError.message || 'Cloud account configuration needs attention.'); }
    }
    vaultRecord = await dbGet();
    if (vaultRecord) {
      const remembered = await deviceRecordGet('remembered-vault-key');
      if (remembered && remembered.key) {
        try {
          const unlocked = await decryptRecordWithKey(vaultRecord, remembered.key);
          vaultKey = remembered.key;
          appData = unlocked.data;
          selectedMonth = monthKey(new Date());
          setDefaultMonthPicker();
          if (cloudSession && await prepareCloudVault() === 'needs-unlock') return;
          showApp();
          showToast('Vault reopened on this device.');
          return;
        } catch (error) {
          await deviceRecordDelete('remembered-vault-key');
        }
      }
    }
    showGate(!vaultRecord);
    if (!vaultRecord) $('#restoreBackupLink').hidden = false;
  } catch (error) {
    showGate(true, error.message || 'Could not initialize the private vault.');
    $('#createVaultForm').querySelector('button[type="submit"]').disabled = true;
  }
  refreshCloudControls();
  setDefaultMonthPicker();
}

startApp().catch(function (error) {
  $('#vaultGate').hidden = false;
  $('#appShell').hidden = true;
  $('#gateError').hidden = false;
  $('#gateError').textContent = error.message || 'Budget App could not start in this browser.';
});
