'use strict';

(function () {
  const SDK_URL = 'https://esm.sh/@supabase/supabase-js@2.105.0';
  let client = null;
  let setupError = '';

  function config() {
    return window.BUDGET_APP_SUPABASE_CONFIG || {};
  }

  function isConfigured() {
    const value = config();
    return Boolean(value.url && value.publishableKey);
  }

  async function init() {
    if (!isConfigured()) return { configured: false };
    if (client) return { configured: true };
    try {
      const module = await import(SDK_URL);
      client = module.createClient(config().url, config().publishableKey, {
        auth: {
          persistSession: true,
          autoRefreshToken: true,
          detectSessionInUrl: true,
          experimental: { passkey: true }
        }
      });
      return { configured: true };
    } catch (error) {
      setupError = error.message || 'Could not load the account service.';
      throw error;
    }
  }

  function requireClient() {
    if (!client) throw new Error(setupError || 'Cloud account setup is not configured yet.');
    return client;
  }

  async function getSession() {
    const api = requireClient();
    const result = await api.auth.getSession();
    if (result.error) throw result.error;
    return result.data.session || null;
  }

  async function onAuthStateChange(callback) {
    const api = requireClient();
    return api.auth.onAuthStateChange(function (_event, session) { callback(session || null); });
  }

  async function sendSignInLink(email) {
    const api = requireClient();
    const result = await api.auth.signInWithOtp({ email: email, options: { shouldCreateUser: true, emailRedirectTo: window.location.href } });
    if (result.error) throw result.error;
    return result.data;
  }

  async function signInWithPasskey() {
    const api = requireClient();
    const result = await api.auth.signInWithPasskey();
    if (result.error) throw result.error;
    return result.data.session || null;
  }

  async function registerPasskey() {
    const api = requireClient();
    const result = await api.auth.registerPasskey();
    if (result.error) throw result.error;
    return result.data;
  }

  async function signOut() {
    const api = requireClient();
    const result = await api.auth.signOut();
    if (result.error) throw result.error;
  }

  async function getEncryptedVault() {
    const api = requireClient();
    const result = await api.from('encrypted_vaults').select('record, revision, updated_at').maybeSingle();
    if (result.error) throw result.error;
    return result.data || null;
  }

  async function saveEncryptedVault(record, expectedRevision) {
    const api = requireClient();
    const result = await api.rpc('save_my_encrypted_vault', { p_expected_revision: expectedRevision, p_record: record });
    if (result.error) throw result.error;
    const revision = Number(result.data);
    if (!Number.isFinite(revision)) throw new Error('The sync service returned an invalid revision.');
    return revision;
  }

  window.BudgetCloud = {
    isConfigured: isConfigured,
    init: init,
    getSession: getSession,
    onAuthStateChange: onAuthStateChange,
    sendSignInLink: sendSignInLink,
    signInWithPasskey: signInWithPasskey,
    registerPasskey: registerPasskey,
    signOut: signOut,
    getEncryptedVault: getEncryptedVault,
    saveEncryptedVault: saveEncryptedVault
  };
}());
