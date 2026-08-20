const { execFile } = require('child_process');

function chatId() {
  const t = $('Telegram Bot (Unique)').item.json;
  return String(t.callback_query?.message?.chat?.id || t.message?.chat?.id || '');
}

function fail(msg, phase) {
  return [{ json: { success: false, error_message: msg, telegram_chat_id: chatId(), phase } }];
}

const callbackData = $('Telegram Bot (Unique)').item.json.callback_query?.data || '';
const parts = callbackData.split(':');
const rawMode = (parts[0] || '').replace('mode_', '').toLowerCase();
const rawIp = (parts[1] || '').trim();

// ── Validation Stricte des Entrées (Protection Anti-Injection) ──
const validModes = ['fast', 'full'];
const mode = validModes.includes(rawMode) ? rawMode : 'fast';

// Regex IPv4 stricte (0.0.0.0 à 255.255.255.255) ou nom d'hôte standard sécurisé
const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const hostRegex = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

if (!rawIp || (!ipv4Regex.test(rawIp) && !hostRegex.test(rawIp))) {
  return fail(`Format d'IP ou de cible invalide ou non autorisé : "${rawIp}"`, 'scan');
}

const target_ip = rawIp;

return new Promise((resolve) => {
  // Utilisation d'execFile avec tableau d'arguments (aucun interpréteur shell = 0 risque d'injection)
  execFile(
    'python',
    ['cli/run_scan.py', '--target', target_ip, '--mode', mode],
    { encoding: 'utf-8', maxBuffer: 20 * 1024 * 1024, timeout: 600000 },
    (error, stdout, stderr) => {
      const out = (stdout || '').trim();

      if (out) {
        try {
          const data = JSON.parse(out);
          if (data.error || data.success === false) {
            return resolve(fail(data.error_message || data.error || 'Erreur scan', 'scan'));
          }
          return resolve([{ json: { success: true, ...data } }]);
        } catch (e) {
          return resolve(fail(`Réponse invalide du scanner : ${out.slice(0, 500)}`, 'scan'));
        }
      }

      if (error) {
        const detail = (stderr || error.message || '').trim();
        return resolve(fail(detail || 'Erreur lors du scan de sécurité', 'scan'));
      }

      return resolve(fail('Le scanner n\'a renvoyé aucune donnée.', 'scan'));
    },
  );
});
