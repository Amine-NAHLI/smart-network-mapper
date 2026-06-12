const { exec } = require('child_process');

function chatId() {
  const t = $('Telegram Bot (Unique)').item.json;
  return String(t.callback_query?.message?.chat?.id || t.message?.chat?.id || '');
}

function fail(msg, phase) {
  return [{ json: { success: false, error_message: msg, telegram_chat_id: chatId(), phase } }];
}

const callbackData = $('Telegram Bot (Unique)').item.json.callback_query.data;
const parts = callbackData.split(':');
const mode = parts[0].replace('mode_', '');
const target_ip = parts[1];

if (!target_ip) {
  return fail('IP cible invalide ou manquante.', 'scan');
}

return new Promise((resolve) => {
  exec(
    `python cli/run_scan.py --target ${target_ip} --mode ${mode}`,
    { encoding: 'utf-8', maxBuffer: 20 * 1024 * 1024 },
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
