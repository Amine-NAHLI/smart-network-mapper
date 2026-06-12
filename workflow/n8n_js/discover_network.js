const { execSync } = require('child_process');

function chatId() {
  const t = $('Telegram Bot (Unique)').item.json;
  return String(t.message?.chat?.id || t.callback_query?.message?.chat?.id || '');
}

function fail(msg, phase) {
  return [{ json: { success: false, error_message: msg, telegram_chat_id: chatId(), phase } }];
}

try {
  let stdout;
  try {
    stdout = execSync('python cli/run_scan.py --discover', {
      encoding: 'utf-8',
      maxBuffer: 10 * 1024 * 1024,
    });
  } catch (e) {
    const out = (e.stdout || '').trim();
    if (out) {
      try {
        const parsed = JSON.parse(out);
        if (parsed.error || parsed.success === false) {
          return fail(parsed.error_message || parsed.error || 'Erreur découverte', 'discover');
        }
      } catch (_) { /* ignore parse error */ }
    }
    const detail = (e.stderr || e.message || '').trim();
    return fail(detail || 'Erreur lors de la découverte réseau', 'discover');
  }

  const data = JSON.parse(stdout.trim());
  if (data.error || data.success === false) {
    return fail(data.error_message || data.error || 'Erreur découverte', 'discover');
  }
  if (!data.hosts || data.hosts.length === 0) {
    return fail('Aucun appareil actif trouvé sur le réseau local.', 'discover');
  }

  const buttons = data.hosts.map((host) => [{
    text: `🎯 ${host.ip}`,
    callback_data: host.ip,
  }]);

  return [{
    json: {
      success: true,
      ...data,
      telegram_buttons: { inline_keyboard: buttons },
      message_text:
        `🔍 **Scan Réseau Terminé**\nInterface : ${data.interface}\n` +
        `Réseau : ${data.subnet}\nAppareils trouvés : ${data.hosts.length}\n\n` +
        `👇 **Choisissez une cible à scanner en profondeur :**`,
    },
  }];
} catch (e) {
  return fail(e.message || String(e), 'discover');
}
