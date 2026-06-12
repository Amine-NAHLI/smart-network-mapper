const scan = $input.first().json;
const trigger = $('Telegram Bot (Unique)').item.json;
const chatId =
  trigger.callback_query?.message?.chat?.id ??
  trigger.message?.chat?.id;

const chunks =
  scan.ai_report_chunks && scan.ai_report_chunks.length > 0
    ? scan.ai_report_chunks
    : scan.ai_report_text
      ? [scan.ai_report_text]
      : ['Aucun rapport IA disponible.'];

return chunks.map((text, i) => ({
  json: {
    ...scan,
    ai_report_text: text,
    telegram_chat_id: chatId,
    chunk_index: i + 1,
    chunk_total: chunks.length,
  },
}));
