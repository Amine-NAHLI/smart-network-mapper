"""
reporter/telegram_utils.py
--------------------------
Utilitaires pour l'envoi de messages via l'API Telegram Bot.
"""

TELEGRAM_MAX_LENGTH = 4096
# Marge de sécurité pour les en-têtes de pagination et le Markdown
TELEGRAM_SAFE_LENGTH = 3900


def split_telegram_message(text: str, max_length: int = TELEGRAM_SAFE_LENGTH) -> list[str]:
    """
    Découpe un texte long en morceaux compatibles avec la limite Telegram (4096 car.).
    Coupe de préférence aux sauts de ligne pour préserver la lisibilité.
    """
    if not text:
        return []
    if len(text) <= max_length:
        return [text]

    chunks: list[str] = []
    remaining = text

    while remaining:
        if len(remaining) <= max_length:
            chunks.append(remaining)
            break

        split_at = remaining.rfind("\n\n", 0, max_length)
        if split_at < max_length // 3:
            split_at = remaining.rfind("\n", 0, max_length)
        if split_at < max_length // 3:
            split_at = remaining.rfind(" ", 0, max_length)
        if split_at < 1:
            split_at = max_length

        chunks.append(remaining[:split_at].rstrip())
        remaining = remaining[split_at:].lstrip()

    return chunks


def format_telegram_chunks(chunks: list[str]) -> list[str]:
    """Ajoute un en-tête de pagination si le message est découpé."""
    total = len(chunks)
    if total <= 1:
        return chunks
    return [f"📄 Rapport IA ({i + 1}/{total})\n\n{chunk}" for i, chunk in enumerate(chunks)]
