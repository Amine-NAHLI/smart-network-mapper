"""Corrige les nœuds IF n8n (comparaison booléenne défaillante) + Chat ID erreurs."""
import json
from pathlib import Path

ROOT = Path(__file__).parent

# Condition fiable : pas de error_message = succès
IF_CONDITION = {
    "string": [
        {
            "value1": "={{ $json.error_message || '' }}",
            "operation": "isEmpty",
        }
    ]
}

CHAT_ID_EXPR = (
    "={{ $('Telegram Bot (Unique)').item.json.message?.chat?.id "
    "|| $('Telegram Bot (Unique)').item.json.callback_query?.message?.chat?.id }}"
)

ERROR_TEXT = (
    "=❌ Erreur SNM ({{ $json.phase || 'inconnue' }})\n\n"
    "{{ $json.error_message }}\n\n"
    "Réessayez ou vérifiez Python et les dépendances."
)


def patch(path: Path, local: bool = False) -> None:
    wf = json.loads(path.read_text(encoding="utf-8"))

    for node in wf["nodes"]:
        if node["name"] in ("Découverte OK ?", "Scan OK ?"):
            node["parameters"]["conditions"] = IF_CONDITION

        if node["name"] == "Envoyer Erreur":
            node["parameters"]["chatId"] = CHAT_ID_EXPR
            node["parameters"]["text"] = ERROR_TEXT
            node["parameters"]["additionalFields"] = {}

        if node["name"] == "Envoyer Rapport IA":
            node["parameters"]["chatId"] = CHAT_ID_EXPR
            node["parameters"].setdefault("additionalFields", {})
            node["parameters"]["additionalFields"].pop("parse_mode", None)

    if local:
        for node in wf["nodes"]:
            if node["name"] == "Envoyer Erreur":
                node.setdefault("credentials", {})["telegramApi"] = {
                    "id": "fQnP5Pe1fZNfrzfM",
                    "name": "Telegram account",
                }

    path.write_text(json.dumps(wf, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Fixed IF + Telegram: {path.name}")


if __name__ == "__main__":
    patch(ROOT / "My workflow SNM.json", local=True)
    patch(ROOT / "SNM_n8n_workflow_template.json", local=False)
