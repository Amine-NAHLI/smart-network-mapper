"""Met à jour les workflows n8n avec la gestion d'erreurs Telegram."""
import json
from pathlib import Path

ROOT = Path(__file__).parent


def load_js(name: str) -> str:
    return (ROOT / "n8n_js" / f"{name}.js").read_text(encoding="utf-8")


def patch_workflow(path: Path, local: bool = False) -> None:
    wf = json.loads(path.read_text(encoding="utf-8"))
    nodes_by_name = {n["name"]: n for n in wf["nodes"]}

    nodes_by_name["Découverte Réseau"]["parameters"]["jsCode"] = load_js("discover_network")
    nodes_by_name["Scanner IP (IA)"]["parameters"]["jsCode"] = load_js("scan_target")

    if "Découverte OK ?" not in nodes_by_name:
        wf["nodes"].extend([
            {
                "parameters": {
                    "conditions": {
                        "boolean": [{
                            "value1": "={{ $json.success !== false }}",
                            "value2": True,
                        }]
                    }
                },
                "name": "Découverte OK ?",
                "type": "n8n-nodes-base.if",
                "typeVersion": 1,
                "position": [960, 0],
                "id": "snm-if-discover-ok",
            },
            {
                "parameters": {
                    "conditions": {
                        "boolean": [{
                            "value1": "={{ $json.success !== false }}",
                            "value2": True,
                        }]
                    }
                },
                "name": "Scan OK ?",
                "type": "n8n-nodes-base.if",
                "typeVersion": 1,
                "position": [1400, 320],
                "id": "snm-if-scan-ok",
            },
            {
                "parameters": {
                    "chatId": "={{ $json.telegram_chat_id }}",
                    "text": "=❌ **Erreur SNM** ({{ $json.phase || 'inconnue' }})\n\n{{ $json.error_message }}\n\n_Réessayez ou vérifiez que Python et les dépendances sont installés._",
                    "additionalFields": {"parse_mode": "Markdown"},
                },
                "name": "Envoyer Erreur",
                "type": "n8n-nodes-base.telegram",
                "typeVersion": 1.2,
                "position": [1200, 640],
                "id": "snm-send-error",
                "credentials": {
                    "telegramApi": {"name": "Telegram account"}
                },
            },
        ])

    conn = wf["connections"]
    conn["Découverte Réseau"] = {"main": [[{"node": "Découverte OK ?", "type": "main", "index": 0}]]}
    conn["Découverte OK ?"] = {
        "main": [
            [{"node": "Envoyer Boutons", "type": "main", "index": 0}],
            [{"node": "Envoyer Erreur", "type": "main", "index": 0}],
        ]
    }
    conn["Scanner IP (IA)"] = {"main": [[{"node": "Scan OK ?", "type": "main", "index": 0}]]}
    conn["Scan OK ?"] = {
        "main": [
            [
                {"node": "Lire HTML", "type": "main", "index": 0},
                {"node": "Découper Rapport IA", "type": "main", "index": 0},
            ],
            [{"node": "Envoyer Erreur", "type": "main", "index": 0}],
        ]
    }

    if local:
        for n in wf["nodes"]:
            if n["name"] == "Envoyer Erreur":
                n.setdefault("credentials", {})["telegramApi"] = {
                    "id": "fQnP5Pe1fZNfrzfM",
                    "name": "Telegram account",
                }

    path.write_text(json.dumps(wf, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Patched {path.name}")


if __name__ == "__main__":
    patch_workflow(ROOT / "My workflow SNM.json", local=True)
    patch_workflow(ROOT / "SNM_n8n_workflow_template.json", local=False)
