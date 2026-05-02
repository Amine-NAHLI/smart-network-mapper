
import json
import os
from datetime import datetime

def generate_html_report(scan_data, output_path="outputs/report.html"):
    """
    Génère un rapport HTML Cyberpunk avec un design Premium.
    """
    target = scan_data.get("cible", "Inconnue")
    date = scan_data.get("date", "Inconnue")
    ports = scan_data.get("ports", [])
    
    # Statistiques
    total = len(ports)
    open_p = len([p for p in ports if p.get("statut") == "ouvert"])
    vuln_p = len([p for p in ports if p.get("vulnerable") == 1])
    
    html_template = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>SNM - Security Report</title>
        <style>
            :root {{
                --bg: #0a0e14;
                --card-bg: #111821;
                --cyan: #00f2ff;
                --red: #ff004c;
                --green: #00ff95;
                --gray: #8892b0;
                --text: #e6edf3;
            }}
            body {{
                background-color: var(--bg);
                color: var(--text);
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 40px;
                line-height: 1.6;
            }}
            .container {{ max-width: 1000px; margin: auto; }}
            header {{
                border-bottom: 2px solid var(--cyan);
                padding-bottom: 20px;
                margin-bottom: 40px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            h1 {{ margin: 0; color: var(--cyan); font-family: 'Courier New', monospace; letter-spacing: 2px; }}
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 20px;
                margin-bottom: 40px;
            }}
            .stat-card {{
                background: var(--card-bg);
                border: 1px solid #1f2937;
                padding: 20px;
                border-radius: 8px;
                text-align: center;
            }}
            .stat-val {{ font-size: 24px; font-weight: bold; color: var(--cyan); display: block; }}
            .stat-label {{ color: var(--gray); font-size: 12px; text-transform: uppercase; }}
            
            table {{
                width: 100%;
                border-collapse: collapse;
                background: var(--card-bg);
                border-radius: 8px;
                overflow: hidden;
            }}
            th {{ background: #1a222c; color: var(--gray); text-align: left; padding: 15px; font-size: 13px; }}
            td {{ padding: 15px; border-bottom: 1px solid #1f2937; font-size: 14px; }}
            
            .vuln-row {{ background: rgba(255, 0, 76, 0.05); }}
            .status-badge {{
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: bold;
                text-transform: uppercase;
            }}
            .badge-vuln {{ background: var(--red); color: white; }}
            .badge-safe {{ background: var(--green); color: #000; }}
            
            .confidence-bar {{
                height: 4px;
                background: #1f2937;
                width: 100px;
                border-radius: 2px;
                margin-top: 5px;
            }}
            .confidence-fill {{ height: 100%; border-radius: 2px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <div>
                    <h1>SMART NETWORK MAPPER</h1>
                    <p style="color: var(--gray)">Rapport de Scan de Sécurité</p>
                </div>
                <div style="text-align: right">
                    <span style="color: var(--cyan)">CIBLE: {target}</span><br>
                    <span style="color: var(--gray)">Généré le {date}</span>
                </div>
            </header>

            <div class="stats-grid">
                <div class="stat-card"><span class="stat-val">{total}</span><span class="stat-label">Total Scan</span></div>
                <div class="stat-card"><span class="stat-val" style="color: var(--cyan)">{open_p}</span><span class="stat-label">Ouverts</span></div>
                <div class="stat-card"><span class="stat-val" style="color: var(--red)">{vuln_p}</span><span class="stat-label">Vulnérables</span></div>
                <div class="stat-card"><span class="stat-val" style="color: var(--green)">{open_p - vuln_p}</span><span class="stat-label">Sécurisés</span></div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>PORT</th>
                        <th>SERVICE</th>
                        <th>VERSION</th>
                        <th>STATUS</th>
                        <th>AI ANALYSIS</th>
                        <th>CONFIDENCE</th>
                    </tr>
                </thead>
                <tbody>
    """
    
    for p in ports:
        is_vuln = p.get("vulnerable") == 1
        row_class = "vuln-row" if is_vuln else ""
        label = p.get("label", "Unknown")
        # Conversion en % pour l'affichage HTML
        conf = round(p.get("confidence", 0) * 100, 1)
        statut = p.get("statut", "ouvert")
        
        # Couleur IA
        ia_color = "var(--red)" if is_vuln else "var(--green)"
        
        html_template += f"""
                    <tr class="{row_class}">
                        <td><b style="color: var(--cyan)">{p.get('port')}</b>/TCP</td>
                        <td>{p.get('service', 'Inconnu')}</td>
                        <td style="color: var(--gray); font-size: 12px;">{p.get('version', 'N/A')}</td>
                        <td>{statut}</td>
                        <td style="color: {ia_color}; font-weight: bold;">{label}</td>
                        <td>
                            {conf}%
                            <div class="confidence-bar">
                                <div class="confidence-fill" style="width: {conf}%; background: {ia_color}"></div>
                            </div>
                        </td>
                    </tr>
        """
        
    html_template += """
                </tbody>
            </table>
            <footer style="margin-top: 50px; text-align: center; color: var(--gray); font-size: 12px;">
                © 2026 Smart Network Mapper - Security Intelligence Platform
            </footer>
        </div>
    </body>
    </html>
    """
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_template)
    return output_path
