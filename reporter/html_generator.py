
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
    total = scan_data.get("total_scanned", len(ports))
    open_p = len([p for p in ports if p.get("statut") == "ouvert"])
    vuln_p = len([p for p in ports if p.get("vulnerable") == 1])
    safe_p = open_p - vuln_p
    
    # Si 0 port ouvert, c'est 100% sécurisé (au lieu de 0% avant)
    safe_percent = int((safe_p / open_p) * 100) if open_p > 0 else 100
    vuln_percent = int((vuln_p / open_p) * 100) if open_p > 0 else 0
    
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
            .badge-high {{ background: #ff8c00; color: white; }}
            .badge-medium {{ background: #ffd700; color: black; }}
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
                <div class="stat-card"><span class="stat-val">{total}</span><span class="stat-label">Ports Scannés</span></div>
                <div class="stat-card"><span class="stat-val" style="color: var(--cyan)">{open_p}</span><span class="stat-label">Ouverts</span></div>
                <div class="stat-card"><span class="stat-val" style="color: var(--red)">{vuln_p}</span><span class="stat-label">Vulnérables</span></div>
                <div class="stat-card"><span class="stat-val" style="color: var(--green)">{safe_p}</span><span class="stat-label">Sécurisés</span></div>
            </div>

            <!-- SVG Chart Section -->
            <div style="display: flex; justify-content: center; margin-bottom: 40px;">
                <svg width="200" height="200" viewBox="0 0 42 42" class="donut">
                    <circle class="donut-hole" cx="21" cy="21" r="15.91549430918954" fill="transparent"></circle>
                    <circle class="donut-ring" cx="21" cy="21" r="15.91549430918954" fill="transparent" stroke="#1f2937" stroke-width="3"></circle>
                    <circle class="donut-segment" cx="21" cy="21" r="15.91549430918954" fill="transparent" stroke="var(--green)" stroke-width="3" stroke-dasharray="{safe_percent} {100 - safe_percent}" stroke-dashoffset="25"></circle>
                    <circle class="donut-segment" cx="21" cy="21" r="15.91549430918954" fill="transparent" stroke="var(--red)" stroke-width="3" stroke-dasharray="{vuln_percent} {100 - vuln_percent}" stroke-dashoffset="{125 - safe_percent}"></circle>
                    <g class="chart-text">
                        <text x="50%" y="50%" class="chart-number" style="fill: white; font-size: 6px; font-weight: bold; text-anchor: middle; dominant-baseline: central;">
                            {safe_percent}%
                        </text>
                        <text x="50%" y="50%" class="chart-label" style="fill: var(--gray); font-size: 2px; text-anchor: middle; transform: translateY(4px);">
                            SAFE
                        </text>
                    </g>
                </svg>
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
        # Confidence déjà en % depuis run_scan.py (pas de re-multiplication)
        conf = round(p.get("confidence", 0), 1)
        statut = p.get("statut", "ouvert")
        
        # Couleur IA
        ia_color = "var(--red)" if is_vuln else "var(--green)"
        
        html_template += f"""
                    <tr class="{row_class}">
                        <td><b style="color: var(--cyan)">{p.get('port')}</b>/{p.get('protocole', 'TCP')}</td>
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
        
    # ── Section CVE OSINT ──────────────────────────────────────
    # Collecter toutes les CVEs de tous les ports (en clonant les dicts pour éviter les conflits de références partagées)
    all_cves = []
    for p in ports:
        port_num = p.get("port", 0)
        service_name = p.get("service", "Inconnu")
        port_cves = p.get("cves", [])
        for cve in port_cves:
            cve_copy = dict(cve)
            cve_copy["_port"] = port_num
            cve_copy["_service"] = service_name
            all_cves.append(cve_copy)
    
    total_cves = len(all_cves)
    critical_cves = len([c for c in all_cves if c.get("cvss_score", 0) >= 9.0])
    high_cves = len([c for c in all_cves if 7.0 <= c.get("cvss_score", 0) < 9.0])

    html_template += """
                </tbody>
            </table>
    """

    if all_cves:
        html_template += f"""
            <!-- ═══════════ SECTION OSINT / CVE ═══════════ -->
            <div style="margin-top: 50px;">
                <h2 style="color: var(--cyan); font-family: 'Courier New', monospace; letter-spacing: 2px; border-bottom: 1px solid #1f2937; padding-bottom: 10px;">
                    🌐 ENRICHISSEMENT OSINT — CVEs CONNUES
                </h2>
                <p style="color: var(--gray); margin-bottom: 20px;">
                    Données issues de la base <b style="color: var(--cyan);">NVD (NIST)</b> — National Vulnerability Database
                </p>

                <div class="stats-grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom: 30px;">
                    <div class="stat-card">
                        <span class="stat-val">{total_cves}</span>
                        <span class="stat-label">CVEs Trouvées</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-val" style="color: var(--red)">{critical_cves}</span>
                        <span class="stat-label">Critiques (CVSS ≥ 9)</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-val" style="color: #ff8c00">{high_cves}</span>
                        <span class="stat-label">Élevées (CVSS 7-9)</span>
                    </div>
                </div>

                <table>
                    <thead>
                        <tr>
                            <th>PORT</th>
                            <th>CVE ID</th>
                            <th>CVSS</th>
                            <th>SÉVÉRITÉ</th>
                            <th>DESCRIPTION</th>
                            <th>DATE</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        for cve in all_cves:
            cvss = cve.get("cvss_score", 0)
            severity = cve.get("severity", "NONE")
            cve_id = cve.get("cve_id", "N/A")
            url = cve.get("url", "#")
            desc = cve.get("description", "")
            published = cve.get("published", "N/A")
            port_num = cve.get("_port", "?")
            service_name = cve.get("_service", "?")

            # Couleur selon sévérité
            if cvss >= 9.0:
                sev_color = "var(--red)"
                badge_class = "badge-vuln"
            elif cvss >= 7.0:
                sev_color = "#ff8c00"
                badge_class = "badge-high"
            elif cvss >= 4.0:
                sev_color = "#ffd700"
                badge_class = "badge-medium"
            else:
                sev_color = "var(--green)"
                badge_class = "badge-safe"

            row_class = "vuln-row" if cvss >= 7.0 else ""

            html_template += f"""
                        <tr class="{row_class}">
                            <td><b style="color: var(--cyan)">{port_num}</b><br><span style="color: var(--gray); font-size: 11px;">{service_name}</span></td>
                            <td><a href="{url}" style="color: var(--cyan); text-decoration: none;" target="_blank">{cve_id}</a></td>
                            <td style="color: {sev_color}; font-weight: bold; font-size: 18px;">{cvss}</td>
                            <td><span class="status-badge {badge_class}">{severity}</span></td>
                            <td style="font-size: 12px; color: var(--gray); max-width: 350px;">{desc}</td>
                            <td style="color: var(--gray); font-size: 12px;">{published}</td>
                        </tr>
            """

        html_template += """
                    </tbody>
                </table>
            </div>
        """
    else:
        html_template += """
            <div style="margin-top: 50px; text-align: center; padding: 30px; background: var(--card-bg); border-radius: 8px; border: 1px solid #1f2937;">
                <p style="color: var(--green); font-size: 18px; font-weight: bold;">✅ Aucune CVE connue trouvée sur NVD</p>
                <p style="color: var(--gray);">Les services détectés ne présentent pas de vulnérabilités référencées dans la base NVD (NIST).</p>
            </div>
        """

    html_template += """
            <footer style="margin-top: 50px; text-align: center; color: var(--gray); font-size: 12px;">
                © 2026 Smart Network Mapper - Security Intelligence Platform<br>
                <span style="font-size: 10px;">Données OSINT : NVD (NIST) — nvd.nist.gov</span>
            </footer>
        </div>
    </body>
    </html>
    """
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_template)
    return output_path
