import json
import os
import html
import re
from datetime import datetime

def markdown_to_html(md_text):
    if not md_text:
        return "<p><i>Aucune analyse IA disponible.</i></p>"
    
    # Échapper le HTML pour éviter les injections XSS
    html_out = html.escape(md_text)
    
    # Headers
    html_out = re.sub(r'^### (.*?)$', r'<h3>\1</h3>', html_out, flags=re.MULTILINE)
    html_out = re.sub(r'^## (.*?)$', r'<h2>\1</h2>', html_out, flags=re.MULTILINE)
    html_out = re.sub(r'^# (.*?)$', r'<h1>\1</h1>', html_out, flags=re.MULTILINE)
    
    # Gras et Italique
    html_out = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', html_out)
    html_out = re.sub(r'\*(.*?)\*', r'<i>\1</i>', html_out)
    
    # Inline code
    html_out = re.sub(r'`(.*?)`', r'<code style="background: rgba(0,242,255,0.1); padding: 2px 5px; border-radius: 4px; color: var(--cyan); font-family: monospace;">\1</code>', html_out)
    
    # Listes
    html_out = re.sub(r'^\s*-\s+(.*?)$', r'<li>\1</li>', html_out, flags=re.MULTILINE)
    
    # Paragraphes (lignes simples)
    lines = html_out.split('\n')
    parsed_lines = []
    in_list = False
    
    for line in lines:
        if line.startswith('<li>'):
            if not in_list:
                parsed_lines.append('<ul>')
                in_list = True
            parsed_lines.append(line)
        else:
            if in_list:
                parsed_lines.append('</ul>')
                in_list = False
            if line.strip() and not line.startswith('<h') and not line.startswith('<ul>') and not line.startswith('<li'):
                parsed_lines.append(f"<p>{line}</p>")
            else:
                parsed_lines.append(line)
                
    if in_list:
        parsed_lines.append('</ul>')
        
    return '\n'.join(parsed_lines)


def generate_html_report(scan_data, output_path="outputs/report.html"):
    """
    Génère un rapport HTML Cyberpunk Premium avec toutes les données (OSINT, IA, HTTP, OS).
    """
    target = scan_data.get("cible", "Inconnue")
    date = scan_data.get("date", "Inconnue")
    source = scan_data.get("source", "Inconnue")
    ports = scan_data.get("ports", [])
    
    # Nouvelles données (OS, Domain, HTTP)
    device_info = scan_data.get("device_info", {})
    domain_info = scan_data.get("domain_info", {})
    ai_text = scan_data.get("ai_report_text", "")
    
    os_name = device_info.get("os_family", "Inconnu") if device_info else "Inconnu"
    org = domain_info.get("whois_rdap", {}).get("organization", "N/A") if domain_info else "N/A"
    country = domain_info.get("whois_rdap", {}).get("country", "N/A") if domain_info else "N/A"
    cf_detected = domain_info.get("security_headers", {}).get("cloudflare_detected", False) if domain_info else False
    waf_detected = domain_info.get("security_headers", {}).get("waf_detected", False) if domain_info else False
    
    # OS Icon Logic
    os_icon = "💻"
    if "win" in os_name.lower(): os_icon = "🪟"
    elif "linux" in os_name.lower(): os_icon = "🐧"
    elif "mac" in os_name.lower() or "apple" in os_name.lower(): os_icon = "🍎"
    elif "freebsd" in os_name.lower(): os_icon = "😈"

    # Statistiques
    total = scan_data.get("total_scanned", len(ports))
    open_p = len([p for p in ports if p.get("statut") == "ouvert"])
    vuln_p = len([p for p in ports if p.get("vulnerable") == 1])
    safe_p = open_p - vuln_p
    
    safe_percent = int((safe_p / open_p) * 100) if open_p > 0 else 100
    vuln_percent = int((vuln_p / open_p) * 100) if open_p > 0 else 0
    
    # Rendu HTML IA
    html_ai = markdown_to_html(ai_text)
    
    html_template = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>SNM - Security Dashboard</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;700&display=swap');
            
            :root {{
                --bg: #05070A;
                --card-bg: rgba(17, 24, 33, 0.7);
                --cyan: #00f2ff;
                --red: #ff004c;
                --green: #00ff95;
                --purple: #b052ff;
                --orange: #ff8c00;
                --gray: #8892b0;
                --text: #e6edf3;
                --glass-border: rgba(255, 255, 255, 0.05);
            }}
            body {{
                background-color: var(--bg);
                background-image: 
                    radial-gradient(circle at 15% 50%, rgba(0, 242, 255, 0.03) 0%, transparent 50%),
                    radial-gradient(circle at 85% 30%, rgba(255, 0, 76, 0.03) 0%, transparent 50%);
                color: var(--text);
                font-family: 'Inter', sans-serif;
                margin: 0;
                padding: 40px;
                line-height: 1.6;
            }}
            .container {{ max-width: 1200px; margin: auto; }}
            
            /* Glassmorphism Cards */
            .glass-panel {{
                background: var(--card-bg);
                backdrop-filter: blur(12px);
                border: 1px solid var(--glass-border);
                border-radius: 12px;
                padding: 24px;
                margin-bottom: 30px;
                box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
            }}
            
            header {{
                display: flex;
                justify-content: space-between;
                align-items: flex-end;
                border-bottom: 2px solid var(--cyan);
                padding-bottom: 20px;
                margin-bottom: 40px;
            }}
            h1, h2, h3 {{ font-family: 'JetBrains Mono', monospace; margin-top: 0; }}
            h1 {{ color: var(--cyan); letter-spacing: 2px; font-size: 28px; text-shadow: 0 0 10px rgba(0, 242, 255, 0.3); }}
            h2 {{ color: var(--purple); font-size: 20px; border-bottom: 1px solid rgba(176, 82, 255, 0.3); padding-bottom: 10px; }}
            
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
            }}
            .stat-card {{
                background: rgba(0, 0, 0, 0.4);
                border: 1px solid var(--glass-border);
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                transition: transform 0.2s ease, border-color 0.2s ease;
            }}
            .stat-card:hover {{ transform: translateY(-5px); border-color: var(--cyan); }}
            .stat-val {{ font-size: 28px; font-weight: 700; font-family: 'JetBrains Mono', monospace; display: block; margin-bottom: 5px; }}
            .stat-label {{ color: var(--gray); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }}
            
            /* Table Styling */
            table {{
                width: 100%;
                border-collapse: separate;
                border-spacing: 0;
            }}
            th {{ 
                background: rgba(0, 0, 0, 0.5); 
                color: var(--gray); 
                text-align: left; 
                padding: 15px; 
                font-size: 12px; 
                text-transform: uppercase;
                letter-spacing: 1px;
            }}
            td {{ padding: 15px; border-bottom: 1px solid var(--glass-border); font-size: 14px; }}
            tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}
            
            .vuln-row {{ background: rgba(255, 0, 76, 0.05); border-left: 3px solid var(--red); }}
            
            .badge {{
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: 700;
                font-family: 'JetBrains Mono', monospace;
                text-transform: uppercase;
                display: inline-block;
            }}
            .badge-red {{ background: rgba(255, 0, 76, 0.2); color: var(--red); border: 1px solid var(--red); }}
            .badge-orange {{ background: rgba(255, 140, 0, 0.2); color: var(--orange); border: 1px solid var(--orange); }}
            .badge-green {{ background: rgba(0, 255, 149, 0.2); color: var(--green); border: 1px solid var(--green); }}
            .badge-cyan {{ background: rgba(0, 242, 255, 0.2); color: var(--cyan); border: 1px solid var(--cyan); }}
            .badge-purple {{ background: rgba(176, 82, 255, 0.2); color: var(--purple); border: 1px solid var(--purple); }}
            
            .ai-content {{
                color: #c9d1d9;
                font-size: 15px;
            }}
            .ai-content h2 {{ color: var(--cyan); margin-top: 30px; font-size: 18px; }}
            .ai-content h3 {{ color: var(--orange); font-size: 16px; }}
            .ai-content p {{ margin-bottom: 15px; }}
            .ai-content ul {{ padding-left: 20px; }}
            .ai-content li {{ margin-bottom: 8px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <div>
                    <h1>SMART NETWORK MAPPER</h1>
                    <p style="color: var(--gray); font-family: 'JetBrains Mono', monospace; margin:0;">Advanced Threat Intelligence Dashboard</p>
                </div>
                <div style="text-align: right; font-family: 'JetBrains Mono', monospace; font-size: 13px;">
                    <div style="color: var(--cyan); font-size: 18px; font-weight:bold; margin-bottom: 5px;">{target}</div>
                    <div style="color: var(--gray)">{date} • Source: {source}</div>
                </div>
            </header>

            <!-- Profil OSINT de la cible -->
            <div class="stats-grid" style="margin-bottom: 30px;">
                <div class="stat-card">
                    <span class="stat-val" style="color: var(--text)">{os_icon}</span>
                    <span class="stat-label">OS Detecté</span>
                    <div style="color: var(--cyan); font-weight:bold; font-size:14px; margin-top:5px;">{os_name}</div>
                </div>
                <div class="stat-card">
                    <span class="stat-val" style="color: var(--text)">🌍</span>
                    <span class="stat-label">Localisation</span>
                    <div style="color: var(--cyan); font-weight:bold; font-size:14px; margin-top:5px;">{country}</div>
                </div>
                <div class="stat-card">
                    <span class="stat-val" style="color: var(--text)">🏢</span>
                    <span class="stat-label">Organisation / FAI</span>
                    <div style="color: var(--cyan); font-weight:bold; font-size:14px; margin-top:5px;">{org}</div>
                </div>
                <div class="stat-card" style="border-color: {'var(--orange)' if cf_detected else 'var(--glass-border)'}">
                    <span class="stat-val" style="color: var(--text)">☁️</span>
                    <span class="stat-label">Protection Web</span>
                    <div style="color: {'var(--orange)' if cf_detected else 'var(--green)'}; font-weight:bold; font-size:14px; margin-top:5px;">
                        {'Cloudflare/WAF Actif' if cf_detected or waf_detected else 'Direct / Pas de WAF'}
                    </div>
                </div>
            </div>

            <!-- Stats Ports -->
            <div class="glass-panel">
                <h2 style="color: var(--cyan);">📊 STATISTIQUES DE SCAN</h2>
                <div class="stats-grid">
                    <div class="stat-card"><span class="stat-val">{total}</span><span class="stat-label">Ports Scannés</span></div>
                    <div class="stat-card"><span class="stat-val" style="color: var(--cyan)">{open_p}</span><span class="stat-label">Ouverts</span></div>
                    <div class="stat-card"><span class="stat-val" style="color: var(--red)">{vuln_p}</span><span class="stat-label">Vulnérables (IA)</span></div>
                    <div class="stat-card"><span class="stat-val" style="color: var(--green)">{safe_p}</span><span class="stat-label">Sécurisés</span></div>
                </div>
            </div>

            <!-- AI AUDIT -->
            <div class="glass-panel" style="border-left: 4px solid var(--purple);">
                <h2 style="color: var(--purple);">🤖 AUDIT EXPERT IA (Llama-3.3-70b)</h2>
                <div class="ai-content">
                    {html_ai}
                </div>
            </div>

            <!-- PORTS DÉTAILLÉS -->
            <div class="glass-panel">
                <h2 style="color: var(--cyan);">🔌 SERVICES & PORTS DÉTECTÉS</h2>
                <table>
                    <thead>
                        <tr>
                            <th>PORT</th>
                            <th>SERVICE / MITRE</th>
                            <th>VERSION</th>
                            <th>STATUS</th>
                            <th>AI PREDICTION</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    
    for p in ports:
        is_vuln = p.get("vulnerable") == 1
        row_class = "vuln-row" if is_vuln else ""
        label = html.escape(str(p.get("label", "Unknown")))
        
        raw_conf = p.get("confidence", 0)
        conf = round(raw_conf * 100, 1) if raw_conf <= 1.0 else round(raw_conf, 1)
        statut = html.escape(str(p.get("statut", "ouvert")))
        
        service_esc = html.escape(str(p.get('service', 'Inconnu')))
        version_esc = html.escape(str(p.get('version', 'N/A')))
        port_num = html.escape(str(p.get('port')))
        proto = html.escape(str(p.get('protocole', 'TCP')))
        
        ia_badge_class = "badge-red" if is_vuln else "badge-green"

        # MITRE
        try:
            from reporter.skills_knowledge import get_mitre_info
            mitre_data = get_mitre_info(p.get("port", 0), p.get("service", ""))
            mitre_badge = f'<br><span class="badge badge-purple" style="margin-top: 5px; font-size: 9px;">🎯 {mitre_data["technique_id"]}</span>'
        except Exception:
            mitre_badge = ""
            
        # HTTP SECURITY HEADERS (si c'est un port web)
        http_badge = ""
        if str(port_num) in ["80", "443", "8080", "8443"] and domain_info:
            sec_headers = domain_info.get("security_headers", {}).get("missing_security_headers", [])
            if sec_headers:
                http_badge = f'<br><span class="badge badge-orange" style="margin-top: 5px; font-size: 9px;">⚠️ {len(sec_headers)} EN-TÊTES MANQUANTS</span>'
            else:
                http_badge = f'<br><span class="badge badge-green" style="margin-top: 5px; font-size: 9px;">🔒 EN-TÊTES SÉCURISÉS</span>'
        
        html_template += f"""
                        <tr class="{row_class}">
                            <td><b style="color: var(--cyan); font-family: 'JetBrains Mono'; font-size: 16px;">{port_num}</b><span style="color:var(--gray);font-size:12px;">/{proto}</span></td>
                            <td><span style="font-weight: 600;">{service_esc}</span>{mitre_badge}{http_badge}</td>
                            <td style="color: var(--gray);">{version_esc}</td>
                            <td><span style="color: var(--gray); text-transform: capitalize;">{statut}</span></td>
                            <td>
                                <span class="badge {ia_badge_class}">{label}</span>
                                <div style="color: var(--gray); font-size: 11px; margin-top: 5px; font-family: monospace;">Confiance: {conf}%</div>
                            </td>
                        </tr>
        """
        
    html_template += """
                    </tbody>
                </table>
            </div>
    """

    # ── Section CVE OSINT & CISA KEV ───────────────────────────
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
    cisa_kev_count = len([c for c in all_cves if c.get("is_cisa_kev", False)])

    if all_cves:
        cisa_alert_html = ""
        if cisa_kev_count > 0:
            cisa_alert_html = f"""
            <div style="background: rgba(255, 0, 76, 0.1); border-left: 4px solid var(--red); padding: 20px; border-radius: 4px; margin-bottom: 24px;">
                <b style="color: var(--red); font-size: 16px; display:flex; align-items:center; gap:10px;">
                    <span style="font-size: 24px;">🚨</span> ALERTE DE THREAT INTELLIGENCE (CISA KEV)
                </b>
                <p style="color: #ffb3c6; font-size: 14px; margin: 10px 0 0 0;">
                    {cisa_kev_count} vulnérabilité(s) activement exploitée(s) dans la nature détectée(s). Un correctif d'urgence est prioritaire.
                </p>
            </div>
            """

        html_template += f"""
            <div class="glass-panel">
                <h2 style="color: var(--orange);">🔥 VULNÉRABILITÉS & CISA KEV</h2>
                
                {cisa_alert_html}

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
                        <span class="stat-val" style="color: var(--red)">{cisa_kev_count}</span>
                        <span class="stat-label">Exploits Actifs (CISA KEV)</span>
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
                        </tr>
                    </thead>
                    <tbody>
        """
        for cve in all_cves:
            cvss = cve.get("cvss_score", 0)
            cve_id = html.escape(str(cve.get("cve_id", "N/A")))
            desc = html.escape(str(cve.get("description", "Pas de description")))
            severity = html.escape(str(cve.get("severity", "NONE")))
            is_kev = cve.get("is_cisa_kev", False)
            
            if len(desc) > 120: desc = desc[:117] + "..."
                
            badge_class = "badge-green"
            if cvss >= 9.0: badge_class = "badge-red"
            elif cvss >= 7.0: badge_class = "badge-orange"
            elif cvss >= 4.0: badge_class = "badge-cyan"
            
            port_esc = html.escape(str(cve.get('_port')))
            service_esc = html.escape(str(cve.get('_service')))
            
            kev_badge = ' <span class="badge badge-red" style="margin-left: 10px;">🔥 KEV</span>' if is_kev else ''

            html_template += f"""
                        <tr>
                            <td>
                                <b style="color: var(--cyan); font-family: monospace;">{port_esc}</b><br>
                                <span style="color: var(--gray); font-size: 11px;">{service_esc}</span>
                            </td>
                            <td><b style="font-family: monospace;">{cve_id}</b>{kev_badge}</td>
                            <td><b style="color: var(--text); font-family: monospace;">{cvss}</b></td>
                            <td><span class="badge {badge_class}">{severity}</span></td>
                            <td style="color: var(--gray); font-size: 13px;">{desc}</td>
                        </tr>
            """
        html_template += """
                    </tbody>
                </table>
            </div>
        """
    else:
        html_template += """
            <div class="glass-panel" style="text-align: center; border-color: var(--green);">
                <div style="font-size: 40px; margin-bottom: 10px;">✅</div>
                <h3 style="color: var(--green); margin:0;">Aucune CVE connue trouvée sur NVD</h3>
                <p style="color: var(--gray);">Les services détectés ne présentent pas de vulnérabilités référencées.</p>
            </div>
        """

    html_template += """
            <footer style="margin-top: 50px; text-align: center; color: var(--gray); font-size: 12px; font-family: 'JetBrains Mono', monospace;">
                © 2026 Smart Network Mapper • PFA IntelTrust<br>
                <span style="opacity: 0.5;">Propulsé par Python, Llama-3, Random Forest & n8n</span>
            </footer>
        </div>
    </body>
    </html>
    """
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_template)
    return output_path
