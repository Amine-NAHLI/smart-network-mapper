import json
import os
import html
import re
from datetime import datetime

def markdown_to_html(md_text):
    if not md_text:
        return "<p><i>Aucune analyse IA disponible.</i></p>"
    
    html_out = html.escape(md_text)
    
    html_out = re.sub(r'^### (.*?)$', r'<h3>\1</h3>', html_out, flags=re.MULTILINE)
    html_out = re.sub(r'^## (.*?)$', r'<h2>\1</h2>', html_out, flags=re.MULTILINE)
    html_out = re.sub(r'^# (.*?)$', r'<h1>\1</h1>', html_out, flags=re.MULTILINE)
    
    html_out = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', html_out)
    html_out = re.sub(r'\*(.*?)\*', r'<i>\1</i>', html_out)
    
    html_out = re.sub(r'`(.*?)`', r'<code style="background: rgba(0,242,255,0.1); padding: 2px 5px; border-radius: 4px; color: var(--cyan); font-family: monospace;">\1</code>', html_out)
    
    html_out = re.sub(r'^\s*-\s+(.*?)$', r'<li>\1</li>', html_out, flags=re.MULTILINE)
    
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
    target = scan_data.get("cible", "Inconnue")
    date = scan_data.get("date", "Inconnue")
    source = scan_data.get("source", "Inconnue")
    ports = scan_data.get("ports", [])
    
    device_info = scan_data.get("device_info", {})
    domain_info = scan_data.get("domain_info", {})
    ai_text = scan_data.get("ai_report_text", "")
    
    os_name = device_info.get("os", "Inconnu") if device_info else "Inconnu"
    org = domain_info.get("whois_rdap", {}).get("organization", "N/A") if domain_info else "N/A"
    country = domain_info.get("whois_rdap", {}).get("country", "N/A") if domain_info else "N/A"
    cf_detected = domain_info.get("security_headers", {}).get("cloudflare_detected", False) if domain_info else False
    waf_detected = domain_info.get("security_headers", {}).get("waf_detected", False) if domain_info else False
    
    # OS Icon Logic with FontAwesome
    os_icon = '<i class="fa-solid fa-server"></i>'
    if "win" in os_name.lower(): os_icon = '<i class="fa-brands fa-windows"></i>'
    elif "linux" in os_name.lower(): os_icon = '<i class="fa-brands fa-linux"></i>'
    elif "mac" in os_name.lower() or "apple" in os_name.lower(): os_icon = '<i class="fa-brands fa-apple"></i>'
    elif "freebsd" in os_name.lower(): os_icon = '<i class="fa-brands fa-freebsd"></i>'

    info_cards_html = ""
    
    if os_name and os_name.lower() not in ["inconnu", "n/a", "none"]:
        info_cards_html += f'''
        <div class="stat-card">
            <div class="stat-icon">{os_icon}</div>
            <span class="stat-val" style="font-size: 18px;">{os_name}</span>
            <span class="stat-label">Système d'exploitation</span>
        </div>
        '''
        
    if country and country.lower() not in ["inconnu", "n/a", "none"]:
        info_cards_html += f'''
        <div class="stat-card">
            <div class="stat-icon"><i class="fa-solid fa-map-location-dot"></i></div>
            <span class="stat-val" style="font-size: 18px;">{country}</span>
            <span class="stat-label">Localisation</span>
        </div>
        '''
        
    if org and org.lower() not in ["inconnu", "n/a", "none", "non identifiée"]:
        info_cards_html += f'''
        <div class="stat-card">
            <div class="stat-icon"><i class="fa-solid fa-building"></i></div>
            <span class="stat-val" style="font-size: 16px;">{org}</span>
            <span class="stat-label">Organisation / FAI</span>
        </div>
        '''
        
    if cf_detected or waf_detected:
        info_cards_html += '''
        <div class="stat-card">
            <div class="stat-icon"><i class="fa-solid fa-cloud-bolt"></i></div>
            <span class="stat-val" style="font-size: 16px; color: var(--orange);">
                WAF / Proxy Détecté
            </span>
            <span class="stat-label">Périmètre de Protection</span>
        </div>
        '''
    else:
        sec_err = domain_info.get("security_headers", {}).get("error") if domain_info else "Error"
        if not sec_err and domain_info:
            info_cards_html += '''
            <div class="stat-card">
                <div class="stat-icon"><i class="fa-solid fa-cloud-bolt"></i></div>
                <span class="stat-val" style="font-size: 16px; color: var(--green);">
                    Connexion Directe
                </span>
                <span class="stat-label">Périmètre de Protection</span>
            </div>
            '''
            
    # Si aucune info n'est dispo, on affiche juste l'hôte
    if not info_cards_html:
        info_cards_html = f'''
        <div class="stat-card">
            <div class="stat-icon"><i class="fa-solid fa-network-wired"></i></div>
            <span class="stat-val" style="font-size: 18px;">{target}</span>
            <span class="stat-label">Hôte Analysé</span>
        </div>
        '''

    total = scan_data.get("total_scanned", len(ports))
    open_p = len([p for p in ports if p.get("statut") == "ouvert"])
    vuln_p = len([p for p in ports if p.get("vulnerable") == 1])
    safe_p = open_p - vuln_p
    
    safe_percent = int((safe_p / open_p) * 100) if open_p > 0 else 100
    vuln_percent = int((vuln_p / open_p) * 100) if open_p > 0 else 0
    
    html_ai = markdown_to_html(ai_text)
    
    html_template = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>SNM - Executive Dashboard</title>
        
        <!-- Fonts -->
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
        
        <!-- FontAwesome Icons -->
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        
        <!-- Chart.js -->
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

        <style>
            :root {{
                --bg: #0b0f19;
                --card-bg: #151b2b;
                --cyan: #00e5ff;
                --red: #ff2a55;
                --green: #00d27a;
                --purple: #9d4edd;
                --orange: #ff9100;
                --gray: #94a3b8;
                --text: #f1f5f9;
                --border: #1e293b;
            }}
            body {{
                background-color: var(--bg);
                color: var(--text);
                font-family: 'Inter', sans-serif;
                margin: 0;
                padding: 40px;
                line-height: 1.6;
            }}
            .container {{ max-width: 1300px; margin: auto; }}
            
            /* Professional Panel */
            .panel {{
                background: var(--card-bg);
                border: 1px solid var(--border);
                border-radius: 8px;
                padding: 24px;
                margin-bottom: 30px;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
            }}
            
            header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-bottom: 1px solid var(--border);
                padding-bottom: 20px;
                margin-bottom: 30px;
            }}
            h1, h2, h3 {{ font-family: 'Inter', sans-serif; margin-top: 0; font-weight: 600; }}
            h1 {{ color: #ffffff; font-size: 24px; display: flex; align-items: center; gap: 12px; }}
            h2 {{ color: #ffffff; font-size: 18px; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }}
            
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                gap: 20px;
            }}
            .stat-card {{
                background: #0f141f;
                border: 1px solid var(--border);
                padding: 20px;
                border-radius: 6px;
                display: flex;
                flex-direction: column;
                position: relative;
                overflow: hidden;
            }}
            .stat-card::before {{
                content: '';
                position: absolute;
                top: 0; left: 0; right: 0; height: 2px;
                background: var(--gray);
                opacity: 0.2;
            }}
            .stat-card.brand-cyan::before {{ background: var(--cyan); opacity: 1; }}
            .stat-card.brand-red::before {{ background: var(--red); opacity: 1; }}
            .stat-card.brand-green::before {{ background: var(--green); opacity: 1; }}
            .stat-card.brand-orange::before {{ background: var(--orange); opacity: 1; }}
            
            .stat-icon {{ font-size: 20px; color: var(--gray); margin-bottom: 15px; }}
            .stat-val {{ font-size: 26px; font-weight: 700; font-family: 'JetBrains Mono', monospace; color: #fff; line-height: 1.2; }}
            .stat-label {{ color: var(--gray); font-size: 12px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 5px; }}
            
            /* Two columns layout */
            .row {{
                display: flex;
                gap: 30px;
                margin-bottom: 30px;
            }}
            .col-70 {{ flex: 0 0 calc(70% - 15px); }}
            .col-30 {{ flex: 0 0 calc(30% - 15px); }}
            
            /* Table Styling */
            table {{ width: 100%; border-collapse: collapse; }}
            th {{ 
                background: #0f141f; 
                color: var(--gray); 
                text-align: left; 
                padding: 12px 15px; 
                font-size: 11px; 
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 1px;
                border-bottom: 1px solid var(--border);
            }}
            td {{ padding: 15px; border-bottom: 1px solid var(--border); font-size: 13px; vertical-align: top; }}
            tr:last-child td {{ border-bottom: none; }}
            tr:hover td {{ background: rgba(255, 255, 255, 0.01); }}
            
            .badge {{
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 10px;
                font-weight: 700;
                font-family: 'JetBrains Mono', monospace;
                text-transform: uppercase;
                display: inline-flex;
                align-items: center;
                gap: 4px;
            }}
            .badge-red {{ background: rgba(255, 42, 85, 0.15); color: var(--red); border: 1px solid rgba(255, 42, 85, 0.3); }}
            .badge-orange {{ background: rgba(255, 145, 0, 0.15); color: var(--orange); border: 1px solid rgba(255, 145, 0, 0.3); }}
            .badge-green {{ background: rgba(0, 210, 122, 0.15); color: var(--green); border: 1px solid rgba(0, 210, 122, 0.3); }}
            .badge-cyan {{ background: rgba(0, 229, 255, 0.15); color: var(--cyan); border: 1px solid rgba(0, 229, 255, 0.3); }}
            .badge-purple {{ background: rgba(157, 78, 221, 0.15); color: var(--purple); border: 1px solid rgba(157, 78, 221, 0.3); }}
            
            .ai-content {{ color: #cbd5e1; font-size: 14px; line-height: 1.7; }}
            .ai-content h2 {{ color: var(--cyan); margin-top: 25px; font-size: 16px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }}
            .ai-content h3 {{ color: var(--text); font-size: 15px; font-weight: 600; margin-top: 20px; }}
            .ai-content p {{ margin-bottom: 12px; }}
            .ai-content ul {{ padding-left: 20px; margin-bottom: 15px; }}
            .ai-content li {{ margin-bottom: 6px; }}
            
            .target-ip {{
                font-family: 'JetBrains Mono', monospace;
                font-size: 20px;
                font-weight: 700;
                color: var(--cyan);
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <div>
                    <h1><i class="fa-solid fa-shield-halved" style="color: var(--cyan);"></i> Smart Network Mapper</h1>
                    <p style="color: var(--gray); font-size: 13px; margin: 5px 0 0 35px;">Executive Security Report</p>
                </div>
                <div style="text-align: right;">
                    <div class="target-ip">{target}</div>
                    <div style="color: var(--gray); font-size: 12px; font-family: 'JetBrains Mono', monospace; margin-top: 4px;">
                        <i class="fa-regular fa-clock"></i> {date} &nbsp; | &nbsp; <i class="fa-solid fa-robot"></i> Source: {source}
                    </div>
                </div>
            </header>

            <div class="row">
                <!-- Gauche : Target OSINT -->
                <div class="col-70">
                    <div class="panel" style="height: 100%; box-sizing: border-box;">
                        <h2><i class="fa-solid fa-crosshairs" style="color: var(--cyan);"></i> Informations sur la Cible</h2>
                        <div class="stats-grid" style="grid-template-columns: repeat(2, 1fr);">
                            {info_cards_html}
                        </div>
                    </div>
                </div>
                
                <!-- Droite : Graphe Récapitulatif -->
                <div class="col-30">
                    <div class="panel" style="height: 100%; box-sizing: border-box; display: flex; flex-direction: column;">
                        <h2><i class="fa-solid fa-chart-pie" style="color: var(--purple);"></i> Bilan de Sécurité</h2>
                        <div style="position: relative; height: 220px; width: 100%;">
                            <canvas id="securityChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Stats Ports -->
            <div class="stats-grid" style="margin-bottom: 30px;">
                <div class="stat-card brand-cyan">
                    <span class="stat-val">{total}</span>
                    <span class="stat-label">Ports Scannés</span>
                </div>
                <div class="stat-card brand-cyan">
                    <span class="stat-val">{open_p}</span>
                    <span class="stat-label">Ports Ouverts</span>
                </div>
                <div class="stat-card brand-red">
                    <span class="stat-val">{vuln_p}</span>
                    <span class="stat-label">Services Vulnérables</span>
                </div>
                <div class="stat-card brand-green">
                    <span class="stat-val">{safe_p}</span>
                    <span class="stat-label">Services Sécurisés</span>
                </div>
            </div>

            <!-- AI AUDIT -->
            <div class="panel" style="border-top: 3px solid var(--purple);">
                <h2><i class="fa-solid fa-brain" style="color: var(--purple);"></i> Audit Expert IA (GPT-OSS-120b)</h2>
                <div class="ai-content">
                    {html_ai}
                </div>
            </div>

            <!-- PORTS DÉTAILLÉS -->
            <div class="panel">
                <h2><i class="fa-solid fa-network-wired" style="color: var(--cyan);"></i> Cartographie des Services</h2>
                <table>
                    <thead>
                        <tr>
                            <th style="width: 15%">PORT</th>
                            <th style="width: 25%">SERVICE / DÉTECTION</th>
                            <th style="width: 25%">VERSION DÉTECTÉE</th>
                            <th style="width: 15%">STATUT</th>
                            <th style="width: 20%">PRÉDICTION ML</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    
    for p in ports:
        is_vuln = p.get("vulnerable") == 1
        label = html.escape(str(p.get("label", "Unknown")))
        
        raw_conf = p.get("confidence", 0)
        conf = round(raw_conf * 100, 1) if raw_conf <= 1.0 else round(raw_conf, 1)
        statut = html.escape(str(p.get("statut", "ouvert")))
        
        service_esc = html.escape(str(p.get('service', 'Inconnu')))
        version_esc = html.escape(str(p.get('version', 'N/A')))
        port_num = html.escape(str(p.get('port')))
        proto = html.escape(str(p.get('protocole', 'TCP')))
        
        ia_badge_class = "badge-red" if is_vuln else "badge-green"
        ia_icon = "fa-bug" if is_vuln else "fa-check"

        # MITRE
        try:
            from reporter.skills_knowledge import get_mitre_info
            mitre_data = get_mitre_info(p.get("port", 0), p.get("service", ""))
            mitre_badge = f'<div style="margin-top: 6px;"><span class="badge badge-purple"><i class="fa-solid fa-crosshairs"></i> {mitre_data["technique_id"]}</span></div>'
        except Exception:
            mitre_badge = ""
            
        # HTTP SECURITY HEADERS
        http_badge = ""
        if str(port_num) in ["80", "443", "8080", "8443"] and domain_info:
            sec_headers = domain_info.get("security_headers", {}).get("missing_security_headers", [])
            if sec_headers:
                http_badge = f'<div style="margin-top: 6px;"><span class="badge badge-orange"><i class="fa-solid fa-triangle-exclamation"></i> {len(sec_headers)} Headers Manquants</span></div>'
            else:
                http_badge = f'<div style="margin-top: 6px;"><span class="badge badge-green"><i class="fa-solid fa-lock"></i> Headers Sécurisés</span></div>'
        
        html_template += f"""
                        <tr>
                            <td>
                                <span style="color: var(--cyan); font-family: 'JetBrains Mono', monospace; font-size: 15px; font-weight: 700;">{port_num}</span>
                                <span style="color: var(--gray); font-size: 11px;">/{proto}</span>
                            </td>
                            <td>
                                <div style="font-weight: 600; color: #fff;">{service_esc}</div>
                                {mitre_badge}
                                {http_badge}
                            </td>
                            <td style="color: var(--gray);">{version_esc}</td>
                            <td><span style="color: var(--gray); text-transform: capitalize;">{statut}</span></td>
                            <td>
                                <span class="badge {ia_badge_class}"><i class="fa-solid {ia_icon}"></i> {label}</span>
                                <div style="color: var(--gray); font-size: 10px; margin-top: 6px; font-family: 'JetBrains Mono', monospace;">Confiance: {conf}%</div>
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
            <div style="background: rgba(255, 42, 85, 0.1); border-left: 4px solid var(--red); padding: 20px; border-radius: 4px; margin-bottom: 24px;">
                <b style="color: var(--red); font-size: 15px; display:flex; align-items:center; gap:10px;">
                    <i class="fa-solid fa-triangle-exclamation" style="font-size: 20px;"></i> ALERTE DE THREAT INTELLIGENCE (CISA KEV)
                </b>
                <p style="color: #ffb3c6; font-size: 13px; margin: 8px 0 0 0;">
                    {cisa_kev_count} vulnérabilité(s) activement exploitée(s) dans la nature détectée(s). Un correctif d'urgence est prioritaire.
                </p>
            </div>
            """

        html_template += f"""
            <div class="panel">
                <h2><i class="fa-solid fa-bug" style="color: var(--red);"></i> Registre des Vulnérabilités (CVE)</h2>
                
                {cisa_alert_html}

                <div class="stats-grid" style="grid-template-columns: repeat(3, 1fr); margin-bottom: 30px;">
                    <div class="stat-card brand-orange">
                        <span class="stat-val">{total_cves}</span>
                        <span class="stat-label">CVEs Identifiées</span>
                    </div>
                    <div class="stat-card brand-red">
                        <span class="stat-val">{critical_cves}</span>
                        <span class="stat-label">Critiques (CVSS ≥ 9)</span>
                    </div>
                    <div class="stat-card brand-red">
                        <span class="stat-val">{cisa_kev_count}</span>
                        <span class="stat-label">Exploits Actifs (KEV)</span>
                    </div>
                </div>

                <table>
                    <thead>
                        <tr>
                            <th style="width: 10%">PORT</th>
                            <th style="width: 15%">CVE ID</th>
                            <th style="width: 10%">CVSS</th>
                            <th style="width: 10%">SÉVÉRITÉ</th>
                            <th style="width: 55%">DESCRIPTION TECHNIQUE</th>
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
            
            if len(desc) > 150: desc = desc[:147] + "..."
                
            badge_class = "badge-green"
            if cvss >= 9.0: badge_class = "badge-red"
            elif cvss >= 7.0: badge_class = "badge-orange"
            elif cvss >= 4.0: badge_class = "badge-cyan"
            
            port_esc = html.escape(str(cve.get('_port')))
            service_esc = html.escape(str(cve.get('_service')))
            
            kev_badge = '<div style="margin-top: 5px;"><span class="badge badge-red"><i class="fa-solid fa-fire"></i> KEV</span></div>' if is_kev else ''

            html_template += f"""
                        <tr>
                            <td>
                                <span style="color: var(--cyan); font-family: 'JetBrains Mono', monospace; font-weight: 700;">{port_esc}</span><br>
                                <span style="color: var(--gray); font-size: 10px; text-transform: uppercase;">{service_esc}</span>
                            </td>
                            <td>
                                <span style="font-family: 'JetBrains Mono', monospace; font-weight: 600; color: #fff;">{cve_id}</span>
                                {kev_badge}
                            </td>
                            <td><span style="color: #fff; font-family: 'JetBrains Mono', monospace; font-weight: 700;">{cvss}</span></td>
                            <td><span class="badge {badge_class}">{severity}</span></td>
                            <td style="color: var(--gray); font-size: 12px; line-height: 1.5;">{desc}</td>
                        </tr>
            """
        html_template += """
                    </tbody>
                </table>
            </div>
        """
    else:
        html_template += """
            <div class="panel" style="text-align: center; border-top: 3px solid var(--green); padding: 40px 20px;">
                <i class="fa-solid fa-shield-check" style="font-size: 40px; color: var(--green); margin-bottom: 15px;"></i>
                <h3 style="color: var(--green); margin:0;">Aucune vulnérabilité CVE détectée</h3>
                <p style="color: var(--gray); font-size: 14px; margin-top: 10px;">Les services analysés ne présentent aucune vulnérabilité publiquement documentée dans la base NVD.</p>
            </div>
        """

    html_template += f"""
            <footer style="margin-top: 50px; text-align: center; color: var(--gray); font-size: 12px; font-family: 'JetBrains Mono', monospace; padding-bottom: 20px;">
                © {datetime.now().year} Smart Network Mapper • Architecture Zero Trust<br>
                <span style="opacity: 0.5;">Core: Python • ML: Random Forest • Threat Intel: CISA/NVD</span>
            </footer>
        </div>
        
        <!-- Script Chart.js -->
        <script>
            const ctx = document.getElementById('securityChart').getContext('2d');
            const data = {{
                labels: ['Services Sécurisés', 'Services Vulnérables'],
                datasets: [{{
                    data: [{safe_p}, {vuln_p}],
                    backgroundColor: ['#00d27a', '#ff2a55'],
                    borderColor: ['#0b0f19', '#0b0f19'],
                    borderWidth: 3,
                    hoverOffset: 4
                }}]
            }};
            
            const config = {{
                type: 'doughnut',
                data: data,
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '75%',
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{
                                color: '#94a3b8',
                                font: {{ family: 'Inter', size: 12 }},
                                padding: 20,
                                usePointStyle: true,
                                pointStyle: 'circle'
                            }}
                        }},
                        tooltip: {{
                            backgroundColor: 'rgba(21, 27, 43, 0.9)',
                            titleColor: '#fff',
                            bodyColor: '#cbd5e1',
                            borderColor: '#1e293b',
                            borderWidth: 1,
                            padding: 12,
                            boxPadding: 6
                        }}
                    }}
                }}
            }};
            
            // Text in center of doughnut
            const centerTextPlugin = {{
                id: 'centerText',
                beforeDraw: function(chart) {{
                    var width = chart.width,
                        height = chart.height,
                        ctx = chart.ctx;
            
                    ctx.restore();
                    var fontSize = (height / 100).toFixed(2);
                    ctx.font = "bold " + fontSize + "em 'JetBrains Mono'";
                    ctx.textBaseline = "middle";
                    ctx.fillStyle = "#ffffff";
            
                    var text = "{open_p}",
                        textX = Math.round((width - ctx.measureText(text).width) / 2),
                        textY = height / 2 - 15;
            
                    ctx.fillText(text, textX, textY);
                    
                    ctx.font = "500 " + (fontSize/2.5).toFixed(2) + "em 'Inter'";
                    ctx.fillStyle = "#94a3b8";
                    var text2 = "PORTS",
                        text2X = Math.round((width - ctx.measureText(text2).width) / 2),
                        text2Y = height / 2 + 10;
                        
                    ctx.fillText(text2, text2X, text2Y);
                    ctx.save();
                }}
            }};

            new Chart(ctx, config, [centerTextPlugin]);
            Chart.register(centerTextPlugin);
        </script>
    </body>
    </html>
    """
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_template)
    return output_path
