import sys
import subprocess

# Force UTF-8 encoding for Windows terminals to display box characters and emojis
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # Fallback si colorama n'est pas installé
    class DummyColor:
        def __getattr__(self, name): return ""
    Fore = Style = DummyColor()

def print_help():
    print(f"\n{Fore.CYAN}{Style.BRIGHT}╔═════════════════════════════════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}{Style.BRIGHT}║                   SMART NETWORK MAPPER (SNM) v1.1.0                     ║")
    print(f"{Fore.CYAN}{Style.BRIGHT}╚═════════════════════════════════════════════════════════════════════════╝\n")
    
    print(f"{Fore.YELLOW}{Style.BRIGHT}🚀 DÉMARRAGE DES INTERFACES (GUI & CLI INTERACTIF)")
    print(f"   {Fore.GREEN}python snm.py gui{Style.RESET_ALL}        {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Lance l'interface graphique complète (CustomTkinter)")
    print(f"   {Fore.GREEN}python snm.py cli{Style.RESET_ALL}        {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Lance l'interface terminal interactive (Menu guidé)")
    print("")

    print(f"{Fore.YELLOW}{Style.BRIGHT}🔍 SCAN AUTOMATIQUE SANS INTERFACE (HEADLESS CLI)")
    print(f"   {Fore.GREEN}python snm.py --discover{Style.RESET_ALL}                   {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Auto-détecte le LAN et liste les hôtes")
    print(f"   {Fore.GREEN}python snm.py --target <IP> --mode fast{Style.RESET_ALL}    {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Scan rapide (24 ports) + IA + OSINT")
    print(f"   {Fore.GREEN}python snm.py --target <IP> --mode full{Style.RESET_ALL}    {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Scan complet (65535 ports) sur la cible")
    print("")

    print(f"{Fore.YELLOW}{Style.BRIGHT}🛠️  COMMANDES 'JUST' (Utilitaires de développement & DevOps)")
    
    print(f"\n   {Fore.CYAN}■ Installation & Setup{Style.RESET_ALL}")
    print(f"      {Fore.GREEN}just setup{Style.RESET_ALL}              {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Configure l'environnement virtuel (uv venv + uv sync)")
    print(f"      {Fore.GREEN}.venv\\Scripts\\activate{Style.RESET_ALL}  {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Active l'environnement virtuel (Windows)")
    
    print(f"\n   {Fore.CYAN}■ Tests & Qualité du code{Style.RESET_ALL}")
    print(f"      {Fore.GREEN}just test{Style.RESET_ALL}               {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Lance la suite complète de 57 tests pytest")
    print(f"      {Fore.GREEN}just lint{Style.RESET_ALL}               {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Vérifie la propreté du code (Ruff / Mypy)")
    print(f"      {Fore.GREEN}just format{Style.RESET_ALL}             {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Formate le code automatiquement (YAPF)")
    
    print(f"\n   {Fore.CYAN}■ Build & Déploiement{Style.RESET_ALL}")
    print(f"      {Fore.GREEN}just build{Style.RESET_ALL}              {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Compile le projet en exécutable .exe")
    print(f"      {Fore.GREEN}just package{Style.RESET_ALL}            {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Crée l'archive ZIP Windows portable")
    
    print(f"\n   {Fore.CYAN}■ Outils Annexes{Style.RESET_ALL}")
    print(f"      {Fore.GREEN}just test-groq{Style.RESET_ALL}          {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Teste la connectivité avec l'API Groq (LLM)")
    print(f"      {Fore.GREEN}just clean{Style.RESET_ALL}              {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Nettoie les caches et fichiers temporaires")
    
    print(f"\n{Fore.CYAN}{Style.BRIGHT}───────────────────────────────────────────────────────────────────────────\n")

def main():
    if len(sys.argv) == 1 or sys.argv[1] in ["-h", "--help", "help"]:
        print_help()
        sys.exit(0)
    
    cmd = sys.argv[1]
    
    # Redirection intelligente vers les vrais modules
    if cmd == "gui":
        sys.exit(subprocess.run([sys.executable, "-m", "core.app"] + sys.argv[2:]).returncode)
    elif cmd == "cli":
        sys.exit(subprocess.run([sys.executable, "-m", "core.main"] + sys.argv[2:]).returncode)
    elif cmd in ["--discover", "--target"]:
        # Transfère les arguments vers run_scan.py (le CLI headless)
        sys.exit(subprocess.run([sys.executable, "-m", "cli.run_scan"] + sys.argv[1:]).returncode)
    else:
        print(f"\n{Fore.RED}Erreur : Commande inconnue '{cmd}'{Style.RESET_ALL}")
        print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
