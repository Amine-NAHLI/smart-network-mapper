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
    print(f"\n{Fore.CYAN}{Style.BRIGHT}╔═════════════════════════════════════════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}{Style.BRIGHT}║                      SMART NETWORK MAPPER (SNM) v1.1.0                          ║")
    print(f"{Fore.CYAN}{Style.BRIGHT}╚═════════════════════════════════════════════════════════════════════════════════╝\n")
    
    print(f"{Fore.YELLOW}{Style.BRIGHT}🚀 1. EXÉCUTION (Lancement de l'application selon le mode souhaité)")
    print(f"   {Fore.GREEN}just run{Style.RESET_ALL}  ou  {Fore.GREEN}just gui{Style.RESET_ALL}   (python snm.py gui)   {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Lance l'interface graphique (CustomTkinter)")
    print(f"   {Fore.GREEN}just cli{Style.RESET_ALL}              (python snm.py cli)   {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Lance le terminal interactif guidé")
    print("")

    print(f"{Fore.YELLOW}{Style.BRIGHT}🔍 2. SCAN RÉSEAU (Moteur de découverte et d'audit rapide / complet)")
    print(f"   {Fore.GREEN}just discover{Style.RESET_ALL}         (python snm.py --discover)                {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Auto-découverte des hôtes du LAN (ARP)")
    print(f"   {Fore.GREEN}just scan-fast <IP>{Style.RESET_ALL}   (python snm.py --target <IP> --mode fast) {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Scan rapide (24 ports) + IA + OSINT")
    print(f"   {Fore.GREEN}just scan-full <IP>{Style.RESET_ALL}   (python snm.py --target <IP> --mode full) {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Scan complet (65 535 ports) sur la cible")
    print("")

    print(f"{Fore.YELLOW}{Style.BRIGHT}🧪 3. QUALITÉ DU CODE (Contrôle de stabilité, typage et lisibilité)")
    print(f"   {Fore.GREEN}just test{Style.RESET_ALL}             {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Exécute la suite complète des 57 tests pytest (100% succès)")
    print(f"   {Fore.GREEN}just test-verbose{Style.RESET_ALL}     {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Exécute les tests avec affichage détaillé et tracebacks")
    print(f"   {Fore.GREEN}just lint{Style.RESET_ALL}             {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Analyse statique du code et contrôle des types (Ruff / Mypy)")
    print(f"   {Fore.GREEN}just format{Style.RESET_ALL}           {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Formate le code automatiquement selon les standards (YAPF)")
    print("")

    print(f"{Fore.YELLOW}{Style.BRIGHT}📦 4. DISTRIBUTION & PACKAGING (Génération d'exécutable et nettoyage)")
    print(f"   {Fore.GREEN}just build{Style.RESET_ALL}            {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Compile le projet en exécutable autonome .exe (PyInstaller)")
    print(f"   {Fore.GREEN}just package{Style.RESET_ALL}          {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Génère l'archive ZIP Windows portable prête à l'emploi")
    print(f"   {Fore.GREEN}just clean{Style.RESET_ALL}            {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Nettoie les caches (__pycache__, pytest, ruff) et outputs temporaires")
    print("")

    print(f"{Fore.YELLOW}{Style.BRIGHT}🛠️  5. SETUP & ENVIRONNEMENT")
    print(f"   {Fore.GREEN}just setup{Style.RESET_ALL}            {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Initialise l'environnement virtuel ultra-rapide (uv sync)")
    print(f"   {Fore.GREEN}just test-groq{Style.RESET_ALL}       {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Valide la connectivité avec l'API Groq (Llama-3.3-70b)")
    print(f"   {Fore.GREEN}docker build -t snm .{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Construit l'image conteneurisée multi-stage")
    print(f"   {Fore.GREEN}docker run -it --rm --network host snm{Style.RESET_ALL} {Fore.LIGHTBLACK_EX}→{Style.RESET_ALL} Exécute SNM en conteneur Docker")
    print(f"\n{Fore.CYAN}{Style.BRIGHT}─────────────────────────────────────────────────────────────────────────────────\n")

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
