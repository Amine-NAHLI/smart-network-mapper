import customtkinter as ctk
import threading
import os

from snm_paths import get_base_dir, get_model_dir

# ── Configuration visuelle (même style que SNM) ──────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class DownloaderApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.base_dir = get_base_dir()
        self.downloading = False

        # ── Fenêtre ──────────────────────────────────────────────────
        self.title("SNM — Modèles IA requis")
        self.geometry("560x420")
        self.resizable(False, False)
        self.configure(fg_color="#0a0a0f")

        # Centrer la fenêtre
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - 280
        y = (self.winfo_screenheight() // 2) - 210
        self.geometry(f"560x420+{x}+{y}")

        self._build_ui()

    def _build_ui(self):
        # ── Titre ─────────────────────────────────────────────────────
        ctk.CTkLabel(
            self,
            text="⚡ SMART NETWORK MAPPER",
            font=ctk.CTkFont(family="Consolas", size=18, weight="bold"),
            text_color="#00d4ff"
        ).pack(pady=(36, 4))

        ctk.CTkLabel(
            self,
            text="Modèles IA requis pour la prédiction de vulnérabilités",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color="#666680"
        ).pack(pady=(0, 28))

        # ── Infos modèles ─────────────────────────────────────────────
        info_frame = ctk.CTkFrame(self, fg_color="#12121e", corner_radius=10)
        info_frame.pack(padx=40, fill="x")

        infos = [
            ("vulnerability_model.pkl", "~5.1 Go"),
            ("quantile_transformer.pkl", "~24 Ko"),
            ("scaler.pkl",              "~895 o"),
            ("feature_names.pkl",       "~1.5 Ko"),
        ]

        for name, size in infos:
            row = ctk.CTkFrame(info_frame, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=4)
            ctk.CTkLabel(
                row,
                text=f"  {name}",
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color="#aaaacc",
                anchor="w"
            ).pack(side="left")
            ctk.CTkLabel(
                row,
                text=size,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color="#444466",
                anchor="e"
            ).pack(side="right")

        # ── Progress bar ──────────────────────────────────────────────
        self.progress_bar = ctk.CTkProgressBar(
            self,
            width=480,
            height=8,
            fg_color="#12121e",
            progress_color="#00d4ff",
            corner_radius=4
        )
        self.progress_bar.pack(pady=(28, 8))
        self.progress_bar.set(0)

        # ── Status label ──────────────────────────────────────────────
        self.status_label = ctk.CTkLabel(
            self,
            text="Prêt à télécharger",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color="#444466"
        )
        self.status_label.pack(pady=(0, 20))

        # ── Bouton ────────────────────────────────────────────────────
        self.btn = ctk.CTkButton(
            self,
            text="TÉLÉCHARGER LES MODÈLES  (~5.1 Go)",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            fg_color="#00d4ff",
            text_color="#0a0a0f",
            hover_color="#00aad4",
            height=44,
            width=480,
            corner_radius=6,
            command=self._start_download
        )
        self.btn.pack(pady=(0, 16))

        ctk.CTkLabel(
            self,
            text="Source : huggingface.co/aminenahli/smart-network-mapper-models",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color="#2a2a3a"
        ).pack()

    def _start_download(self):
        if self.downloading:
            return
        self.downloading = True
        self.btn.configure(state="disabled", text="Téléchargement en cours...")
        threading.Thread(target=self._download_worker, daemon=True).start()

    def _download_worker(self):
        try:
            from huggingface_hub import hf_hub_download, list_repo_files
            import huggingface_hub

            repo_id = "aminenahli/smart-network-mapper-models"
            model_dir = get_model_dir()
            os.makedirs(model_dir, exist_ok=True)

            files = [
                "vulnerability_model.pkl",
                "quantile_transformer.pkl",
                "scaler.pkl",
                "feature_names.pkl",
            ]

            total = len(files)

            for i, filename in enumerate(files):
                self._update_status(
                    f"Téléchargement {i+1}/{total} : {filename}",
                    (i / total)
                )

                hf_hub_download(
                    repo_id=repo_id,
                    filename=filename,
                    local_dir=model_dir,
                )

                self._update_status(
                    f"✓ {filename}",
                    ((i + 1) / total)
                )

            # Succès
            self._update_status("✅ Téléchargement terminé ! Lancement de SNM...", 1.0)
            self.after(1500, self._launch_app)

        except Exception as e:
            self._update_status(f"❌ Erreur : {str(e)}", 0)
            self.after(0, lambda: self.btn.configure(
                state="normal",
                text="RÉESSAYER"
            ))
            self.downloading = False

    def _update_status(self, text, progress):
        self.after(0, lambda: self.status_label.configure(text=text))
        self.after(0, lambda: self.progress_bar.set(progress))

    def _launch_app(self):
        self.destroy()
        from app import run_app
        run_app()


def run_downloader():
    app = DownloaderApp()
    app.mainloop()


if __name__ == "__main__":
    run_downloader()
