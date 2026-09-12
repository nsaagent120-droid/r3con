# 📘 Carnet Système — Mon espace de publication technique

> Mon carnet de recherche personnel : **systèmes embarqués, kernels & OS, analyse de CVE, protocoles IoT.**
> J'y documente mes recherches, mes labs et mes analyses — un article par semaine, en français.

![Bannière Carnet Système](site/docs/assets/banniere.png)

---

## 🗂️ Contenu de ce dossier

| Fichier / dossier | Rôle |
|---|---|
| [`PROFIL_GITHUB.md`](PROFIL_GITHUB.md) | Le README de **ta page de profil GitHub** (à copier dans un repo `ton-pseudo/ton-pseudo`) |
| [`PLAN_CARRIERE.md`](PLAN_CARRIERE.md) | La stratégie complète : séries, cadence hebdo, pipeline éditorial, plan 12 semaines, KPI |
| [`templates/`](templates/) | **5 templates** prêts à remplir : article kernel, writeup CVE, firmware/driver, protocole IoT, fiche de lecture |
| [`site/`](site/) | Le **site de publication** (MkDocs Material) : page d'accueil, 4 séries, 3 premiers articles |
| [`site/.github/workflows/deploy-docs.yml`](site/.github/workflows/deploy-docs.yml) | Workflow GitHub Actions : le site se publie **automatiquement** sur GitHub Pages à chaque `git push` |

---

## 🚀 Démarrage rapide

### Option A — Lire les documents
Tout est en Markdown, lisibles directement ici. Commence par [`PLAN_CARRIERE.md`](PLAN_CARRIERE.md).

### Option B — Faire tourner le site en local (5 min)

```bash
cd publication/site
python -m venv .venv && source .venv/bin/activate
pip install mkdocs-material
mkdocs serve          # → http://127.0.0.1:8000
```

### Option C — Le sortir sur TON compte GitHub (le vrai lancement)

Ce dossier est **100 % autonome**. Pour en faire ton repo public de carrière :

```bash
# 1. Copie le dossier hors de ce projet
cp -r publication ~/carnet-systeme && cd ~/carnet-systeme

# 2. Crée le repo sur github.com (ex: <ton-pseudo>/carnet-systeme), puis :
git init
git add .
git commit -m "Carnet Système — lancement"
git branch -M main
git remote add origin https://github.com/<ton-pseudo>/carnet-systeme.git
git push -u origin main
```

Ensuite :
1. **GitHub Pages** : `Settings → Pages → Source : GitHub Actions` — le workflow inclus déploiera le site à chaque push.
2. **Profil** : crée un repo nommé exactement `<ton-pseudo>/<ton-pseudo>`, colle-y le contenu de [`PROFIL_GITHUB.md`](PROFIL_GITHUB.md) (en le personnalisant) dans `README.md`.
3. **Personnalise** : remplace tous les placeholders `[...]` (bio, liens, pseudo).

---

## ✍️ Comment publier un nouvel article (le rituel hebdo)

1. **Choisis** un sujet dans le backlog de la série concernée (voir [`PLAN_CARRIERE.md`](PLAN_CARRIERE.md)).
2. **Copie** le template correspondant depuis [`templates/`](templates/) vers `site/docs/articles/AAAA-MM-JJ-mon-sujet.md`.
3. **Écris** dans le lab d'abord : chaque affirmation technique doit être **testée** (QEMU, Raspberry Pi,VM…).
4. **Renseigne** la navigation dans `site/mkdocs.yml` et marque l'article ✅ dans la page de sa série.
5. `git push` → le site se redéploie tout seul.
6. **Annonce** l'article sur LinkedIn/X avec le lien GitHub Pages.

> ⚖️ **Éthique** : les writeups de CVE ne concernent que des vulnérabilités **publiées et corrigées**, avec PoC pédagogique. Jamais d'exploit clé en main. Voir la charte dans [`PLAN_CARRIERE.md`](PLAN_CARRIERE.md).
