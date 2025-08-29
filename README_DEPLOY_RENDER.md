# One‑Click Deploy to Render

## Option A — Blueprint (recommended)
1. Push this folder to a new GitHub repo (public).
2. Go to Render → **New → Blueprint** → select your repo.
3. Confirm settings and **Deploy**.
4. After deploy, attach a **Disk** (if not already created) at `/opt/render/project/src/data` (2 GB).
5. Open the app URL.

## Option B — Manual Web Service
1. Render → **New → Web Service** → pick your repo.
2. Build Command:
   ```bash
   pip install -r requirements.txt
   python - <<'PY'
import nltk
for pkg in ["punkt","stopwords","vader_lexicon"]:
    nltk.download(pkg)
PY
   ```
3. Start Command:
   ```bash
   streamlit run app.py --server.port $PORT --server.address 0.0.0.0
   ```
4. Environment:
   - `STREAMLIT_SERVER_HEADLESS=true`
   - `PYTHONUNBUFFERED=1`
   - *(optional)* `VIRUSTOTAL_API_KEY=...`
5. Disks → Add:
   - name: `phishguard-data`, mountPath: `/opt/render/project/src/data`, size: 2 GB

> **Note**: Gmail OAuth (beta) requires a local redirect, so for cloud use IMAP with app passwords.