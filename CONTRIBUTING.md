# Contributing to Agni (अग्नि)

Thank you for your interest in contributing to Agni! We welcome contributions to our detection rules, sensor collectors, correlation engine, and web dashboard.

---

## Development Environment Setup

### Prerequisites

- **Python 3.11+** (Python 3.12 or 3.13 recommended)
- **Node.js 18+** & **npm 9+**
- **Git**
- Optional: Google Chrome (for headless screenshot automation)

### 1. Clone the Repository

```bash
git clone https://github.com/adiz777/Agni.git
cd Agni
```

### 2. Backend Setup

```bash
# Create and activate virtual environment
python -m venv .venv
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
# On Linux / macOS (Bash):
source .venv/bin/activate

# Install backend dependencies in editable mode
pip install -r backend/requirements.txt
# Or via pyproject.toml:
pip install -e backend/
```

### 3. Frontend Setup

```bash
cd frontend
npm install
cd ..
```

---

## Running the Application Locally

In two separate terminals:

### Terminal 1: Backend API & Detection Engine
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir backend --reload
```
The backend initializes SQLite in WAL mode and starts listening on `http://127.0.0.1:8000`.
API documentation is available at `http://127.0.0.1:8000/docs`.

### Terminal 2: React SOC Dashboard
```bash
cd frontend
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## Code Quality Standards & Verification

Before submitting any pull request, all automated checks must pass:

### Backend Checks
```bash
# Run backend unit, integration, and security tests
python -m pytest tests/backend/ -v

# Run the complete end-to-end opaque-box test runner
python tests/e2e/runner.py

# Lint and check code style with Ruff
python -m ruff check backend/ tests/ --config backend/pyproject.toml
```

### Frontend Checks
```bash
cd frontend

# Run frontend component tests
npm run test

# Typecheck with TypeScript
npx tsc --noEmit

# Verify production build bundle
npm run build
```

---

## Contributing Detection Rules

Agni uses declarative **Varuna YAML/JSON detection rules** mapped to MITRE ATT&CK. New rules belong in `backend/rules/`.

When adding or modifying rules:
1. Follow the Varuna Rule schema (`id`, `title`, `severity`, `mitre_attack`, `condition_tree`).
2. Provide descriptive rationales and remediation playbooks.
3. Add a corresponding test scenario in `tests/backend/test_rules.py`.

---

## Pull Request Guidelines

1. **Branch Naming**:
   - `feat/feature-name`
   - `fix/bug-fix-name`
   - `rules/mitre-technique-name`
   - `docs/doc-update`
2. **Commit Messages**: Follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat: add macOS LaunchDaemon persistence collector`
   - `fix: resolve race condition in SQLite WAL concurrent writer`
   - `test: add boundary test for long cmdline parsing`
3. **Keep Changes Minimal**: Avoid unrelated refactoring outside the PR's focused scope.
4. **Sign Off**: Ensure your code conforms to the project's MIT License.
