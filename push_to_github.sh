#!/usr/bin/env bash
# push_to_github.sh
# Run this once from the project root to initialise and push to your GitHub repo.
# Usage: bash push_to_github.sh
# Requires: git, a GitHub Personal Access Token (classic) with repo scope.

set -e

REPO_URL="https://github.com/adarshray416/GRC.git"

echo ""
echo "=== BABCOM GRC — Push to GitHub ==="
echo ""
echo "This script will push the entire project to: $REPO_URL"
echo ""
read -p "Enter your GitHub Personal Access Token (ghp_...): " GH_TOKEN
echo ""

# Strip any trailing whitespace
GH_TOKEN=$(echo "$GH_TOKEN" | tr -d '[:space:]')

AUTH_URL="https://${GH_TOKEN}@github.com/adarshray416/GRC.git"

# Initialise git if needed
if [ ! -d ".git" ]; then
  git init
  echo "Git repo initialised"
fi

# Set identity if not set
git config user.email 2>/dev/null || git config user.email "grc@babcom.local"
git config user.name  2>/dev/null || git config user.name  "BABCOM GRC"

# Stage everything
git add -A

# Commit
git commit -m "feat: BABCOM GRC Platform v2 — FastAPI + React + GitHub scraper" 2>/dev/null || echo "(nothing new to commit)"

# Set remote
git remote remove origin 2>/dev/null || true
git remote add origin "$AUTH_URL"

# Push
git branch -M main
git push -u origin main --force

echo ""
echo "✅ Pushed successfully to https://github.com/adarshray416/GRC"
echo ""
echo "Next steps:"
echo "  1. cd backend && uvicorn main:app --reload"
echo "  2. Open frontend/index.html in your browser"
echo "  3. Push evidence files to the repo — they will be auto-scraped"
