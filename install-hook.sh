#!/bin/sh

HOOK_FILE=".git/hooks/pre-commit"

# Check if in Git repository
if [ ! -d ".git" ]; then
  echo "Error: This directory is not a Git repository"
  exit 1
fi

# Create pre-commit hook
echo "Creating pre-commit hook..."
cat << 'EOF' > "$HOOK_FILE"
#!/bin/sh

# Run formatter
pnpm format

# Capture exit code
STATUS=$?

# Add formatted files to commit
git add -u

# Exit with original status code
exit $STATUS
EOF

# Make hook executable
chmod +x "$HOOK_FILE"
echo "Pre-commit hook installed successfully."