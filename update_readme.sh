
#!/bin/bash

# Define markers
START="<!-- project-list-start -->"
END="<!-- project-list-end -->"

# Generate formatted list of folders (ignore hidden/system folders)
PROJECTS=$(find . -maxdepth 1 -type d ! -name ".*" ! -name "target" ! -name "__pycache__" ! -name "." | sort)
LIST=""
for DIR in $PROJECTS; do
    NAME=$(basename "$DIR")
    LIST+="🔹 \`$NAME\`  \n"
done

# Replace the content in README.md
awk -v start="$START" -v end="$END" -v new="$LIST" '
    $0 ~ start { print; print new; inblock=1; next }
    $0 ~ end { inblock=0 }
    !inblock { print }
' README.md > README.tmp && mv README.tmp README.md

echo "✅ README.md updated with current project list."
