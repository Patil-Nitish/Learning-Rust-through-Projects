#!/bin/bash

# Define the start and end markers
START="<!-- project-list-start -->"
END="<!-- project-list-end -->"

# Find all top-level folders (excluding hidden/system)
projects=$(find . -maxdepth 1 -type d ! -name ".*" ! -name "target" ! -name "__pycache__" ! -name ".git" | grep -v '^.$' | sort)

# Format the list
formatted=""
for folder in $projects; do
    name=$(basename "$folder")
    formatted+="🔹 \`$name\`  \n"
done

# Escape slashes for use in sed
formatted_escaped=$(echo -e "$formatted" | sed 's/[&/\]/\\&/g')

# Replace content between markers in README.md
awk -v start="$START" -v end="$END" -v content="$formatted_escaped" '
BEGIN {in=0}
/start/ {print; print content; in=1; next}
/end/ {in=0}
!in {print}
' README.md > README.tmp && mv README.tmp README.md

echo "✅ README.md updated with project list."
