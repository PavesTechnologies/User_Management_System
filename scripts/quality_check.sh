#!/bin/bash

# --- Configuration ---
TARGET_DIR="Backend"
TEST_DIR="tests"
MIN_COVERAGE=70

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Starting Quality Checks..."

# 1. Autoflake
echo -e "\n[1/7] Running Autoflake..."
autoflake --in-place --remove-all-unused-imports --recursive $TARGET_DIR

# 2. Black (Formatting)
echo -e "\n[2/7] Running Black..."
black $TARGET_DIR
if [ $? -ne 0 ]; then
    echo -e "${RED}Black failed${NC}"
    exit 1
fi

# 3. Flake8 (Linting)
echo -e "\n[3/7] Running Linter (Flake8)..."

FLAKE_OUTPUT=$(flake8 $TARGET_DIR \
    --count \
    --max-line-length=88 \
    --extend-ignore=E203,E501 \
    --statistics)

FLAKE_EXIT_CODE=$?

if [ $FLAKE_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}Flake8 found the following issues:${NC}"
    echo "$FLAKE_OUTPUT"
    exit 1
fi

echo -e "${GREEN}Flake8 passed${NC}"

# 4. Bandit (Security)
echo -e "\n[4/7] Running Bandit Security Scan..."

BANDIT_OUTPUT=$(bandit -r $TARGET_DIR -ll -ii 2>&1)
BANDIT_EXIT_CODE=$?

if [ $BANDIT_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}Security vulnerabilities detected!${NC}"
    echo "$BANDIT_OUTPUT"
    exit 1
fi

echo -e "${GREEN}Bandit passed${NC}"

# 5. pip-audit (Dependency Vulnerability Scan)
echo -e "\n[5/7] Running pip-audit (Dependency CVE Scan)..."

pip-audit -r $TARGET_DIR/requirements.txt
PIP_AUDIT_EXIT_CODE=$?

if [ $PIP_AUDIT_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}Vulnerable dependencies found! Update requirements.txt before proceeding.${NC}"
    exit 1
fi

echo -e "${GREEN}pip-audit passed${NC}"

# 6. Mypy (Type Checking)
echo -e "\n[6/7] Running Mypy (Type Checker)..."

mypy $TARGET_DIR --ignore-missing-imports --explicit-package-bases
MYPY_EXIT_CODE=$?

if [ $MYPY_EXIT_CODE -ne 0 ]; then
    echo -e "${RED}Type errors found! Fix type issues before proceeding.${NC}"
    exit 1
fi

echo -e "${GREEN}Mypy passed${NC}"

# # 7. Pytest (Coverage)
# echo -e "\n[7/7] Running Tests (Coverage Gate: ${MIN_COVERAGE}%)..."

# pytest \
#     --cov=$TARGET_DIR \
#     $TEST_DIR \
#     --cov-report=term-missing \
#     --cov-fail-under=$MIN_COVERAGE

# if [ $? -eq 0 ]; then
#     echo -e "\n${GREEN}ALL QUALITY GATES PASSED ✓${NC}"
#     exit 0
# else
#     echo -e "\n${RED}QUALITY GATE FAILED${NC}"
#     echo -e "${YELLOW}Hint: Run 'pytest --cov=$TARGET_DIR $TEST_DIR --cov-report=html' locally to see uncovered lines.${NC}"
#     exit 1
# fi