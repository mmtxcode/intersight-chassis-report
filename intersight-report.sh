#!/usr/bin/env bash
# intersight-report.sh — launcher with preflight checks and menu.
#
# Runs four validation steps before showing the menu:
#   1. A Python interpreter at or above MIN_PY is available.
#   2. A virtual environment exists with all required packages.
#   3. .env exists and the API key file is reachable.
#   4. The API key can authenticate against Intersight (also captures the
#      account display name so the menu can use it in output filenames).
#
# Once preflight passes, the menu lets the user produce a CSV, PDF, or
# both — output named "<account-name>-chassis-report.{csv,pdf}".
#
# Usage:
#   chmod +x intersight-report.sh
#   ./intersight-report.sh

set -uo pipefail

# ---------- Constants ----------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly VENV_DIR="${SCRIPT_DIR}/.venv"
readonly ENV_FILE="${SCRIPT_DIR}/.env"
readonly REQS_FILE="${SCRIPT_DIR}/requirements.txt"
readonly REPORT_SCRIPT="${SCRIPT_DIR}/chassis_report.py"
readonly PREFLIGHT_SCRIPT="${SCRIPT_DIR}/preflight.py"
readonly MIN_PY_MAJOR=3
readonly MIN_PY_MINOR=10

# Set by preflight steps.
PYTHON_CMD=""
ACCOUNT_NAME=""

# ---------- Output helpers ----------
heading() { printf "\n\033[1;36m%s\033[0m\n" "$*"; }
ok()      { printf "  \033[32m✓\033[0m %s\n" "$*"; }
warn()    { printf "  \033[33m!\033[0m %s\n" "$*"; }
err()     { printf "  \033[31m✗\033[0m %s\n" "$*" >&2; }

# ---------- Preflight 1: locate a Python interpreter ----------
find_python() {
    heading "[1/4] Locating Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ interpreter"
    local candidate ver
    for candidate in python3.13 python3.12 python3.11 python3.10 python3 python; do
        if command -v "$candidate" >/dev/null 2>&1; then
            if "$candidate" -c "import sys; sys.exit(0 if sys.version_info >= (${MIN_PY_MAJOR}, ${MIN_PY_MINOR}) else 1)" 2>/dev/null; then
                PYTHON_CMD="$candidate"
                ver=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')
                ok "Using $candidate (Python $ver)"
                return 0
            fi
        fi
    done
    err "No Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ found in PATH."
    err "Install from https://www.python.org/ or your OS package manager, then retry."
    return 1
}

# ---------- Preflight 2: build / refresh venv ----------
ensure_venv() {
    heading "[2/4] Preparing virtual environment"
    if [[ ! -d "$VENV_DIR" ]]; then
        echo "  Creating venv at ${VENV_DIR} ..."
        if ! "$PYTHON_CMD" -m venv "$VENV_DIR" 2>&1; then
            err "Failed to create virtual environment."
            return 1
        fi
    fi
    local pip="${VENV_DIR}/bin/pip"
    if [[ ! -x "$pip" ]]; then
        err "pip not found inside venv at $pip"
        return 1
    fi
    echo "  Installing dependencies from $(basename "$REQS_FILE") ..."
    if ! "$pip" install --quiet --disable-pip-version-check --upgrade pip 2>&1; then
        warn "Could not upgrade pip (continuing with existing version)."
    fi
    if ! "$pip" install --quiet --disable-pip-version-check -r "$REQS_FILE" 2>&1; then
        err "Failed to install dependencies."
        return 1
    fi
    ok "Dependencies installed"
}

# ---------- Preflight 3: .env file ----------
check_env() {
    heading "[3/4] Checking .env file"
    if [[ ! -f "$ENV_FILE" ]]; then
        err ".env not found at $ENV_FILE"
        err "Copy .env.example to .env and fill in INTERSIGHT_API_KEY_ID and"
        err "INTERSIGHT_API_KEY_FILE before re-running."
        return 1
    fi
    ok ".env present"
}

# ---------- Preflight 4: API connection + capture account name ----------
test_connection() {
    heading "[4/4] Testing Intersight connection"
    local py="${VENV_DIR}/bin/python"
    local output
    # preflight.py writes the account name to stdout on success, or a
    # diagnostic message to stderr with a non-zero exit on failure. We
    # capture both into $output via 2>&1 and branch on the exit code.
    if output=$("$py" "$PREFLIGHT_SCRIPT" 2>&1); then
        ACCOUNT_NAME="$output"
        ok "Connected. Account: $ACCOUNT_NAME"
        return 0
    else
        err "$output"
        return 1
    fi
}

# ---------- Helpers ----------
# Replace anything outside [A-Za-z0-9._-] with '-' so the account name is
# safe to use as part of a filename on every supported OS.
sanitize_filename() {
    printf "%s" "$1" | sed 's/[^A-Za-z0-9._-]/-/g'
}

press_enter() {
    echo
    read -rp "Press Enter to continue..." _ || true
}

# ---------- Menu: chassis inventory submenu ----------
chassis_inventory_menu() {
    local safe_name base_name py
    safe_name="$(sanitize_filename "$ACCOUNT_NAME")"
    base_name="${safe_name}-chassis-report"
    py="${VENV_DIR}/bin/python"

    while true; do
        printf "\n\033[1m===== Chassis Inventory Report =====\033[0m\n"
        echo "  Account     : $ACCOUNT_NAME"
        echo "  Output dir  : $SCRIPT_DIR"
        echo "  File prefix : $base_name"
        echo
        echo "  1) Generate CSV"
        echo "  2) Generate PDF"
        echo "  3) Generate both"
        echo "  0) Back to main menu"
        echo
        read -rp "Choose: " choice
        case "$choice" in
            1)
                echo
                "$py" "$REPORT_SCRIPT" --format csv -o "${SCRIPT_DIR}/${base_name}.csv"
                press_enter
                ;;
            2)
                echo
                "$py" "$REPORT_SCRIPT" --format pdf -o "${SCRIPT_DIR}/${base_name}.pdf"
                press_enter
                ;;
            3)
                echo
                "$py" "$REPORT_SCRIPT" --format csv -o "${SCRIPT_DIR}/${base_name}.csv"
                "$py" "$REPORT_SCRIPT" --format pdf -o "${SCRIPT_DIR}/${base_name}.pdf"
                press_enter
                ;;
            0)
                return
                ;;
            *)
                warn "Invalid choice: '$choice'"
                ;;
        esac
    done
}

# ---------- Main menu ----------
main_menu() {
    while true; do
        printf "\n\033[1m===== Intersight Reports =====\033[0m\n"
        echo "  1) Chassis Inventory Report"
        echo "  0) Exit"
        echo
        read -rp "Choose: " choice
        case "$choice" in
            1) chassis_inventory_menu ;;
            0)
                echo
                echo "Goodbye."
                exit 0
                ;;
            *) warn "Invalid choice: '$choice'" ;;
        esac
    done
}

# ---------- Entry point ----------
cd "$SCRIPT_DIR"

printf "\n\033[1;36m─── Intersight Report Launcher ───\033[0m\n"

find_python      || exit 1
ensure_venv      || exit 1
check_env        || exit 1
test_connection  || exit 1

main_menu
