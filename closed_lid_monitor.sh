#!/bin/sh
set -u

APP_PID="$1"
USER_ID="$2"
STATE_FILE="$3"
STOP_FILE="$4"

ORIGINAL_DISABLE="$(/usr/bin/pmset -g | /usr/bin/awk '/SleepDisabled/ { print $2; exit }')"
ORIGINAL_DISABLE="${ORIGINAL_DISABLE:-0}"
ORIGINAL_BATTERY_MODE="$(/usr/bin/pmset -g custom | /usr/bin/awk '
    /^Battery Power:/ { section = "battery"; next }
    /^AC Power:/ { section = "ac"; next }
    section == "battery" && $1 == "powermode" { print $2; exit }
')"
ORIGINAL_AC_MODE="$(/usr/bin/pmset -g custom | /usr/bin/awk '
    /^Battery Power:/ { section = "battery"; next }
    /^AC Power:/ { section = "ac"; next }
    section == "ac" && $1 == "powermode" { print $2; exit }
')"
ORIGINAL_BATTERY_MODE="${ORIGINAL_BATTERY_MODE:-0}"
ORIGINAL_AC_MODE="${ORIGINAL_AC_MODE:-0}"
DISABLE_APPLIED=0

restore_settings() {
    if [ "$DISABLE_APPLIED" = "1" ]; then
        /usr/bin/pmset -a disablesleep "$ORIGINAL_DISABLE" >/dev/null 2>&1 || true
        /usr/bin/pmset -b powermode "$ORIGINAL_BATTERY_MODE" >/dev/null 2>&1 || true
        /usr/bin/pmset -c powermode "$ORIGINAL_AC_MODE" >/dev/null 2>&1 || true
    fi
    /bin/rm -f "$STATE_FILE" "$STOP_FILE"
}

trap restore_settings EXIT
trap 'exit 0' HUP INT TERM
/bin/rm -f "$STOP_FILE"
/usr/bin/printf 'pid=%s\nuid=%s\ndisablesleep=%s\nbattery_powermode=%s\nac_powermode=%s\n' \
    "$APP_PID" "$USER_ID" "$ORIGINAL_DISABLE" "$ORIGINAL_BATTERY_MODE" "$ORIGINAL_AC_MODE" > "$STATE_FILE"
/bin/chmod 644 "$STATE_FILE"

if ! /usr/bin/pmset -a disablesleep 1 >/dev/null 2>&1; then
    exit 1
fi
DISABLE_APPLIED=1
if ! /usr/bin/pmset -g | /usr/bin/awk '
    $1 == "SleepDisabled" && $2 == "1" { active = 1 }
    END { exit(active ? 0 : 1) }
'; then
    exit 1
fi

LAST_LID_STATE=""
while /bin/kill -0 "$APP_PID" >/dev/null 2>&1 && [ ! -e "$STOP_FILE" ]; do
    POWER_OUTPUT="$(/usr/bin/pmset -g batt)"
    if ! /usr/bin/printf '%s\n' "$POWER_OUTPUT" | /usr/bin/grep -q "AC Power"; then
        BATTERY_PERCENT="$(/usr/bin/printf '%s\n' "$POWER_OUTPUT" | /usr/bin/awk '
            match($0, /[0-9]+%/) { value = substr($0, RSTART, RLENGTH - 1); print value; exit }
        ')"
        if [ -n "$BATTERY_PERCENT" ] && [ "$BATTERY_PERCENT" -le 10 ]; then
            break
        fi
    fi

    LID_STATE="$(/usr/sbin/ioreg -r -k AppleClamshellState -d 4 | /usr/bin/awk '
        /AppleClamshellState/ { print ($NF == "Yes" ? "closed" : "open"); exit }
    ')"
    LID_STATE="${LID_STATE:-open}"
    if [ "$LID_STATE" != "$LAST_LID_STATE" ]; then
        if [ "$LID_STATE" = "closed" ]; then
            /usr/bin/pmset -a powermode 1 >/dev/null 2>&1 || true
        else
            /usr/bin/pmset -b powermode "$ORIGINAL_BATTERY_MODE" >/dev/null 2>&1 || true
            /usr/bin/pmset -c powermode "$ORIGINAL_AC_MODE" >/dev/null 2>&1 || true
        fi
        LAST_LID_STATE="$LID_STATE"
    fi
    /bin/sleep 2
done

exit 0
