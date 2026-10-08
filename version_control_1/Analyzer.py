# Patient Data Access Log Analyzer
# Reads access_log.csv (FAKE data only) and flags suspicious activity.
# Expected columns: timestamp, user_id, role, patient_id, action, success

# ---------- 1. IMPORTS ----------
import csv
import os
from collections import Counter, defaultdict
from datetime import datetime

# ---------- 2. RULES (edit these to tune detection) ----------

# What each role is allowed to do
ALLOWED_ACTIONS = {
    "nurse":   {"view_chart", "update_chart"},
    "doctor":  {"view_chart", "update_chart", "prescribe"},
    "billing": {"view_billing"},
}

# Normal working hours (24-hour clock): 7 AM to 7 PM
BUSINESS_HOURS = (7, 19)

# More distinct patient records than this in one hour is suspicious
MAX_RECORDS_PER_HOUR = 20

# This many failed logins in a row is suspicious
MAX_FAILED_LOGINS = 3

# Severity for each type of alert
SEVERITY = {
    "role_violation":   "HIGH",
    "after_hours":      "MEDIUM",
    "excessive_access": "MEDIUM",
    "failed_logins":    "HIGH",
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# Look for the CSV next to this script, no matter where you run it from
HERE = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(HERE, "access_log.csv")
REPORT_FILE = os.path.join(HERE, "report.txt")


# ---------- 3. HELPERS ----------

def parse_time(text):
    """Turn '2026-10-04 03:12:00' or '2026-10-04T03:12:00' into a datetime."""
    return datetime.fromisoformat(text.strip())


def is_failure(row):
    """True if the 'success' column says the action failed."""
    return row["success"].strip().lower() in ("false", "no", "0", "n", "failed")


def make_alert(kind, row_time, message):
    return {
        "type": kind,
        "severity": SEVERITY[kind],
        "message": message,
        "time": row_time,
    }


# ---------- 4. DETECTORS ----------

def check_role_violation(rows):
    alerts = []
    for row in rows:
        if row["action"] == "login":      # logins aren't role-specific
            continue
        allowed = ALLOWED_ACTIONS.get(row["role"], set())   # unknown role = nothing allowed
        if row["action"] not in allowed:
            alerts.append(make_alert(
                "role_violation",
                row["timestamp"],
                f"{row['user_id']} ({row['role']}) did '{row['action']}' on {row['patient_id']}",
            ))
    return alerts


def check_after_hours(rows):
    alerts = []
    start, end = BUSINESS_HOURS
    for row in rows:
        if row["action"] == "login":
            continue
        hour = parse_time(row["timestamp"]).hour
        if hour < start or hour >= end:
            alerts.append(make_alert(
                "after_hours",
                row["timestamp"],
                f"{row['user_id']} accessed {row['patient_id']} at {hour}:00",
            ))
    return alerts


def check_volume(rows):
    # Collect the distinct patients each user touched in each hour
    seen = defaultdict(set)
    for row in rows:
        if row["action"] == "login":
            continue
        t = parse_time(row["timestamp"])
        key = (row["user_id"], t.strftime("%Y-%m-%d %H:00"))
        seen[key].add(row["patient_id"])

    alerts = []
    for (user, hour_label), patients in seen.items():
        if len(patients) > MAX_RECORDS_PER_HOUR:
            alerts.append(make_alert(
                "excessive_access",
                hour_label + ":00",
                f"{user} viewed {len(patients)} different records in one hour",
            ))
    return alerts


def check_failed_logins(rows):
    # Go through each user's login attempts in time order
    logins = defaultdict(list)
    for row in rows:
        if row["action"] == "login":
            logins[row["user_id"]].append(row)

    alerts = []
    for user, attempts in logins.items():
        attempts.sort(key=lambda r: parse_time(r["timestamp"]))
        streak = 0
        for row in attempts:
            if is_failure(row):
                streak += 1
                if streak == MAX_FAILED_LOGINS:     # alert once per streak
                    alerts.append(make_alert(
                        "failed_logins",
                        row["timestamp"],
                        f"{user} had {MAX_FAILED_LOGINS} failed logins in a row",
                    ))
            else:
                streak = 0
    return alerts


# Add new detectors to this list and they plug into the report automatically
DETECTORS = [
    check_role_violation,
    check_after_hours,
    check_volume,
    check_failed_logins,
]


# ---------- 5. REPORT ----------

def build_report(alerts):
    alerts = sorted(alerts, key=lambda a: (SEVERITY_ORDER[a["severity"]], a["time"]))

    lines = []
    lines.append("=" * 60)
    lines.append("PATIENT DATA ACCESS AUDIT REPORT")
    lines.append(f"Generated: {datetime.now():%Y-%m-%d %H:%M}")
    lines.append("=" * 60)

    counts = Counter(a["severity"] for a in alerts)
    lines.append(f"Total alerts: {len(alerts)}")
    for level in ("HIGH", "MEDIUM", "LOW"):
        lines.append(f"  {level}: {counts.get(level, 0)}")
    lines.append("-" * 60)

    for a in alerts:
        lines.append(f"[{a['severity']:<6}] {a['time']}  {a['message']}")

    if not alerts:
        lines.append("No suspicious activity found.")

    return "\n".join(lines)


# ---------- 6. MAIN ----------

def main():
    if not os.path.exists(LOG_FILE):
        print(f"Could not find {LOG_FILE}")
        print("Create access_log.csv in the same folder as Analyzer.py.")
        return

    with open(LOG_FILE, newline="") as f:
        rows = list(csv.DictReader(f))
    print(f"Loaded {len(rows)} log rows")

    all_alerts = []
    for detector in DETECTORS:
        all_alerts.extend(detector(rows))

    report = build_report(all_alerts)
    print(report)

    with open(REPORT_FILE, "w") as f:
        f.write(report)
    print(f"\nSaved to {REPORT_FILE}")


if __name__ == "__main__":
    main()
