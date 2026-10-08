# Generates a FAKE patient access log (access_log.csv) with suspicious events planted in it.
# Uses a fixed seed and "w" mode, so every run produces the same file.

import csv
import os
import random
import datetime

random.seed(42)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_FILE = os.path.join(HERE, "access_log.csv")

USERS = [
    ("akhan",  "nurse"),
    ("mlee",   "nurse"),
    ("drpatel", "doctor"),
    ("drsmith", "doctor"),
    ("jsmith", "billing"),
    ("tgreen", "billing"),
]

ACTIONS_BY_ROLE = {
    "nurse":   ["view_chart", "update_chart"],
    "doctor":  ["view_chart", "update_chart", "prescribe"],
    "billing": ["view_billing"],
}

PATIENTS = [f"P-{n}" for n in range(1001, 1061)]
DAY = datetime.datetime(2026, 10, 4)

rows = []


def add(ts, user, role, patient, action, success="True"):
    rows.append([ts.strftime("%Y-%m-%d %H:%M:%S"), user, role, patient, action, success])


# --- Normal activity: business hours, allowed actions, a few records each ---
for _ in range(60):
    user, role = random.choice(USERS)
    ts = DAY + datetime.timedelta(hours=random.randint(8, 17), minutes=random.randint(0, 59))
    add(ts, user, role, random.choice(PATIENTS), random.choice(ACTIONS_BY_ROLE[role]))

# --- Planted suspicious events ---

# 1. Role violation: billing clerk opens a clinical chart (HIGH)
add(DAY + datetime.timedelta(hours=10, minutes=5), "jsmith", "billing", "P-1042", "view_chart")

# 2. After-hours access at 3 AM (MEDIUM)
add(DAY + datetime.timedelta(hours=3, minutes=12), "akhan", "nurse", "P-1018", "view_chart")

# 3. Excessive access: one nurse opens 25 different records in one hour (MEDIUM)
for i in range(25):
    add(DAY + datetime.timedelta(hours=14, minutes=i), "mlee", "nurse", PATIENTS[i], "view_chart")

# 4. Three failed logins in a row (HIGH)
for m in (0, 2, 4):
    add(DAY + datetime.timedelta(hours=9, minutes=m), "tgreen", "billing", "-", "login", "False")

# A normal successful login too, so the data isn't all attacks
add(DAY + datetime.timedelta(hours=9, minutes=10), "tgreen", "billing", "-", "login", "True")

rows.sort(key=lambda r: r[0])

with open(OUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "user_id", "role", "patient_id", "action", "success"])
    writer.writerows(rows)

print(f"Wrote {len(rows)} rows to {OUT_FILE}")
