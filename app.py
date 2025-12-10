import os
import csv
import json
import base64
import tempfile

import requests
from dotenv import load_dotenv
from flask import Flask, render_template, request

load_dotenv()

CLIENT_ID     = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
API_BASE      = os.getenv("API_BASE", "https://api.ramp.com")
SCOPES        = os.getenv(
    "SCOPES",
    "limits:write cards:read cards:write transactions:read users:read"
)
OWNER_USER_ID = os.getenv("OWNER_USER_ID")
ENTITY_ID     = os.getenv("ENTITY_ID")

# MAP_FILE = "card_limits_map.csv"

app = Flask(__name__)

LOGIN_EMAIL = "hello@digitechio.com"
LOGIN_PASSWORD = "abarakarabadra09003493$"


def check_credentials(req):
    email = (req.form.get("email") or "").strip()
    password = (req.form.get("password") or "").strip()

    if email != LOGIN_EMAIL or password != LOGIN_PASSWORD:
        return False, "Invalid email or password"
    return True, None
class RampClient:
    def __init__(self):
        if not CLIENT_ID or not CLIENT_SECRET:
            raise ValueError("CLIENT_ID / CLIENT_SECRET missing")

        if not ENTITY_ID:
            raise ValueError("ENTITY_ID missing in .env (required for virtual cards)")

        print(f"Using Client ID: {CLIENT_ID[:12]}...")
        print(f"Using ENTITY_ID: {ENTITY_ID}")
        self.token = self._get_token()
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Client-Id": CLIENT_ID,
        }

    def _get_token(self):
        token_url = f"{API_BASE}/developer/v1/token"

        raw_pair = f"{CLIENT_ID}:{CLIENT_SECRET}"
        basic_auth = base64.b64encode(raw_pair.encode()).decode()

        headers = {
            "Authorization": f"Basic {basic_auth}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data = {
            "grant_type": "client_credentials",
            "scope": SCOPES
        }

        print("Requesting Access Token...")
        r = requests.post(token_url, headers=headers, data=data)
        print("Token Status:", r.status_code)
        print("Token Body:", r.text)
        r.raise_for_status()

        token = r.json().get("access_token")
        if not token:
            raise RuntimeError("No access_token in token response")
        return token

    def create_card(self, display_name: str, amount_usd: float, user_id: str):

        url = f"{API_BASE}/developer/v1/cards/deferred/virtual"

        # FIX: amount in cents
        amount_cents = int(amount_usd)

        payload = {
            "display_name": display_name,
            "entity_id": ENTITY_ID,
            "idempotency_key": os.urandom(16).hex(),
            "spending_restrictions": {
                "amount": amount_cents,
                "categories": [],
                "currency": "USD",
                "interval": "TOTAL",
                "transaction_amount_limit": amount_cents,
            },
            "user_id": user_id
        }

        print(f"\n[CREATE VIRTUAL] {display_name} | ${amount_usd} | user={user_id}")
        print("POST", url)
        print("Payload:", json.dumps(payload))

        r = requests.post(url, headers=self.headers, json=payload)
        print("Status:", r.status_code)
        print("Response:", r.text)
        return r


    def patch_limit_amount(self, limit_id: str, new_amount_usd: float):
        url = f"{API_BASE}/developer/v1/limits/{limit_id}"

        payload = {
            "spending_restrictions": {
                "interval": "TOTAL",
                "limit": {
                    "amount": int(new_amount_usd * 100),
                    "currency_code": "USD",
                }
            }
        }

        print(f"\n[UPDATE] limit {limit_id} -> ${new_amount_usd}")
        print("PATCH", url)
        print("Payload:", json.dumps(payload))

        r = requests.patch(url, headers=self.headers, json=payload)
        print("Status:", r.status_code)
        print("Response:", r.text)
        return r

    def terminate_limit(self, limit_id: str):
        """
        Terminate/disable a limit (and its virtual card).
        NOTE: this does not remove it from Ramp UI; it just disables it.
        """
        url = f"{API_BASE}/developer/v1/limits/{limit_id}/terminate"

        print(f"\n[DELETE] Terminating limit {limit_id}")
        print("POST", url)

        r = requests.post(url, headers=self.headers, json={})
        print("Status:", r.status_code)
        print("Response:", r.text)
        return r

    def resolve_limit_from_task(self, task_id: str) -> str:
        """
        Convert deferred task id -> real spend_limit / limit id.
        """
        status_url = f"{API_BASE}/developer/v1/limits/deferred/status/{task_id}"
        print(f"\nResolving deferred task: {task_id}")
        print("GET", status_url)

        r = requests.get(status_url, headers=self.headers)
        print("Status (status endpoint):", r.status_code)
        print("Body (status endpoint):", r.text)
        r.raise_for_status()

        data = r.json()

        limit_id = None

        # prefer nested data.spend_limit_id if present
        if isinstance(data.get("data"), dict):
            limit_id = data["data"].get("spend_limit_id") or data["data"].get("limit_id")

        if not limit_id:
            # fallback to top-level keys if Ramp changes response shape
            limit_id = data.get("spend_limit_id") or data.get("limit_id")

        if not limit_id:
            print("⚠ Could not automatically find limit_id in deferred status JSON.")
            print("Full JSON for manual inspection:")
            print(json.dumps(data, indent=2))
            raise RuntimeError("Could not determine limit_id from deferred task status.")

        print(f"✔ Resolved limit_id for task {task_id}: {limit_id}")
        return limit_id

    def list_limits(self):
        """
        Fetch all limits from Ramp and return as a list.
        We'll use this to map display_name -> limit_id when updating.
        """
        url = f"{API_BASE}/developer/v1/limits"
        print("\n[LIST LIMITS] GET", url)

        r = requests.get(
            url,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                "Client-Id": CLIENT_ID,
            },
        )
        print("Status (list_limits):", r.status_code)
        print("Response (list_limits):", r.text)
        r.raise_for_status()

        body = r.json()
        return body.get("data", [])

# def load_mapping(map_file: str) -> dict:
#     """
#     Load display_name -> limit_id mapping from CSV.
#     """
#     mapping = {}
#     if not os.path.exists(map_file):
#         return mapping

#     with open(map_file, "r", newline="", encoding="utf-8") as f:
#         reader = csv.DictReader(f)
#         for row in reader:
#             name = (row.get("display_name") or "").strip()
#             lim  = (row.get("limit_id") or "").strip()
#             if name and lim:
#                 mapping[name] = lim
#     return mapping

# def save_mapping(map_file: str, mapping: dict):
#     """
#     Save display_name -> limit_id mapping back to CSV.
#     """
#     with open(map_file, "w", newline="", encoding="utf-8") as f:
#         writer = csv.writer(f)
#         writer.writerow(["display_name", "limit_id"])
#         for name, lim in mapping.items():
#             writer.writerow([name, lim])


@app.route("/", methods=["GET", "POST"])
def login():
    """
    Simple login page. No session management.
    - GET: show login form
    - POST: check credentials; if OK, render the main index.html panel
    """
    if request.method == "POST":
        ok, err = check_credentials(request)
        if not ok:
            return render_template("login.html", error=err)
        return render_template("index.html")

    return render_template("login.html")

# @app.route("/create-list", methods=["POST"])
# def create_list():
#     try:
#         if not OWNER_USER_ID:
#             return "OWNER_USER_ID missing in .env"

#         amount_str = (request.form.get("amount_usd") or "").strip()
#         if not amount_str:
#             return "Amount (USD) is required."

#         try:
#             amount_usd = float(amount_str)
#         except ValueError:
#             return f"Invalid amount_usd value: {amount_str}"

#         lines_text = (request.form.get("display_names") or "").strip()
#         if not lines_text:
#             return "No display names provided. Please paste at least one line."

#         ramp = RampClient()
#         results = []

#         mapping = load_mapping(MAP_FILE)
#         map_exists = os.path.exists(MAP_FILE)
#         map_f = open(MAP_FILE, "a", newline="", encoding="utf-8")
#         map_writer = csv.writer(map_f)
#         if not map_exists:
#             map_writer.writerow(["display_name", "limit_id"])

#         for raw_line in lines_text.splitlines():
#             display_name = raw_line.strip()
#             if not display_name:
#                 continue

#             resp = ramp.create_card(display_name, amount_usd, OWNER_USER_ID)
#             success = resp.status_code in (200, 201, 202)
#             stored_id = None

#             if success:
#                 try:
#                     body = resp.json()
#                     print("Create body parsed:", body)

#                     # 1) Try to read a direct limit id if Ramp returns it
#                     stored_id = (
#                         body.get("spend_limit_id")
#                         or body.get("limit_id")
#                     )

#                     if not stored_id and isinstance(body.get("data"), dict):
#                         stored_id = (
#                             body["data"].get("spend_limit_id")
#                             or body["data"].get("limit_id")
#                         )

#                     # 2) If we STILL don't have a limit_id, we probably only have a deferred task_id
#                     if not stored_id:
#                         task_id = (
#                             body.get("id")
#                             or (isinstance(body.get("data"), dict) and body["data"].get("id"))
#                         )
#                         if task_id:
#                             try:
#                                 # This calls /limits/deferred/status/{task_id}
#                                 stored_id = ramp.resolve_limit_from_task(task_id)
#                             except Exception as e:
#                                 print("Could not resolve task -> limit_id:", e)

#                     if stored_id:
#                         mapping[display_name] = stored_id
#                         map_writer.writerow([display_name, stored_id])
#                     else:
#                         print(f"⚠ No limit_id found for {display_name} in create response")

#                 except Exception as e:
#                     print("Error parsing create response JSON:", e)

#             results.append({
#                 "display_name": display_name,
#                 "status": resp.status_code,
#                 "success": success,
#                 "response": resp.text
#             })

#         map_f.close()

#         return render_template("results.html", mode="create_list", results=results)

#     except Exception as e:
#         return f"Error (create list): {e}"

@app.route("/create-list", methods=["POST"])
def create_list():
    try:
        if not OWNER_USER_ID:
            return "OWNER_USER_ID missing in .env"

        amount_str = (request.form.get("amount_usd") or "").strip()
        if not amount_str:
            return "Amount (USD) is required."

        try:
            amount_usd = float(amount_str)
        except ValueError:
            return f"Invalid amount_usd value: {amount_str}"

        lines_text = (request.form.get("display_names") or "").strip()
        if not lines_text:
            return "No display names provided. Please paste at least one line."

        ramp = RampClient()
        results = []

        for raw_line in lines_text.splitlines():
            display_name = raw_line.strip()
            if not display_name:
                continue

            resp = ramp.create_card(display_name, amount_usd, OWNER_USER_ID)
            success = resp.status_code in (200, 201, 202)

            results.append({
                "display_name": display_name,
                "status": resp.status_code,
                "success": success,
                "response": resp.text
            })

        return render_template("results.html", mode="create_list", results=results)

    except Exception as e:
        return f"Error (create list): {e}"


# @app.route("/update-manual", methods=["POST"])
# def update_manual():
#     try:
#         amount_str = (request.form.get("amount_usd") or "").strip()
#         if not amount_str:
#             return "Amount (USD) is required."

#         try:
#             new_amount = float(amount_str)
#         except ValueError:
#             return f"Invalid amount value: {amount_str}"

#         lines_text = (request.form.get("lines") or "").strip()
#         if not lines_text:
#             return "No display names provided. Please enter at least one line."
# #
#         mapping = load_mapping(MAP_FILE)

#         ramp = RampClient()

#         all_limits = ramp.list_limits()
#         limits_by_name = {}
#         for lim in all_limits:
#             name = (lim.get("display_name") or "").strip()
#             lim_id = (lim.get("id") or "").strip()
#             if name and lim_id:
#                 limits_by_name[name] = lim_id

#         results = []

#         for raw_line in lines_text.splitlines():
#             display_name = raw_line.strip()
#             if not display_name or display_name.startswith("#"):
#                 continue

#             stored_id = limits_by_name.get(display_name) or mapping.get(display_name)

#             if not stored_id:
#                 results.append({
#                     "display_name": display_name,
#                     "status": None,
#                     "success": False,
#                     "response": f"No limit_id found for {display_name} in Ramp or mapping file"
#                 })
#                 continue
#             resp = ramp.patch_limit_amount(stored_id, new_amount)

#             if resp.status_code == 404 and "Limit does not exist" in resp.text:
#                 try:
#                     real_limit_id = ramp.resolve_limit_from_task(stored_id)
#                     resp2 = ramp.patch_limit_amount(real_limit_id, new_amount)

#                     results.append({
#                         "display_name": display_name,
#                         "status": resp2.status_code,
#                         "success": resp2.status_code in (200, 201, 202),
#                         "response": resp2.text
#                     })

#                     mapping[display_name] = real_limit_id
#                     continue

#                 except Exception as e:
#                     results.append({
#                         "display_name": display_name,
#                         "status": None,
#                         "success": False,
#                         "response": f"Could not resolve deferred task: {e}"
#                     })
#                     continue
#             results.append({
#                 "display_name": display_name,
#                 "status": resp.status_code,
#                 "success": resp.status_code in (200, 201, 202),
#                 "response": resp.text
#             })
#         return render_template("results.html", mode="update_manual", results=results)

#     except Exception as e:
#         return f"Error (update manual): {e}"

@app.route("/update-manual", methods=["POST"])
def update_manual():
    try:
        amount_str = (request.form.get("amount_usd") or "").strip()
        if not amount_str:
            return "Amount (USD) is required."

        try:
            new_amount = float(amount_str)
        except ValueError:
            return f"Invalid amount value: {amount_str}"

        lines_text = (request.form.get("lines") or "").strip()
        if not lines_text:
            return "No display names provided. Please enter at least one line."

        ramp = RampClient()

        # get all live limits from Ramp
        all_limits = ramp.list_limits()
        limits_by_name = {
            (lim.get("display_name") or "").strip(): (lim.get("id") or "").strip()
            for lim in all_limits
        }

        results = []

        for raw_line in lines_text.splitlines():
            display_name = raw_line.strip()
            if not display_name:
                continue

            stored_id = limits_by_name.get(display_name)

            if not stored_id:
                results.append({
                    "display_name": display_name,
                    "status": None,
                    "success": False,
                    "response": f"No limit_id found for {display_name} in Ramp"
                })
                continue

            resp = ramp.patch_limit_amount(stored_id, new_amount)

            results.append({
                "display_name": display_name,
                "status": resp.status_code,
                "success": resp.status_code in (200, 201, 202),
                "response": resp.text
            })

        return render_template("results.html", mode="update_manual", results=results)

    except Exception as e:
        return f"Error (update manual): {e}"


# if __name__ == "__main__":
#     app.run(host="192.168.18.25", port=5000, debug=True)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

