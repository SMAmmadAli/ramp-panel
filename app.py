import os
import json
import base64
import time
import requests
import pyotp
import firebase_admin
from firebase_admin import credentials, firestore
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session
from functools import wraps
from datetime import timedelta, datetime, timezone

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

TOTP_SECRET = os.getenv("TOTP_SECRET")

LOGIN_EMAIL = os.getenv("LOGIN_EMAIL")
LOGIN_PASSWORD = os.getenv("LOGIN_PASSWORD")

FIREBASE_KEY_PATH = os.path.join(os.path.dirname(__file__), "ramp_panel_firebase_key.json")

FIREBASE_SERVICE_ACCOUNT_B64 = os.getenv("FIREBASE_SERVICE_ACCOUNT_B64")
FIREBASE_SERVICE_ACCOUNT     = os.getenv("FIREBASE_SERVICE_ACCOUNT")

if not firebase_admin._apps:
    if FIREBASE_SERVICE_ACCOUNT_B64:
        decoded = base64.b64decode(FIREBASE_SERVICE_ACCOUNT_B64).decode("utf-8")
        service_account_info = json.loads(decoded)
        cred = credentials.Certificate(service_account_info)
    elif FIREBASE_SERVICE_ACCOUNT:
        service_account_info = json.loads(FIREBASE_SERVICE_ACCOUNT)
        cred = credentials.Certificate(service_account_info)
    else:
        cred = credentials.Certificate(FIREBASE_KEY_PATH)

    firebase_admin.initialize_app(cred)

db = firestore.client()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-this-secret-key")
app.permanent_session_lifetime = timedelta(minutes=30)


def check_credentials(req):
    email = (req.form.get("email") or "").strip()
    password = (req.form.get("password") or "").strip()

    if email != LOGIN_EMAIL or password != LOGIN_PASSWORD:
        return False, "Invalid email or password"
    return True, None


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


@app.before_request
def check_session_timeout():
    if session.get("authenticated"):
        now = time.time()
        last_active = session.get("last_active", now)
        if now - last_active > 30 * 60:
            session.clear()
            return redirect(url_for("login"))
        session["last_active"] = now


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
        print("-------------------------------------------------------------")
        r.raise_for_status()
        token = r.json().get("access_token")
        if not token:
            raise RuntimeError("No access_token in token response")
        return token

    def create_card(self, display_name: str, amount_usd: float, user_id: str):
        url = f"{API_BASE}/developer/v1/cards/deferred/virtual"
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

    def resolve_limit_from_task(self, task_id: str) -> str:
        status_url = f"{API_BASE}/developer/v1/limits/deferred/status/{task_id}"
        print(f"\nResolving deferred task: {task_id}")
        print("GET", status_url)
        r = requests.get(status_url, headers=self.headers)
        print("Status (status endpoint):", r.status_code)
        print("Body (status endpoint):", r.text)
        r.raise_for_status()
        data = r.json()
        limit_id = None
        if isinstance(data.get("data"), dict):
            limit_id = data["data"].get("spend_limit_id") or data["data"].get("limit_id")
        if not limit_id:
            limit_id = data.get("spend_limit_id") or data.get("limit_id")
        if not limit_id:
            print("Could not automatically find limit_id in deferred status JSON.")
            print("Full JSON for manual inspection:")
            print(json.dumps(data, indent=2))
            raise RuntimeError("Could not determine limit_id from deferred task status.")
        print(f"✔ Resolved limit_id for task {task_id}: {limit_id}")
        return limit_id

    def list_limits(self):
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


# @app.route("/", methods=["GET", "POST"])
# def login():
#     if request.method == "GET" and session.get("authenticated"):
#         return render_template("index.html")

#     if request.method == "POST":
#         ok, err = check_credentials(request)
#         if not ok:
#             return render_template("login.html", error=err)

#         if not TOTP_SECRET:
#             return render_template("login.html", error="TOTP secret not configured.")

#         session["totp_stage"] = "pending"
#         return render_template("2fa.html")

#     return render_template("login.html")


# @app.route("/verify-2fa", methods=["POST"])
# def verify_2fa():
#     user_code = (request.form.get("code") or "").strip()

#     if not TOTP_SECRET:
#         session.clear()
#         return render_template("login.html", error="TOTP secret not configured.")

#     totp = pyotp.TOTP(TOTP_SECRET)

#     if not totp.verify(user_code):
#         return render_template("2fa.html", error="Invalid or expired code. Try again.")

#     session["authenticated"] = True
#     session["last_active"] = time.time()
#     session.permanent = True
#     session.pop("totp_stage", None)

#     return render_template("index.html")


# @app.route("/logout")
# def logout():
#     session.clear()
#     return redirect(url_for("login"))


# @app.route("/create-list", methods=["POST"])
# @login_required
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

#         for raw_line in lines_text.splitlines():
#             display_name = raw_line.strip()
#             if not display_name:
#                 continue

#             resp = ramp.create_card(display_name, amount_usd, OWNER_USER_ID)
#             success = resp.status_code in (200, 201, 202)

#             activity_doc = {
#                 "action": "create_card",
#                 "display_name": display_name,
#                 "amount_usd": amount_usd,
#                 "user_id": OWNER_USER_ID,
#                 "status_code": resp.status_code,
#                 "success": success,
#                 "response_body": resp.text,
#                 "timestamp": firestore.SERVER_TIMESTAMP,
#             }
#             db.collection("card_activity").add(activity_doc)

#             results.append({
#                 "display_name": display_name,
#                 "status": resp.status_code,
#                 "success": success,
#                 "response": resp.text
#             })

#         return render_template("results.html", mode="create_list", results=results)
#     except Exception as e:
#         return f"Error (create list): {e}"

# @app.route("/update-manual", methods=["POST"])
# @login_required
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

#         ramp = RampClient()
#         all_limits = ramp.list_limits()
#         limits_by_name = {
#             (lim.get("display_name") or "").strip(): (lim.get("id") or "").strip()
#             for lim in all_limits
#         }

#         results = []
#         for raw_line in lines_text.splitlines():
#             display_name = raw_line.strip()
#             if not display_name:
#                 continue

#             stored_id = limits_by_name.get(display_name)
#             if not stored_id:
#                 results.append({
#                     "display_name": display_name,
#                     "status": None,
#                     "success": False,
#                     "response": f"No limit_id found for {display_name} in Ramp"
#                 })
#                 db.collection("card_activity").add({
#                     "action": "update_limit_not_found",
#                     "display_name": display_name,
#                     "amount_usd": new_amount,
#                     "limit_id": None,
#                     "status_code": None,
#                     "success": False,
#                     "response_body": "No limit_id found for this display_name in Ramp",
#                     "timestamp": firestore.SERVER_TIMESTAMP,
#                 })
#                 continue

#             resp = ramp.patch_limit_amount(stored_id, new_amount)
#             success = resp.status_code in (200, 201, 202)

#             activity_doc = {
#                 "action": "update_limit",
#                 "display_name": display_name,
#                 "amount_usd": new_amount,
#                 "limit_id": stored_id,
#                 "status_code": resp.status_code,
#                 "success": success,
#                 "response_body": resp.text,
#                 "timestamp": firestore.SERVER_TIMESTAMP,
#             }
#             db.collection("card_activity").add(activity_doc)

#             results.append({
#                 "display_name": display_name,
#                 "status": resp.status_code,
#                 "success": success,
#                 "response": resp.text
#             })

#         return render_template("results.html", mode="update_manual", results=results)
#     except Exception as e:
#         return f"Error (update manual): {e}"

# @app.route("/activity")
# @login_required
# def activity():
#     start_date_str = request.args.get("start_date")
#     end_date_str = request.args.get("end_date")    
#     search = (request.args.get("search") or "").strip().lower()
#     docs = db.collection("card_activity").stream()
#     activities = []
#     for doc in docs:
#         data = doc.to_dict() or {}
#         data["id"] = doc.id
#         ts = data.get("timestamp")
#         dt_obj = None
#         if ts is not None:
#             if isinstance(ts, datetime):
#                 dt_obj = ts
#             elif hasattr(ts, "to_datetime"):
#                 dt_obj = ts.to_datetime()
#             elif isinstance(ts, str):
#                 try:
#                     dt_obj = datetime.fromisoformat(ts)
#                 except ValueError:
#                     dt_obj = None
#         if isinstance(dt_obj, datetime) and dt_obj.tzinfo is not None:
#             dt_obj = dt_obj.astimezone(timezone.utc).replace(tzinfo=None)
#         data["dt_obj"] = dt_obj
#         data["timestamp_str"] = dt_obj.strftime("%Y-%m-%d %H:%M:%S") if dt_obj else ""
#         activities.append(data)
#     def in_date_range(item):
#         dt_obj = item.get("dt_obj")
#         if not dt_obj:
#             return True
#         if start_date_str:
#             try:
#                 start_dt = datetime.strptime(start_date_str, "%Y-%m-%d")
#                 if dt_obj < start_dt:
#                     return False
#             except ValueError:
#                 pass
#         if end_date_str:
#             try:
#                 end_dt = datetime.strptime(end_date_str, "%Y-%m-%d")
#                 end_dt_plus = end_dt + timedelta(days=1)
#                 if dt_obj >= end_dt_plus:
#                     return False
#             except ValueError:
#                 pass
#         return True
#     activities = [a for a in activities if in_date_range(a)]
#     if search:
#         filtered = []
#         for a in activities:
#             combined = " ".join([
#                 str(a.get("action", "")),
#                 str(a.get("display_name", "")),
#                 str(a.get("limit_id", "")),
#                 str(a.get("user_id", "")),
#                 str(a.get("status_code", "")),
#             ]).lower()
#             if search in combined:
#                 filtered.append(a)
#         activities = filtered
#     activities.sort(
#         key=lambda x: x.get("dt_obj") or datetime.min,
#         reverse=True
#     )
#     return render_template(
#         "activity.html",
#         activities=activities,
#         start_date=start_date_str or "",
#         end_date=end_date_str or "",
#         search=search or "",
#     )

# ---------- AUTH + MAIN ROUTES ----------

@app.route("/", methods=["GET", "POST"])
def login():
    # GET: show login OR redirect to panel if already logged in
    if request.method == "GET":
        if session.get("authenticated"):
            # Already authenticated -> go to main panel
            return redirect(url_for("panel"))
        return render_template("login.html")

    # POST: handle login form
    ok, err = check_credentials(request)
    if not ok:
        return render_template("login.html", error=err)

    if not TOTP_SECRET:
        return render_template("login.html", error="TOTP secret not configured.")

    # Show 2FA page
    session["totp_stage"] = "pending"
    return render_template("2fa.html")


@app.route("/verify-2fa", methods=["POST"])
def verify_2fa():
    user_code = (request.form.get("code") or "").strip()

    if not TOTP_SECRET:
        session.clear()
        return render_template("login.html", error="TOTP secret not configured.")

    totp = pyotp.TOTP(TOTP_SECRET)

    if not totp.verify(user_code):
        # Stay on 2FA page if wrong
        return render_template("2fa.html", error="Invalid or expired code. Try again.")

    # 2FA success
    session["authenticated"] = True
    session["last_active"] = time.time()
    session.permanent = True
    session.pop("totp_stage", None)

    # IMPORTANT: redirect to main panel (URL will become /panel, not /verify-2fa)
    return redirect(url_for("panel"))


@app.route("/panel")
@login_required
def panel():
    # This is your main index screen
    return render_template("index.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- CARD CREATION & UPDATE ROUTES ----------

@app.route("/create-list", methods=["POST"])
@login_required
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

            activity_doc = {
                "action": "create_card",
                "display_name": display_name,
                "amount_usd": amount_usd,
                "user_id": OWNER_USER_ID,
                "status_code": resp.status_code,
                "success": success,
                "response_body": resp.text,
                "timestamp": firestore.SERVER_TIMESTAMP,
            }
            db.collection("card_activity").add(activity_doc)

            results.append({
                "display_name": display_name,
                "status": resp.status_code,
                "success": success,
                "response": resp.text
            })

        return render_template("results.html", mode="create_list", results=results)
    except Exception as e:
        return f"Error (create list): {e}"


@app.route("/update-manual", methods=["POST"])
@login_required
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
                db.collection("card_activity").add({
                    "action": "update_limit_not_found",
                    "display_name": display_name,
                    "amount_usd": new_amount,
                    "limit_id": None,
                    "status_code": None,
                    "success": False,
                    "response_body": "No limit_id found for this display_name in Ramp",
                    "timestamp": firestore.SERVER_TIMESTAMP,
                })
                continue

            resp = ramp.patch_limit_amount(stored_id, new_amount)
            success = resp.status_code in (200, 201, 202)

            activity_doc = {
                "action": "update_limit",
                "display_name": display_name,
                "amount_usd": new_amount,
                "limit_id": stored_id,
                "status_code": resp.status_code,
                "success": success,
                "response_body": resp.text,
                "timestamp": firestore.SERVER_TIMESTAMP,
            }
            db.collection("card_activity").add(activity_doc)

            results.append({
                "display_name": display_name,
                "status": resp.status_code,
                "success": success,
                "response": resp.text
            })

        return render_template("results.html", mode="update_manual", results=results)
    except Exception as e:
        return f"Error (update manual): {e}"


# ---------- ACTIVITY ROUTE ----------

@app.route("/activity")
@login_required
def activity():
    start_date_str = request.args.get("start_date")
    end_date_str = request.args.get("end_date")
    search = (request.args.get("search") or "").strip().lower()

    docs = db.collection("card_activity").stream()
    activities = []

    for doc in docs:
        data = doc.to_dict() or {}
        data["id"] = doc.id

        ts = data.get("timestamp")
        dt_obj = None
        if ts is not None:
            if isinstance(ts, datetime):
                dt_obj = ts
            elif hasattr(ts, "to_datetime"):
                dt_obj = ts.to_datetime()
            elif isinstance(ts, str):
                try:
                    dt_obj = datetime.fromisoformat(ts)
                except ValueError:
                    dt_obj = None

        if isinstance(dt_obj, datetime) and dt_obj.tzinfo is not None:
            dt_obj = dt_obj.astimezone(timezone.utc).replace(tzinfo=None)

        data["dt_obj"] = dt_obj
        data["timestamp_str"] = dt_obj.strftime("%Y-%m-%d %H:%M:%S") if dt_obj else ""
        activities.append(data)

    def in_date_range(item):
        dt_obj = item.get("dt_obj")
        if not dt_obj:
            return True

        if start_date_str:
            try:
                start_dt = datetime.strptime(start_date_str, "%Y-%m-%d")
                if dt_obj < start_dt:
                    return False
            except ValueError:
                pass

        if end_date_str:
            try:
                end_dt = datetime.strptime(end_date_str, "%Y-%m-%d")
                end_dt_plus = end_dt + timedelta(days=1)
                if dt_obj >= end_dt_plus:
                    return False
            except ValueError:
                pass

        return True

    activities = [a for a in activities if in_date_range(a)]

    if search:
        filtered = []
        for a in activities:
            combined = " ".join([
                str(a.get("action", "")),
                str(a.get("display_name", "")),
                str(a.get("limit_id", "")),
                str(a.get("user_id", "")),
                str(a.get("status_code", "")),
            ]).lower()
            if search in combined:
                filtered.append(a)
        activities = filtered

    activities.sort(
        key=lambda x: x.get("dt_obj") or datetime.min,
        reverse=True
    )

    return render_template(
        "activity.html",
        activities=activities,
        start_date=start_date_str or "",
        end_date=end_date_str or "",
        search=search or "",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
