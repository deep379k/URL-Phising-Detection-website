# from flask import Flask, request, render_template, url_for
# import pickle
# import numpy as np
# import json
# import requests

# app = Flask(__name__)
# with open('Phishing_model.pkl', 'rb') as file:
#     model = pickle.load(file)

# @app.route("/")
# def f():
#     return render_template("index.html")

# @app.route("/inspect")
# def inspect():
#     return render_template("inspect.html")


# @app.route("/output", methods=["GET", "POST"])
# def output():
#     if request.method == 'POST':
#         var1 = request.form["UsingIP"]
#         var2 = request.form["PrefixSuffix-"]
#         var3 = request.form["SubDomains"]
#         var4 = request.form["HTTPS"]
#         var5 = request.form["NonStdPort"]
#         var6 = request.form["HTTPSDomainURL"]
#         var7 = request.form["RequestURL"]
#         var8 = request.form["AnchorURL"]
#         var9 = request.form["LinksInScriptTags"]
#         var10 = request.form["ServerFormHandler"]
#         var11 = request.form["InfoEmail"]
#         var12 = request.form["AbnormalURL"]
#         var13 = request.form["WebsiteForwarding"]
#         var14 = request.form["StatusBarCust"]
#         var15 = request.form["DisableRightClick"]
#         var16 = request.form["AgeofDomain"]
#         var17 = request.form["DNSRecording"]
#         var18 = request.form["WebsiteTraffic"]
#         var19 = request.form["PageRank"]
#         var20 = request.form["GoogleIndex"]
#         var21 = request.form["StatsReport"]

#         # Convert the input data into a numpy array
#         predict_data = np.array([var1, var2, var3, var4, var5, var6, var7, var8, var9, var10, 
#                                  var11, var12,var13,var14,var15,var16,var17,var18,var19,var20,var21]).reshape(1, -1)
#         # Use the loaded model to make predictions
#         predict = model.predict(predict_data)

#         if (predict == 1):
#             return render_template('output.html', predict="safe")
#         elif (predict == -1):
#             return render_template('output.html', predict= "Not safe")
#         else:
#             return render_template('output.html', predict="Suspicious")
#     return render_template("output.html")

# if __name__ == "__main__":
#     app.run(debug=False)


from pathlib import Path
from functools import wraps
import os
import secrets

from flask import Flask, request, render_template, jsonify, redirect, send_from_directory
from dotenv import load_dotenv
import pickle
import numpy as np
import pandas as pd
from werkzeug.security import check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from database import (
    configure_database,
    initialize_database,
    record_email_scan,
    record_message_scan,
    record_url_scan,
)
from services.analytics import overview, recent_scans, trends
from services.email_analysis import InvalidEmail, analyze_email
from services.message_prediction import InvalidMessage, MessagePredictionService
from services.url_prediction import URLPredictionService
from url_features import InvalidURL

BACKEND_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_ROOT.parent
load_dotenv(PROJECT_ROOT / ".env")
FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"
app = Flask(
    __name__,
    static_folder=str(FRONTEND_DIST),
    static_url_path="",
    template_folder=str(PROJECT_ROOT / "templates"),
)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true",
    ADMIN_USERNAME=os.getenv("ADMIN_USERNAME", "admin"),
    ADMIN_PASSWORD_HASH=os.getenv("ADMIN_PASSWORD_HASH", ""),
)
if os.getenv("TRUST_PROXY", "false").lower() == "true":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
    default_limits=[],
    meta_limits=["20/hour"],
)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' "
        "https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    )
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(429)
def rate_limit_exceeded(_error):
    return jsonify({"success": False, "error": "Too many requests. Please wait and try again."}), 429
configure_database(app)

try:
    url_prediction_service = URLPredictionService()
    url_model_error = None
except Exception as exc:
    url_prediction_service = None
    url_model_error = str(exc)

try:
    message_prediction_service = MessagePredictionService()
    message_model_error = None
except Exception as exc:
    message_prediction_service = None
    message_model_error = str(exc)

# Keep the original model available only for the legacy manual feature form.
try:
    with (PROJECT_ROOT / "Phishing_model.pkl").open("rb") as file:
        legacy_model = pickle.load(file)
    legacy_model_error = None
except Exception as exc:
    # The legacy notebook model may have been serialized by an older
    # scikit-learn release. It must never prevent the primary scanners or
    # health endpoint from starting in production.
    legacy_model = None
    legacy_model_error = str(exc)

initialize_database(app)

LEGACY_URL_FEATURES = [
    "UsingIP", "PrefixSuffix-", "SubDomains", "HTTPS", "NonStdPort",
    "HTTPSDomainURL", "RequestURL", "AnchorURL", "LinksInScriptTags",
    "ServerFormHandler", "InfoEmail", "AbnormalURL", "WebsiteForwarding",
    "StatusBarCust", "DisableRightClick", "AgeofDomain", "DNSRecording",
    "WebsiteTraffic", "PageRank", "GoogleIndex", "StatsReport",
]


def require_admin(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        from flask import session
        if not session.get("admin_authenticated"):
            return jsonify({"success": False, "error": "Admin authentication required."}), 401
        return view(*args, **kwargs)
    return wrapped


@app.post("/api/admin/login")
@limiter.limit("10/minute")
def admin_login():
    from flask import session
    if not request.is_json:
        return jsonify({"success": False, "error": "Request body must be JSON."}), 415
    password_hash = app.config.get("ADMIN_PASSWORD_HASH", "")
    if not password_hash:
        return jsonify({"success": False, "error": "Admin credentials are not configured."}), 503
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", ""))
    password = str(payload.get("password", ""))
    valid_username = secrets.compare_digest(username, app.config["ADMIN_USERNAME"])
    valid_password = check_password_hash(password_hash, password)
    if not (valid_username and valid_password):
        return jsonify({"success": False, "error": "Invalid username or password."}), 401
    session.clear()
    session["admin_authenticated"] = True
    return jsonify({"success": True, "username": username})


@app.get("/api/admin/session")
def admin_session():
    from flask import session
    return jsonify({"success": True, "authenticated": bool(session.get("admin_authenticated"))})


@app.post("/api/admin/logout")
@limiter.limit("30/minute")
def admin_logout():
    from flask import session
    session.clear()
    return jsonify({"success": True})

@app.route("/")
def home():
    if (FRONTEND_DIST / "index.html").exists():
        return send_from_directory(FRONTEND_DIST, "index.html")
    return render_template("index.html")

@app.route("/inspect")
def inspect():
    return redirect("/scanner/url", code=302)


@app.get("/admin")
def admin_dashboard():
    if (FRONTEND_DIST / "index.html").exists():
        return send_from_directory(FRONTEND_DIST, "index.html")
    return render_template("admin.html")


@app.get("/scanner/<path:scanner_path>")
def scanner_frontend(scanner_path):
    if (FRONTEND_DIST / "index.html").exists():
        return send_from_directory(FRONTEND_DIST, "index.html")
    return redirect("/inspect", code=302)

@app.route("/output", methods=["GET", "POST"])
def output():
    if request.method == 'POST':
        try:
            # Get form data and convert to integers
            var1 = int(request.form.get("UsingIP", 0))
            var2 = int(request.form.get("PrefixSuffix-", 0))
            var3 = int(request.form.get("SubDomains", 0))
            var4 = int(request.form.get("HTTPS", 0))
            var5 = int(request.form.get("NonStdPort", 0))
            var6 = int(request.form.get("HTTPSDomainURL", 0))
            var7 = int(request.form.get("RequestURL", 0))
            var8 = int(request.form.get("AnchorURL", 0))
            var9 = int(request.form.get("LinksInScriptTags", 0))
            var10 = int(request.form.get("ServerFormHandler", 0))
            var11 = int(request.form.get("InfoEmail", 0))
            var12 = int(request.form.get("AbnormalURL", 0))
            var13 = int(request.form.get("WebsiteForwarding", 0))
            var14 = int(request.form.get("StatusBarCust", 0))
            var15 = int(request.form.get("DisableRightClick", 0))
            var16 = int(request.form.get("AgeofDomain", 0))
            var17 = int(request.form.get("DNSRecording", 0))
            var18 = int(request.form.get("WebsiteTraffic", 0))
            var19 = int(request.form.get("PageRank", 0))
            var20 = int(request.form.get("GoogleIndex", 0))
            var21 = int(request.form.get("StatsReport", 0))

            # Convert the input data into a numpy array
            predict_data = np.array([var1, var2, var3, var4, var5, var6, var7, var8, var9, var10, 
                                     var11, var12, var13, var14, var15, var16, var17, var18, var19, var20, var21]).reshape(1, -1)
            
            # Use the loaded model to make predictions
            if legacy_model is None:
                raise RuntimeError("Legacy model is unavailable.")
            predict = legacy_model.predict(predict_data)[0]

            if predict == 1:
                result = "Safe"
            elif predict == -1:
                result = "Not Safe"
            else:
                result = "Suspicious"
            
            return render_template('output.html', predict=result)
        except Exception as e:
            return render_template('output.html', predict=f"Error: {str(e)}")
    
    return render_template("output.html")

def _predict_url_response():
    if not request.is_json:
        return jsonify({"success": False, "error": "Request body must be JSON."}), 415
    payload = request.get_json(silent=True) or {}
    if url_prediction_service is None:
        return jsonify({"success": False, "error": "URL model is unavailable."}), 503
    try:
        result = url_prediction_service.predict(
            payload.get("url", ""),
            live_checks=payload.get("live_checks") is True,
        )
    except InvalidURL as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception:
        app.logger.exception("URL prediction failed")
        return jsonify({"success": False, "error": "URL analysis failed."}), 500
    if app.config.get("DATABASE_CONNECTED"):
        try:
            record_url_scan(result)
        except Exception:
            app.logger.exception("Could not store URL scan")
            from database import db

            db.session.rollback()
    return jsonify({
        "success": True,
        "stored": bool(app.config.get("DATABASE_CONNECTED")),
        **result,
    })


@app.post("/api/predict/url")
@limiter.limit("120/minute")
def predict_url():
    return _predict_url_response()


@app.post("/api/predict/url/manual")
@limiter.limit("20/minute")
def predict_url_manual():
    if not request.is_json:
        return jsonify({"success": False, "error": "Request body must be JSON."}), 415
    if legacy_model is None:
        return jsonify({"success": False, "error": "Manual feature model is unavailable."}), 503

    payload = request.get_json(silent=True) or {}
    feature_values = payload.get("features")
    if not isinstance(feature_values, dict):
        return jsonify({"success": False, "error": "A features object is required."}), 400

    values = []
    for feature_name in LEGACY_URL_FEATURES:
        try:
            value = int(feature_values[feature_name])
        except (KeyError, TypeError, ValueError):
            return jsonify({"success": False, "error": f"{feature_name} must be -1, 0, or 1."}), 400
        if value not in {-1, 0, 1}:
            return jsonify({"success": False, "error": f"{feature_name} must be -1, 0, or 1."}), 400
        values.append(value)

    feature_frame = pd.DataFrame([values], columns=LEGACY_URL_FEATURES)
    predicted_class = int(legacy_model.predict(feature_frame)[0])
    prediction = "Likely Legitimate" if predicted_class == 1 else (
        "Potential Phishing" if predicted_class == -1 else "Suspicious"
    )
    risk_level = "Low" if predicted_class == 1 else ("High" if predicted_class == -1 else "Medium")
    return jsonify({
        "success": True,
        "prediction": prediction,
        "risk_level": risk_level,
        "analysis_source": "legacy-manual-feature-model",
        "model_name": type(legacy_model).__name__,
        "feature_count": len(values),
        "disclaimer": "This result depends entirely on the manually supplied feature values.",
    })


@app.post("/api/predict/message")
@limiter.limit("20/minute")
def predict_message():
    if not request.is_json:
        return jsonify({"success": False, "error": "Request body must be JSON."}), 415
    if message_prediction_service is None:
        return jsonify({"success": False, "error": "Message model is unavailable."}), 503
    payload = request.get_json(silent=True) or {}
    raw_message = payload.get("message", "")
    try:
        result = message_prediction_service.predict(raw_message, url_prediction_service)
    except InvalidMessage as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception:
        app.logger.exception("Message prediction failed")
        return jsonify({"success": False, "error": "Message analysis failed."}), 500

    if app.config.get("DATABASE_CONNECTED"):
        try:
            record_message_scan(result, len(str(raw_message)))
        except Exception:
            app.logger.exception("Could not store message scan")
            from database import db

            db.session.rollback()
    return jsonify({"success": True, "stored": bool(app.config.get("DATABASE_CONNECTED")), **result})


@app.post("/api/predict/email")
@limiter.limit("15/minute")
def predict_email():
    if not request.is_json:
        return jsonify({"success": False, "error": "Request body must be JSON."}), 415
    if message_prediction_service is None or url_prediction_service is None:
        return jsonify({"success": False, "error": "Email analysis services are unavailable."}), 503
    payload = request.get_json(silent=True) or {}
    raw_email = payload.get("email", "")
    try:
        result = analyze_email(raw_email, message_prediction_service, url_prediction_service)
    except InvalidEmail as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception:
        app.logger.exception("Email analysis failed")
        return jsonify({"success": False, "error": "Email analysis failed."}), 500

    if app.config.get("DATABASE_CONNECTED"):
        try:
            record_email_scan(result, len(str(raw_email)))
        except Exception:
            app.logger.exception("Could not store email scan")
            from database import db

            db.session.rollback()
    return jsonify({"success": True, "stored": bool(app.config.get("DATABASE_CONNECTED")), **result})


@app.post("/analyze_url")
@limiter.limit("30/minute")
def analyze_url_endpoint():
    """Compatibility endpoint for the existing scanner UI."""
    response = _predict_url_response()
    if isinstance(response, tuple):
        return response
    data = response.get_json()
    if data.get("success"):
        data["prediction"] = "Not Safe" if data["prediction"] == "Potential Phishing" else "Safe"
        response.set_data(app.json.dumps(data))
    return response


@app.get("/api/model-metrics")
def model_metrics():
    if url_prediction_service is None and message_prediction_service is None:
        return jsonify({"success": False, "error": "Model metrics are unavailable."}), 503
    return jsonify({
        "success": True,
        "url": url_prediction_service.metrics if url_prediction_service else None,
        "message": message_prediction_service.metrics if message_prediction_service else None,
    })


def _analytics_unavailable():
    return jsonify({
        "success": True,
        "database_connected": False,
        "message": "Configure MySQL to enable persistent analytics.",
        "data": None,
    })


@app.get("/api/analytics/overview")
@require_admin
def analytics_overview():
    if not app.config.get("DATABASE_CONNECTED"):
        return _analytics_unavailable()
    return jsonify({"success": True, "database_connected": True, "data": overview()})


@app.get("/api/analytics/trends")
@require_admin
def analytics_trends():
    if not app.config.get("DATABASE_CONNECTED"):
        return _analytics_unavailable()
    try:
        days = int(request.args.get("days", 30))
    except ValueError:
        return jsonify({"success": False, "error": "days must be a number."}), 400
    return jsonify({"success": True, "database_connected": True, "data": trends(days)})


@app.get("/api/analytics/recent")
@require_admin
def analytics_recent():
    if not app.config.get("DATABASE_CONNECTED"):
        return _analytics_unavailable()
    try:
        limit = int(request.args.get("limit", 10))
    except ValueError:
        return jsonify({"success": False, "error": "limit must be a number."}), 400
    return jsonify({"success": True, "database_connected": True, "data": recent_scans(limit)})


@app.get("/api/health")
def health():
    healthy = url_prediction_service is not None and message_prediction_service is not None
    payload = {
        "success": healthy,
        "status": "healthy" if healthy else "degraded",
        "url_model_loaded": url_prediction_service is not None,
        "message_model_loaded": message_prediction_service is not None,
        "database_configured": bool(app.config.get("DATABASE_ENABLED")),
        "database_connected": bool(app.config.get("DATABASE_CONNECTED")),
    }
    if not healthy and app.debug:
        payload["detail"] = url_model_error
    return jsonify(payload), 200 if healthy else 503

if __name__ == "__main__":
    print("Starting Flask server...")
    # Disable the reloader so the process doesn't exit and restart under the dev server
    app.run(debug=False, port=5000, use_reloader=False)
    
    
