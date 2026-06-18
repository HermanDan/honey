"""
Flask Phishing Decoy — with MailHog MFA
"""

import os, json, uuid, time, random, string, smtplib, logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from flask import Flask, request, session, render_template, redirect, url_for
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

os.makedirs("/app/logs", exist_ok=True)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("honeypot")
log_handler = logging.FileHandler("/app/logs/flask.json")
log_handler.setLevel(logging.INFO)
logger.addHandler(log_handler)

def log_event(event):
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    event["sensor"] = "flask-phishing-decoy"
    line = json.dumps(event)
    logger.info(line)
    print(line, flush=True)

def get_db():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST","localhost"),
        port=os.environ.get("DB_PORT",5432),
        dbname=os.environ.get("DB_NAME","honeypot"),
        user=os.environ.get("DB_USER","honeypot"),
        password=os.environ.get("DB_PASSWORD","honeypot123"),
        cursor_factory=RealDictCursor,
    )

def db_log_session(data):
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("""
            INSERT INTO phishing_sessions
                (session_id,src_ip,user_agent,stage,username,password,
                 time_on_page_ms,typing_delay_ms,field_corrections,login_success)
            VALUES
                (%(session_id)s,%(src_ip)s,%(user_agent)s,%(stage)s,%(username)s,
                 %(password)s,%(time_on_page_ms)s,%(typing_delay_ms)s,
                 %(field_corrections)s,%(login_success)s)
            ON CONFLICT (session_id) DO UPDATE SET
                stage=EXCLUDED.stage, username=EXCLUDED.username,
                password=EXCLUDED.password, time_on_page_ms=EXCLUDED.time_on_page_ms,
                login_success=EXCLUDED.login_success
        """, data)
        conn.commit(); cur.close(); conn.close()
    except Exception as e:
        print(f"[DB ERROR] {e}", flush=True)

def check_credentials(username, password):
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT id FROM credentials WHERE username=%s AND password=%s AND active=true",(username,password))
        result = cur.fetchone(); cur.close(); conn.close()
        return result is not None
    except Exception:
        return False

def generate_mfa_code():
    return ''.join(random.choices(string.digits, k=6))

def send_mfa_email(username, mfa_code):
    smtp_host = os.environ.get("SMTP_HOST","mailhog")
    smtp_port = int(os.environ.get("SMTP_PORT",1025))
    sender    = os.environ.get("MFA_SENDER","security@corpcorp.com")
    recipient = f"{username}@corpcorp.com"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "CorpNet Security — Your verification code"
    msg["From"]    = f"CorpNet Security <{sender}>"
    msg["To"]      = recipient
    msg["X-Session-Username"] = username

    text = f"Your CorpNet verification code is: {mfa_code}\nExpires in 10 minutes."
    html = f"""<html><body style="font-family:sans-serif;max-width:480px;margin:40px auto">
  <div style="background:#0052CC;padding:20px;border-radius:8px 8px 0 0">
    <h2 style="color:white;margin:0">CorpNet Security</h2>
  </div>
  <div style="border:1px solid #ddd;border-top:none;padding:30px;border-radius:0 0 8px 8px">
    <p>Your one-time verification code is:</p>
    <div style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#0052CC;
                text-align:center;padding:20px;background:#f4f5f7;border-radius:6px;margin:20px 0">
      {mfa_code}
    </div>
    <p style="color:#6b778c;font-size:13px">Expires in 10 minutes. Do not share.</p>
  </div>
</body></html>"""

    msg.attach(MIMEText(text,"plain"))
    msg.attach(MIMEText(html,"html"))
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=5) as s:
            s.sendmail(sender,[recipient],msg.as_string())
        log_event({"eventid":"phishing.mfa.email_sent","username":username,
                   "recipient":recipient,"mfa_code":mfa_code})
        return True
    except Exception as e:
        print(f"[SMTP ERROR] {e}", flush=True)
        return False

def get_session_id():
    if "session_id" not in session:
        session["session_id"] = uuid.uuid4().hex
    return session["session_id"]

def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)

@app.route("/", methods=["GET","POST"])
def login():
    session_id = get_session_id()
    src_ip     = get_client_ip()
    user_agent = request.headers.get("User-Agent","")

    if request.method == "GET":
        session["login_start"] = time.time()
        log_event({"eventid":"phishing.page.visit","session_id":session_id,
                   "stage":"login","src_ip":src_ip,"user_agent":user_agent})
        return render_template("login.html")

    username          = request.form.get("username","").strip()
    password          = request.form.get("password","").strip()
    time_on_page_ms   = int((time.time()-session.get("login_start",time.time()))*1000)
    typing_delay_ms   = int(request.form.get("typing_delay",0))
    field_corrections = int(request.form.get("corrections",0))
    valid             = check_credentials(username, password)

    log_event({"eventid":"phishing.credential.submitted","session_id":session_id,
               "stage":"login","src_ip":src_ip,"user_agent":user_agent,
               "username":username,"password":password,
               "time_on_page_ms":time_on_page_ms,"typing_delay_ms":typing_delay_ms,
               "field_corrections":field_corrections,"login_success":valid})

    db_log_session({"session_id":session_id,"src_ip":src_ip,"user_agent":user_agent,
                    "stage":"login","username":username,"password":password,
                    "time_on_page_ms":time_on_page_ms,"typing_delay_ms":typing_delay_ms,
                    "field_corrections":field_corrections,"login_success":valid})

    mfa_code = generate_mfa_code()
    session["mfa_code"]     = mfa_code
    session["username"]     = username
    session["password"]     = password
    session["mfa_start"]    = time.time()
    session["mfa_attempts"] = 0
    send_mfa_email(username, mfa_code)
    return redirect(url_for("mfa"))

@app.route("/mfa", methods=["GET","POST"])
def mfa():
    session_id = get_session_id()
    src_ip     = get_client_ip()
    user_agent = request.headers.get("User-Agent","")

    if request.method == "GET":
        log_event({"eventid":"phishing.page.visit","session_id":session_id,
                   "stage":"mfa","src_ip":src_ip,"user_agent":user_agent})
        return render_template("mfa.html", username=session.get("username","user"),
                               error=None)

    submitted_code   = request.form.get("mfa_code","").strip()
    expected_code    = session.get("mfa_code","")
    time_on_page_ms  = int((time.time()-session.get("mfa_start",time.time()))*1000)
    session["mfa_attempts"] = session.get("mfa_attempts",0) + 1
    mfa_correct      = submitted_code == expected_code

    log_event({"eventid":"phishing.mfa.submitted","session_id":session_id,
               "stage":"mfa","src_ip":src_ip,"user_agent":user_agent,
               "mfa_code":submitted_code,"mfa_correct":mfa_correct,
               "mfa_attempts":session["mfa_attempts"],"time_on_page_ms":time_on_page_ms})

    if not mfa_correct and session["mfa_attempts"] < 3:
        return render_template("mfa.html", username=session.get("username","user"),
                               error="Invalid code. Please try again.")

    session["success_start"] = time.time()
    return redirect(url_for("success"))

@app.route("/success")
def success():
    session_id = get_session_id()
    src_ip     = get_client_ip()
    user_agent = request.headers.get("User-Agent","")
    log_event({"eventid":"phishing.session.complete","session_id":session_id,
               "stage":"success","src_ip":src_ip,"user_agent":user_agent,
               "username":session.get("username",""),
               "mfa_attempts":session.get("mfa_attempts",0),
               "total_duration_ms":int((time.time()-session.get("login_start",time.time()))*1000)})
    return render_template("success.html", username=session.get("username","User"))

@app.route("/health")
def health():
    return {"status":"ok"}, 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)