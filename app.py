from datetime import timedelta
import re
import secrets
import hashlib

from flask import Flask, render_template, request, session, redirect, url_for, abort, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from is_safe_url import is_safe_url
import mysql.connector
import mysql.connector.errorcode


# 機密情報を扱うSECRETS.pyをインポート
import SECRETS

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRETS.KEY
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)
login_manager = LoginManager()
login_manager.login_view = "/login"
login_manager.login_message = "サービスを利用するためにはログインが必要です．"
login_manager.init_app(app)

def get_mysql_conn():
    conn = mysql.connector.connect(
        host=SECRETS.HOSTS,
        port=SECRETS.MYSQL_PORT,
        user=SECRETS.USER_ID,
        password=SECRETS.PASSWORD,
        database=SECRETS.USER_ID
    )
    return conn

class User(UserMixin):
    def __init__(self, uid):
        self.id = uid

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# セッションの永続化
@app.before_first_request  
def make_session_permanent():
    session.permanent = True

@app.route("/")
def index(): 
    return render_template('index.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "GET":
        return render_template("login.html")
    if request.method == "POST":
        user_id = request.form["user_id"]
        password = request.form["password"]
        if re.fullmatch(r"[0-9A-Za-z_]+", user_id) is None:
            # SQLインジェクション対策
            flash("ユーザIDは半角英数字とアンダーバーのみ利用できます．")
            return redirect(url_for("login"))
        # 認証
        conn = get_mysql_conn()
        cur = conn.cursor()
        redirect_flag = False
        try:
            cur.execute("select Password, Salt from report_user where User_id = %s", [user_id])
            ret = cur.fetchall()
        except mysql.connector.Error as e:
            flash("不明なエラーが発生しました．")
            return redirect(url_for("login"))
        finally:
            conn.close()
            cur.close()

        if not ret:
            redirect_flag = True # ユーザーIDの非存在は開示しないほうが良い
        else:
            hashed_db = ret[0][0]
            salt = ret[0][1]        
            auth :str = password + salt
            hashed_in = hashlib.sha224(auth.encode()).hexdigest()
            if hashed_db != hashed_in:
                redirect_flag = True
        if redirect_flag:
            flash("ユーザーID・パスワードが一致しません．")
            return redirect(url_for("login"))

        login_user(User(user_id))
        next = request.form["next"]
        # is_safe_url should check if the url is safe for redirects.
        if is_safe_url(next, {f"dbs1.slis.tsukuba.ac.jp:{SECRETS.PORT}"}):
            return redirect(next)
        else:
            return abort(400)

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "GET":
        return render_template("register.html")
    if request.method == "POST":
        user_id = request.form["user_id"]
        password = request.form["password"]

        redirect_flag = False
        if len(user_id) < 3 or len(user_id) > 100:
            flash("ユーザIDは3文字以上100文字以下にしてください．")
            redirect_flag = True
        if re.fullmatch(r"[0-9A-Za-z_]+", user_id) is None:
            flash("ユーザIDは半角英数字とアンダーバーのみ利用できます．")
            redirect_flag = True
        if len(password) < 5 or len(password) > 50:
             flash("パスワードは5文字以上50文字以内で設定してください．")
             redirect_flag = True
        if redirect_flag:
            return redirect(url_for("register"))

        salt = secrets.token_hex(16)
        auth :str = password + salt
        hashed = hashlib.sha224(auth.encode()).hexdigest()
        conn = get_mysql_conn()
        cur = conn.cursor()

        try:
            cur.execute("insert into report_user values (%s, %s, %s);", [user_id, hashed, salt])
            conn.commit()
        except mysql.connector.Error as e:
            if e.errno == mysql.connector.errorcode.ER_DUP_ENTRY:
                flash("そのユーザーIDはすでに登録されています．")
            else:
                flash("不明なエラーが発生しました．")
            return redirect(url_for("register"))
        finally:
            conn.close()
            cur.close()
        login_user(User(user_id))
        return redirect(url_for("index"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/post", methods=["GET", "POST"])
@login_required
def post():
    return "工事中"


if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=SECRETS.PORT)
