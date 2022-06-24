from datetime import timedelta

from flask import Flask, render_template, request, session, redirect, url_for, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from is_safe_url import is_safe_url



# 機密情報を扱うSECRETS.pyをインポート
import SECRETS

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRETS.KEY
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)
login_manager = LoginManager()
login_manager.login_view = "/login"
login_manager.login_message = "サービスを利用するためにはログインが必要です．"
login_manager.init_app(app)

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
    if request.method == "GET":
        return render_template("login.html")
    if request.method == "POST":
        user_id = request.form["user_id"]
        password = request.form["password"]
        # 何らかの認証
        login_user(User("hoge1"))
        next = request.form["next"]
        # is_safe_url should check if the url is safe for redirects.
        if is_safe_url(next, {f"dbs1.slis.tsukuba.ac.jp:{SECRETS.PORT}"}):
            return redirect(next)
        else:
            return abort(400)

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
