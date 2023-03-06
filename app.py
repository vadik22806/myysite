import math
import sqlite3

from flask import Flask, render_template, url_for, request, redirect, session,flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, time
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin,  login_required, login_user, current_user, logout_user
from flask_migrate import Migrate
from flask_mail import Mail
from wtforms import StringField, SubmitField, TextAreaField,  BooleanField, PasswordField
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Email
#from flask_script import Manager, Command
import os



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///blog.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
app.app_context().push()
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY


class PRIEM1(db.Model):
      app.app_context()
      id = db.Column(db.Integer, primary_key=True)
      title = db.Column(db.String(100),nullable=False)
      text = db.Column(db.Text, nullable=False)
      intro = db.Column(db.Text, nullable=False)
      date = db.Column(db.DateTime, default=datetime.utcnow)

      def __repr__(self):
          return f"<users {self.id}>"


class PRIEM2(db.Model):
    app.app_context()
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    text = db.Column(db.Text, nullable=False)
    intro = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<users {self.id}>"

class Img(db.Model):
    app.app_context()
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    intro = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<users {self.id}>"

class News(db.Model):
    app.app_context()
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    intro = db.Column(db.Text, nullable=False)
    text = db.Column(db.Text, nullable=False)
    img = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<users {self.id}>"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(100))
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    updated_on = db.Column(db.DateTime(), default=datetime.utcnow,  onupdate=datetime.utcnow)

    def __repr__(self):
        return "<{}:{}>".format(self.id, self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def load_user(user_id):
        return db.session.query(User).get(user_id)





@app.route("/")
def index():
    return render_template("lyceum88.html")


@app.route("/news")
def news():
    blogs4= News.query.order_by(News.date.desc()).all()
    return render_template("newslyceum.html", blogs4=blogs4)

@app.route('/NEWS/<int:id>')
def NEWS(id):
    blog4 = News.query.get(id)
    return render_template("news.html",blog4=blog4)

@app.route("/contacts")
def contacts():
    return render_template("contacts.html")

@app.route("/pedsostav")
def pedsostav():
    return render_template("pedsostav.html")


@app.route("/priems")
def priems():
    blogs = PRIEM1.query.order_by(PRIEM1.date.desc()).all()
    blogs2 = PRIEM2.query.order_by(PRIEM2.date.desc()).all()
    return render_template("priem2.html", blogs=blogs, blogs2=blogs2)

@app.route("/raspisanie")
def raspisanie():
    blogs3 = Img.query.order_by(Img.date.desc()).all()
    return render_template("raspisanie.html", blogs3=blogs3)

@app.route('/create1', methods=['POST', 'GET'])
@login_required
def create1():
    blogs = PRIEM1.query.order_by(PRIEM1.date.desc()).all()
    if request.method == "POST":
        title = request.form['title']
        text = request.form['text']
        intro = request.form['intro']


        blog = PRIEM1(title=title, text=text, intro=intro,)

        try:
            db.session.add(blog)
            db.session.commit()
            return redirect('/create1')
        except:
            return "Ошибка"
    else:

        return render_template('create1.html', blogs=blogs)

@app.route('/create1_detail/<int:id>')
@login_required
def create1_detail(id):
    blog = PRIEM1.query.get(id)
    return render_template("create1_detail.html",blog=blog)

@app.route('/create1_detail/<int:id>/delete')
@login_required
def create1_delete(id):
    blog = PRIEM1.query.get_or_404(id)

    try:
        db.session.delete(blog)
        db.session.commit()
        return redirect('/create1')
    except:
        return "При удалении статьи произошла ошибка"


@app.route('/create1_detail/<int:id>/update', methods=['POST', 'GET'])
@login_required
def create1_update(id):
    blog = PRIEM1.query.get(id)
    if request.method == "POST":
        blog.title = request.form['title']
        blog.text = request.form['text']
        blog.intro = request.form['intro']

        try:
            db.session.commit()
            return redirect('/create1')
        except:
            return "Ошибка"
    else:

        return render_template('create1_update.html', blog=blog)

@app.route('/create2', methods=['POST', 'GET'])
@login_required
def create2():
    blogs2 = PRIEM2.query.order_by(PRIEM2.date.desc()).all()
    if request.method == "POST":
        title = request.form['title']
        text = request.form['text']
        intro = request.form['intro']


        blog2 = PRIEM2(title=title, text=text, intro=intro,)

        try:
            db.session.add(blog2)
            db.session.commit()
            return redirect('/create2')
        except:
            return "Ошибка"
    else:

        return render_template('create2.html', blogs2=blogs2)

@app.route('/create2_detail/<int:id>')
@login_required
def create2_detail(id):
    blog2 = PRIEM2.query.get(id)
    return render_template("create2_detail.html",blog2=blog2)

@app.route('/create2_detail/<int:id>/delete')
@login_required
def create2_delete(id):
    blog2 = PRIEM2.query.get_or_404(id)

    try:
        db.session.delete(blog2)
        db.session.commit()
        return redirect('/create2')
    except:
        return "При удалении статьи произошла ошибка"

@app.route('/create2_detail/<int:id>/update', methods=['POST', 'GET'])
@login_required
def create2_update(id):
    blog2 = PRIEM2.query.get(id)
    if request.method == "POST":
        blog2.title = request.form['title']
        blog2.text = request.form['text']
        blog2.intro = request.form['intro']

        try:
            db.session.commit()
            return redirect('/create2')
        except:
            return "Ошибка"
    else:

        return render_template('create2_update.html', blog2=blog2)

@app.route("/create3", methods=['POST', 'GET'])
@login_required
def create3():
    blogs3 = Img.query.order_by(Img.date.desc()).all()
    if request.method == "POST":
        title = request.form['title']
        intro = request.form['intro']

        blog3 = Img(title=title,intro=intro)

        try:
            db.session.add(blog3)
            db.session.commit()
            return redirect('/create3')
        except:
            return "Ошибка"
    else:

        return render_template('create3.html', blogs3=blogs3)

@app.route('/create3_detail/<int:id>')
@login_required
def create3_detail(id):
    blog3 = Img.query.get(id)
    return render_template("create3_detail.html",blog3=blog3)

@app.route('/create3_detail/<int:id>/delete')
@login_required
def create3_delete(id):
    blog3 = Img.query.get_or_404(id)

    try:
        db.session.delete(blog3)
        db.session.commit()
        return redirect('/create3')
    except:
        return "При удалении статьи произошла ошибка"

@app.route('/create3_detail/<int:id>/update', methods=['POST', 'GET'])
@login_required
def create3_update(id):
    blog3 = Img.query.get(id)
    if request.method == "POST":
        blog3.title = request.form['title']
        blog3.intro = request.form['intro']

        try:
            db.session.commit()
            return redirect('/create3')
        except:
            return "Ошибка"
    else:

        return render_template('create3_update.html', blog3=blog3)


@app.route("/create4", methods=['POST', 'GET'])
@login_required
def create4():
    blogs4 = News.query.order_by(News.date.desc()).all()
    if request.method == "POST":
        title = request.form['title']
        intro = request.form['intro']
        text = request.form['text']
        img = request.form['img']

        blog4 = News(title=title,intro=intro,text=text,img=img)

        try:
            db.session.add(blog4)
            db.session.commit()
            return redirect('/create4')
        except:
            return "Ошибка"
    else:

        return render_template('create4.html', blogs4=blogs4)

@app.route('/create4_detail/<int:id>')
@login_required
def create4_detail(id):
    blog4 = News.query.get(id)
    return render_template("create4_detail.html",blog4=blog4)


@app.route('/create4_detail/<int:id>/delete')
@login_required
def create4_delete(id):
    blog4 = News.query.get_or_404(id)

    try:
        db.session.delete(blog4)
        db.session.commit()
        return redirect('/create4')
    except:
        return "При удалении статьи произошла ошибка"

@app.route('/create4_detail/<int:id>/update', methods=['POST', 'GET'])
@login_required
def create4_update(id):
    blog4 = News.query.get(id)
    if request.method == "POST":
        blog4.title = request.form['title']
        blog4.intro = request.form['intro']
        blog4.text = request.form['text']
        blog4.img = request.form['img']

        try:
            db.session.commit()
            return redirect('/create4')
        except:
            return "Ошибка"
    else:

        return render_template('create4_update.html', blog4=blog4)

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)

@app.route('/login/admin')
@login_required
def admin():
    return render_template('admin.html')

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField()

@app.route('/login/', methods=['post', 'get'])
def login():
    if current_user.is_authenticated:
	    return redirect(url_for('admin'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter(User.username == form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect('/login/admin')

        flash("Invalid username/password", 'error')
        return redirect(url_for('login'))
    return render_template('login.html', form=form)

@app.route('/logout/')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('login'))





if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)