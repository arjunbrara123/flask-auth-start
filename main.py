from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/files/'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    def __repr__(self):
        return '<User %r>' % self.name


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

def user_by_email(user_email):
    return User.query.filter_by(email=user_email).first()

#Line below only required once, when creating DB. 
# db.create_all()


def download_file():
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               'static/files/cheat_sheet.pdf', as_attachment=False)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        new_user = User()
        new_user.email = request.form['email']
        new_user.name = request.form['name']
        new_user.password = generate_password_hash(str(request.form['password']), method='pbkdf2:sha256', salt_length=8)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('secrets'))
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password_hash = generate_password_hash(str(request.form['password']), method='pbkdf2:sha256', salt_length=8)
        new_user = user_by_email(request.form['email'])
        entered_hash = new_user.password
        if check_password_hash(entered_hash, request.form['password']):
            login_user(new_user)
            return redirect(url_for('secrets'))
        else:
            flash("Incorrect password")
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               'cheat_sheet.pdf', as_attachment=False)


if __name__ == "__main__":
    app.run(debug=True)
