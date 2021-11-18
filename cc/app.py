from flask import Flask, render_template, url_for, redirect, flash
from flask.helpers import flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_manager, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt #this is to hash passwords




app = Flask(__name__)
bcrypt = Bcrypt(app) #for password hashing
db = SQLAlchemy(app) #creating db instance
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' 
app.config['SECRET_KEY'] = 'aypproject'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), nullable = False, unique = True)
    password = db.Column(db.String(80), nullable = False)


class RegisterForm(FlaskForm):#class for the registration form
    username = StringField(validators=[InputRequired(), Length(
     min = 6, max = 15 #username length range
    )], render_kw={"placeholder": "Username"})

    password = PasswordField(validators = [InputRequired(), Length(
        min = 7, max = 15 #password length range
    )], render_kw={"placeholder" : "Password"})

    submit = SubmitField("Sign up")
    same_username = ""

    def validate_username(self, username): #make sure usernames are unique
        existing_un = User.query.filter_by(username=username.data).first()
        if existing_un:
            self.same_username = "This username is used by someone else. Choose a different one."
            raise ValidationError( #if there is a similar username, raise an error
                "This username is used by someone else. Choose a different one."
            )
           


class LoginForm(FlaskForm): #class for login form
    username = StringField(validators=[InputRequired(), Length(
     min = 6, max = 15
    )], render_kw={"placeholder": "Username"})

    password = PasswordField(validators = [InputRequired(), Length(
        min = 7, max = 15
    )], render_kw={"placeholder" : "Password"})

    submit = SubmitField("Login")


@app.route("/")
def home():
    return render_template("home.html")



@app.route("/login", methods = ['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit(): #checking if form is valid
        user = User.query.filter_by(username = form.username.data).first()
        if user: #if user exists
            if bcrypt.check_password_hash(user.password, form.password.data): #check if password is correct
                login_user(user)
                return redirect(url_for('profile')) #if so, then login
            else:
                flash("Wrong password") #if the password is wrong
        else:
            flash("Username doesn't exist") #if username doesn't exist
            
   
        return redirect(url_for("login"))

    return render_template("login.html", form=form)



@app.route('/logout', methods = ['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/profile", methods = ['GET', 'POST'])
@login_required
def profile():
    return render_template("profile.html")


@app.route("/signup", methods = ['GET', 'POST'])
def signup():
    form = RegisterForm()
    message = ""
    if form.validate_on_submit(): # if info input is valid
        #form.validate_username(form.username.data)
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username = form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))
    else:
        flash(form.same_username)
        form.same_username = ""
        
    
    return render_template("signup.html", form=form)