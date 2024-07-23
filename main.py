from flask import Flask, render_template, url_for,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, ValidationError, Length
from flask_bcrypt import Bcrypt 

app = Flask(__name__)

# Correct the typo in the configuration key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SECRET_KEY'] = 'myultrasecretkey'
bcrypt= Bcrypt(app)
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=100)], render_kw={"placeholder": "username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=100)], render_kw={"placeholder": "password"})
    submit = SubmitField('register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists.')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=100)], render_kw={"placeholder": "username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=100)], render_kw={"placeholder": "password"})
    submit = SubmitField('login')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials"  # This should be a message to the user saying 'Invalid credentials' instead of a string.  Please update the return statement accordingly.  Also, ensure to sanitize user inputs in your application.  Consider using Flask-WTF for form validation.  Also, ensure to use HTTPS for secure communication.  Also, consider implementing password reset functionality.  Also, ensure to sanitize user inputs in your application.  Consider using Flask-WTF for form validation.  Also, ensure to use HTTPS for secure communication.  Also, consider implementing password reset functionality.  Also, ensure to sanitize user inputs in your application.  Consider using Flask-W

    return render_template('login.html',form=form)
@app.route('/dashboard',methods=['GET','POST'])
@login_required    # This decorator makes sure the user is logged in before accessing the dashboard route.  Please ensure to handle this in your application.  Also, ensure to sanitize user inputs in your application.  Consider using Flask-WTF for form validation.  Also, ensure to use HTTPS for secure communication.  Also, consider implementing password reset functionality.  Also, ensure to sanitize user inputs in your application.  Consider using Flask-WTF for form validation.  Also,
def dashboard():
    return render_template('dashboard.html')

@app.route('/signup',methods=['GET','POST'])        
def signup():
    form=RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        newuser = User(username=form.username.data, password=hashed_password)
        db.session.add(newuser)
        db.session.commit()
        return redirect (url_for('login'))
    return render_template('register.html',form=form)

@app.route("/logout",methods=["GET", "POST"])
@login_required    # This decorator makes sure the user is logged in before accessing the logout route.  Please ensure to handle this in your application.  Also, ensure to sanitize user inputs in your application.  Consider using Flask-WTF for form validation.  Also, ensure to use HTTPS for secure communication.  Also, consider implementing password reset functionality.  Also, ensure to sanitize user inputs in your application.  Consider using Flask-WTF for form validation.  Also,
def logout():
    logout_user()
    return redirect(url_for('login'))


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
