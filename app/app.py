import os
from os import urandom
from flask import Flask
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from datetime import timedelta
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import bcrypt
from flask_login import UserMixin

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, InputRequired, Length, ValidationError


import os
from flask import app, render_template, request, url_for, redirect, flash
from flask.globals import session
from flask_bcrypt import bcrypt
#libreria para migraciones
from flask_login import login_user, login_required, logout_user
#library forms
from werkzeug.utils import secure_filename


UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}



app = Flask(__name__)
db = SQLAlchemy(app)
app.secret_key = urandom(24)
bcrypt = Bcrypt(app)
migrate = Migrate()

migrate.init_app(app, db)
login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"
app.permanent_session_lifetime  = timedelta(minutes=5)

#se infica cual es la url que usara para la conexion a la base de datos
#credenciales de conecction 
db_user = 'postgres'
db_pswd = 'phyla'
db_host = '127.0.0.1'
db_name = 'mdoc'
db_port = 5432


ENV = 'dev'

if ENV == 'dev':
    app.debug = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:phyla@127.0.0.1:5432/mdoc'
else:
    app.debug = False
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://qvwbtqyblaxsbp:06d6378d72b9088edd1e8b88797ffe6ddd02a634b95fa4abe91925bdd5cd27dc@ec2-54-204-148-110.compute-1.amazonaws.com:5432/dbno3c6rrs95vc'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_IMAGE_EXTENTIONS'] = ALLOWED_EXTENSIONS


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
 
#tablas db
class Urlpresentaciones(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.VARCHAR(100), nullable=False)

    def __str__(self):
        return (
            f'id: {self.id}, '
            f'url: {self.url}'
        )
        
class Urlfondos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.VARCHAR(255), nullable=False)

    def __str__(self):
        return (
            f'id: {self.id}, '
            f'url: {self.url}'
        )
        
class RecomendationPresent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recomendation = db.Column(db.VARCHAR(200), nullable=False)

    def __str__(self):
        return (
            f'id: {self.id}, '
            f'recomendation: {self.recomendation}'
        )

class Tutoriales(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.VARCHAR(100), nullable=False)
    name = db.Column(db.VARCHAR(100), nullable=False)
    
    def __str__(self):
        return (
            f'id:{self.id}, '
            f'url:{self.url}, '
            f'name:{self.name} '
        )

#tables users
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    admin = db.Column(db.Boolean, default=False)    
   
    def set_password(self, password):
        """Set password."""
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    # Flask-Login integration
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def is_admin(self):
        return self.admin

class Sugerencias(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sugerencia = db.Column(db.VARCHAR(200), nullable=False)
    
    def __str__(self):
        return(
            f'id: {self.id}, '
            f'sugerencia: {self.sugerencia}, '
        )

#forms fondos
class FondosForm(FlaskForm):
    url = StringField('url', validators=[DataRequired()])
    guardar = SubmitField('guardar')

#forms sugerencia
class SugerenciaForm(FlaskForm):
    sugerencia = StringField('sugerencia', validators=[DataRequired()])
    enviar = SubmitField('enviar')

#forms Users
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length( min=4, max=20)], render_kw={
        "Placeholder": "Username",
        })
    
    password = PasswordField(validators=[InputRequired(), Length( min=4, max=20)], render_kw={
        "Placeholder": "Password",
        })
    
    admin = BooleanField()
    
    guardar = SubmitField('guardar')
    
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        
        if existing_user_username:
            raise ValidationError("Ese usuario ya esta registrado, favor de elegir otro.")

#LogInUsers
class LogInForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length( min=4, max=20)], render_kw={
        "Placeholder": "Username",
        })
    password = PasswordField(validators=[InputRequired(), Length( min=4, max=20)], render_kw={
        "Placeholder": "Password",
        })
    ingresar = SubmitField('ingresar')

#forms tutoriales
class TutorialesForm(FlaskForm):
    url = StringField('url', validators=[DataRequired()])
    name = StringField('name', validators=[DataRequired()])
    guardar = SubmitField('guardar')

#forms urls
class UrlsForm(FlaskForm):
    url = StringField('url', validators=[DataRequired()])
    guardar = SubmitField('guardar')
    
#forms recom
class PresentationForm(FlaskForm):
    recomendation = StringField('recomendation', validators=[DataRequired()])
    enviar = SubmitField('enviar')

@app.route("/", methods=['GET'])
def index():
    presentations = RecomendationPresent.query.all()
    urls_p = Urlpresentaciones.query.all()
    return render_template('index.html', presentations = presentations, urls_p=urls_p)

@app.route("/tutoriales")
def tutoriales():
    tutos = Tutoriales.query.order_by('id')
    return render_template('tutoriales.html', tutos=tutos)

@app.route("/fondos",  methods=['GET'])
def fondos():
    url_fondos = Urlfondos.query.order_by('id')
    return render_template('fondos.html', url_fondos=url_fondos)

@app.route("/sugerencias", methods=['GET', 'POST'])
def sugerencias():
    suges = Sugerencias()
    sugesform = SugerenciaForm(obj=suges)
    if request.method == 'POST':
        if sugesform.validate_on_submit():
           sugesform.populate_obj(suges)
           db.session.add(suges)
           db.session.commit()
           flash('Gracias por sus sugerencias')
        return redirect(request.url)
    return render_template('sugerencias.html', form=sugesform)

#apartado admin
@app.route("/admin",methods=['GET','POST'])
@login_required
def admin():
    presentations = RecomendationPresent.query.order_by('id')
    present = RecomendationPresent()
    PresentForm = PresentationForm(obj=present)
    if request.method == 'POST':
        if PresentForm.validate_on_submit():
            PresentForm.populate_obj(present)
            db.session.add(present)
            db.session.commit()
            return redirect(url_for('admin'))
    return render_template('admin/admin.html', presentations=presentations, form = PresentForm)

@app.route('/editar/<int:id>', methods=['GET','POST'])
@login_required
def editar_recom(id):
    present = RecomendationPresent.query.get_or_404(id)
    PresentForm = PresentationForm(obj=present)
    if request.method == 'POST':
        if PresentForm.validate_on_submit():
            PresentForm.populate_obj(present)
            db.session.commit()
            return redirect(url_for('admin'))
    return render_template('admin/editar_recom.html', form=PresentForm)

@app.route('/eliminar/<int:id>')
@login_required
def eliminar_recom(id):
    presentation = RecomendationPresent.query.get_or_404(id)
    db.session.delete(presentation)
    db.session.commit()
    return redirect(url_for('admin'))

@app.route('/actualizar', methods=['GET','POST'])
@login_required
def actualizarurls():
    url_present = Urlpresentaciones.query.order_by('id')
    present_url = Urlpresentaciones()
    urlform = UrlsForm(obj=present_url)
    if request.method == 'POST':
        if urlform.validate_on_submit():
            urlform.populate_obj(present_url)
            db.session.add(present_url)
            db.session.commit()
            return redirect(url_for('actualizarurls'))
    return render_template('admin/url.html', url_present=url_present, form=urlform)

@app.route('/eliminarurl/<int:id>')
@login_required
def eliminar_url(id):
    urlspres = Urlpresentaciones.query.get_or_404(id)
    db.session.delete(urlspres)
    db.session.commit()
    return redirect(url_for('actualizarurls'))

@app.route('/admin/tutoriales', methods=['GET','POST'])
@login_required
def admintutoriales():
    tutos = Tutoriales.query.order_by('id')
    tutorial = Tutoriales()
    tutoform = TutorialesForm(obj=tutorial)
    if request.method == 'POST':
        if tutoform.validate_on_submit():
            tutoform.populate_obj(tutorial)
            db.session.add(tutorial)
            db.session.commit()
            return redirect(url_for('admintutoriales'))
    return render_template('admin/admin_tutoriales.html', tutos=tutos, form = tutoform)

@app.route('/admin/eliminartuto/<int:id>')
@login_required
def eliminar_tutorial(id):
    tutos = Tutoriales.query.get_or_404(id)
    db.session.delete(tutos)
    db.session.commit()
    return redirect(url_for('admintutoriales'))

#listar, agregar y eliminar fondos
def allowed_image(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/admin/fondos', methods=['GET', 'POST'])
@login_required
def adminfondos():
    fondos = Urlfondos.query.order_by('id')
    url_fondos = Urlfondos()
    UrlForm = UrlsForm(obj=url_fondos)
    if request.method == 'POST':
        if UrlForm.validate_on_submit():
            UrlForm.populate_obj(url_fondos)
            db.session.add(url_fondos)
            db.session.commit()
            return redirect(url_for('adminfondos'))
    return render_template('admin/admin_fondos.html', fondos=fondos, form=UrlForm)

@app.route('/admin/eliminarfondo/<int:id>')
@login_required
def defeletefondos(id):
    fondo = Urlfondos.query.get_or_404(id)
    db.session.delete(fondo)
    db.session.commit()
    return redirect(url_for('adminfondos'))    

@app.route('/admin/sugerencias')
@login_required
def adminsugerencias():
    sugess = Sugerencias.query.all()
    return render_template('admin/admin_sugerencias.html', sugess=sugess)

#fin apartado admin
@app.errorhandler(404)
def paginanoencontrada(error):
    return render_template('error404.html', error=error),404

#Login 
@app.route('/admin/users', methods=['GET', 'POST'])
def adminusers():
    userslists = User.query.order_by('id')
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('adminusers'))
    return render_template('admin/admin_users.html', form=form, userslists=userslists)

@app.route('/admin/deluser/<int:id>')
@login_required
def eliminar_user(id):
    userslists = User.query.get_or_404(id)
    db.session.delete(userslists)
    db.session.commit()
    return redirect(url_for('adminusers'))

@app.route("/login", methods=['GET','POST'])
def login():
    form = LogInForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password.encode('utf8'), form.password.data):
                flash("you login!")
                login_user(user)
                session.permanent = True
                return redirect(url_for('admin'))
        else:
            flash('Invalid Username and Password')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(port=8000 ,debug=True)
    