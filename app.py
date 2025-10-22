from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'troque_esta_chave_por_uma_segura'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='user', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='post', lazy=True)
    likes = db.relationship('Like', backref='post', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

# Formulários
class RegisterForm(FlaskForm):
    username = StringField('Nome de usuário', validators=[DataRequired(), Length(min=3, max=60)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Confirmar senha', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrar')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[DataRequired()])
    submit = SubmitField('Entrar')

class PostForm(FlaskForm):
    content = TextAreaField('Conteúdo', validators=[DataRequired(), Length(min=1)])
    submit = SubmitField('Publicar')

class ProfileForm(FlaskForm):
    username = StringField('Nome de usuário', validators=[DataRequired(), Length(min=3, max=60)])
    password = PasswordField('Nova senha (opcional)')
    submit = SubmitField('Salvar')

# Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Rotas
@app.route('/')
def home():
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter((User.email == form.email.data) | (User.username == form.username.data)).first():
            flash('Email ou username já existe.', 'danger')
            return redirect(url_for('register'))
        hashed = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        u = User(username=form.username.data, email=form.email.data, password=hashed)
        db.session.add(u)
        db.session.commit()
        flash('Conta criada. Faça login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        u = User.query.filter_by(email=form.email.data).first()
        if u and u.is_active and check_password_hash(u.password, form.password.data):
            login_user(u)
            flash('Bem vindo!', 'success')
            return redirect(url_for('home'))
        flash('Credenciais inválidas ou conta desativada.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout efetuado.', 'info')
    return redirect(url_for('home'))

@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        p = Post(content=form.content.data, user_id=current_user.id)
        db.session.add(p)
        db.session.commit()
        flash('Post publicado!', 'success')
        return redirect(url_for('home'))
    return render_template('new_post.html', form=form)

@app.route('/post/<int:post_id>', methods=['GET'])
def view_post(post_id):
    p = Post.query.get_or_404(post_id)
    return render_template('view_post.html', post=p)

@app.route('/like/<int:post_id>')
@login_required
def like_post(post_id):
    p = Post.query.get_or_404(post_id)
    existing = Like.query.filter_by(user_id=current_user.id, post_id=p.id).first()
    if existing:
        db.session.delete(existing)
    else:
        db.session.add(Like(user_id=current_user.id, post_id=p.id))
    db.session.commit()
    return redirect(request.referrer or url_for('home'))

@app.route('/comment/<int:post_id>', methods=['POST'])
@login_required
def comment(post_id):
    content = request.form.get('content')
    if content:
        c = Comment(content=content, user_id=current_user.id, post_id=post_id)
        db.session.add(c)
        db.session.commit()
    return redirect(request.referrer or url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    if request.method == 'GET':
        form.username.data = current_user.username
    if form.validate_on_submit():
        if form.username.data != current_user.username:
            if User.query.filter_by(username=form.username.data).first():
                flash('Nome de usuário já em uso.', 'danger')
                return redirect(url_for('profile'))
            current_user.username = form.username.data
        if form.password.data:
            current_user.password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        db.session.commit()
        flash('Perfil atualizado.', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', form=form)

# Admin
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    users = User.query.all()
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('admin.html', users=users, posts=posts)

@app.route('/admin/toggle_user/<int:user_id>')
@login_required
def admin_toggle_user(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Não é possível desativar um admin.', 'danger')
    else:
        user.is_active = not user.is_active
        db.session.commit()
        flash('Status do usuário alterado.', 'success')
    return redirect(url_for('admin'))

# Create DB & User Admin Padrão
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email='admin@admin.com').first():
        admin_user = User(
            username='admin',
            email='admin@admin.com',
            password=generate_password_hash('admin123', method='pbkdf2:sha256'),
            is_admin=True
        )
        db.session.add(admin_user)
        db.session.commit()

# Rodar
if __name__ == '__main__':
    app.run(debug=True)
