from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

# Inicialização do Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'segredo-muito-seguro'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Banco de dados
db = SQLAlchemy(app)

# Login Manager
login_manager = LoginManager(app)
login_manager.login_view = "login"

# -----------------------
# MODELS
# -----------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
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

# -----------------------
# LOGIN MANAGER
# -----------------------
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# -----------------------
# ROTAS
# -----------------------
@app.route('/')
def home():
    posts = Post.query.order_by(Post.date_posted.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
            flash("Email ou username já cadastrado!", "danger")
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Conta criada com sucesso!", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.is_active and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        flash("Login inválido ou usuário desativado", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/post', methods=['GET', 'POST'])
@login_required
def post():
    if request.method == 'POST':
        content = request.form.get('content')
        new_post = Post(content=content, user_id=current_user.id)
        db.session.add(new_post)
        db.session.commit()
        flash("Post publicado!", "success")
        return redirect(url_for('home'))
    return render_template('posts.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        current_user.username = username
        if password:
            current_user.password = generate_password_hash(password)
        db.session.commit()
        flash("Perfil atualizado!", "success")
        return redirect(url_for('profile'))
    return render_template('profile.html')

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash("Acesso negado!", "danger")
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/toggle_user/<int:user_id>')
@login_required
def toggle_user(user_id):
    if not current_user.is_admin:
        flash("Acesso negado!", "danger")
        return redirect(url_for('home'))
    user = User.query.get_or_404(user_id)
    if not user.is_admin:
        user.is_active = not user.is_active
        db.session.commit()
        flash("Status do usuário alterado!", "success")
    return redirect(url_for('admin'))

@app.route('/like/<int:post_id>')
@login_required
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post.id).first()
    if existing_like:
        db.session.delete(existing_like)
    else:
        db.session.add(Like(user_id=current_user.id, post_id=post.id))
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/comment/<int:post_id>', methods=['POST'])
@login_required
def comment(post_id):
    content = request.form.get('content')
    if content:
        db.session.add(Comment(content=content, user_id=current_user.id, post_id=post_id))
        db.session.commit()
    return redirect(url_for('home'))

# -----------------------
# CRIAR BANCO E ADMIN
# -----------------------
with app.app_context():
    db.create_all()
    # Criar admin se não existir
    if not User.query.filter_by(email="admin@admin.com").first():
        admin_user = User(
            username="admin",
            email="admin@admin.com",
            password=generate_password_hash("admin123"),
            is_admin=True
        )
        db.session.add(admin_user)
        db.session.commit()

# -----------------------
# RODAR APP
# -----------------------
if __name__ == '__main__':
    app.run(debug=True)
