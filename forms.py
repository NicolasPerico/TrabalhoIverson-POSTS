from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Senha", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Registrar")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Senha", validators=[DataRequired()])
    submit = SubmitField("Entrar")

class EditProfileForm(FlaskForm):
    username = StringField("Nome de usuário", validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField("Nova senha (deixe vazio se não quiser mudar)")
    submit = SubmitField("Salvar alterações")
