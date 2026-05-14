from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField
from wtforms.validators import DataRequired, Email, Length, EqualTo

class LoginForm(FlaskForm):
    email = StringField('Adresse Email', validators=[DataRequired(), Email()])
    password = PasswordField('Mot de Passe', validators=[DataRequired()])
    submit = SubmitField('Connexion')

class RegisterForm(FlaskForm):
    full_name = StringField('Nom Complet',
                            validators=[DataRequired(), Length(min=2, max=100)],
                            render_kw={"placeholder": "Jean Dupont"})
    email = StringField('Adresse Email',
                        validators=[DataRequired(), Email()],
                        render_kw={"placeholder": "vous@exemple.com"})
    phone = StringField('Numéro de Téléphone',
                        validators=[DataRequired(), Length(min=8, max=20)],
                        render_kw={"placeholder": "76 12 34 56"})
    password = PasswordField('Mot de Passe',
                             validators=[DataRequired(), Length(min=6)],
                             render_kw={"placeholder": "Créez un mot de passe fort"})
    confirm_password = PasswordField('Confirmer le Mot de Passe',
                                     validators=[DataRequired(), EqualTo('password')],
                                     render_kw={"placeholder": "Répétez votre mot de passe"})
    submit = SubmitField('Créer un Compte')

class TwoFAChoiceForm(FlaskForm):
    method = RadioField('Méthode',
                        choices=[('otp', 'Vérification OTP'),
                                 ('qr', 'Vérification par QR Code')],
                        validators=[DataRequired()])
    submit = SubmitField('Continuer')

class OTPForm(FlaskForm):
    code = StringField('Code OTP',
                       validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Vérifier le Code')