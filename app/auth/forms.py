from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                             Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1, 64),
                                           Email()])
    username = StringField('Username', validators=[
        Required(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                          'Usernames must have only letters, '
                                          'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[
        Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


#修改密码表单
class ChangePassword(FlaskForm):
    old_password = PasswordField('old password', validators=[Required()])
    new_password = PasswordField('new password', validators=[
        Required(), EqualTo('new_password2', message='password must match')])
    new_password2 = PasswordField('confirm password', validators=[Required()])
    submit = SubmitField('submit')


#发送修改邮件表单
class ResendEmailForm(FlaskForm):
    email = StringField('email', validators=[Required(), Length(1, 64),
                                             Email()])
    submit = SubmitField('send')
    
#修改表单
class ResetPasswordForm(FlaskForm):
    email = StringField('email', validators=[Required(), Length(1, 64),
                                             Email()])
    newpassword = PasswordField('new password', validators=[
        Required(), EqualTo('newpassword2', message='password must match')])
    newpassword2 = PasswordField('confirm password', validators=[Required()])
    submit = SubmitField('submit')

#修改邮件表单
class ChangeEmailForm(FlaskForm):
    email = StringField('new email', validators=[Required(),
                                                 Email(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('submit')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')
