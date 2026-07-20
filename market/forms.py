"""WTForms form definitions.

Every state-changing request goes through one of these forms, which gives
us (1) server-side input validation and (2) CSRF token verification via
Flask-WTF on every POST.
"""
import re

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import (IntegerField, PasswordField, StringField, TextAreaField,
                     SelectField)
from wtforms.validators import (DataRequired, Length, NumberRange, Regexp,
                                ValidationError, Optional)

USERNAME_RE = r"^[A-Za-z0-9_]{3,20}$"
USERNAME_MSG = "아이디는 3~20자의 영문/숫자/밑줄(_)만 사용할 수 있습니다."

# Rejected even though they pass the length/charset rule: top-of-list
# passwords from public breach-corpus frequency lists (e.g. RockYou),
# adapted to fit our "letters+digits" policy. Defense-in-depth on top of
# the lockout/rate-limit — these are the first guesses any brute-force
# tool tries.
_COMMON_WEAK_PASSWORDS = {
    "password1", "password12", "password123", "12345678", "123456789",
    "1234567890", "qwerty123", "qwertyui1", "abc12345", "iloveyou1",
    "admin1234", "letmein12", "welcome12", "monkey123", "football1",
    "dragon123", "passw0rd1", "trustno12", "sunshine1", "princess1",
}


def validate_password_strength(form, field):
    pw = field.data or ""
    if len(pw) < 8 or len(pw) > 64:
        raise ValidationError("비밀번호는 8~64자여야 합니다.")
    if not re.search(r"[A-Za-z]", pw) or not re.search(r"[0-9]", pw):
        raise ValidationError("비밀번호는 영문과 숫자를 모두 포함해야 합니다.")
    if pw.lower() in _COMMON_WEAK_PASSWORDS:
        raise ValidationError("너무 흔하게 쓰이는 비밀번호입니다. 다른 비밀번호를 사용하세요.")


class RegisterForm(FlaskForm):
    username = StringField("아이디", validators=[
        DataRequired(message="아이디를 입력하세요."),
        Regexp(USERNAME_RE, message=USERNAME_MSG),
    ])
    password = PasswordField("비밀번호", validators=[
        DataRequired(message="비밀번호를 입력하세요."),
        validate_password_strength,
    ])
    password2 = PasswordField("비밀번호 확인", validators=[DataRequired(message="비밀번호 확인을 입력하세요.")])

    def validate_password2(self, field):
        if field.data != self.password.data:
            raise ValidationError("비밀번호가 일치하지 않습니다.")


class LoginForm(FlaskForm):
    username = StringField("아이디", validators=[
        DataRequired(message="아이디를 입력하세요."), Length(max=20)])
    password = PasswordField("비밀번호", validators=[
        DataRequired(message="비밀번호를 입력하세요."), Length(max=64)])


class BioForm(FlaskForm):
    bio = TextAreaField("소개글", validators=[Length(max=500, message="소개글은 500자 이하여야 합니다.")])


class PasswordChangeForm(FlaskForm):
    current_password = PasswordField("현재 비밀번호", validators=[DataRequired(message="현재 비밀번호를 입력하세요.")])
    new_password = PasswordField("새 비밀번호", validators=[
        DataRequired(message="새 비밀번호를 입력하세요."), validate_password_strength])
    new_password2 = PasswordField("새 비밀번호 확인", validators=[DataRequired(message="새 비밀번호 확인을 입력하세요.")])

    def validate_new_password2(self, field):
        if field.data != self.new_password.data:
            raise ValidationError("새 비밀번호가 일치하지 않습니다.")


class ProductForm(FlaskForm):
    title = StringField("상품명", validators=[
        DataRequired(message="상품명을 입력하세요."),
        Length(min=1, max=100, message="상품명은 100자 이하여야 합니다.")])
    description = TextAreaField("상품 설명", validators=[
        DataRequired(message="상품 설명을 입력하세요."),
        Length(max=2000, message="상품 설명은 2000자 이하여야 합니다.")])
    price = IntegerField("가격(원)", validators=[
        DataRequired(message="가격을 숫자로 입력하세요."),
        NumberRange(min=0, max=100_000_000, message="가격은 0원 이상 1억원 이하여야 합니다.")])
    image = FileField("상품 사진", validators=[
        Optional(),
        FileAllowed(["png", "jpg", "jpeg", "gif", "webp"],
                    message="이미지 파일(png/jpg/jpeg/gif/webp)만 업로드할 수 있습니다.")])


class ReportForm(FlaskForm):
    reason = TextAreaField("신고 사유", validators=[
        DataRequired(message="신고 사유를 반드시 입력해야 합니다."),
        Length(min=5, max=500, message="신고 사유는 5자 이상 500자 이하로 작성하세요.")])


class TransferForm(FlaskForm):
    receiver = StringField("받는 사람 아이디", validators=[
        DataRequired(message="받는 사람 아이디를 입력하세요."),
        Regexp(USERNAME_RE, message=USERNAME_MSG)])
    amount = IntegerField("금액(원)", validators=[
        DataRequired(message="금액을 숫자로 입력하세요."),
        NumberRange(min=1, max=10_000_000, message="금액은 1원 이상 1천만원 이하여야 합니다.")])
    memo = StringField("메모", validators=[Length(max=100, message="메모는 100자 이하여야 합니다.")])


class AdminUserForm(FlaskForm):
    """Admin: change a user's status/role.

    "admin" is intentionally NOT one of the role choices here: granting
    admin is a privilege escalation and goes through GrantAdminForm's
    step-up (re-authenticated) flow instead, not this one-click row form.
    A tampered POST with role=admin fails WTForms choice validation.
    """
    status = SelectField("상태", choices=[("active", "active"), ("dormant", "dormant"), ("banned", "banned")])
    role = SelectField("권한", choices=[("user", "user")])


class GrantAdminForm(FlaskForm):
    """Step-up re-authentication required to grant admin privileges."""
    password = PasswordField("본인 비밀번호 확인", validators=[
        DataRequired(message="관리자 승격을 위해 본인 비밀번호를 입력하세요.")])


class EmptyForm(FlaskForm):
    """CSRF-only form for simple POST actions (delete, block, resolve...)."""
    pass
