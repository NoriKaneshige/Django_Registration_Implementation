from django import forms
from django.contrib.auth.forms import (
    AuthenticationForm, UserCreationForm
)
from django.contrib.auth import get_user_model

User = get_user_model()


class LoginForm(AuthenticationForm):
    """ login form """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control' # just a styling
            field.widget.attrs['placeholder'] = field.label  # use field label as placeholder

class UserCreateForm(UserCreationForm):
    """user registraion form"""

    class Meta:
        model = User
        fields = ('email',)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

    def clean_email(self):
        email = self.cleaned_data['email']
        User.objects.filter(email=email, is_active=False).delete()
        return email

# In case that user finished a temporary registration, but the time expired,
# this user's email is already stored, and he gets error.
# To fix this, clean_email delete emails that have 1s_active=False.