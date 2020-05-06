from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import (
    LoginView, LogoutView
)
from django.contrib.sites.shortcuts import get_current_site

# django.core.signing.dump generates token. This is based on SECRET_KEY.
# The generated url based on SECRET_KEY for registration is sent to user.
from django.core.signing import BadSignature, SignatureExpired, loads, dumps

from django.http import Http404, HttpResponseBadRequest
from django.shortcuts import redirect
from django.template.loader import render_to_string
from django.views import generic
from .forms import (
    LoginForm, UserCreateForm
)

# get_user_model function receives UserModel (default User or custom User) that is currently used.
User = get_user_model()

class Top(generic.TemplateView):
    template_name = 'register/top.html'


class Login(LoginView):
    """ login page """
    form_class = LoginForm
    template_name = 'register/login.html'


class Logout(LogoutView):
    """ logout page """
    template_name = 'register/top.html'


class UserCreate(generic.CreateView):
    """ User temporary registration """
    template_name = 'register/user_create.html'
    form_class = UserCreateForm

    def form_valid(self, form):
        """ email for temporary / actual registration """
        # is_active attribute is convenient for temporay/actual registration
        user = form.save(commit=False)
        user.is_active = False
        user.save()

        # url for activation
        current_site = get_current_site(self.request)
        domain = current_site.domain
        context = {
            'protocol': self.request.scheme,
            'domain': domain,
            'token': dumps(user.pk),
            'user': user,
        }

        subject = render_to_string('register/mail_template/create/subject.txt', context)
        message = render_to_string('register/mail_template/create/message.txt', context)

        user.email_user(subject, message)
        return redirect('register:user_create_done')


class UserCreateDone(generic.TemplateView):
    """ user registration confirmation """
    template_name = 'register/user_create_done.html'


class UserCreateComplete(generic.TemplateView):
    """ accessing url in the email enables the registration """
    template_name = 'register/user_create_complete.html'
    timeout_seconds = getattr(settings, 'ACTIVATION_TIMEOUT_SECONDS', 60*60*24)  # 1 day is default

    def get(self, request, **kwargs):
        """ if token is correct, proceed"""
        token = kwargs.get('token')
        try:
            user_pk = loads(token, max_age=self.timeout_seconds)

        # time expiration
        except SignatureExpired:
            return HttpResponseBadRequest()

        # token is not correct
        except BadSignature:
            return HttpResponseBadRequest()

        # token is correct
        else:
            try:
                user = User.objects.get(pk=user_pk)
            except User.DoesNotExist:
                return HttpResponseBadRequest()
            else:
                if not user.is_active:
                    # if there is no problem, proceed
                    user.is_active = True
                    user.save()
                    return super().get(request, **kwargs)

        return HttpResponseBadRequest()