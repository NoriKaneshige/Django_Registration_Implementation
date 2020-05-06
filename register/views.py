from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.views import (
    LoginView, LogoutView, PasswordChangeView, PasswordChangeDoneView,
    PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
)
from django.contrib.sites.shortcuts import get_current_site

# django.core.signing.dump generates token. This is based on SECRET_KEY.
# The generated url based on SECRET_KEY for registration is sent to user.
from django.core.signing import BadSignature, SignatureExpired, loads, dumps

from django.http import Http404, HttpResponseBadRequest
from django.shortcuts import redirect, resolve_url
from django.urls import reverse_lazy
from django.template.loader import render_to_string
from django.views import generic
from .forms import (
    LoginForm, UserCreateForm, UserUpdateForm, MyPasswordChangeForm,
    MyPasswordResetForm, MySetPasswordForm
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



class OnlyYouMixin(UserPassesTestMixin):
    raise_exception = True
    # if user doesn't meet requirements, show 403 page
    # False, redirect to login page

    def test_func(self):
        user = self.request.user
        return user.pk == self.kwargs['pk'] or user.is_superuser


class UserDetail(OnlyYouMixin, generic.DetailView):
    model = User
    template_name = 'register/user_detail.html'


class UserUpdate(OnlyYouMixin, generic.UpdateView):
    model = User
    form_class = UserUpdateForm
    template_name = 'register/user_form.html'

    def get_success_url(self):
        return resolve_url('register:user_detail', pk=self.kwargs['pk'])


class PasswordChange(PasswordChangeView):
    """ password change view """
    form_class = MyPasswordChangeForm
    success_url = reverse_lazy('register:password_change_done')
    template_name = 'register/password_change.html'


class PasswordChangeDone(PasswordChangeDoneView):
    """ password change done view """
    template_name = 'register/password_change_done.html'


class PasswordReset(PasswordResetView):
    """ password change url message page"""
    subject_template_name = 'register/mail_template/password_reset/subject.txt'
    email_template_name = 'register/mail_template/password_reset/message.txt'
    template_name = 'register/password_reset_form.html'
    form_class = MyPasswordResetForm
    success_url = reverse_lazy('register:password_reset_done')


class PasswordResetDone(PasswordResetDoneView):
    """ password change url was sent: page """
    template_name = 'register/password_reset_done.html'


class PasswordResetConfirm(PasswordResetConfirmView):
    """ password input page """
    form_class = MySetPasswordForm
    success_url = reverse_lazy('register:password_reset_complete')
    template_name = 'register/password_reset_confirm.html'


class PasswordResetComplete(PasswordResetCompleteView):
    """ password change compelete notification page """
    template_name = 'register/password_reset_complete.html'

