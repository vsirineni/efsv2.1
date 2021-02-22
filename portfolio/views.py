from django.contrib.auth.decorators import login_required
from django.shortcuts import render, reverse
from .models import *
from .forms import *
from django.shortcuts import render, get_object_or_404
from django.shortcuts import redirect
from django.contrib.auth import authenticate
from django.contrib.auth import login, logout
from django.urls import reverse_lazy
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template import loader
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.views.generic import *
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.conf import settings
from django.db.models import Q, Sum

from json.decoder import JSONDecodeError
try:
    import simplejson as json
except ImportError:
    import json
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import CustomerSerializer


from django.http import HttpResponse
from django.views.generic import View
from .utils import render_to_pdf
from django.template.loader import get_template


now = timezone.now()


def signup(request, user_type):
    signup_error = ''
    if user_type in ['Staff', 'Customer', 'Financial Advisor']:
        if request.method == 'GET':
            form = SignUpForm()
            if request.user.is_authenticated:
                return redirect(reverse('portfolio:home'))
            return render(request, "registration/form.html", {'form': form, 'form_value': 'SignUp', 'form_name': 'SignUp Form'})

        if request.method == "POST":
            form = SignUpForm(request.POST)
            if User.objects.filter(email=request.POST.get('email')).exists():
                signup_error = 'User Already Exists'
            else:
                user = User.objects.create(
                    username=request.POST.get('username'), email=request.POST.get('email'))
                if user_type == 'Financial Advisor':
                    user.is_finance_advisor = True
                else:
                    user.is_customer = True
                user.set_password(request.POST.get('password'))
                user.save()
                login(request, user)
                return redirect(reverse('portfolio:home'))
        return render(request, "registration/form.html", {'form': form, 'form_value': 'SignUp', 'form_name': 'SignUp Form', 'signup_error': signup_error})
    messages.error(
        request, "Got Wrong user_type. Please Refresh the page and try Again.")
    return redirect('portfolio:home')


# @login_required
# def user_profile(request):
#     customer_data = Customer.objects.filter(email=request.user.email).first()
#     return render(request, 'portfolio/profile.html', {'customer_data': customer_data})


def login_view(request):
    form = LoginForm()
    if request.method == 'GET':
        if request.user.is_authenticated:
            return redirect(reverse('portfolio:home'))
        return render(request, "registration/form.html", {'form': form, 'form_value': 'Login', 'form_name': 'Login Form'})

    if request.method == "POST":
        form = LoginForm(request.POST)
        user = authenticate(username=request.POST.get(
            'email'), password=request.POST.get('password'))
        if user is not None:
            login(request, user)
            return redirect(reverse('portfolio:home'))
        error_message = 'User Not Found. Please check the email and password.'
    return render(request, "registration/form.html", {'login_error_msg': error_message, 'form': form, 'form_value': 'Login', 'form_name': 'Login Form'})


@login_required
def logout_view(request):
    logout(request)
    return redirect(reverse('portfolio:login_view'))


def home(request):
    print(request.user)
    return render(request, 'portfolio/home.html',
                  {'portfolio': home})


@login_required
def change_password(request):
    form = SetPasswordForm(request.POST, request.user)
    if request.method == 'GET':
        #form = SetPasswordForm()
        return render(request, "registration/password_change_form.html", {"form": form})
    if request.method == 'POST':

        if form.is_valid():
            user = request.user
            user.set_password(request.POST.get("new_password1"))
            user.save()
            # form.save()
            return render(
                request, "registration/password_change_done.html", {}
            )
        return render(
            request, "registration/password_change_form.html", {
                "errors": form.errors}
        )


@login_required
def customer_new(request):
    if (request.user.is_staff or request.user.is_finance_advisor):
        form = CustomerForm(request.POST)
        if request.method == "POST":
            if form.is_valid():
                customer = form.save(commit=False)
                customer.created_date = timezone.now()
                customer.created_by = request.user
                customer.save()
                return redirect('portfolio:customer_list')
        return render(request, 'portfolio/customer_new.html', {'form': form})
    messages.error(request, "You Don't have access to Create User")
    return redirect('portfolio:home')


@login_required
def customer_list(request):
    if request.user.is_staff:
        customer = Customer.objects.filter(created_date__lte=timezone.now())
    elif request.user.is_finance_advisor:
        customer = Customer.objects.filter((Q(created_by=request.user) | Q(
            user=request.user)), created_date__lte=timezone.now())
    else:
        # messages.error(request, "You Don't have access to View Users")
        customer = Customer.objects.filter(
            created_date__lte=timezone.now(), user=request.user)
    return render(request, 'portfolio/customer_list.html', {'customers': customer})


@login_required
def customer_edit(request, pk):
    customer = get_object_or_404(Customer, pk=pk)
    if request.user.is_staff or customer.created_by == request.user:
        if request.method == "POST":
            # update
            form = CustomerForm(request.POST, instance=customer)
            if form.is_valid():
                customer = form.save(commit=False)
                customer.updated_date = timezone.now()
                customer.save()
                return redirect('portfolio:customer_list')
        form = CustomerForm(instance=customer)
        return render(request, 'portfolio/customer_edit.html', {'form': form})
    # messages.error(request, "You Don't have access to Edit User")
    return redirect('portfolio:home')


@login_required
def customer_delete(request, pk):
    customer = get_object_or_404(Customer, pk=pk)
    if request.user.is_staff or customer.created_by == request.user:
        customer.delete()
        return redirect('portfolio:customer_list')
    # messages.error(request, "You Don't have access to Delete User")
    return redirect('portfolio:home')


@login_required
def stock_list(request):
    if request.user.is_staff:
        stocks = Stock.objects.filter(purchase_date__lte=timezone.now())
    elif request.user.is_finance_advisor:
        stocks = Stock.objects.filter((Q(customer__created_by=request.user) | Q(
            customer__user=request.user)), purchase_date__lte=timezone.now())
    else:
        # messages.error(request, "You Don't have access to View stocks")
        stocks = Stock.objects.filter(
            purchase_date__lte=timezone.now(), customer__user=request.user)
    return render(request, 'portfolio/stock_list.html', {'stocks': stocks})


@login_required
def stock_new(request):
    if (request.user.is_staff or request.user.is_finance_advisor):
        form = StockForm(request.POST)
        if request.user.is_finance_advisor:
            form.fields["customer"].queryset = Customer.objects.filter(
                created_by=request.user.id)
        if request.method == "POST":
            if form.is_valid():
                stock = form.save(commit=False)
                stock.created_date = timezone.now()
                stock.save()
                return redirect('portfolio:stock_list')
        return render(request, 'portfolio/stock_new.html', {'form': form})
    # messages.error(request, "You Don't have access to Create Stock")
    return redirect('portfolio:home')


@login_required
def stock_edit(request, pk):
    stock = get_object_or_404(Stock, pk=pk)
    if request.user.is_staff or (request.user.is_finance_advisor and stock.customer.created_by == request.user):
        if request.method == "POST":
            form = StockForm(request.POST, instance=stock)
            if form.is_valid():
                stock = form.save()
                # stock.customer = stock.id
                stock.updated_date = timezone.now()
                stock.save()
                return redirect('portfolio:stock_list')
        form = StockForm(instance=stock)
        if request.user.is_finance_advisor:
            form.fields["customer"].queryset = Customer.objects.filter(
                created_by=request.user.id)
        return render(request, 'portfolio/stock_edit.html', {'form': form})
    # messages.error(request, "You Don't have access to Edit Stock")
    return redirect('portfolio:home')


@login_required
def stock_delete(request, pk):
    stock = get_object_or_404(Stock, pk=pk)
    if request.user.is_staff or (request.user.is_finance_advisor and stock.customer.created_by == request.user):
        stock.delete()
        return redirect('portfolio:stock_list')
    # messages.error(request, "You Don't have access to Delete Stock")
    return redirect('portfolio:home')


@login_required
def investment_list(request):
    if request.user.is_staff:
        investment = Investment.objects.filter(
            acquired_date__lte=timezone.now())
    elif request.user.is_finance_advisor:
        investment = Investment.objects.filter((Q(customer__created_by=request.user) | Q(
            customer__user=request.user)), acquired_date__lte=timezone.now())
    else:
        # messages.error(request, "You Don't have access to View Investments")
        investment = Investment.objects.filter(
            acquired_date__lte=timezone.now(), customer__user=request.user)
    return render(request, 'portfolio/investment_list.html', {'investments': investment})


@login_required
def investment_new(request):
    if (request.user.is_staff or request.user.is_finance_advisor):
        form = InvestmentForm(request.POST)
        if request.user.is_finance_advisor:
            form.fields["customer"].queryset = Customer.objects.filter(
                created_by=request.user.id)
        if request.method == "POST":
            if form.is_valid():
                investment = form.save(commit=False)
                investment.created_date = timezone.now()
                investment.save()
                return redirect('portfolio:investment_list')
        return render(request, 'portfolio/investment_new.html', {'form': form})
    # messages.error(request, "You Don't have access to Create Investment")
    return redirect('portfolio:home')


@login_required
def investment_edit(request, pk):
    investment = get_object_or_404(Investment, pk=pk)
    is_finance_advisor_true = Investment.objects.filter()
    if request.user.is_staff or (request.user.is_finance_advisor and investment.customer.created_by == request.user):
        if request.method == "POST":
            form = InvestmentForm(request.POST, instance=investment)
            if form.is_valid():
                investment = form.save()
                # stock.customer = stock.id
                investment.updated_date = timezone.now()
                investment.save()
                return redirect('portfolio:investment_list')
        form = InvestmentForm(instance=investment)
        if request.user.is_finance_advisor:
            form.fields["customer"].queryset = Customer.objects.filter(
                created_by=request.user.id)
        return render(request, 'portfolio/investment_edit.html', {'form': form})
    # messages.error(request, "You Don't have access to Edit Invetsment")
    return redirect('portfolio:home')


@login_required
def investment_delete(request, pk):
    investment = get_object_or_404(Investment, pk=pk)
    if request.user.is_staff or (request.user.is_finance_advisor and investment.customer.created_by == request.user):
        investment.delete()
        return redirect('portfolio:investment_list')
    # messages.error(request, "You Don't have access to Delete Investment")
    return redirect('portfolio:home')


@login_required
def portfolio(request, pk):
    customer = get_object_or_404(Customer, pk=pk)
    #customers = Customer.objects.filter(created_date__lte=timezone.now())
    investments = Investment.objects.filter(customer=pk)
    stocks = Stock.objects.filter(customer=pk)

    sum_recent_value = Investment.objects.filter(
        customer=pk).aggregate(Sum('recent_value'))
    sum_acquired_value = Investment.objects.filter(
        customer=pk).aggregate(Sum('acquired_value'))
    print(sum_acquired_value)
    acquired_total = sum_acquired_value['acquired_value__sum']
    recent_total = sum_recent_value['recent_value__sum']

    overall_investment_results = recent_total - acquired_total
    print(overall_investment_results)

    # Initialize the value of the stocks
    sum_current_stocks_value = 0
    sum_of_initial_stock_value = 0

    # Loop through each stock and add the value to the total
    for stock in stocks:
        sum_current_stocks_value += stock.current_stock_value()
        sum_of_initial_stock_value += stock.initial_stock_value()

    sumofinitialprice = float(sum_of_initial_stock_value)
    results = sum_current_stocks_value - sumofinitialprice
    print(results)

    return render(request, 'portfolio/portfolio.html', {'customer': customer,
                                                        'investments': investments,
                                                        'stocks': stocks,
                                                        'sum_acquired_value': sum_acquired_value,
                                                        'sum_recent_value': sum_recent_value,

                                                        'acquired_total': acquired_total,
                                                        'recent_total': recent_total,
                                                        'results': results,

                                                        'overall_investment_results': overall_investment_results,
                                                        'sum_current_stocks_value': sum_current_stocks_value,
                                                        'sum_of_initial_stock_value': sum_of_initial_stock_value, })


def portfolio_summary_pdf(request, pk):
    customer = get_object_or_404(Customer, pk=pk)
    customers = Customer.objects.filter(created_date__lte=timezone.now())
    investments = Investment.objects.filter(customer=pk)
    stocks = Stock.objects.filter(customer=pk)

    sum_recent_value = Investment.objects.filter(
        customer=pk).aggregate(Sum('recent_value'))
    sum_acquired_value = Investment.objects.filter(
        customer=pk).aggregate(Sum('acquired_value'))
    print(sum_acquired_value)
    acquired_total = sum_acquired_value['acquired_value__sum']
    recent_total = sum_recent_value['recent_value__sum']

    overall_investment_results = recent_total - acquired_total
    print(overall_investment_results)

    # Initialize the value of the stocks

    sum_current_stocks_value = 0
    sum_of_initial_stock_value = 0

    # Loop through each stock and add the value to the total
    for stock in stocks:
        sum_current_stocks_value += stock.current_stock_value()
        sum_of_initial_stock_value += stock.initial_stock_value()

    sumofinitialprice = float(sum_of_initial_stock_value)
    results = sum_current_stocks_value - sumofinitialprice

    context = {'customers': customers,
               'investments': investments,
               'stocks': stocks,
               'sum_acquired_value': sum_acquired_value,
               'sum_recent_value': sum_recent_value,

               'acquired_total': acquired_total,
               'recent_total': recent_total,
               'results': results,

               'overall_investment_results': overall_investment_results,
               'sum_current_stocks_value': sum_current_stocks_value,
               'sum_of_initial_stock_value': sum_of_initial_stock_value, }
    template = get_template('portfolio/portfolio_summary_pdf.html')
    html = template.render(context)
    pdf = render_to_pdf('portfolio/portfolio_summary_pdf.html', context)
    return pdf


class CustomerList(APIView):
    def get(self, request):
        customers_json = Customer.objects.all()
        serializer = CustomerSerializer(customers_json, many=True)
        return Response(serializer.data)


class ResetPasswordRequestView(FormView):
    template_name = "registration/password_reset_form.html"
    success_url = reverse_lazy('portfolio:home')
    form_class = PasswordResetRequestForm

    @staticmethod
    def validate_email_address(email):
        try:
            validate_email(email)
            return True
        except ValidationError:
            return False

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        if form.is_valid():
            data = form.cleaned_data["email"]
        if self.validate_email_address(data) is True:
            c = {}
            subject_template_name = 'registration/password_reset_subject.txt'
            email_template_name = 'registration/password_reset_done.html'
            subject = loader.render_to_string(subject_template_name, c)
            subject = ''.join(subject.splitlines())
            email = loader.render_to_string(email_template_name, c)
            send_mail(subject, email, settings.DEFAULT_FROM_EMAIL,
                      [data], fail_silently=False)
            associated_users = User.objects.filter(email=data)
            if associated_users.exists():
                for user in associated_users:
                    print(user.pk, user, urlsafe_base64_encode(force_bytes(
                        user.pk)), default_token_generator.make_token(user))
                    try:
                        uid_data = urlsafe_base64_encode(
                            force_bytes(user.pk)).decode("utf-8")
                    except:
                        uid_data = urlsafe_base64_encode(force_bytes(user.pk))

                    c = {
                        'email': user.email,
                        'domain': request.META['HTTP_HOST'],
                        'site_name': 'Expenses Management App',
                        'uid': uid_data,
                        'user': user,
                        'token': default_token_generator.make_token(user),
                        'protocol': 'http',
                    }
                    subject_template_name = 'registration/password_reset_subject.txt'
                    # copied from django/contrib/admin/templates/registration/password_reset_subject.txt to templates directory
                    email_template_name = 'registration/password_reset_email.html'
                    # copied from django/contrib/admin/templates/registration/password_reset_email.html to templates directory
                    subject = loader.render_to_string(subject_template_name, c)
                    # Email subject *must not* contain newlines
                    subject = ''.join(subject.splitlines())
                    email = loader.render_to_string(email_template_name, c)
                    send_mail(subject, email, settings.DEFAULT_FROM_EMAIL, [
                              user.email], fail_silently=False)
                result = self.form_valid(form)
                messages.success(request, 'An email has been sent to ' + data +
                                 ". Please check its inbox to continue reseting password.")
                return result
            result = self.form_invalid(form)
            messages.error(
                request, 'No user is associated with this email address')
            return result
        messages.error(request, 'Invalid Input')
        return self.form_invalid(form)


class PasswordResetConfirmView(FormView):
    template_name = "registration/password_reset_confirm.html"
    success_url = reverse_lazy('portfolio:home')
    form_class = SetPasswordForm

    def post(self, request, uidb64=None, token=None, *arg, **kwargs):
        """
        View that checks the hash in a password reset link and presents a
        form for entering a new password.
        """
        UserModel = get_user_model()
        form = self.form_class(request.POST)
        assert uidb64 is not None and token is not None  # checked by URLconf
        try:
            uid = urlsafe_base64_decode(uidb64)
            print(uid, "uid")
            user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            user = None
        if user is not None and default_token_generator.check_token(user, token):
            if form.is_valid():
                new_password = form.cleaned_data['new_password2']
                user.set_password(new_password)
                user.save()
                messages.success(request, 'Password has been reset.')
                c = {
                    'email': user.email,
                    'domain': request.META['HTTP_HOST'],
                    'site_name': 'Expenses Management App',
                    'user': user,
                    'protocol': 'http',
                }
                subject_template_name = 'registration/password_reset_completed.txt'
                email_template_name = 'registration/password_reset_complete.html'
                subject = loader.render_to_string(subject_template_name, c)
                # Email subject *must not* contain newlines
                subject = ''.join(subject.splitlines())
                email = loader.render_to_string(email_template_name, c)
                send_mail(subject, email, settings.DEFAULT_FROM_EMAIL, [
                          user.email], fail_silently=False)
                return self.form_valid(form)
            else:
                messages.error(
                    request, 'Password reset has not been unsuccessful.')
                return self.form_invalid(form)
        else:
            messages.error(
                request, 'The reset password link is no longer valid.')
            return self.form_invalid(form)
