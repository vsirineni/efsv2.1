from django import forms
from .models import Customer, Stock, Investment, User


class CustomerForm(forms.ModelForm):
    created_date = forms.DateTimeField(
        widget=forms.TextInput(attrs={'class': 'date-picker'}))

    class Meta:
        model = Customer
        fields = ('user', 'name', 'address', 'city',
                  'state', 'zipcode', 'cell_phone', 'created_date',)


class StockForm(forms.ModelForm):
    purchase_date = forms.DateField(
        widget=forms.TextInput(attrs={'class': 'date-picker'}))

    class Meta:
        model = Stock
        fields = ('customer', 'symbol', 'name', 'shares',
                  'purchase_price', 'purchase_date',)


class InvestmentForm(forms.ModelForm):
    acquired_date = forms.DateField(
        widget=forms.TextInput(attrs={'class': 'date-picker'}))
    recent_date = forms.DateField(
        widget=forms.TextInput(attrs={'class': 'date-picker'}))

    class Meta:
        model = Investment
        fields = ('customer', 'category', 'description', 'acquired_value',
                  'acquired_date', 'recent_value', 'recent_date',)


class LoginForm(forms.Form):
    email = forms.CharField(widget=forms.EmailInput(
        attrs={'class': 'form-control', 'placeholder': 'Email'}))
    password = forms.CharField(widget=forms.PasswordInput(
        attrs={'class': 'form-control', 'placeholder': 'Password'}))
    fields = ['username', 'password']


class SignUpForm(forms.ModelForm):
    username = forms.CharField(widget=forms.TextInput(
        attrs={'class': 'form-control', 'placeholder': 'Username'}))
    password = forms.CharField(widget=forms.PasswordInput(
        attrs={'class': 'form-control', 'placeholder': 'Password'}))
    email = forms.CharField(widget=forms.EmailInput(
        attrs={'class': 'form-control', 'placeholder': 'Email'}))

    class Meta:
        model = User
        fields = ('email', 'username', 'password')


class PasswordResetRequestForm(forms.Form):
    email = forms.CharField(widget=forms.TextInput(attrs={
                            'class': 'form-control', 'placeholder': 'Email'}), label=("Email"), max_length=254)


class SetPasswordForm(forms.Form):
    def _init_(self, *args, **kwargs):
        self.user = kwargs.pop("user", None)
        super(SetPasswordForm, self)._init_(args, *kwargs)

    error_messages = {
        'password_mismatch': ("The two password fields didn't match."),
    }
    new_password1 = forms.CharField(label=("New password"),
                                    widget=forms.PasswordInput)
    new_password2 = forms.CharField(label=("New password confirmation"),
                                    widget=forms.PasswordInput)

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError(
                    self.error_messages['password_mismatch'],
                    code='password_mismatch',
                )
        return password2
