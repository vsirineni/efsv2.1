from . import views
from django.urls import path
from django.conf.urls import url


app_name = 'portfolio'
urlpatterns = [
    path('signup/<str:user_type>/', views.signup, name='sign_up'),
    path('login/', views.login_view, name='login_view'),
    # path('profile/', views.user_profile, name='user_profile'),
    path('logout/', views.logout_view, name='logout_view'),
    path('reset_password/',
         views.ResetPasswordRequestView.as_view(), name="reset_password"),
    # url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
    #     views.PasswordResetConfirmView.as_view(), name='reset_password_confirm'),
    path('reset_password_confirm/<str:uidb64>/<str:token>/',
         views.PasswordResetConfirmView.as_view(), name='reset_password_confirm'),
    path('', views.home, name='home'),
    path('home/', views.home, name='home'),
    path('customer_list', views.customer_list, name='customer_list'),
    path('customer/<int:pk>/edit/', views.customer_edit, name='customer_edit'),
    path('customer/create/', views.customer_new, name='customer_new'),
    path('customer/<int:pk>/delete/',
         views.customer_delete, name='customer_delete'),

    path('stock_list', views.stock_list, name='stock_list'),
    path('stock/create/', views.stock_new, name='stock_new'),
    path('stock/<int:pk>/edit/', views.stock_edit, name='stock_edit'),
    path('stock/<int:pk>/delete/', views.stock_delete, name='stock_delete'),
    path('investment_list', views.investment_list, name='investment_list'),
    path('investment/create/', views.investment_new, name='investment_new'),
    path('investment/<int:pk>/edit/',
         views.investment_edit, name='investment_edit'),
    path('investment/<int:pk>/delete/',
         views.investment_delete, name='investment_delete'),
    path("change-password/", views.change_password, name="change_password"),
    path('customer/<int:pk>/portfolio/', views.portfolio, name='portfolio'),
    path('customer/<int:pk>/portfolio/summary_pdf/', views.portfolio_summary_pdf, name='portfolio_summary_pdf'),
    path('customers_json/', views.CustomerList.as_view()),



]
