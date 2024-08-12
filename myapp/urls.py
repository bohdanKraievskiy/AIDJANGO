from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('register/', views.reg_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
]