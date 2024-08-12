from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseBadRequest
from django.conf import settings
from django.contrib import messages
from pymongo.errors import DuplicateKeyError
from django.views.decorators.csrf import csrf_exempt
import json
db = settings.MONGO_DB
users_collection = settings.MONGO_DB['users']
def home(request):
    return render(request, 'auth/home.html')

def authenticate(request, username, password):
    user = users_collection.find_one({'username': username, 'password': password})
    if user:
        # Создаем объект пользователя для Django
        class User:
            def __init__(self, username):
                self.username = username
                self.is_authenticated = True

        return User(username)
    return None


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('login')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user:
            auth_login(request, user)
            messages.success(request, 'Login successful')
            return redirect('home')
        else:
            messages.error(request, 'Invalid username or password')
            return redirect('login')

    return render(request, 'auth/login.html')


def reg_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('password2')

        if not username or not email or not password or not confirm_password:
            messages.error(request, "All fields are required")
            return redirect('register')

        if password != confirm_password:
            messages.error(request, "Passwords do not match")
            return redirect('register')

        if users_collection.find_one({'username': username}):
            messages.error(request, "Username already exists")
            return redirect('register')

        if users_collection.find_one({'email': email}):
            messages.error(request, "Email already exists")
            return redirect('register')

        try:
            users_collection.insert_one({
                'username': username,
                'email': email,
                'password': password
            })
            messages.success(request, "Registration successful")
            return redirect('home')
        except DuplicateKeyError:
            messages.error(request, "Username or email already exists")
            return redirect('register')

    return render(request, 'auth/reg.html')

def logout_view(request):
    auth_logout(request)
    return redirect('home')
