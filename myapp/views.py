from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.conf import settings
from django.contrib import messages
from rest_framework_simplejwt.tokens import RefreshToken
from pymongo.errors import DuplicateKeyError
import re
import uuid

db = settings.MONGO_DB
users_collection = settings.MONGO_DB['users']

def home(request):
    return render(request, 'auth/home.html')

class CustomUser:
    def __init__(self, id, username):
        self.id = id
        self.username = username
        self.is_authenticated = True

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    return True, ""

def get_mac_address():
    mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
    return mac

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('login')
        password = request.POST.get('password')

        user = users_collection.find_one({'username': username, 'password': password})
        if user:
            custom_user = CustomUser(id=user['_id'], username=user['username'])
            refresh = RefreshToken.for_user(custom_user)
            access_token = str(refresh.access_token)

            # Обновлення інформації в MongoDB
            users_collection.update_one({'username': username},
                                        {'$set': {'auth_status': 'authorized', 'token': access_token}})

            messages.success(request, 'Login successful')
            response = redirect('login')
            response.set_cookie('access_token', access_token)
            return response
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

        if len(username) < 5:
            messages.error(request, "Username must be at least 5 characters long")
            return redirect('register')

        if password != confirm_password:
            messages.error(request, "Passwords do not match")
            return redirect('register')

        is_valid, error_msg = validate_password(password)
        if not is_valid:
            messages.error(request, error_msg)
            return redirect('register')

        if users_collection.find_one({'username': username}):
            messages.error(request, "Username already exists")
            return redirect('register')

        if users_collection.find_one({'email': email}):
            messages.error(request, "Email already exists")
            return redirect('register')

        mac_address = get_mac_address()

        try:
            users_collection.insert_one({
                'username': username,
                'email': email,
                'password': password,
                'mac_address': mac_address,
                'auth_status': 'unauthorized'
            })
            messages.success(request, "Registration successful")
            return redirect('home')
        except DuplicateKeyError:
            messages.error(request, "Username or email already exists")
            return redirect('register')

    return render(request, 'auth/reg.html')

def logout_view(request):
    response = redirect('home')
    response.delete_cookie('access_token')
    return response
