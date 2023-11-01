from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.db.utils import IntegrityError
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required

# 
def show_registration(request):
    #
    if request.method == "POST":
        #
        username = request.POST.get("username")
        password = request.POST.get("password")
        password_confirm = request.POST.get("password_confirm")
        #
        if password == password_confirm:
            #
            try:
                #
                User.objects.create_user(username=username, password=password)
                #
                return redirect("successfulreg")
            #
            except IntegrityError:
                #
                return render(request, "userapp/reg.html", context={"text_error" : "This user exsists"})
        else:
            #
            return render(request, "userapp/reg.html", context={"text_error" : "passwords aren't the same"})
    #
    return render(request, "userapp/reg.html")

#
def successful_registartion(request):
    #
    return render(request, "userapp/successful_reg.html")

#
def view_login(request):
    #
    if request.method == "POST":
        #
        username = request.POST.get("username")
        password = request.POST.get("password")
        # Возвращает None, если такого пользователя нет. Если он есть - возвращает запись юзера из БД
        user = authenticate(request, username=username, password=password)
        #
        if user is not None:
            #
            login(request, user)
            #
            return redirect("successful_log")
        # Додаткове завдання: дописати код, що буде відображати помилку користувачеві на сторінці,
        # у разі, якщо користувач неправильно ввів логін або пароль
        # else:
            # error: password or login isnt correct
    #
    return render(request, 'userapp/login.html' )

#
def show_successful_login(request):
    #
    if request.user.is_authenticated:
        #
        return render(request, "userapp/succesful_login.html")
    #
    else:
        #
        return redirect("login")

#
def user_logout(request):
    #
    logout(request)
    #
    return redirect("login")