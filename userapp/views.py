from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.db.utils import IntegrityError
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required

# повертаемо запрос корестувача
def show_registration(request):
    #створиемо метод якщо повернутій метод доривнюе пост
    if request.method == "POST":
        #запитуе пароль та питверджуемо його
        username = request.POST.get("username")
        password = request.POST.get("password")
        password_confirm = request.POST.get("password_confirm")
        # якщо паспорт правельний то
        if password == password_confirm:
            # спробувати
            try:
                #додати до бази даних им'я як им'я та пароль як пароль
                User.objects.create_user(username=username, password=password)
                # повептаемо користувачу що в нбого правильний пароль
                return redirect("successfulreg")
            # створюемо помилку
            except IntegrityError:
                # якщо в нас такий користавач е видпровляемо користувасу такий користувач є
                return render(request, "userapp/reg.html", context={"text_error" : "This user exsists"})
        else:
            #якщо паспорт виявився неправильним то виводимо паспорт неправельний
            return render(request, "userapp/reg.html", context={"text_error" : "passwords aren't the same"})
    #записуемо користувача в базу
    return render(request, "userapp/reg.html")

# функція підтвердженого пароля ?
def successful_registartion(request):
    #?
    return render(request, "userapp/successful_reg.html")

# функція перегляду логіну
def view_login(request):
    # якщо метод равен пост 
    if request.method == "POST":
        #то отримуемо пароль та логій(ім'я)
        username = request.POST.get("username")
        password = request.POST.get("password")
        # Возвращает None, если такого пользователя нет. Если он есть - возвращает запись юзера из БД
        user = authenticate(request, username=username, password=password)
        #якщо юсер такий є
        if user is not None:
            # 
            login(request, user)
            # виводему користувачу що логій вірний логину
            return redirect("successful_log")
        # Додаткове завдання: дописати код, що буде відображати помилку користувачеві на сторінці,
        # у разі, якщо користувач неправильно ввів логін або пароль
        else:
            error: password or login is None:
            login(request, context={"text_error" : "passwords aren't the same, or login is not corect"})
    #
    return render(request, 'userapp/login.html' )

#створюемо функцію перевірки логіну
def show_successful_login(request):
    # якщо юзер підтвердений
    if request.user.is_authenticated:
        #добавляемо його у корустувачив які підтверджені у файл succesful_login.html
        return render(request, "userapp/succesful_login.html")
    #якщо ні то
    else:
        # видаемо помилку?
        return redirect("login")

#тут в мене питаня що воно робить?)
def user_logout(request):
    #
    logout(request)
    #
    return redirect("login")
#єто прото для комита