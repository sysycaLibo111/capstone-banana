from itertools import count
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from supabase import create_client, Client
from geopy.geocoders import Nominatim
import os
import json
from datetime import timedelta
from django.utils import timezone
from django.db.models import Sum, Count, Avg, Q
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from decimal import Decimal
import requests
import binascii
from django.core.serializers.json import DjangoJSONEncoder
from django.views.decorators.http import require_http_methods
from dotenv import load_dotenv
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth import logout
from django.contrib.auth.hashers import check_password
from django.http import HttpResponse
from bananae.supabase_config import supabase 
from django.contrib.auth.hashers import make_password
from .models import CustomUser, Payment, Store, Customer, Product, Category, Order, Cart, Cartitems,ShippingAddress, CustomerPurchase, StoreValidation,  DeliverySchedule, ShippingFee, PostalCodeLocation, Review,KnowledgeBase, BananaVariety
from .models import DetectionRecord
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from django.conf import settings
from django.core.mail import EmailMessage
from django.utils import timezone
from escan.middleware import supabase_login_required
from django.urls import reverse
from .models import PasswordReset
from django.contrib.auth.hashers import make_password
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json, uuid
import torchvision.transforms as transforms
from django.views.decorators.http import require_POST
from .forms import StoreForm,ProductForm,UserProfileForm,ShippingAddressForm,MessageForm,StoreValidationForm
from .supabase_helper import upload_image_to_supabase
import logging
from django.core.files.storage import FileSystemStorage
import io
import base64
from PIL import Image as PILImage
import torch
import torchvision.models as models
from torchvision import transforms
from datetime import datetime, timedelta
from io import BytesIO
import tempfile
from decimal import Decimal
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from django.templatetags.static import static
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from django.db.models import Sum, Count, Q , Avg
from django.contrib.staticfiles import finders  # For finding static files
from .models import Thread, Message
from django.db.models import OuterRef, Subquery, Max
import torch.nn as nn
from torchvision import models, transforms
from .forms import ImageUploadForm
import torch.serialization
import numpy as np
from django.http import StreamingHttpResponse
from django.db import transaction


from geopy.distance import geodesic

from .models import (
    Product, Store, Customer, ShippingAddress, Order, Payment,
    CustomerPurchase, ShippingRule, PostalCodeLocation
)

from .models import ShippingAddress
from .forms import ShippingAddressForm

# Track last action (undo support)
last_action = {}



logger = logging.getLogger(__name__)



User = get_user_model()

# Load environment variables
load_dotenv()
SUPABASE_URL = settings.SUPABASE_URL
SUPABASE_API_KEY = settings.SUPABASE_API_KEY
SUPABASE_BUCKET = "product-images"
# SUPABASE_BUCKET = "uploads"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_API_KEY)
# Supabase Credentials
OPENWEATHER_API_KEY = settings.OPENWEATHER_API_KEY
# Renders Pages
# Landing Page
def landing_page(request):
    return render(request, 'landing.html')
# Scan Signup & Login
def signup(request):
    return render(request, "escan/User/signup.html")
# Login
def login(request):
    return render(request, "escan/login.html")
# Base
def fnavbase(request):
    return render(request, "escan/Fnavbase.html")
def a_scan_nav(request):
    return render(request, "escan/a_scan_nav.html")

def m_sidenav(request):
    return render(request, "escan/m_sidenav.html")


def a_side_nav(request):
    return render(request, "escan/a_side_nav.html")
# Forgot Passwords
def ForgotPassword(request):
    if request.method == "POST":
        email = request.POST.get('email')

        try:
            user = User.objects.get(email=email)

            new_password_reset = PasswordReset(user=user)
            new_password_reset.save()
            password_reset_url = reverse('reset-password', kwargs={'reset_id': new_password_reset.reset_id})

            full_password_reset_url = f'{request.scheme}://{request.get_host()}{password_reset_url}'

            context = {
                'user': user,
                'reset_url': full_password_reset_url,
            }

            email_body = render_to_string('escan/email/password_reset_email.html', context)

            email_message = EmailMessage(
                'Reset your password',
                email_body,
                settings.EMAIL_HOST_USER, 
                [email]
            )

            email_message.content_subtype = "html"

            email_message.fail_silently = True
            email_message.send()

            return redirect('password-reset-sent', reset_id=new_password_reset.reset_id)

        except User.DoesNotExist:
            messages.error(request, f"No user with email '{email}' found")
            return redirect('forgot-password')

    return render(request, 'escan/email/forgot_password.html')
def PasswordResetSent(request, reset_id):
    if PasswordReset.objects.filter(reset_id=reset_id).exists():
        return render(request, 'escan/email/password_reset_sent.html')
    else:
        messages.error(request, 'Invalid reset id')
        return redirect('forgot-password')

def ResetPassword(request, reset_id):
    try:
        reset_entry = PasswordReset.objects.get(reset_id=reset_id)
        user = reset_entry.user

        if request.method == "POST":
            new_password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            if new_password == confirm_password:
                user.password = make_password(new_password)  # ✅ Hash password before saving
                user.save()

                messages.success(request, "Password reset successful! You can now log in.")
                return redirect('login')
            else:
                messages.error(request, "Passwords do not match!")

        return render(request, 'escan/email/reset_password.html', {'reset_id': reset_id})

    except PasswordReset.DoesNotExist:
        messages.error(request, 'Invalid reset link.')
        return redirect('forgot-password')
    
# Messaging 

def inbox(request):
    # Get all messages for the current logged-in user
    messages = Message.objects.filter(receiver=request.user).order_by('-timestamp')

    # Logic to filter users based on role
    if request.user.role == 'User':
        receivers = CustomUser.objects.filter(role='Admin')
    elif request.user.role == 'Admin':
        receivers = CustomUser.objects.filter(role='User')
    else:
        receivers = CustomUser.objects.none()  # No receivers for other roles

    # Pass receivers to the form dynamically
    form = MessageForm()
    form.fields['receiver'].queryset = receivers  # Filter the receiver field

    if request.method == 'POST':
        form = MessageForm(request.POST)
        if form.is_valid():
            receiver = form.cleaned_data['receiver']
            content = form.cleaned_data['content']
            subject = form.cleaned_data['subject']

            logging.debug(f"Form valid. Receiver: {receiver}, Content: {content}, Subject: {subject}")

            # Create a new thread if it doesn't exist
            thread, created = Thread.objects.get_or_create(user=request.user, admin=receiver)

            # Create the message and save it
            Message.objects.create(
                thread=thread,
                sender=request.user,
                receiver=receiver,
                content=content,
                subject=subject
            )
            logging.debug(f"Message created.")
            return redirect('inbox')
        else:
            logging.debug(f"Form errors: {form.errors}")
            return HttpResponse("Form is not valid")

    return render(request, 'escan/messages/inbox.html', {'messages': messages, 'form': form, 'receivers': receivers})

def unread_message_count(request):
    # Count all unread messages for the badge
    unread_count = Message.objects.filter(receiver=request.user, is_read=False).count()

    # Get the latest message for each sender to this user
    latest_msg_subquery = Message.objects.filter(
        receiver=request.user,
        is_read=False,
        sender=OuterRef('sender')
    ).order_by('-timestamp')

    # Get latest messages by each sender
    latest_messages = Message.objects.filter(
        id__in=Subquery(
            latest_msg_subquery.values('id')[:1]
        )
    ).order_by('-timestamp')[:5]  # Limit to top 5 most recent latest messages

    unread_messages_data = [
        {
            'thread_id': msg.thread.id,
            'sender_image_url': msg.sender.image_url.url if msg.sender.image_url else '',
            'sender_username': msg.sender.username,
            'content': msg.content[:30],
            'is_read': msg.is_read,
        }
        for msg in latest_messages
    ]

    return JsonResponse({
        'unread_count': unread_count,
        'unread_messages': unread_messages_data
    })

def mark_messages_as_read(request):
    Message.objects.filter(receiver=request.user, is_read=False).update(is_read=True)
    return JsonResponse({'status': 'success'})

def thread_view(request, thread_id):
    thread = Thread.objects.get(id=thread_id)
    
    # Update 'is_read' flag for messages when viewed
    thread.messages.filter(receiver=request.user, is_read=False).update(is_read=True)
    messages = thread.messages.all()
    unread_messages = thread.messages.filter(receiver=request.user, is_read=False)

    if request.method == "POST":
        form = MessageForm(request.POST)
        if form.is_valid():
            message = form.save(commit=False)
            message.sender = request.user  # Set the logged-in user as the sender
            message.thread = thread
            message.receiver = thread.admin  # The receiver of the message (admin or user)
            message.save()

            return redirect('thread_view', thread_id=thread.id)
    
    else:
        # form = MessageForm()
        form = MessageForm(user=request.user)

    return render(request, 'escan/messages/thread.html', {'thread': thread, 'messages': messages, 'form': form, 'unread_messages': unread_messages})

def send_message(request):
    if request.method == "POST":
        form = MessageForm(request.POST)
        if form.is_valid():
            message = form.save(commit=False)
            message.sender = request.user  # Set the logged-in user as the sender

            # Get the receiver and make sure the thread is appropriately assigned.
            receiver = form.cleaned_data['receiver']
            message.receiver = receiver

            # Check if a thread exists between the user and receiver. Create one if necessary.
            thread, created = Thread.objects.get_or_create(user=request.user, admin=receiver)

            # Assign the thread to the message.
            message.thread = thread
            message.save()

            return redirect('thread_view', thread_id=thread.id)  # Redirect to the thread view
    else:
        form = MessageForm()

    return render(request, 'escan/messages/inbox.html', {'form': form})


@csrf_exempt  # Optional if you're manually handling CSRF (best to keep CSRF check!)
def mark_single_message_as_read(request):
    if request.method == "POST":
        data = json.loads(request.body)
        thread_id = data.get('thread_id')
        Message.objects.filter(thread_id=thread_id, receiver=request.user, is_read=False).update(is_read=True)
        return JsonResponse({'status': 'marked'})
    return JsonResponse({'error': 'Invalid request'}, status=400)

def latest_message_for_thread(request):
    # Step 1: Get the latest messages per thread+sender to this user
    latest_messages = (
        Message.objects
        .filter(receiver=request.user)
        .values('sender__username', 'thread__id')
        .annotate(latest_time=Max('timestamp'))
    )

    # Step 2: Collect the actual message content + is_read flag
    data = []
    for msg in latest_messages:
        message = (
            Message.objects
            .filter(
                sender__username=msg['sender__username'],
                thread_id=msg['thread__id'],
                receiver=request.user  # Ensures it’s a message TO the current user
            )
            .order_by('-timestamp')
            .first()
        )

        if message:
            data.append({
                'sender': msg['sender__username'],
                'content': message.content,
                'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M'),
                'thread_id': msg['thread__id'],
                'is_read': message.is_read,
            })

    # Step 3: Sort unread messages first, then newest to oldest
    data.sort(key=lambda x: (x['is_read'], -int("".join(x['timestamp'].replace("-", "").replace(":", "").replace(" ", "")))))

    return JsonResponse(data, safe=False)

def thread_placeholder(request):
    messages = (
        Message.objects.filter(receiver=request.user)
        .order_by('-timestamp')
    )

    latest_by_sender = {}
    for msg in messages:
        if msg.sender_id not in latest_by_sender:
            latest_by_sender[msg.sender_id] = msg

    form = MessageForm(user=request.user)  # Pass user here

    return render(request, 'escan/messages/thread.html', {
        'thread': None,
        'messages': [],
        'latest_messages': latest_by_sender.values(),
        'form': form
    })


@login_required
def compose_message(request):
    if request.method == 'POST':
        subject = request.POST.get('subject')
        content = request.POST.get('content')
        current_user = request.user

        # Determine the recipient based on role
        if current_user.role == 'Admin':
            receiver = User.objects.filter(role='User', is_deleted=False).exclude(id=current_user.id).first()
        else:
            receiver = User.objects.filter(role='Admin', is_deleted=False).exclude(id=current_user.id).first()

        if not receiver:
            # Handle if there's no receiver found
            messages.error(request, "No recipient available.")
            return redirect('inbox')

        # Try to find existing thread
        thread = Thread.objects.filter(user__in=[current_user, receiver], admin__in=[current_user, receiver]).first()
        if not thread:
            if current_user.role == 'Admin':
                thread = Thread.objects.create(user=receiver, admin=current_user)
            else:
                thread = Thread.objects.create(user=current_user, admin=receiver)

        # Create and save the message
        Message.objects.create(
            thread=thread,
            sender=current_user,
            receiver=receiver,
            content=content
        )

        return redirect('thread_placeholder')


# Login Admin/Farmers/MarketEntity
# def login_view(request):
#     if request.method == "POST":
#         username = request.POST.get("username")
#         password = request.POST.get("password")
#         # Authenticate user
#         user = authenticate(request, username=username, password=password)
#         if user is not None:
#             # Log the user in BEFORE redirecting
#             auth_login(request, user)
#             # Ensure role is set if it's not set
#             if not user.role:
#                 user.role = "User"
#                 user.save()
#             # Redirect based on role
#             if user.role == "Admin":
#                 return redirect("admin_dashboard")
#             else:
#                 return redirect("user_dashboard")
#         else:
#             messages.error(request, "Invalid username or password.")
#             return redirect("login")
#     return render(request, "login.html")
def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        # Authenticate user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Log the user in
            auth_login(request, user)

            # Ensure role is set (default: User)
            if not user.role:
                user.role = "Farmer"
                user.save()

            # Redirect based on role
            if user.role == "Admin":
                return redirect("admin_dashboard")
            elif user.role == "Farmer":
                return redirect("farmer_dashboard")
            elif user.role == "Market-entity":
                return redirect("market_landing")
            else:
                messages.warning(request, "No dashboard assigned to your role.")
                return redirect("login")
        else:
            messages.error(request, "Invalid username or password.")
            return redirect("login")

    return render(request, "login.html")


# Logout
def user_logout(request):
    logout(request)
    messages.success(request, "You have successfully logged out.")
    return redirect('login')  # Redirect to login page after logout

# SignUp
def signup_view(request):
    if request.method == "POST":
        form = UserProfileForm(request.POST, request.FILES)  # Use the form to handle POST data
        if form.is_valid():
            # Check if username or email already exists
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            if CustomUser .objects.filter(username=username).exists():
                messages.error(request, "Username is already taken.")
                return redirect("signup_view")
            if CustomUser .objects.filter(email=email).exists():
                messages.error(request, "Email is already registered.")
                return redirect("signup_view")
            # Save the user
            form.save()
            messages.success(request, "Account created successfully! Please log in.")
            return redirect("login")  # Redirect to the login page after successful signup
        else:
            messages.error(request, "Form is invalid. Please correct the errors.")
    else:
        form = UserProfileForm()  # Create an empty form instance
    return render(request, "signup.html", {'form': form})




# ----------------------------------------------------------------------------
# Market Entity
def m_setting(request):
    return render(request, "escan/Market_Entity/m_setting.html")

@login_required
def market_landing(request):
    return render(request, 'escan/Market_Entity/market_landing.html')


#Market Entity Marketplace  marketplace_dashboard
@login_required
def marketplace_dashboard(request):
    return render(request, 'escan/Market_Entity/E-commerce/Marketplace/marketplace_dashboard.html')

@login_required
def market_place(request):
    # customer, created = Customer.objects.get_or_create(user=request.user)
    # cart, created = Cart.objects.get_or_create(customer=customer, completed=False)
    cart = Cart.objects.filter(customer=request.user, completed=False).first()
    products = Product.objects.filter(is_deleted=False) 
    return render(request, 'escan/Market_Entity/E-commerce/Marketplace/market_place.html', {'products': products, 'cart': cart, 'cart_item_count': cart.get_item_total if cart else 0,})

@login_required
def my_orders_part(request):
    # --- Store detection ---
    admin_store = None
    if hasattr(request.user, 'store_owner'):
        admin_store = request.user.store_owner
    elif hasattr(request.user, 'store'):
        admin_store = request.user.store
    elif hasattr(request.user, 'stores') and request.user.stores.exists():
        admin_store = request.user.stores.first()

    # --- Filters ---
    today = datetime.today()
    month = int(request.GET.get("month", today.month))
    year = int(request.GET.get("year", today.year))

    # --- Base queries ---
    new_orders = Order.objects.filter(customer=request.user, status='Pending')
    total_orders = Order.objects.filter(customer=request.user).exclude(status='Pending')
    if admin_store:
        customer_orders = Order.objects.filter(store=admin_store).exclude(customer=request.user)
    else:
        customer_orders = Order.objects.none()

    # --- Calendar grid for the month ---
    cal = calendar.Calendar(firstweekday=6)  # Sunday start
    month_days = cal.monthdatescalendar(year, month)  # 2D weeks grid

    calendar_data = []
    if admin_store:
        orders = Order.objects.filter(store=admin_store)

        # Top offsets for each status
        status_top_map = {
            "Pending": 5,
            "On Process": 30,
            "Delivered": 55,
            "Completed": 80,
        }

        for week in month_days:
            week_data = []
            bars = []

            # Map day -> column index (1..7 for CSS grid)
            day_to_col = {day: idx + 1 for idx, day in enumerate(week)}

            # --- Bars for orders ---
            for order in orders:
                top_offset = 0

                # Pending = single day
                if order.status == "Pending" and order.order_date:
                    top_offset = status_top_map["Pending"]
                    if order.order_date.date() in week:
                        col = day_to_col[order.order_date.date()]
                        bars.append({
                            "type": "pending",
                            "label": f"#{order.id}",
                            "start_col": col,
                            "end_col": col + 1,
                            "top": top_offset
                        })

                # On Process = range (process_start → process_end)
                elif order.status == "On Process" and order.process_start and order.process_end:
                    top_offset = status_top_map["On Process"]
                    start = max(order.process_start.date(), week[0])
                    end = min(order.process_end.date(), week[-1])
                    if start <= end:
                        bars.append({
                            "type": "process",
                            "label": f"#{order.id}",
                            "start_col": day_to_col[start],
                            "end_col": day_to_col[end] + 1,
                            "top": top_offset
                        })

                # Delivered = range (delivery_start → delivery_end)
                elif order.status == "Delivered" and order.delivery_start and order.delivery_end:
                    top_offset = status_top_map["Delivered"]
                    start = max(order.delivery_start.date(), week[0])
                    end = min(order.delivery_end.date(), week[-1])
                    if start <= end:
                        bars.append({
                            "type": "delivery",
                            "label": f"#{order.id}",
                            "start_col": day_to_col[start],
                            "end_col": day_to_col[end] + 1,
                            "top": top_offset
                        })

                # Completed = single day
                elif order.status == "Completed" and order.completion_date:
                    top_offset = status_top_map["Completed"]
                    if order.completion_date.date() in week:
                        col = day_to_col[order.completion_date.date()]
                        bars.append({
                            "type": "completed",
                            "label": f"#{order.id}",
                            "start_col": col,
                            "end_col": col + 1,
                            "top": top_offset
                        })

            # --- Day data for this week ---
            for day in week:
                day_data = {
                    "date": day,
                    "is_current_month": (day.month == month)
                }
                week_data.append(day_data)

            # Push week into calendar_data
            calendar_data.append({
                "days": week_data,
                "bars": bars
            })

    context = {
        "new_orders": new_orders,
        "total_orders": total_orders,
        "customer_orders": customer_orders,
        "calendar_data": calendar_data,   # each week has days + bars
        "current_month": month,
        "current_year": year,
        "now": today,
    }
    return render(request, "escan/Market_Entity/E-commerce/Marketplace/my_orders_part.html", context)

@login_required
def customer_detail(request, customer_id):
    try:
        store = Store.objects.get(owner=request.user)
        customer = get_object_or_404(Customer, pk=customer_id, order__store=store)
        
        # Get customer's order history for this store
        orders = Order.objects.filter(
            store=store, 
            customer=customer,
            status="Completed"
        ).order_by('-order_date')
        
        # Calculate customer metrics
        total_spent = orders.aggregate(total=Sum('total_amount'))['total'] or 0
        order_count = orders.count()
        avg_order_value = total_spent / order_count if order_count > 0 else 0
        
        context = {
            'customer': customer,
            'orders': orders,
            'total_spent': total_spent,
            'order_count': order_count,
            'avg_order_value': avg_order_value,
        }
        
        return render(request, 'escan/Market_Entity/E-commerce/MyStore/customer_detail.html', context)
        
    except Store.DoesNotExist:
        return redirect('my_store_dashboard')
    
# Market Entity Customer List
# def u_customer_table(request):
#     try:
#         store = Store.objects.get(owner=request.user)
        
#         # Get customers with their order statistics
#         customers = Customer.objects.filter(
#             order__store=store
#         ).annotate(
#             order_count=Count('order', filter=Q(order__store=store)),
#             total_spent=Sum('order__total_amount', filter=Q(order__store=store, order__status="Completed")),
#             last_order_date=Max('order__order_date', filter=Q(order__store=store))
#         ).distinct().order_by('-last_order_date')
        
#         # Calculate average order value for each customer
#         for customer in customers:
#             customer.avg_order_value = 0
#             if customer.order_count and customer.order_count > 0 and customer.total_spent:
#                 customer.avg_order_value = customer.total_spent / customer.order_count
        
#     except Store.DoesNotExist:
#         customers = Customer.objects.none()
    
#     # # Get the store owned by the currently logged-in user
#     # try:
#     #     store = Store.objects.get(owner=request.user)
        
#     #     # Get all orders for this store
#     #     store_orders = Order.objects.filter(store=store)
        
#     #     # Get all customers who placed these orders
#     #     customer_ids = store_orders.values_list('customer', flat=True).distinct()
#     #     customers = Customer.objects.filter(id__in=customer_ids).select_related('user')
        
#     # except Store.DoesNotExist:
#     #     # If the user doesn't have a store, return empty queryset
#     #     customers = Customer.objects.none()
    
#     return render(request, 'escan/Market_Entity/E-commerce/MyStore/u_customer_list.html', {
#         'customers': customers,
#     })
# @login_required
# def u_customer_table(request):
#     try:
#         store = Store.objects.get(owner=request.user)
        
#         # Get customers who have made purchases from this store
#         # Using the correct relationship field name (purchases instead of order)
#         customers = Customer.objects.filter(
#             purchases__store=store
#         ).annotate(
#             order_count=Count('purchases', filter=Q(purchases__store=store)),
#             total_spent=Sum('purchases__total_amount', filter=Q(purchases__store=store, purchases__status="Completed")),
#             last_order_date=Max('purchases__order_date', filter=Q(purchases__store=store))
#         ).distinct().order_by('-last_order_date')
        
#         # Calculate average order value for each customer
#         for customer in customers:
#             customer.avg_order_value = 0
#             if customer.order_count and customer.order_count > 0 and customer.total_spent:
#                 customer.avg_order_value = customer.total_spent / customer.order_count
        
#     except Store.DoesNotExist:
#         customers = Customer.objects.none()
    
#     return render(request, 'escan/Market_Entity/E-commerce/MyStore/u_customer_list.html', {
#         'customers': customers,
#     })

from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.db.models import Sum
from escan.models import Store, Customer, Order
from collections import defaultdict
from datetime import datetime

@login_required
def u_customer_table(request):
    try:
        store = Store.objects.get(owner=request.user)
        
        # Get all completed orders for this store
        completed_orders = Order.objects.filter(
            store=store, 
            status="Completed"
        ).select_related('customer')
        
        # Create a dictionary to track unique customers and their data
        customer_dict = {}
        
        for order in completed_orders:
            customer = order.customer
            
            if customer.id not in customer_dict:
                customer_dict[customer.id] = {
                    'customer': customer,
                    'order_count': 0,
                    'total_spent': 0,
                    'last_order_date': None
                }
            
            data = customer_dict[customer.id]
            data['order_count'] += 1
            data['total_spent'] += float(order.total_amount or 0)
            
            if not data['last_order_date'] or order.order_date > data['last_order_date']:
                data['last_order_date'] = order.order_date
        
        # Convert to list and calculate averages
        customers = []
        for data in customer_dict.values():
            customer = data['customer']
            customer.order_count = data['order_count']
            customer.total_spent = data['total_spent']
            customer.last_order_date = data['last_order_date']
            customer.avg_order_value = data['total_spent'] / data['order_count'] if data['order_count'] > 0 else 0
            customers.append(customer)
        
        # Sort by last order date (most recent first)
        customers.sort(key=lambda x: x.last_order_date or datetime.min, reverse=True)
        
    except Store.DoesNotExist:
        customers = []
    
    return render(request, 'escan/Market_Entity/E-commerce/MyStore/u_customer_list.html', {
        'customers': customers,
    })

def customer_print_preview(request, customer_id):
    """
    Preview the customer print layout before actual printing
    """
    # Ensure the customer belongs to the current store owner
    try:
        store = Store.objects.get(owner=request.user)
        customer = get_object_or_404(Customer, pk=customer_id, order__store=store)
    except Store.DoesNotExist:
        return HttpResponse("Store not found", status=404)
        
    context = {
        'customer': customer,
        'preview_mode': True,
    }
    return render(request, 'customers/print_template.html', context)

def customer_print(request, customer_id):
    """
    Generate a PDF for a single customer and return it as a download
    """
    # Ensure the customer belongs to the current store owner
    try:
        store = Store.objects.get(owner=request.user)
        customer = get_object_or_404(Customer, pk=customer_id, order__store=store)
    except Store.DoesNotExist:
        return HttpResponse("Store not found", status=404)
        
    context = {
        'customer': customer,
        'preview_mode': False,
    }
    
    # Render HTML template
    html_string = render_to_string('customers/print_template.html', context)
    
    # Generate PDF
    html = HTML(string=html_string, base_url=request.build_absolute_uri())
    pdf = html.write_pdf()
    
    # Create response
    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="customer_{customer_id}.pdf"'
    return response

def print_selected_customers(request):
    """
    Handle bulk printing of multiple customers
    """
    if request.method == 'POST':
        # Ensure the customers belong to the current store owner
        try:
            store = Store.objects.get(owner=request.user)
            customer_ids = request.POST.getlist('customer_ids')
            customers = Customer.objects.filter(
                id__in=customer_ids, 
                order__store=store
            ).distinct()
        except Store.DoesNotExist:
            return HttpResponse("Store not found", status=404)
        
        if not customers.exists():
            return HttpResponse("No customers selected", status=400)
            
        context = {
            'customers': customers,
            'preview_mode': False,
        }
        
        # Render HTML template
        html_string = render_to_string('customers/bulk_print_template.html', context)
        
        # Generate PDF
        html = HTML(string=html_string, base_url=request.build_absolute_uri())
        pdf = html.write_pdf()
        
        # Create response
        response = HttpResponse(pdf, content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="customers_bulk_print.pdf"'
        return response
    
    return HttpResponse("Invalid request method", status=405)




# ------------------------------------------------------------------------------------------
#Market Entity Mystore 
# @login_required
# def my_store_dashboard(request):
#     return render(request, 'escan/Market_Entity/E-commerce/MyStore/my_store_dashboard.html')
from django.db.models import Sum, Count, Q
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal
import json
from .models import Product, Order, CustomerPurchase, Store

@login_required
def my_store_dashboard(request):
    # Check if user has a store
    try:
        store = Store.objects.get(owner=request.user)
    except Store.DoesNotExist:
        return render(request, 'escan/Market_Entity/E-commerce/MyStore/my_store_dashboard.html', {
            'no_store': True
        })

    # Current date for calculations
    today = timezone.now().date()
    week_ago = today - timedelta(days=7)
    month_ago = today - timedelta(days=30)
    year_ago = today - timedelta(days=365)

    # ========== CUSTOMER METRICS ==========
    # Total unique customers who bought from your store (completed orders only)
    total_customers = Order.objects.filter(
        store=store, 
        status="Completed"
    ).values('customer').distinct().count()

    # New customers this month
    new_customers_month = Order.objects.filter(
        store=store,
        status="Completed",
        order_date__gte=month_ago
    ).values('customer').distinct().count()

    # Repeat customers (customers with more than 1 completed order)
    from django.db.models import Count
    repeat_customers = Order.objects.filter(
        store=store,
        status="Completed"
    ).values('customer').annotate(
        order_count=Count('id')
    ).filter(order_count__gt=1).count()

    # ========== SALES & REVENUE METRICS ==========
    # Total sales revenue (all completed orders)
    total_sales = Order.objects.filter(
        store=store, 
        status="Completed"
    ).aggregate(total_sales=Sum("total_amount"))["total_sales"] or 0

    # Today's sales
    today_sales = Order.objects.filter(
        store=store,
        status="Completed",
        order_date__date=today
    ).aggregate(total_sales=Sum("total_amount"))["total_sales"] or 0

    # Weekly sales
    weekly_sales = Order.objects.filter(
        store=store,
        status="Completed", 
        order_date__gte=week_ago
    ).aggregate(total_sales=Sum("total_amount"))["total_sales"] or 0

    # Monthly sales
    monthly_sales = Order.objects.filter(
        store=store,
        status="Completed",
        order_date__gte=month_ago
    ).aggregate(total_sales=Sum("total_amount"))["total_sales"] or 0

    # Yearly sales
    yearly_sales = Order.objects.filter(
        store=store,
        status="Completed", 
        order_date__gte=year_ago
    ).aggregate(total_sales=Sum("total_amount"))["total_sales"] or 0

    # ========== STOCK METRICS ==========
    # Total products in stock
    total_stocks = Product.objects.filter(store=store).aggregate(
        total_stock=Sum('stock')
    )['total_stock'] or 0

    # Low stock products (less than 10)
    low_stock_products = Product.objects.filter(
        store=store,
        stock__lt=10,
        stock__gt=0
    ).count()

    # Out of stock products
    out_of_stock_products = Product.objects.filter(
        store=store,
        stock=0
    ).count()

    # Stock value (total value of all inventory)
    stock_value = Product.objects.filter(store=store).aggregate(
        total_value=Sum('price') * Sum('stock')
    )['total_value'] or 0

    # ========== ORDER METRICS ==========
    total_orders = Order.objects.filter(store=store).count()
    completed_orders = Order.objects.filter(store=store, status="Completed").count()
    pending_orders = Order.objects.filter(store=store, status="Pending").count()

    # ========== SALES CHART DATA ==========
    # Weekly sales data for chart (last 7 days)
    weekly_sales_data = []
    for i in range(7):
        date = today - timedelta(days=i)
        day_sales = Order.objects.filter(
            store=store,
            status="Completed",
            order_date__date=date
        ).aggregate(
            total_sales=Sum('total_amount'),
            order_count=Count('id')
        )
        weekly_sales_data.append({
            'date': date.strftime('%Y-%m-%d'),
            'day': date.strftime('%a'),
            'total_sales': float(day_sales['total_sales'] or 0),
            'order_count': day_sales['order_count'] or 0
        })
    weekly_sales_data.reverse()

    # Monthly sales data (last 12 months)
    monthly_sales_data = []
    for i in range(12):
        month_start = today.replace(day=1) - timedelta(days=30*i)
        month_end = (month_start + timedelta(days=32)).replace(day=1) - timedelta(days=1)
        
        month_sales = Order.objects.filter(
            store=store,
            status="Completed",
            order_date__range=[month_start, month_end]
        ).aggregate(
            total_sales=Sum('total_amount')
        )
        monthly_sales_data.append({
            'month': month_start.strftime('%b %Y'),
            'total_sales': float(month_sales['total_sales'] or 0)
        })
    monthly_sales_data.reverse()

    # ========== TOP PRODUCTS ==========
    top_products = Product.objects.filter(
        store=store,
        order__status="Completed"
    ).annotate(
        total_sold=Sum('order__quantity'),
        total_revenue=Sum('order__total_amount')
    ).order_by('-total_sold')[:5]

    # ========== ORDER STATUS DISTRIBUTION ==========
    order_status_data = []
    statuses = ['Pending', 'On Process', 'Delivered', 'Completed', 'Cancelled']
    for status in statuses:
        count = Order.objects.filter(store=store, status=status).count()
        order_status_data.append({
            'status': status,
            'count': count
        })

    context = {
        'store': store,
        
        # Customer metrics
        'total_customers': total_customers,
        'new_customers_month': new_customers_month,
        'repeat_customers': repeat_customers,
        
        # Sales & Revenue metrics
        'total_sales': total_sales,
        'today_sales': today_sales,
        'weekly_sales': weekly_sales,
        'monthly_sales': monthly_sales,
        'yearly_sales': yearly_sales,
        
        # Stock metrics
        'total_stocks': total_stocks,
        'low_stock_products': low_stock_products,
        'out_of_stock_products': out_of_stock_products,
        'stock_value': stock_value,
        
        # Order metrics
        'total_orders': total_orders,
        'completed_orders': completed_orders,
        'pending_orders': pending_orders,
        
        # Chart data
        'weekly_sales_data': weekly_sales_data,
        'weekly_sales_json': json.dumps(weekly_sales_data),
        'monthly_sales_json': json.dumps(monthly_sales_data),
        'order_status_json': json.dumps(order_status_data),
        
        # Top products
        'top_products': top_products,
    }
    
    return render(request, 'escan/Market_Entity/E-commerce/MyStore/my_store_dashboard.html', context)




# Market Entity
import uuid
# from .forms import StoreValidationForm
import traceback
# --------------------------------------------------------------------------------------------
#Market Entity Side Category
@login_required
def u_category_list(request):
    # Get categories only for stores owned by the current user
    user_stores = Store.objects.filter(owner=request.user)
    u_categories = Category.objects.filter(store__in=user_stores).order_by("name")
    return render(request, 'escan/Market_Entity/E-commerce/MyStore/u_category_list.html', {'u_categories': u_categories})

@csrf_exempt
@login_required
def u_add_category(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_stores = Store.objects.filter(owner=request.user)
            
            if not user_stores.exists():
                return JsonResponse({"error": "You need to have a store to create categories"}, status=403)
                
            # Use the first store (or you can modify to select specific store)
            store = user_stores.first()
            category = Category.objects.create(
                store=store,
                name=data["name"],
                description=data.get("description", "")
            )
            return JsonResponse({
                "id": category.id, 
                "name": category.name,
                "description": category.description
            }, status=201)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)

@csrf_exempt
@login_required
def u_edit_category(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    
    # Verify the category belongs to the user's store
    if category.store.owner != request.user:
        return JsonResponse({"error": "Unauthorized"}, status=403)
        
    if request.method == "POST":
        data = json.loads(request.body)
        category.name = data.get("name", category.name)
        category.description = data.get("description", category.description)
        category.save()
        return JsonResponse({
            "id": category.id, 
            "name": category.name,
            "description": category.description
        })

@csrf_exempt
@login_required
def u_delete_category(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    
    # Verify the category belongs to the user's store
    if category.store.owner != request.user:
        return JsonResponse({"error": "Unauthorized"}, status=403)
        
    category.delete()
    return JsonResponse({"message": "Category deleted successfully"})


# -------------------------------------------------------------------------------------------------------------------
# Market Entity Store Manage

@login_required
@require_POST
def apply_seller(request):
    """
    Handle seller application submission.
    Users can reapply if their previous application was rejected.
    """
    print("\n" + "="*50)
    print("APPLY SELLER VIEW CALLED")
    print("="*50)
    print(f"User: {request.user.username} (ID: {request.user.id})")
    print(f"Method: {request.method}")
    print(f"POST data: {request.POST}")
    print(f"FILES: {request.FILES}")
    print("="*50 + "\n")
    
    try:
        # Check for existing active applications (pending or approved)
        active_application = StoreValidation.objects.filter(
            store_owner=request.user,
            status__in=['pending', 'approved']
        ).order_by('-created_at').first()
        
        if active_application:
            print(f"Active application found. Status: {active_application.status}")
            
            if active_application.status == 'pending':
                return JsonResponse({
                    'success': False,
                    'message': 'You already have a pending application. Please wait for review.'
                }, status=400)
            elif active_application.status == 'approved':
                return JsonResponse({
                    'success': False,
                    'message': 'You are already an approved seller.'
                }, status=400)
        
        # Check if user had a rejected application
        rejected_apps_count = StoreValidation.objects.filter(
            store_owner=request.user,
            status='rejected'
        ).count()
        
        if rejected_apps_count > 0:
            print(f"User has {rejected_apps_count} rejected application(s). Allowing reapplication.")

        # Create and validate form
        form = StoreValidationForm(request.POST, request.FILES)
        
        print("\n--- Form Validation ---")
        if form.is_valid():
            print("✅ Form is valid")
            print(f"Cleaned data: {form.cleaned_data}")
            
            try:
                # Save with user context
                validation = form.save(commit=False, user=request.user)
                validation.store_owner = request.user
                validation.status = 'pending'
                validation.save()
                
                print(f"✅ Application saved successfully!")
                print(f"Validation ID: {validation.id}")
                print(f"Store Owner: {validation.store_owner.username}")
                print(f"Status: {validation.status}")
                print(f"ID Picture URL: {validation.id_picture}")
                print("="*50 + "\n")
                
                return JsonResponse({
                    'success': True,
                    'message': 'Application submitted successfully! Your application is under review.'
                })
                
            except IntegrityError as e:
                print(f"\n❌ INTEGRITY ERROR:")
                print(f"Error: {e}")
                traceback.print_exc()
                return JsonResponse({
                    'success': False,
                    'message': 'You already have an active application. Please try again later.'
                }, status=400)
                
            except Exception as save_error:
                print(f"\n❌ ERROR SAVING APPLICATION:")
                print(f"Error type: {type(save_error).__name__}")
                print(f"Error message: {str(save_error)}")
                traceback.print_exc()
                
                return JsonResponse({
                    'success': False,
                    'message': f'Error saving application: {str(save_error)}'
                }, status=500)
                
        else:
            print("❌ Form is INVALID")
            print(f"Form errors: {form.errors.as_json()}")
            
            # Convert errors to a more readable format
            error_dict = {}
            for field, errors in form.errors.items():
                error_dict[field] = [str(error) for error in errors]
            
            return JsonResponse({
                'success': False,
                'message': 'Please correct the errors below',
                'errors': error_dict
            }, status=400)
            
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR:")
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        traceback.print_exc()
        
        return JsonResponse({
            'success': False,
            'message': f'An unexpected error occurred: {str(e)}'
        }, status=500)



# ==================== HELPER FUNCTIONS ====================

def get_user_application_status(user):
    """
    Helper function to get user's current application status.
    Returns a dict with status information.
    """
    latest_validation = StoreValidation.objects.filter(
        store_owner=user
    ).order_by('-created_at').first()
    
    if not latest_validation:
        return {
            'has_application': False,
            'status': None,
            'can_apply': True,
            'can_create_store': False
        }
    
    return {
        'has_application': True,
        'status': latest_validation.status,
        'can_apply': latest_validation.status == 'rejected',
        'can_create_store': latest_validation.status == 'approved',
        'application_id': latest_validation.id,
        'created_at': latest_validation.created_at
    }

#Market Entity Manage Products/Stocks
@login_required
def u_product_list(request):
    try:
        # Get the user's store if it exists
        store = request.user.store
        products = Product.objects.filter(store=store, is_deleted=False).select_related('category')
        # Get all categories (shared across all users)
        categories = Category.objects.all()
    except (Store.DoesNotExist, AttributeError):
        products = Product.objects.none()
        categories = Category.objects.none()
        if not hasattr(request, 'warning_message'):
            messages.warning(request, "You need to create a store first before adding products")

    context = {
        'products': products,
        'categories': categories,
        'has_store': hasattr(request.user, 'store')
    }
    return render(request, "escan/Market_Entity/E-commerce/MyStore/my_store.html", context)


@login_required
def u_product_print(request):
    try:
        store = request.user.store
        products = Product.objects.filter(store=store, is_deleted=False).select_related('category')
    except Store.DoesNotExist:
        products = Product.objects.none()
    
    context = {
        'products': products,
        'store': getattr(request.user, 'store', None)
    }
    return render(request, "escan/Market_Entity/E-commerce/MyStore/product_print.html", context)

@login_required
@require_POST
def u_create_store(request):
    """Create a new store for an approved seller"""
    print(f"\n{'='*50}")
    print(f"CREATE STORE REQUEST from {request.user.username}")
    print(f"{'='*50}")
    print(f"POST data: {request.POST}")
    print(f"FILES: {request.FILES}")
    
    try:
        approved_validation = StoreValidation.objects.filter(
            store_owner=request.user,
            status='approved'
        ).first()
        
        if not approved_validation:
            print("❌ No approved seller validation found")
            return JsonResponse({
                'success': False,
                'message': 'Your seller application must be approved first before creating a store.'
            }, status=403)
        
        if hasattr(request.user, 'store') and request.user.store:
            print("❌ User already has a store")
            return JsonResponse({
                'success': False,
                'message': 'You already have a store. Use the update function instead.'
            }, status=400)

        form = StoreForm(request.POST, request.FILES, request=request)
        
        print("\n--- Form Validation ---")
        if form.is_valid():
            print("✅ Form is valid")
            try:
                store = form.save()
                
                print(f"✅ Store created successfully!")
                print(f"Store ID: {store.id}")
                print(f"Store Name: {store.name}")
                print(f"Store Owner: {store.owner.username}")
                
                return JsonResponse({
                    'success': True,
                    'message': 'Store created successfully! You can now add products.'
                })
            except Exception as e:
                print(f"❌ Error saving store: {e}")
                traceback.print_exc()
                return JsonResponse({
                    'success': False,
                    'message': f'Error creating store: {str(e)}'
                }, status=500)
        else:
            print("❌ Form validation failed")
            print(f"Form errors: {form.errors.as_json()}")
            
            error_dict = {}
            for field, errors in form.errors.items():
                error_dict[field] = [str(error) for error in errors]
            
            return JsonResponse({
                'success': False,
                'message': 'Please correct the errors below',
                'errors': error_dict
            }, status=400)
            
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'message': f'An unexpected error occurred: {str(e)}'
        }, status=500)


@login_required
def my_store(request):
    """
    Main view for store management page.
    Shows different states based on user's seller application status.
    """
    user = request.user
    
    # Get user's latest application status
    latest_validation = StoreValidation.objects.filter(
        store_owner=user
    ).order_by('-created_at').first()
    
    # Determine application status
    has_seller_application = latest_validation is not None
    is_approved_seller = latest_validation and latest_validation.status == 'approved'
    is_pending_seller = latest_validation and latest_validation.status == 'pending'
    is_rejected_seller = latest_validation and latest_validation.status == 'rejected'
    
    # Check if user has a store
    has_store = hasattr(user, 'store') and user.store is not None
    
    # Get products if store exists
    products = []
    if has_store:
        products = Product.objects.filter(store=user.store).select_related('category')
    
    # Get categories
    categories = Category.objects.all()
    
    context = {
        'has_seller_application': has_seller_application,
        'is_approved_seller': is_approved_seller,
        'is_pending_seller': is_pending_seller,
        'is_rejected_seller': is_rejected_seller,
        'has_store': has_store,
        'products': products,
        'categories': categories,
        'application_status': latest_validation.status if latest_validation else None,
        'rejection_reason': latest_validation.rejection_reason if is_rejected_seller else None,
    }
    
    return render(request, 'escan/Market_Entity/E-commerce/MyStore/my_store.html', context)

@login_required
@require_POST
def u_update_store(request):
    """Update existing store information"""
    print(f"\n{'='*60}")
    print(f"UPDATE STORE REQUEST")
    print(f"User: {request.user.username}")
    print(f"User ID: {request.user.id}")
    print(f"Method: {request.method}")
    print(f"{'='*60}")
    
    # Debug request data
    print("\nREQUEST.POST data:")
    for key, value in request.POST.items():
        print(f"  {key}: {value}")
    
    print("\nREQUEST.FILES data:")
    for key, file in request.FILES.items():
        if hasattr(file, 'name'):
            print(f"  {key}: {file.name} ({file.size} bytes, {file.content_type})")
        else:
            print(f"  {key}: {file}")
    
    try:
        if not hasattr(request.user, 'store') or not request.user.store:
            print("❌ User doesn't have a store")
            return JsonResponse({
                'success': False,
                'message': 'You don\'t have a store to update. Please create one first.'
            }, status=400)

        store_instance = request.user.store
        print(f"\nEXISTING STORE:")
        print(f"  Store ID: {store_instance.id}")
        print(f"  Store Name: {store_instance.name}")
        print(f"  Current Logo URL: {store_instance.logo}")
        
        form = StoreForm(
            request.POST, 
            request.FILES, 
            request=request, 
            instance=store_instance
        )
        
        print(f"\nFORM STATUS:")
        print(f"  Is bound: {form.is_bound}")
        print(f"  Is valid: {form.is_valid()}")
        
        if form.is_valid():
            print("\n✅ FORM IS VALID")
            print(f"Cleaned data keys: {list(form.cleaned_data.keys())}")
            
            # Check logo specifically
            if 'logo' in form.cleaned_data:
                logo = form.cleaned_data['logo']
                print(f"Logo in cleaned_data: {logo}")
                if logo:
                    print(f"Logo details - Name: {logo.name}, Size: {logo.size}")
            
            try:
                print("\nSAVING FORM...")
                updated_store = form.save()
                
                print(f"\n✅ STORE UPDATED SUCCESSFULLY")
                print(f"  Store ID: {updated_store.id}")
                print(f"  Store Name: {updated_store.name}")
                print(f"  New Logo URL: {updated_store.logo}")
                print(f"  Changed fields: {form.changed_data}")
                
                return JsonResponse({
                    'success': True,
                    'message': 'Store updated successfully!',
                    'latitude': updated_store.latitude,
                    'longitude': updated_store.longitude,
                    'logo_url': updated_store.logo  # Send back for debugging
                })
            except Exception as e:
                print(f"\n❌ ERROR SAVING FORM: {e}")
                import traceback
                traceback.print_exc()
                return JsonResponse({
                    'success': False,
                    'message': f'Error updating store: {str(e)}'
                }, status=500)
        else:
            print("\n❌ FORM VALIDATION FAILED")
            print(f"Form errors: {form.errors}")
            print(f"Form non-field errors: {form.non_field_errors()}")
            
            error_dict = {}
            for field, errors in form.errors.items():
                error_dict[field] = [str(error) for error in errors]
            
            return JsonResponse({
                'success': False,
                'message': 'Please correct the errors below',
                'errors': error_dict
            }, status=400)
            
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'message': f'An unexpected error occurred: {str(e)}'
        }, status=500)
    
# @login_required
# @require_POST
# def u_update_store(request):
#     """Update existing store information"""
#     print(f"\n{'='*50}")
#     print(f"UPDATE STORE REQUEST from {request.user.username}")
#     print(f"{'='*50}")
#     print(f"POST data: {request.POST}")
#     print(f"FILES: {request.FILES}")
    
#     try:
#         if not hasattr(request.user, 'store') or not request.user.store:
#             print("❌ User doesn't have a store")
#             return JsonResponse({
#                 'success': False,
#                 'message': 'You don\'t have a store to update. Please create one first.'
#             }, status=400)

#         store_instance = request.user.store
        
#         form = StoreForm(
#             request.POST, 
#             request.FILES, 
#             request=request, 
#             instance=store_instance
#         )
        
#         print("\n--- Form Validation ---")
#         if form.is_valid():
#             print("✅ Form is valid")
#             try:
#                 updated_store = form.save()
                
#                 print(f"✅ Store updated successfully!")
#                 print(f"Store ID: {updated_store.id}")
#                 print(f"Store Name: {updated_store.name}")
#                 print(f"Updated fields: {form.changed_data}")
                
#                 return JsonResponse({
#                     'success': True,
#                     'message': 'Store updated successfully!'
#                 })
#             except Exception as e:
#                 print(f"❌ Error updating store: {e}")
#                 traceback.print_exc()
#                 return JsonResponse({
#                     'success': False,
#                     'message': f'Error updating store: {str(e)}'
#                 }, status=500)
#         else:
#             print("❌ Form validation failed")
#             print(f"Form errors: {form.errors.as_json()}")
            
#             error_dict = {}
#             for field, errors in form.errors.items():
#                 error_dict[field] = [str(error) for error in errors]
            
#             return JsonResponse({
#                 'success': False,
#                 'message': 'Please correct the errors below',
#                 'errors': error_dict
#             }, status=400)
            
#     except Exception as e:
#         print(f"❌ Unexpected error: {e}")
#         traceback.print_exc()
#         return JsonResponse({
#             'success': False,
#             'message': f'An unexpected error occurred: {str(e)}'
#         }, status=500)
    
# Market Entity
@login_required
@transaction.atomic
def u_add_product(request):
    """Add a new product to the user's store"""
    if request.method == "POST":
        print(f"\n{'='*50}")
        print(f"ADD PRODUCT REQUEST from {request.user.username}")
        print(f"POST data: {dict(request.POST)}")
        print(f"FILES: {dict(request.FILES)}")
        print(f"{'='*50}")
        
        try:
            # Check if user is approved seller
            approved_validation = StoreValidation.objects.filter(
                store_owner=request.user,
                status='approved'
            ).first()
            
            if not approved_validation:
                print("❌ User is not an approved seller")
                return JsonResponse({
                    "success": False,
                    "message": "You must be an approved seller to add products."
                }, status=403)
            
            # Check if user has a store
            if not hasattr(request.user, 'store') or not request.user.store:
                print("❌ User doesn't have a store")
                return JsonResponse({
                    "success": False,
                    "message": "You must create a store before adding products."
                }, status=403)
            
            store = request.user.store
            print(f"✅ Store found: {store.name}")
            
            # Create form with request for context if needed
            form = ProductForm(request.POST, request.FILES)
            
            print(f"Form is valid: {form.is_valid()}")
            if not form.is_valid():
                print(f"❌ Form errors: {form.errors}")
                return JsonResponse({
                    "success": False,
                    "message": "Please correct the errors",
                    "errors": form.errors
                }, status=400)
            
            # Save product
            product = form.save(commit=False)
            product.store = store
            product.save()

            print(f"✅ Product added successfully! Product ID: {product.id}")
            print(f"Product Name: {product.name}")
            print(f"Store: {store.name}")
            
            return JsonResponse({
                "success": True,
                "message": "Product added successfully!"
            })

        except Exception as e:
            print(f"❌ Error adding product: {str(e)}")
            import traceback
            traceback.print_exc()
            return JsonResponse({
                "success": False,
                "message": f"Error adding product: {str(e)}"
            }, status=500)

    return JsonResponse({
        "success": False,
        "message": "Invalid request method"
    }, status=405)

@login_required
@transaction.atomic
def u_edit_product(request, product_id):
    """Edit existing product"""
    product = get_object_or_404(Product, id=product_id, store=request.user.store)
    
    if request.method == 'POST':
        # Pass the request to the form
        form = ProductForm(request.POST, request.FILES, instance=product, request=request)
        if form.is_valid():
            try:
                global last_action
                last_action = {
                    'type': 'edit',
                    'product_id': product.id,
                    'previous_data': {
                        'name': product.name,
                        'category': product.category.id if product.category else None,
                        'description': product.description,
                        'price': str(product.price),
                        'stock': product.stock,
                        'image_url': str(product.image_url) if product.image_url else None
                    }
                }
                
                form.save()
                return JsonResponse({
                    'success': True,
                    'message': 'Product updated successfully!'
                })
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'message': f'Error updating product: {str(e)}'
                }, status=500)
        else:
            return JsonResponse({
                'success': False,
                'message': 'Please correct the errors below',
                'errors': form.errors.get_json_data()
            }, status=400)
    
    return JsonResponse({
        'success': False,
        'message': 'Invalid request method'
    }, status=405)
@login_required
@require_POST
@transaction.atomic
def u_delete_product(request, product_id):
    """Soft delete a product"""
    try:
        # Add safety check for user store
        if not hasattr(request.user, 'store'):
            return JsonResponse({
                'success': False, 
                'message': 'Store not found'
            }, status=400)
            
        product = get_object_or_404(Product, id=product_id, store=request.user.store)
        
        global last_action
        last_action = {
            'type': 'delete',
            'product_id': product.id,
            'product_data': {
                'name': product.name,
                'category': product.category.id if product.category else None,
                'description': product.description,
                'price': str(product.price),
                'stock': product.stock,
                'image_url': str(product.image_url) if product.image_url else None,
            }
        }
        product.soft_delete()
        return JsonResponse({'success': True, 'message': 'Product deleted successfully.'})
    except Exception as e:
        print(f"Error in u_delete_product: {e}")
        return JsonResponse({'success': False, 'message': str(e)}, status=400)
last_action = None
@login_required
@require_POST
def u_undo_last_action(request):
    """Undo the last product action"""
    global last_action
    if not last_action:
        return JsonResponse({'success': False, 'message': 'No action to undo'})
    
    try:
        if last_action['type'] == 'delete':
            # Use get_object_or_404 for safety
            product = get_object_or_404(Product, id=last_action['product_id'])
            product.restore()
            message = "Product restoration successful"
        elif last_action['type'] == 'add':
            # Use filter().delete() for safety
            deleted_count = Product.objects.filter(id=last_action['product_id']).delete()
            message = "Product creation undone"
        elif last_action['type'] == 'edit':
            product = get_object_or_404(Product, id=last_action['product_id'])
            previous_data = last_action['previous_data']
            product.name = previous_data['name']
            if previous_data['category']:
                product.category_id = previous_data['category']
            product.description = previous_data['description']
            product.price = previous_data['price']
            product.stock = previous_data['stock']
            product.image_url = previous_data['image_url']
            product.save()
            message = "Product edit undone"
        else:
            return JsonResponse({'success': False, 'message': 'Unknown action type'})
        
        last_action = None
        return JsonResponse({'success': True, 'message': message})
    except Exception as e:
        print(f"Error in u_undo_last_action: {e}")
        return JsonResponse({'success': False, 'message': str(e)}, status=400)
    
@login_required
def u_search_products(request):
    """Search products in user's store"""
    query = request.GET.get('query', '').strip()
    if not query:
        return JsonResponse({'results': []})
    
    try:
        # Add safety checks for user and store
        if not hasattr(request.user, 'store'):
            return JsonResponse({'results': []})
            
        store = request.user.store
        products = Product.objects.filter(
            store=store,
            is_deleted=False
        ).filter(
            models.Q(name__icontains=query) |
            models.Q(category__name__icontains=query) |
            models.Q(description__icontains=query)
        ).select_related('category')
        
        results = [
            {
                'id': p.id,
                'name': p.name,
                'category': p.category.name if p.category else 'No Category',
                'description': p.description or '',
                'price': str(p.price),
                'stock': p.stock,
                'image_url': p.image_url if p.image_url else ''
            }
            for p in products
        ]
        return JsonResponse({'results': results})
    except Store.DoesNotExist:
        return JsonResponse({'results': []})
    except Exception as e:
        print(f"Error in u_search_products: {e}")
        return JsonResponse({'results': []})  # Return empty results instead of error


# -------------------------------------------------------------------------------------
# Market Entity Checkout
@login_required
def u_checkout_view(request):
    # Determine if this is a direct purchase or cart checkout
    product_id = request.GET.get('product')
    is_u_direct_checkouts = product_id is not None
    
    if is_u_direct_checkouts:
        return handle_direct_checkouts(request)
    else:
        return handle_cart_checkouts(request)


@login_required
def handle_direct_checkouts(request):
    try:
        product = get_object_or_404(Product, id=request.GET.get('product'))
        store = get_object_or_404(Store, id=request.GET.get('store'))
        quantity = int(request.GET.get('quantity', 1))
        
        # Check stock availability
        if product.stock < quantity:
            messages.error(request, f"Sorry, only {product.stock} items available in stock.")
            return redirect("market_place")
        
        # Get the user's default address or the last one
        shipping_address = ShippingAddress.objects.filter(
            customer=request.user, 
            is_default=True
        ).first()
        
        if not shipping_address:
            shipping_address = ShippingAddress.objects.filter(
                customer=request.user
            ).last()
        
        action = request.POST.get("action") if request.method == "POST" else None

        if action == "update_address":
            # Get or create the address
            address_data = {
                "phone_number": request.POST.get("phone_number"),
                "address": request.POST.get("address"),
                "city": request.POST.get("city"),
                "province": request.POST.get("province"),
                "zipcode": request.POST.get("zipcode"),
            }
            
            # Remove empty values to avoid overwriting with empty strings
            address_data = {k: v for k, v in address_data.items() if v}
            
            shipping_address, created = ShippingAddress.objects.update_or_create(
                customer=request.user,
                defaults=address_data
            )
            
            if created:
                messages.success(request, "Shipping address created successfully.")
            else:
                messages.success(request, "Shipping address updated successfully.")
                
            return redirect(f"{reverse('u_direct_checkout')}?product={product.id}&store={store.id}&quantity={quantity}")

        elif action == "place_order":
            use_existing = request.POST.get("use_existing_address") == "on"
            
            if use_existing and not shipping_address:
                messages.error(request, "No existing address found, please add one.")
                return redirect(f"{reverse('u_direct_checkout')}?product={product.id}&store={store.id}&quantity={quantity}")
            
            if not use_existing:
                # Create a new address
                address_data = {
                    "phone_number": request.POST.get("phone_number"),
                    "address": request.POST.get("address"),
                    "city": request.POST.get("city"),
                    "province": request.POST.get("province"),
                    "zipcode": request.POST.get("zipcode"),
                }
                
                # Remove empty values
                address_data = {k: v for k, v in address_data.items() if v}
                
                shipping_address = ShippingAddress.objects.create(
                    customer=request.user,
                    **address_data
                )
                
                # Set as default if requested
                if request.POST.get("set_as_default"):
                    shipping_address.is_default = True
                    shipping_address.save()

            # Calculate order totals
            subtotal = product.price * quantity
            shipping_fee = calculate_shipping_fee(store, shipping_address) if shipping_address else Decimal("0.00")
            total_amount = subtotal + shipping_fee
            payment_method = request.POST.get("payment_method", "COD")

            if payment_method == "COD":
                # Use transaction to ensure stock is properly decreased
                with transaction.atomic():
                    # Create the order
                    order = Order.objects.create(
                        customer=request.user,
                        store=store,
                        product=product,
                        shipping_address=shipping_address,
                        quantity=quantity,
                        subtotal=subtotal,
                        shipping_fee=shipping_fee,
                        total_amount=total_amount,
                        payment_method=payment_method,
                        paid=False,
                        status="Pending",
                    )
                    
                    # Decrease product stock
                    product.stock -= quantity
                    product.save()
                
                return redirect("u_order_confirmation", order_id=order.id)
            else:
                # Handle online payment methods
                request.session['pending_order_data'] = {
                    'store_id': store.id,
                    'product_id': product.id,
                    'shipping_address_id': shipping_address.id,
                    'quantity': quantity,
                    'subtotal': str(subtotal),
                    'shipping_fee': str(shipping_fee),
                    'total_amount': str(total_amount),
                    'payment_method': payment_method,
                }
                return initiate_paymongo_checkout(request, product, store, quantity, shipping_address, [payment_method.lower()])

        # GET request - show the form
        subtotal = product.price * quantity
        shipping_fee = calculate_shipping_fee(store, shipping_address) if shipping_address else Decimal("0.00")

        context = {
            "is_u_direct_checkouts": True,
            "product": product,
            "store": store,
            "quantity": quantity,
            "shipping_address": shipping_address,
            "shipping_fee": shipping_fee,
            "subtotal": subtotal,
            "total_amount": subtotal + shipping_fee,
            "has_address": shipping_address is not None,
            "PAYMENT_METHOD_CHOICES": Order.PAYMENT_METHOD_CHOICES,
        }
        return render(request, "escan/Market_Entity/E-commerce/Marketplace/u_checkout.html", context)

    except (Product.DoesNotExist, Store.DoesNotExist, ValueError) as e:
        messages.error(request, f"Invalid product selection: {e}")
        return redirect("market_place")
    

def initiate_paymongo_checkout(request, product, store, quantity, shipping_address, paymongo_methods):
    subtotal = product.price * quantity
    shipping_fee = calculate_shipping_fee(store, shipping_address)
    total_amount = (subtotal + shipping_fee).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    # amount_in_cents = int(total_amount * 100)

    print("✅ Total amount to PayMongo:", total_amount)
    # print("✅ Amount in centavos:", product_amount_cents)

    product_amount_cents = int((product.price * 100).quantize(Decimal("1")))
    shipping_amount_cents = int((shipping_fee * 100).quantize(Decimal("1")))


    payload = {
        "data": {
            "attributes": {
                "line_items": [
                    {
                        "currency": "PHP",
                        "amount": product_amount_cents,
                        "description": (product.description or product.name)[:255],
                        "name": product.name,
                        "quantity": quantity,
                    },
                    {
                        "currency": "PHP",
                        "amount": shipping_amount_cents,
                        "description": "Shipping Fee",
                        "name": "Shipping fee",
                        "quantity": 1,
                    }
                ],
                "payment_method_types": paymongo_methods,
                "redirect": {
                    "success": request.build_absolute_uri(reverse("paymongo_success")) + f"?product_id={product.id}&store_id={store.id}&quantity={quantity}",
                    "failed": request.build_absolute_uri(reverse("paymongo_failed")),
                },
                "metadata": {
                    "user_id": request.user.id,
                },
            }
        }
    }

    headers = {
        "Authorization": f"Basic {base64.b64encode(settings.PAYMONGO_SECRET_API_KEY.encode()).decode()}",
        "Content-Type": "application/json",
    }

    response = requests.post("https://api.paymongo.com/v1/checkout_sessions", headers=headers, json=payload)

    if response.ok:
        checkout_url = response.json()["data"]["attributes"]["checkout_url"]
        return redirect(checkout_url)

    messages.error(request, "Unable to initiate payment.")
    return redirect(f"{reverse('u_direct_checkout')}?product={product.id}&store={store.id}&quantity={quantity}")

# ols
# @login_required
# def paymongo_success(request):
#     pending = request.session.get("pending_order_data")
#     if not pending:
#         messages.error(request, "Payment succeeded but order data was lost.")
#         return redirect("market_place")

#     try:
#         store = Store.objects.get(id=pending['store_id'])
#         product = Product.objects.get(id=pending['product_id'])
#         shipping_address = ShippingAddress.objects.get(id=pending['shipping_address_id'])

#         subtotal = Decimal(pending['subtotal'])
#         shipping_fee = Decimal(pending['shipping_fee'])
#         total_amount = Decimal(pending['total_amount'])
#         quantity = int(pending['quantity'])

#         order = Order.objects.create(
#             customer=request.user,
#             store=store,
#             product=product,
#             shipping_address=shipping_address,
#             quantity=quantity,
#             subtotal=subtotal,
#             shipping_fee=shipping_fee,
#             total_amount=total_amount,
#             payment_method=pending['payment_method'],
#             paid=True,
#             status="Completed",
#         )

#         # Clear session
#         del request.session["pending_order_data"]

#         messages.success(request, "Payment successful!")
#         return redirect("u_order_confirmation", order_id=order.id)

#     except Exception as e:
#         print("Error creating order after payment:", e)
#         messages.error(request, "Payment succeeded but order creation failed.")
#         return redirect("market_place")

@login_required
def paymongo_success(request):
    pending = request.session.get("pending_order_data")
    if not pending:
        messages.error(request, "Payment succeeded but order data was lost.")
        return redirect("market_place")

    try:
        store = Store.objects.get(id=pending['store_id'])
        product = Product.objects.get(id=pending['product_id'])
        shipping_address = ShippingAddress.objects.get(id=pending['shipping_address_id'])

        subtotal = Decimal(pending['subtotal'])
        shipping_fee = Decimal(pending['shipping_fee'])
        total_amount = Decimal(pending['total_amount'])
        quantity = int(pending['quantity'])
        
        # Use transaction to ensure both order creation and stock reduction happen
        with transaction.atomic():
            # Create the order
            order = Order.objects.create(
                customer=request.user,
                store=store,
                product=product,
                shipping_address=shipping_address,
                quantity=quantity,
                subtotal=subtotal,
                shipping_fee=shipping_fee,
                total_amount=total_amount,
                payment_method=pending['payment_method'],
                paid=True,
                status="Completed",
            )
            
            # Decrease product stock
            product.stock -= quantity
            product.save()

        # Clear session
        if "pending_order_data" in request.session:
            del request.session["pending_order_data"]

        messages.success(request, "Payment successful!")
        return redirect("u_order_confirmation", order_id=order.id)

    except Exception as e:
        print("Error creating order after payment:", e)
        messages.error(request, "Payment succeeded but order creation failed.")
        return redirect("market_place")
    


@login_required
def paymongo_failed(request):
    order = get_object_or_404(Order, id=request.GET.get("order_id"), customer=request.user)
    order.status = "Cancelled"
    order.save()
    messages.error(request, "Payment failed.")
    return redirect("u_direct_checkout")

# new
@transaction.atomic
def process_direct_checkouts(request, product, store, quantity):
    try:
        payment_method = request.POST.get('payment_method', 'COD')
        total_amount = product.price * quantity

        # Always resolve the shipping address FIRST
        if request.POST.get('use_existing_address') == 'on':
            shipping_address = ShippingAddress.objects.filter(customer=request.user).first()
            if not shipping_address:
                raise ValueError("No existing address found")
        else:
            # If a new address was entered, either update the old one or create a fresh one
            shipping_address, _ = ShippingAddress.objects.update_or_create(
                customer=request.user,
                defaults={
                    "phone_number": request.POST.get("phone_number"),
                    "address": request.POST.get("address"),
                    "city": request.POST.get("city"),
                    "province": request.POST.get("province"),
                    "zipcode": request.POST.get("zipcode"),
                }
            )

        # ✅ Calculate shipping fee only once, using the resolved address
        shipping_fee = calculate_shipping_fee(store, shipping_address)
        total_amount += shipping_fee

        # Create the order
        order = Order.objects.create(
            customer=request.user,
            store=store,
            product=product,
            shipping_address=shipping_address,
            quantity=quantity,
            total_amount=total_amount,
            shipping_fee=shipping_fee,
            payment_method=payment_method,
            status='Pending'
        )

        if payment_method != 'COD':
            Payment.objects.create(
                order=order,
                method=payment_method,
                amount_paid=order.total_amount,
                confirmed=False
            )

        # Reduce stock
        product.stock -= quantity
        product.save()

        # Track purchase history
        customer, _ = Customer.objects.get_or_create(user=request.user)
        CustomerPurchase.objects.create(
            customer=customer,
            store=store,
            product=product,
            category=product.category,
            quantity=quantity,
            total_amount=order.total_amount,
            is_completed=True
        )

        customer.stores_purchased_from.add(store)

        return redirect('u_order_confirmation', order_id=order.id)

    except Exception as e:
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect(request.META.get('HTTP_REFERER', 'checkout'))


from decimal import Decimal
from geopy.distance import geodesic

def get_lat_lon_from_address(address):
    """Fetch latitude and longitude from a string address using Nominatim."""
    try:
        url = "https://nominatim.openstreetmap.org/search"
        params = {"q": address, "format": "json"}
        res = requests.get(url, params=params, headers={"User-Agent": "BanaeScanApp"}).json()
        if res:
            return float(res[0]["lat"]), float(res[0]["lon"])
    except Exception as e:
        print("Nominatim error:", e)
    return None, None

def calculate_shipping_fee(store, shipping_address):
    try:
        # Get coordinates of buyer based on shipping address (or fallback)
        if shipping_address.latitude and shipping_address.longitude:
            buyer_coords = (shipping_address.latitude, shipping_address.longitude)
        else:
            # Fallback: use PostalCodeLocation by ZIP code
            try:
                buyer_loc = PostalCodeLocation.objects.get(postal_code=shipping_address.zipcode)
                buyer_coords = (buyer_loc.latitude, buyer_loc.longitude)
            except PostalCodeLocation.DoesNotExist:
                # Fallback to Nominatim geolocation service
                geolocator = Nominatim(user_agent="escan")
                location = geolocator.geocode(f"{shipping_address.address}, {shipping_address.city}, {shipping_address.province}, {shipping_address.zipcode}")
                if not location:
                    return Decimal("0.00")  # Return 0 if no location is found
                buyer_coords = (location.latitude, location.longitude)
    except Exception as e:
        print(f"Error getting buyer coordinates: {e}")
        return Decimal("0.00")  # Return 0 if there's any error

    # Get store coordinates (fallback if missing)
    if not (store.latitude and store.longitude):
        print("Store coordinates missing")
        return Decimal("0.00")

    store_coords = (store.latitude, store.longitude)
    print("Buyer coordinates:", buyer_coords)
    print("Store coordinates:", store_coords)

    # Calculate distance in kilometers
    distance_km = geodesic(store_coords, buyer_coords).km

    # Get shipping fee from store's shipping rule
    rule = getattr(store, "shipping_rule", None)
    base_fee = rule.base_fee if rule else Decimal("10.00")
    per_km_rate = rule.per_km_rate if rule else Decimal("5.00")

    # Calculate total shipping fee
    shipping_fee = base_fee + (Decimal(distance_km) * per_km_rate)

    # Return the rounded shipping fee (rounded to 2 decimal places)
    return shipping_fee.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)



@login_required
def set_default_address(request, address_id):
    address = get_object_or_404(ShippingAddress, id=address_id, customer=request.user)

    if request.method == 'POST':
        # Set this address as default
        address.is_default = True
        address.save()  # Your model logic will unset others

    return redirect(request.META.get('HTTP_REFERER', 'market_place'))  # return to the page/modal

@login_required
def update_shipping_address(request, address_id):
    address = get_object_or_404(ShippingAddress, id=address_id, customer=request.user)

    if request.method == 'POST':
        address.phone_number = request.POST.get('phone_number')
        address.address = request.POST.get('address')
        address.city = request.POST.get('city')
        address.province = request.POST.get('province')
        address.zipcode = request.POST.get('zipcode')
        
        # Handle setting default
        if request.POST.get('is_default') == 'on':
            address.is_default = True
        else:
            address.is_default = False

        address.save()
        return redirect(request.META.get('HTTP_REFERER', 'marke_place'))  # Refresh the page/modal

    # If GET, redirect or render a page (not needed if only posting from modal)
    return redirect('/')

# not neccessat
@csrf_exempt
def create_gcash_payment(request):
    if request.method == 'POST':
        amount = int(Decimal(request.POST.get('amount')) * 100)  # Convert to centavos
        redirect_url = request.build_absolute_uri('/payment/success/')
        failed_url = request.build_absolute_uri('/payment/failed/')
        reference_id = f"gcash-{uuid.uuid4()}"

        headers = {
            'Authorization': f'Basic {settings.PAYMONGO_SECRET_KEY}',
            'Content-Type': 'application/json'
        }

        payload = {
            "data": {
                "attributes": {
                    "amount": amount,
                    "redirect": {
                        "success": redirect_url,
                        "failed": failed_url
                    },
                    "type": "gcash",
                    "currency": "PHP",
                    "metadata": {
                        "user_id": request.user.id,
                        "reference_id": reference_id
                    }
                }
            }
        }

        response = requests.post(
            "https://api.paymongo.com/v1/checkout_sessions",
            headers=headers,
            json=payload
        )

        if response.status_code == 200:
            gcash_url = response.json()["data"]["attributes"]["checkout_url"]
            return redirect(gcash_url)
        else:
            return render(request, 'payment/error.html', {'error': response.json()})  

def payment_success(request):
    return render(request, 'payment/success.html')

def payment_failed(request):
    return render(request, 'payment/failed.html')


# ORIGINAL
# @login_required
# def handle_cart_checkouts(request):
#     cart = Cart.objects.filter(customer=request.user, completed=False).first()
    
#     if not cart or not cart.cartitems.exists():
#         messages.warning(request, "Your cart is empty")
#         return redirect('u_carts')
    
#     cart_items = cart.cartitems.select_related('product').all()
#     shipping_address = ShippingAddress.objects.filter(customer=request.user).first()
    
#     # Calculate shipping fee estimate if address exists
#     shipping_fee_estimate = Decimal('0.00')
#     quantity_surcharge_estimate = Decimal('0.00')
    
#     if shipping_address:
#         # For cart, we need to calculate shipping per store
#         store_shipping = {}
#         for item in cart_items:
#             if item.product.store.id not in store_shipping:
#                 # Create a temporary order to calculate shipping
#                 temp_order = Order(
#                     customer=request.user,
#                     store=item.product.store,
#                     product=item.product,
#                     shipping_address=shipping_address,
#                     quantity=item.quantity,
#                     total_amount=item.get_total
#                 )
#                 shipping_total = temp_order.calculate_shipping_fee()
#                 store_shipping[item.product.store.id] = {
#                     'shipping_fee': temp_order.shipping_fee,
#                     'quantity_surcharge': temp_order.quantity_surcharge
#                 }
        
#         # Sum up all shipping fees
#         for store_data in store_shipping.values():
#             shipping_fee_estimate += store_data['shipping_fee']
#             quantity_surcharge_estimate += store_data['quantity_surcharge']
    
#     if request.method == 'POST':
#         return process_cart_checkouts(request, cart, cart_items)
    
#     context = {
#         'is_u_direct_checkouts': False,
#         'cart_items': cart_items,
#         'cart_total': cart.get_cart_total,
#         'item_count': cart.get_item_total,
#         'shipping_address': shipping_address,
#         'has_address': shipping_address is not None,
#         'shipping_fee_estimate': shipping_fee_estimate,
#         'quantity_surcharge_estimate': quantity_surcharge_estimate,
#         'PAYMENT_METHOD_CHOICES': Order.PAYMENT_METHOD_CHOICES,
#     }
#     return render(request, 'escan/User/E-commerceUser/umarketplace/u_checkout.html', context)

# 1
# @login_required
# def handle_cart_checkouts(request):
#     cart = Cart.objects.filter(customer=request.user, completed=False).first()
    
#     if not cart or not cart.cartitems.exists():
#         messages.warning(request, "Your cart is empty")
#         return redirect('carts')
    
#     cart_items = cart.cartitems.select_related('product__store').all()
#     shipping_address = ShippingAddress.objects.filter(customer=request.user).last()

#     # Subtotal = products only
#     subtotal = cart.get_subtotal
#     shipping_fee = Decimal("0.00")
#     store = None

#     if shipping_address and cart_items:
#         store = cart_items[0].product.store
#         print("Store:", store.name)
#         shipping_fee = calculate_shipping_fee(store, shipping_address)

#     total_amount = subtotal + shipping_fee

#     if request.method == 'POST':
#         return process_cart_checkout(request, cart, cart_items)

#     context = {
#         'is_direct_checkout': False,
#         "store": store,  # whole store object, not just name
#         'cart_items': cart_items,
#         'cart_total': subtotal,
#         'item_count': cart.get_item_total,
#         'shipping_address': shipping_address,
#         'has_address': shipping_address is not None,
#         'shipping_fee': shipping_fee,
#         'subtotal': subtotal,
#         'total_amount': total_amount,
#         'PAYMENT_METHOD_CHOICES': Order.PAYMENT_METHOD_CHOICES,
#     }
#     return render(request, 'escan/User/E-commerceUser/umarketplace/u_checkout.html', context)

# User Side Checkout
@login_required
def handle_cart_checkouts(request):
    cart = Cart.objects.filter(customer=request.user, completed=False).first()
    
    if not cart or not cart.cartitems.exists():
        messages.warning(request, "Your cart is empty")
        return redirect('carts')
    
    cart_items = cart.cartitems.select_related('product__store').all()
    shipping_address = ShippingAddress.objects.filter(customer=request.user).last()

    subtotal = cart.get_subtotal
    shipping_total = Decimal("0.00")
    store = None

    # Calculate shipping fee per item (based on its store + shipping address)
    if shipping_address and cart_items:
        for item in cart_items:
            store = item.product.store
            item.shipping_fee = calculate_shipping_fee(store, shipping_address)
            item.total_price = (item.product_price_at_addition * item.quantity) + item.shipping_fee
            item.save(update_fields=["shipping_fee", "total_price"])
            shipping_total += item.shipping_fee

    total_amount = subtotal + shipping_total

    if request.method == 'POST':
        return process_cart_checkout(request, cart, cart_items)

    context = {
        'is_direct_checkout': False,
        "store": store,  
        'cart_items': cart_items,
        'cart_total': subtotal,
        'item_count': cart.get_item_total,
        'shipping_address': shipping_address,
        'has_address': shipping_address is not None,
        'shipping_fee': shipping_total,
        'subtotal': subtotal,
        'total_amount': total_amount,
        'PAYMENT_METHOD_CHOICES': Order.PAYMENT_METHOD_CHOICES,
    }
    return render(request, 'escan/User/E-commerceUser/umarketplace/u_checkout.html', context)



from decimal import Decimal, ROUND_HALF_UP
from .models import Cart, ShippingAddress  # assuming you have this

@login_required
def cart_checkout_view(request):
    cart = Cart.objects.filter(customer=request.user, completed=False).first()
    shipping_address = ShippingAddress.objects.filter(customer=request.user).last()
    has_address = bool(shipping_address)

    if not cart or not cart.cartitems.exists():
        return render(request, "escan/User/E-commerceUser/umarketplace/u_checkout.html", {
            "is_u_direct_checkouts": False,
            "cart_items": [],
            "cart_total": Decimal("0.00"),
            "item_count": 0,
            "shipping_address": shipping_address,
            "shipping_fee": Decimal("0.00"),
            "subtotal": Decimal("0.00"),
            "total_amount": Decimal("0.00"),
            "has_address": has_address,
            "PAYMENT_METHOD_CHOICES": Order.PAYMENT_METHOD_CHOICES,
        })

    # Recalculate item prices & shipping fee
    subtotal = sum(item.product.price * item.quantity for item in cart.cartitems.all())
    shipping_fee = calculate_shipping_fee(cart.cartitems.first().product.store, shipping_address) if has_address else Decimal("0.00")
    total_amount = subtotal + shipping_fee

    context = {
        "is_u_direct_checkouts": False,
        "cart_items": cart.cartitems.all(),
        "cart_total": subtotal,
        "item_count": cart.get_item_total,
        "shipping_address": shipping_address,
        "shipping_fee": shipping_fee,
        "subtotal": subtotal.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
        "total_amount": total_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
        "has_address": has_address,
        "PAYMENT_METHOD_CHOICES": Order.PAYMENT_METHOD_CHOICES,
    }

    return render(request, "escan/User/E-commerceUser/umarketplace/u_checkout.html", context)

# Admin Side Store Validation
# -----------------------------------------------------------
# helper to check if user is admin
def is_admin(user):
    return user.is_authenticated and user.role == "Admin"

@login_required
@user_passes_test(is_admin)
def validation_list(request):
    # Filter out admin users - only show regular users who applied to be sellers
    validations = StoreValidation.objects.exclude(
        store_owner__is_staff=True
    ).exclude(
        store_owner__is_superuser=True
    ).order_by('-created_at')
    
    return render(request, 'escan/Admin/E-commerce/store_validation.html', {'validations': validations})

@login_required
@user_passes_test(is_admin)
def approve_validation(request, pk):
    validation = get_object_or_404(StoreValidation, pk=pk)
    validation.status = StoreValidation.APPROVED
    validation.reviewed_by = request.user
    validation.reviewed_at = timezone.now()
    validation.rejection_reason = None
    validation.save()
    return redirect('validation_list')

@login_required
@user_passes_test(is_admin)
def validation_detail(request, pk):
    validation = get_object_or_404(StoreValidation, pk=pk)
    return render(request, 'escan/Admin/E-commerce/store_validation.html', {"validation": validation})


@login_required
@user_passes_test(is_admin)
def update_validation_status(request, pk):
    validation = get_object_or_404(StoreValidation, pk=pk)

    if request.method == "POST":
        status = request.POST.get("status")
        reason = request.POST.get("reason", "").strip()

        if status == "approved":
            validation.status = StoreValidation.APPROVED
            validation.reviewed_by = request.user
            validation.reviewed_at = timezone.now()
            validation.rejection_reason = None
            validation.save()

        elif status == "rejected":
            if reason:  # 👈 only reject if reason is provided
                validation.status =  StoreValidation.REJECTED
                validation.reviewed_by = request.user
                validation.reviewed_at = timezone.now()
                validation.rejection_reason = reason
                validation.save()
            else:
                messages.error(request, "Rejection reason is required to reject an application.")

    return redirect("validation_list")

# not neccessary
@login_required
@user_passes_test(is_admin)
def reject_validation(request, pk):
    validation = get_object_or_404(StoreValidation, pk=pk)
    if request.method == "POST":
        reason = request.POST.get("rejection_reason", "")
        # validation.status = StoreValidation.REJECTED
        validation.status = StoreValidation.REJECTED
        validation.reviewed_by = request.user
        validation.reviewed_at = timezone.now()
        validation.rejection_reason = reason
        validation.save()
        return redirect('validation_list')
    return render(request, 'escan/Admin/E-commerce/store_reject_form.html', {'validation': validation})

# --------------------------------------------------------------------------------------------


# User Side Cart Checkout
@transaction.atomic
def process_cart_checkouts(request, cart, cart_items):
    try:
        payment_method = request.POST.get('payment_method', 'COD')
        
        # Handle shipping address
        if request.POST.get('use_existing_address') == 'on':
            shipping_address = ShippingAddress.objects.filter(customer=request.user).first()
            if not shipping_address:
                raise ValueError("No existing address found")
        else:
            shipping_address = ShippingAddress.objects.create(
                customer=request.user,
                phone_number=request.POST.get('phone_number'),
                address=request.POST.get('address'),
                city=request.POST.get('city'),
                province=request.POST.get('province'),
                zipcode=request.POST.get('zipcode')
            )
        
        # Create orders for each cart item
        orders = []
        for item in cart_items:
            total_amount = item.get_total
            
            # Create order (will automatically calculate shipping fee in save method)
            order = Order.objects.create(
                customer=request.user,
                store=item.product.store,
                product=item.product,
                shipping_address=shipping_address,
                quantity=item.quantity,
                total_amount=total_amount,  # This will be updated with shipping in save()
                payment_method=payment_method,
                status='Pending'
            )
            orders.append(order)
            
            # Create payment record if not COD
            if payment_method != 'COD':
                Payment.objects.create(
                    order=order,
                    method=payment_method,
                    amount_paid=order.total_amount,
                    confirmed=False
                )
            
            # Update product stock
            item.product.stock -= item.quantity
            item.product.save()
            
            # Add to customer purchase history
            customer, created = Customer.objects.get_or_create(user=request.user)
            CustomerPurchase.objects.create(
                customer=customer,
                store=item.product.store,
                product=item.product,
                category=item.product.category,
                quantity=item.quantity,
                total_amount=order.total_amount,
                is_completed=True
            )
            
            # Add store to customer's purchased stores
            customer.stores_purchased_from.add(item.product.store)
        
        # Mark cart as completed and clear items
        cart.completed = True
        cart.save()
        
        # Redirect to order confirmation for the first order
        return redirect('u_order_confirmation', order_id=orders[0].id)
        
    except Exception as e:
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect('u_checkouts')

@login_required
def u_direct_item_checkouts(request, item_id):
    try:
        cart_item = get_object_or_404(
            Cartitems, 
            id=item_id, 
            cart__customer=request.user,
            cart__completed=False
        )
        
        # Redirect to checkout with this single item
        return redirect(
            reverse('u_checkouts') + 
            f"?product={cart_item.product.id}&store={cart_item.product.store.id}&quantity={cart_item.quantity}"
        )
        
    except Exception as e:
        messages.error(request, f"Error processing checkout: {str(e)}")
        return redirect('u_carts')

@login_required
def u_manage_shipping_fees(request, store_id):
    store = get_object_or_404(Store, id=store_id, owner=request.user)
    shipping_fees = ShippingFee.objects.filter(store=store)
    
    if request.method == 'POST':
        form_type = request.POST.get('form_type')
        
        if form_type == 'add_fee':
            zip_code = request.POST.get('zip_code')
            fee = request.POST.get('fee')
            
            # Check if fee already exists for this zip code
            existing_fee = ShippingFee.objects.filter(store=store, zip_code=zip_code).first()
            
            if existing_fee:
                existing_fee.fee = fee
                existing_fee.is_active = True
                existing_fee.save()
                messages.success(request, f"Updated shipping fee for {zip_code}")
            else:
                ShippingFee.objects.create(
                    store=store,
                    zip_code=zip_code,
                    fee=fee
                )
                messages.success(request, f"Added shipping fee for {zip_code}")
        
        elif form_type == 'update_fee':
            fee_id = request.POST.get('fee_id')
            new_fee = request.POST.get(f'fee_{fee_id}')
            
            try:
                shipping_fee = ShippingFee.objects.get(id=fee_id, store=store)
                shipping_fee.fee = new_fee
                shipping_fee.save()
                messages.success(request, f"Updated shipping fee")
            except ShippingFee.DoesNotExist:
                messages.error(request, "Shipping fee not found")
        
        elif form_type == 'toggle_fee':
            fee_id = request.POST.get('fee_id')
            
            try:
                shipping_fee = ShippingFee.objects.get(id=fee_id, store=store)
                shipping_fee.is_active = not shipping_fee.is_active
                shipping_fee.save()
                
                status = "activated" if shipping_fee.is_active else "deactivated"
                messages.success(request, f"Shipping fee {status}")
            except ShippingFee.DoesNotExist:
                messages.error(request, "Shipping fee not found")
        
        return redirect('u_manage_shipping_fees', store_id=store_id)
    
    context = {
        'store': store,
        'shipping_fees': shipping_fees,
    }
    return render(request, 'escan/Market_Entity/E-commerce/Marketplace/manage_shipping_fees.html', context)

@login_required
def u_order_confirmation_view(request, order_id):
    order = get_object_or_404(Order, id=order_id, customer=request.user)
    return render(request, 'escan/Market_Entity/E-commerce/Marketplace/u_order_confirmation.html', {'order': order})


#Market Entity Cart
@login_required
def u_carts(request):
    cart = Cart.objects.filter(customer=request.user, completed=False).first()
    
    if cart:
        cart_items = cart.cartitems.select_related('product').all()
        cart_total = cart.get_cart_total
        item_count = cart.get_item_total
    else:
        cart_items = []
        cart_total = 0
        item_count = 0
    
    context = {
        'cart_items': cart_items,
        'cart_total': cart_total,
        'item_count': item_count,
    }
    return render(request, 'escan/Market_Entity/E-commerce/Marketplace/u_carts.html', context)


@login_required
@require_POST
@csrf_exempt
def u_add_to_carts(request, product_id):
    try:
        # Parse JSON data from request body
        data = json.loads(request.body)
        quantity = int(data.get('quantity', 1))
        
        # Validate quantity
        if quantity <= 0:
            return JsonResponse({
                'success': False,
                'error': 'Quantity must be at least 1'
            }, status=400)
        
        # Get product and validate stock
        product = get_object_or_404(Product, id=product_id)
        if quantity > product.stock:
            return JsonResponse({
                'success': False,
                'error': f'Only {product.stock} items available in stock'
            }, status=400)
        
        # Get or create cart for current user - CHANGED FROM user TO customer
        cart, created = Cart.objects.get_or_create(customer=request.user, completed=False)
        
        # Get or create cart item
        cart_item, created = Cartitems.objects.get_or_create(cart=cart, product=product)
        
        # Calculate new quantity
        new_quantity = cart_item.quantity + quantity if not created else quantity
        
        # Validate stock again with new quantity
        if new_quantity > product.stock:
            return JsonResponse({
                'success': False,
                'error': f'Cannot add {quantity} more items (would exceed available stock)'
            }, status=400)
        
        # Update cart item
        cart_item.quantity = new_quantity
        cart_item.save()
        
        # Return success response
        return JsonResponse({
            'success': True,
            'item_count': cart.get_item_total,
            'cart_total': cart.get_cart_total,
            'message': f'{product.name} added to cart successfully!'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
 
@login_required
@require_POST
@csrf_exempt
def u_update_cart_items(request, item_id):
    try:
        data = json.loads(request.body)
        new_quantity = int(data.get('quantity', 1))
        
        cart_item = get_object_or_404(
            Cartitems, 
            id=item_id, 
            cart__customer=request.user
        )
        
        if new_quantity <= 0:
            cart_item.delete()
            return JsonResponse({
                'success': True,
                'item_count': cart_item.cart.get_item_total,
                'cart_total': cart_item.cart.get_cart_total,
                'message': 'Item removed from cart'
            })
        
        if new_quantity > cart_item.product.stock:
            return JsonResponse({
                'success': False,
                'error': f'Only {cart_item.product.stock} items available in stock'
            }, status=400)
        
        cart_item.quantity = new_quantity
        cart_item.save()
        
        return JsonResponse({
            'success': True,
            'item_count': cart_item.cart.get_item_total,
            'cart_total': cart_item.cart.get_cart_total,
            'item_total': cart_item.get_total,
            'message': 'Cart updated successfully'
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)

@login_required
@require_POST
@csrf_exempt
def u_remove_from_carts(request, item_id):
    try:
        cart_item = get_object_or_404(
            Cartitems, 
            id=item_id, 
            cart__customer=request.user
        )
        cart = cart_item.cart
        cart_item.delete()
        
        return JsonResponse({
            'success': True,
            'item_count': cart.get_item_total,
            'cart_total': cart.get_cart_total,
            'message': 'Item removed from cart'
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)

#Market Entity 
def my_store_orders_part(request):
    # --- Store detection ---
    admin_store = None
    if hasattr(request.user, 'store_owner'):
        admin_store = request.user.store_owner
    elif hasattr(request.user, 'store'):
        admin_store = request.user.store
    elif hasattr(request.user, 'stores') and request.user.stores.exists():
        admin_store = request.user.stores.first()

    # --- Filters ---
    today = datetime.today()
    month = int(request.GET.get("month", today.month))
    year = int(request.GET.get("year", today.year))

    # --- Base queries ---
    new_orders = Order.objects.filter(customer=request.user, status='Pending')
    total_orders = Order.objects.filter(customer=request.user).exclude(status='Pending')
    if admin_store:
        customer_orders = Order.objects.filter(store=admin_store).exclude(customer=request.user)
    else:
        customer_orders = Order.objects.none()

    # --- Calendar grid for the month ---
    cal = calendar.Calendar(firstweekday=6)  # Sunday start
    month_days = cal.monthdatescalendar(year, month)  # 2D weeks grid

    calendar_data = []
    if admin_store:
        orders = Order.objects.filter(store=admin_store)

        # Top offsets for each status
        status_top_map = {
            "Pending": 5,
            "On Process": 30,
            "Delivered": 55,
            "Completed": 80,
        }

        for week in month_days:
            week_data = []
            bars = []

            # Map day -> column index (1..7 for CSS grid)
            day_to_col = {day: idx + 1 for idx, day in enumerate(week)}

            # --- Bars for orders ---
            for order in orders:
                top_offset = 0

                # Pending = single day
                if order.status == "Pending" and order.order_date:
                    top_offset = status_top_map["Pending"]
                    if order.order_date.date() in week:
                        col = day_to_col[order.order_date.date()]
                        bars.append({
                            "type": "pending",
                            "label": f"#{order.id}",
                            "start_col": col,
                            "end_col": col + 1,
                            "top": top_offset
                        })

                # On Process = range (process_start → process_end)
                elif order.status == "On Process" and order.process_start and order.process_end:
                    top_offset = status_top_map["On Process"]
                    start = max(order.process_start.date(), week[0])
                    end = min(order.process_end.date(), week[-1])
                    if start <= end:
                        bars.append({
                            "type": "process",
                            "label": f"#{order.id}",
                            "start_col": day_to_col[start],
                            "end_col": day_to_col[end] + 1,
                            "top": top_offset
                        })

                # Delivered = range (delivery_start → delivery_end)
                elif order.status == "Delivered" and order.delivery_start and order.delivery_end:
                    top_offset = status_top_map["Delivered"]
                    start = max(order.delivery_start.date(), week[0])
                    end = min(order.delivery_end.date(), week[-1])
                    if start <= end:
                        bars.append({
                            "type": "delivery",
                            "label": f"#{order.id}",
                            "start_col": day_to_col[start],
                            "end_col": day_to_col[end] + 1,
                            "top": top_offset
                        })

                # Completed = single day
                elif order.status == "Completed" and order.completion_date:
                    top_offset = status_top_map["Completed"]
                    if order.completion_date.date() in week:
                        col = day_to_col[order.completion_date.date()]
                        bars.append({
                            "type": "completed",
                            "label": f"#{order.id}",
                            "start_col": col,
                            "end_col": col + 1,
                            "top": top_offset
                        })

            # --- Day data for this week ---
            for day in week:
                day_data = {
                    "date": day,
                    "is_current_month": (day.month == month)
                }
                week_data.append(day_data)

            # Push week into calendar_data
            calendar_data.append({
                "days": week_data,
                "bars": bars
            })

    context = {
        "new_orders": new_orders,
        "total_orders": total_orders,
        "customer_orders": customer_orders,
        "calendar_data": calendar_data,   # each week has days + bars
        "current_month": month,
        "current_year": year,
        "now": today,
    }
    return render(request, "escan/Market_Entity/E-commerce/MyStore/my_store_orders_part.html", context)
# @login_required
# def u_update_order_status(request, order_id):
#     if request.method == 'POST':
#         new_status = request.POST.get('status')
#         order = get_object_or_404(Order, pk=order_id, customer=request.user)
        
#         # Only allow certain status changes from user side
#         if new_status in ['Cancelled']:  # Users can only cancel orders
#             order.status = new_status
#             order.save()
        
#         return redirect('my_store_orders_part')
@login_required
def u_update_order(request):
    """Update multiple order fields (quantity, amount, status)"""
    if request.method == 'POST':
        try:
            order_id = request.POST.get('order_id')
            quantity = request.POST.get('quantity')
            total_amount = request.POST.get('total_amount')
            status = request.POST.get('status')
            
            # Get the order - make sure it belongs to the user's store
            order = get_object_or_404(Order, id=order_id, store__owner=request.user)
            
            # Update only the fields that were provided and changed
            if quantity and int(quantity) != order.quantity:
                order.quantity = int(quantity)
                
            if total_amount and float(total_amount) != order.total_amount:
                order.total_amount = float(total_amount)
                
            if status and status != order.status:
                order.status = status
            
            order.save()
            
            return JsonResponse({
                'success': True,
                'order_id': order_id,
                'message': 'Order updated successfully'
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            })
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@login_required
def u_update_order_status(request, order_id):
    """Quick update for status only (useful for dropdown changes)"""
    if request.method == 'POST':
        try:
            new_status = request.POST.get('status')
            order = get_object_or_404(Order, pk=order_id, store__owner=request.user)
            
            # Store owners can update to any status
            if new_status in ['Pending', 'On Process', 'Delivered', 'Completed', 'Cancelled']:
                order.status = new_status
                order.save()
                
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'success': True, 'new_status': new_status})
                else:
                    return redirect('my_store_orders_part')
            else:
                return JsonResponse({'success': False, 'error': 'Invalid status'})
                
        except Order.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Order not found'})
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@login_required
def u_add_review(request):
    if request.method == 'POST':
        order_id = request.POST.get('order_id')
        product_id = request.POST.get('product_id')
        rating = request.POST.get('rating')
        comment = request.POST.get('comment')
        
        order = get_object_or_404(Order, id=order_id, customer=request.user)
        product = get_object_or_404(Product, id=product_id)
        
        # Check if review already exists
        review, created = Review.objects.get_or_create(
            product=product,
            customer=request.user,
            defaults={
                'rating': rating,
                'comment': comment,
                'is_approved': False
            }
        )
        
        if not created:
            review.rating = rating
            review.comment = comment
            review.save()
        
        return redirect('my_orders_part')
    





#********************************************************************************

def get_store_customers_count(user):
    """Helper function to count customers for a specific store"""
    try:
        store = Store.objects.get(owner=user)
        store_orders = Order.objects.filter(store=store)
        customer_ids = store_orders.values_list('customer', flat=True).distinct()
        return Customer.objects.filter(id__in=customer_ids).count()
    except Store.DoesNotExist:
        return 0

@login_required
# def admin_dashboard(request):
#     if not hasattr(request.user, "role") or request.user.role != "Admin":
#         return redirect("user_dashboard")

#     users = CustomUser.objects.filter(is_deleted=False)
#     customer = Customer.objects.all()
#     total_users = users.exclude(role="Admin").count()
#     total_customer = customer.count()
#     total_orders = Order.objects.count()

#     # Sum only 'Completed' orders
#     total_sales = Order.objects.filter(status="Completed").aggregate(
#         total_sales=Sum("total_amount")
#     )["total_sales"] or 0

#     # Get the store owned by the currently logged-in admin
#     try:
#         store = Store.objects.get(owner=request.user)
        
#         # Count unique customers who have purchased from this store (based on completed orders)
#         store_customer_count = Order.objects.filter(
#             store=store, 
#             status="Completed"
#         ).values('customer').distinct().count()
        
#     except Store.DoesNotExist:
#         # If the user doesn't have a store, set count to 0
#         store_customer_count = 0

#     # Aggregate data for completed orders
#     sales_summary = Order.objects.filter(status='Completed').values('product__name').annotate(
#         total_quantity=Sum('quantity'),
#         total_amount=Sum('total_amount')
#     )

#     # Prepare data for the chart
#     product_names = [item['product__name'] for item in sales_summary]
#     total_quantities = [item['total_quantity'] for item in sales_summary]
#     total_amounts = [item['total_amount'] for item in sales_summary]

#     return render(request, "escan/Admin/admin_dashboard.html", {
#         "users": users,
#         "total_users": total_users,
#         "customer": customer,
#         "total_customer": total_customer,
#         "store_customer_count": store_customer_count,  # Add this
#         "total_orders": total_orders,
#         "total_sales": total_sales,
#         "product_names": product_names,
#         "total_quantities": total_quantities,
#         "total_amounts": total_amounts,
#     })


# @login_required
# def admin_dashboard(request):
#     if not hasattr(request.user, "role") or request.user.role != "Admin":
#         return redirect("user_dashboard")

#     users = CustomUser.objects.filter(is_deleted=False)
#     total_users = users.exclude(role="Admin").count()

#     # Get the store owned by the currently logged-in admin
#     try:
#         store = Store.objects.get(owner=request.user)
#     except Store.DoesNotExist:
#         store = None

#     # Current date for calculations
#     today = timezone.now().date()
#     week_ago = today - timedelta(days=7)
#     month_ago = today - timedelta(days=30)
#     year_ago = today - timedelta(days=365)

#     # Initialize all metrics with default values
#     total_customers = 0
#     new_customers_month = 0
#     repeat_customers = 0
#     total_sales = 0
#     today_sales = 0
#     weekly_sales = 0
#     monthly_sales = 0
#     yearly_sales = 0
#     total_stocks = 0
#     low_stock_products = 0
#     out_of_stock_products = 0
#     stock_value = 0
#     total_orders = 0
#     completed_orders = 0
#     pending_orders = 0
#     weekly_sales_data = []
#     top_products = []
#     order_status_data = []

#     if store:
#         # ========== CUSTOMER METRICS ==========
#         # Total unique customers who bought from your store (completed orders only)
#         total_customers = Order.objects.filter(
#             store=store, 
#             status="Completed"
#         ).values('customer').distinct().count()

#         # New customers this month
#         new_customers_month = Order.objects.filter(
#             store=store,
#             status="Completed",
#             order_date__gte=month_ago
#         ).values('customer').distinct().count()

#         # Repeat customers (customers with more than 1 completed order)
#         repeat_customers = Order.objects.filter(
#             store=store,
#             status="Completed"
#         ).values('customer').annotate(
#             order_count=Count('id')
#         ).filter(order_count__gt=1).count()

#         # ========== SALES & REVENUE METRICS ==========
#         # Total sales revenue (all completed orders)
#         total_sales = Order.objects.filter(
#             store=store, 
#             status="Completed"
#         ).aggregate(total_sales=Sum("total_amount"))["total_sales"] or 0

#         # Today's sales
#         today_sales = Order.objects.filter(
#             store=store,
#             status="Completed",
#             order_date__date=today
#         ).aggregate(total_sales=Sum("total_amount"))["total_sales"] or 0

#         # Weekly sales
#         weekly_sales = Order.objects.filter(
#             store=store,
#             status="Completed", 
#             order_date__gte=week_ago
#         ).aggregate(total_sales=Sum("total_amount"))["total_sales"] or 0

#         # Monthly sales
#         monthly_sales = Order.objects.filter(
#             store=store,
#             status="Completed",
#             order_date__gte=month_ago
#         ).aggregate(total_sales=Sum("total_amount"))["total_sales"] or 0

#         # Yearly sales
#         yearly_sales = Order.objects.filter(
#             store=store,
#             status="Completed", 
#             order_date__gte=year_ago
#         ).aggregate(total_sales=Sum("total_amount"))["total_sales"] or 0

#         # ========== STOCK METRICS ==========
#         # Total products in stock
#         total_stocks = Product.objects.filter(store=store).aggregate(
#             total_stock=Sum('stock')
#         )['total_stock'] or 0

#         # Low stock products (less than 10)
#         low_stock_products = Product.objects.filter(
#             store=store,
#             stock__lt=10,
#             stock__gt=0
#         ).count()

#         # Out of stock products
#         out_of_stock_products = Product.objects.filter(
#             store=store,
#             stock=0
#         ).count()

#         # Stock value (total value of all inventory)
#         # Calculate manually to avoid F expression issues
#         products = Product.objects.filter(store=store)
#         stock_value = sum(product.price * product.stock for product in products)

#         # ========== ORDER METRICS ==========
#         total_orders = Order.objects.filter(store=store).count()
#         completed_orders = Order.objects.filter(store=store, status="Completed").count()
#         pending_orders = Order.objects.filter(store=store, status="Pending").count()

#         # ========== SALES CHART DATA ==========
#         # Weekly sales data for chart (last 7 days)
#     weekly_sales_data = []
#     for i in range(6, -1, -1):  # Last 7 days including today
#         date = today - timedelta(days=i)
#         day_sales = Order.objects.filter(
#             store=store,
#             status="Completed",
#             order_date__date=date
#         ).aggregate(
#             total_sales=Sum('total_amount'),
#             order_count=Count('id')
#         )
#         weekly_sales_data.append({
#             'date': date.strftime('%Y-%m-%d'),
#             'day': date.strftime('%a'),  # Short day name (Mon, Tue, etc.)
#             'total_sales': float(day_sales['total_sales'] or 0),
#             'order_count': day_sales['order_count'] or 0
#         })

#         # ========== TOP PRODUCTS ==========
#         # Simple approach - get products with highest stock
#         top_products = Product.objects.filter(store=store).order_by('-stock')[:5]
#         for product in top_products:
#             # Add placeholder values for the template
#             product.total_sold = product.stock  # Using stock as placeholder
#             product.total_revenue = product.price * product.stock  # Placeholder

#         # ========== ORDER STATUS DISTRIBUTION ==========
#     statuses = ['Pending', 'On Process', 'Delivered', 'Completed', 'Cancelled']
#     order_status_data = []
#     for status in statuses:
#         count = Order.objects.filter(store=store, status=status).count()
#         order_status_data.append({
#             'status': status,
#             'count': count
#         })

#     # Debug: Print data to console to verify
#     print("Weekly Sales Data:", weekly_sales_data)
#     print("Order Status Data:", order_status_data)

#     # For product sales chart (admin view of all products)
#     # Simple approach - use product data without complex joins
#     product_data = Product.objects.all()[:10]
#     product_names = [product.name for product in product_data]
#     total_quantities = [product.stock for product in product_data]  # Using stock as placeholder
#     total_amounts = [product.price * product.stock for product in product_data]  # Placeholder

#     context = {
#         'total_users': total_users,
#         'store': store,
        
#         # Customer metrics
#         'total_customers': total_customers,
#         'new_customers_month': new_customers_month,
#         'repeat_customers': repeat_customers,
        
#         # Sales & Revenue metrics
#         'total_sales': total_sales,
#         'today_sales': today_sales,
#         'weekly_sales': weekly_sales,
#         'monthly_sales': monthly_sales,
#         'yearly_sales': yearly_sales,
        
#         # Stock metrics
#         'total_stocks': total_stocks,
#         'low_stock_products': low_stock_products,
#         'out_of_stock_products': out_of_stock_products,
#         'stock_value': stock_value,
        
#         # Order metrics
#         'total_orders': total_orders,
#         'completed_orders': completed_orders,
#         'pending_orders': pending_orders,
        
#         # Chart data
#         'weekly_sales_data': weekly_sales_data,
#         'weekly_sales_json': json.dumps(weekly_sales_data),
#         'order_status_json': json.dumps(order_status_data),
        
#         # Top products
#         'top_products': top_products,
        
#         # Product sales data for charts
#         'product_names': product_names,
#         'total_quantities': total_quantities,
#         'total_amounts': total_amounts,
        
#         # User data for join date chart
#         'users': users,
#     }
    
#     return render(request, 'escan/Admin/admin_dashboard.html', context)

  
# My oldst admin dashboard code before major revamp

# @login_required
# def admin_dashboard(request):
#     if not hasattr(request.user, "role") or request.user.role != "Admin":
#         return redirect("user_dashboard")

#     users = CustomUser.objects.filter(is_deleted=False)
#     total_users = users.exclude(role="Admin").count()

#     # Get the store owned by the currently logged-in admin
#     try:
#         store = Store.objects.get(owner=request.user)
#     except Store.DoesNotExist:
#         store = None

#     # Current date for calculations
#     today = timezone.now().date()
#     week_ago = today - timedelta(days=7)
#     month_ago = today - timedelta(days=30)
#     year_ago = today - timedelta(days=365)

#     # Initialize all metrics with default values
#     context = {
#         'total_users': total_users,
#         'store': store,
#         'users': users,
#     }

#     if store:
#         # ========== MY STORE DATA ==========
        
#         # Customer metrics
#         total_customers = Order.objects.filter(
#             store=store, status="Completed"
#         ).values('customer').distinct().count()
        
#         new_customers_month = Order.objects.filter(
#             store=store, status="Completed", order_date__gte=month_ago
#         ).values('customer').distinct().count()
        
#         repeat_customers = Order.objects.filter(
#             store=store, status="Completed"
#         ).values('customer').annotate(
#             order_count=Count('id')
#         ).filter(order_count__gt=1).count()

#         # Sales & Revenue metrics
#         total_sales = Order.objects.filter(
#             store=store, status="Completed"
#         ).aggregate(total=Sum("total_amount"))["total"] or 0
        
#         today_sales = Order.objects.filter(
#             store=store, status="Completed", order_date__date=today
#         ).aggregate(total=Sum("total_amount"))["total"] or 0
        
#         weekly_sales = Order.objects.filter(
#             store=store, status="Completed", order_date__gte=week_ago
#         ).aggregate(total=Sum("total_amount"))["total"] or 0
        
#         monthly_sales = Order.objects.filter(
#             store=store, status="Completed", order_date__gte=month_ago
#         ).aggregate(total=Sum("total_amount"))["total"] or 0
        
#         yearly_sales = Order.objects.filter(
#             store=store, status="Completed", order_date__gte=year_ago
#         ).aggregate(total=Sum("total_amount"))["total"] or 0

#         # Stock metrics
#         total_stocks = Product.objects.filter(store=store).aggregate(
#             total=Sum('stock')
#         )['total'] or 0
        
#         low_stock_products = Product.objects.filter(
#             store=store, stock__lt=10, stock__gt=0
#         ).count()
        
#         out_of_stock_products = Product.objects.filter(
#             store=store, stock=0
#         ).count()
        
#         products = Product.objects.filter(store=store)
#         stock_value = sum(p.price * p.stock for p in products)

#         # Order metrics
#         total_orders = Order.objects.filter(store=store).count()
#         completed_orders = Order.objects.filter(store=store, status="Completed").count()
#         pending_orders = Order.objects.filter(store=store, status="Pending").count()

#         # Weekly sales data for chart
#         weekly_sales_data = []
#         for i in range(6, -1, -1):
#             date = today - timedelta(days=i)
#             day_sales = Order.objects.filter(
#                 store=store, status="Completed", order_date__date=date
#             ).aggregate(
#                 total_sales=Sum('total_amount'),
#                 order_count=Count('id')
#             )
#             weekly_sales_data.append({
#                 'date': date.strftime('%Y-%m-%d'),
#                 'day': date.strftime('%a'),
#                 'total_sales': float(day_sales['total_sales'] or 0),
#                 'order_count': day_sales['order_count'] or 0
#             })

#         # Top products
#         top_products = Product.objects.filter(store=store).order_by('-stock')[:5]
#         for product in top_products:
#             product.total_sold = product.stock
#             product.total_revenue = product.price * product.stock

#         # Order status distribution
#         statuses = ['Pending', 'On Process', 'Delivered', 'Completed', 'Cancelled']
#         order_status_data = []
#         for status in statuses:
#             count = Order.objects.filter(store=store, status=status).count()
#             order_status_data.append({'status': status, 'count': count})

#         context.update({
#             'total_customers': total_customers,
#             'new_customers_month': new_customers_month,
#             'repeat_customers': repeat_customers,
#             'total_sales': total_sales,
#             'today_sales': today_sales,
#             'weekly_sales': weekly_sales,
#             'monthly_sales': monthly_sales,
#             'yearly_sales': yearly_sales,
#             'total_stocks': total_stocks,
#             'low_stock_products': low_stock_products,
#             'out_of_stock_products': out_of_stock_products,
#             'stock_value': stock_value,
#             'total_orders': total_orders,
#             'completed_orders': completed_orders,
#             'pending_orders': pending_orders,
#             'weekly_sales_data': weekly_sales_data,
#             'weekly_sales_json': json.dumps(weekly_sales_data),
#             'order_status_json': json.dumps(order_status_data),
#             'top_products': top_products,
#         })

#         # ========== MY PURCHASES FROM OTHER STORES ==========
        
#         # Get all orders where the admin is the customer
#         my_purchases = Order.objects.filter(
#             customer=request.user,
#             status="Completed"
#         ).select_related('product', 'store')

#         # Total purchases stats
#         total_purchase_amount = my_purchases.aggregate(
#             total=Sum('total_amount')
#         )['total'] or 0
        
#         total_purchase_count = my_purchases.count()

#         # Products purchased - group by product
#         products_purchased = my_purchases.values(
#             'product__name', 'product__id', 'store__name'
#         ).annotate(
#             total_quantity=Sum('quantity'),
#             total_spent=Sum('total_amount'),
#             order_count=Count('id')
#         ).order_by('-total_quantity')[:10]

#         # Most purchased product
#         most_purchased_product = products_purchased[0] if products_purchased else None

#         # Purchases by store
#         purchases_by_store = my_purchases.values(
#             'store__name'
#         ).annotate(
#             total_orders=Count('id'),
#             total_spent=Sum('total_amount')
#         ).order_by('-total_orders')

#         # Monthly purchase trend (last 6 months)
#         monthly_purchases = []
#         for i in range(5, -1, -1):
#             month_date = today - timedelta(days=30*i)
#             month_start = month_date.replace(day=1)
#             if i > 0:
#                 next_month = month_date.replace(day=1) + timedelta(days=32)
#                 month_end = next_month.replace(day=1) - timedelta(days=1)
#             else:
#                 month_end = today
            
#             month_data = my_purchases.filter(
#                 order_date__date__gte=month_start,
#                 order_date__date__lte=month_end
#             ).aggregate(
#                 total_spent=Sum('total_amount'),
#                 order_count=Count('id')
#             )
            
#             monthly_purchases.append({
#                 'month': month_start.strftime('%b %Y'),
#                 'total_spent': float(month_data['total_spent'] or 0),
#                 'order_count': month_data['order_count'] or 0
#             })

#         context.update({
#             'total_purchase_amount': total_purchase_amount,
#             'total_purchase_count': total_purchase_count,
#             'products_purchased': products_purchased,
#             'most_purchased_product': most_purchased_product,
#             'purchases_by_store': purchases_by_store,
#             'monthly_purchases': monthly_purchases,
#             'monthly_purchases_json': json.dumps(monthly_purchases),
#             'products_purchased_json': json.dumps(list(products_purchased)),
#         })

#     # ========== USER VISUALIZATION (NON-ADMIN) ==========
    
#     non_admin_users = users.exclude(role="Admin")
    
#     # Prepare user data with role field
#     users_with_role = []
#     for user in non_admin_users:
#         users_with_role.append({
#             "id": user.id,
#             "first_name": user.first_name,
#             "last_name": user.last_name,
#             "username": user.username,
#             "email": user.email,
#             "role": user.role,
#             "date_joined": user.date_joined.strftime('%Y-%m-%d')
#         })
    
#     # User statistics
#     total_non_admin_users = non_admin_users.count()
#     farmers_count = non_admin_users.filter(role='Farmer').count()
#     market_entities_count = non_admin_users.filter(role='Market-entity').count()
    
#     # User growth by month
#     user_growth_data = []
#     for i in range(11, -1, -1):
#         month_date = today - timedelta(days=30*i)
#         month_start = month_date.replace(day=1)
#         if i > 0:
#             next_month = month_date.replace(day=1) + timedelta(days=32)
#             month_end = next_month.replace(day=1) - timedelta(days=1)
#         else:
#             month_end = today
        
#         new_users = non_admin_users.filter(
#             date_joined__date__gte=month_start,
#             date_joined__date__lte=month_end
#         ).count()
        
#         user_growth_data.append({
#             'month': month_start.strftime('%b %Y'),
#             'count': new_users
#         })

#     context.update({
#         'users_data_json': json.dumps(users_with_role),
#         'total_non_admin_users': total_non_admin_users,
#         'farmers_count': farmers_count,
#         'market_entities_count': market_entities_count,
#         'user_growth_data': user_growth_data,
#         'user_growth_json': json.dumps(user_growth_data),
#     })

#     # ========== FARMER ACTIVITIES ==========
    
#     farmers = CustomUser.objects.filter(role='Farmer', is_deleted=False)
#     total_farmers = farmers.count()
    
#     # Detection records analysis
#     disease_scans = DetectionRecord.objects.filter(
#         model_type='disease',
#         user__role='Farmer'
#     ).select_related('user')
    
#     variety_scans = DetectionRecord.objects.filter(
#         model_type='variety',
#         user__role='Farmer'
#     ).select_related('user')
    
#     total_disease_scans = disease_scans.count()
#     total_variety_scans = variety_scans.count()
#     total_scans = total_disease_scans + total_variety_scans
    
#     # Active farmers (farmers who have scanned at least once)
#     active_farmers = farmers.filter(
#         Q(detectionrecord__model_type='disease') | 
#         Q(detectionrecord__model_type='variety')
#     ).distinct().count()
    
#     # Top active farmers by scan count
#     top_active_farmers = farmers.annotate(
#         total_scans=Count('detectionrecord')
#     ).filter(total_scans__gt=0).order_by('-total_scans')[:10]
    
#     top_farmers_data = []
#     for farmer in top_active_farmers:
#         disease_count = DetectionRecord.objects.filter(
#             user=farmer, model_type='disease'
#         ).count()
#         variety_count = DetectionRecord.objects.filter(
#             user=farmer, model_type='variety'
#         ).count()
        
#         top_farmers_data.append({
#             'id': farmer.id,
#             'name': f"{farmer.first_name} {farmer.last_name}",
#             'username': farmer.username,
#             'email': farmer.email,
#             'disease_scans': disease_count,
#             'variety_scans': variety_count,
#             'total_scans': disease_count + variety_count,
#             'date_joined': farmer.date_joined.strftime('%Y-%m-%d')
#         })
    
#     # Scan activity over time (last 30 days)
#     daily_scan_activity = []
#     for i in range(29, -1, -1):
#         date = today - timedelta(days=i)
#         day_scans = DetectionRecord.objects.filter(
#             user__role='Farmer',
#             timestamp__date=date
#         ).aggregate(
#             disease_scans=Count('id', filter=Q(model_type='disease')),
#             variety_scans=Count('id', filter=Q(model_type='variety'))
#         )
        
#         daily_scan_activity.append({
#             'date': date.strftime('%Y-%m-%d'),
#             'day': date.strftime('%b %d'),
#             'disease_scans': day_scans['disease_scans'] or 0,
#             'variety_scans': day_scans['variety_scans'] or 0,
#             'total_scans': (day_scans['disease_scans'] or 0) + (day_scans['variety_scans'] or 0)
#         })
    
#     # Most detected diseases
#     top_diseases = DetectionRecord.objects.filter(
#         model_type='disease',
#         user__role='Farmer'
#     ).values('prediction').annotate(
#         count=Count('id')
#     ).order_by('-count')[:5]
    
#     # Most detected varieties
#     top_varieties = DetectionRecord.objects.filter(
#         model_type='variety',
#         user__role='Farmer'
#     ).values('prediction').annotate(
#         count=Count('id')
#     ).order_by('-count')[:5]
    
#     # Average confidence scores
#     avg_disease_confidence = DetectionRecord.objects.filter(
#         model_type='disease',
#         user__role='Farmer'
#     ).aggregate(avg=Avg('confidence'))['avg'] or 0
    
#     avg_variety_confidence = DetectionRecord.objects.filter(
#         model_type='variety',
#         user__role='Farmer'
#     ).aggregate(avg=Avg('confidence'))['avg'] or 0
    
#     context.update({
#         'total_farmers': total_farmers,
#         'active_farmers': active_farmers,
#         'total_disease_scans': total_disease_scans,
#         'total_variety_scans': total_variety_scans,
#         'total_scans': total_scans,
#         'top_farmers_data': top_farmers_data,
#         'top_farmers_json': json.dumps(top_farmers_data),
#         'daily_scan_activity': daily_scan_activity,
#         'daily_scan_activity_json': json.dumps(daily_scan_activity),
#         'top_diseases': top_diseases,
#         'top_diseases_json': json.dumps(list(top_diseases)),
#         'top_varieties': top_varieties,
#         'top_varieties_json': json.dumps(list(top_varieties)),
#         'avg_disease_confidence': round(avg_disease_confidence * 100, 2),
#         'avg_variety_confidence': round(avg_variety_confidence * 100, 2),
#     })
    
#     return render(request, 'escan/Admin/admin_dashboard.html', context)
@login_required
def admin_dashboard(request):
    if not hasattr(request.user, "role") or request.user.role != "Admin":
        return redirect("user_dashboard")

    users = CustomUser.objects.filter(is_deleted=False)
    total_users = users.exclude(role="Admin").count()

    # Get the store owned by the currently logged-in admin
    try:
        store = Store.objects.get(owner=request.user)
        has_store = True
    except Store.DoesNotExist:
        store = None
        has_store = False

    # Current date for calculations
    today = timezone.now().date()
    week_ago = today - timedelta(days=7)
    month_ago = today - timedelta(days=30)
    year_ago = today - timedelta(days=365)

    # Initialize context
    context = {
        'total_users': total_users,
        'store': store,
        'has_store': has_store,
        'users': users,
    }

    # ========== MY STORE DATA ==========
    if has_store and store:
        # Customer metrics
        total_customers = Order.objects.filter(
            store=store, status="Completed"
        ).values('customer').distinct().count()
        
        new_customers_month = Order.objects.filter(
            store=store, status="Completed", order_date__gte=month_ago
        ).values('customer').distinct().count()
        
        # Sales & Revenue metrics
        total_sales = Order.objects.filter(
            store=store, status="Completed"
        ).aggregate(total=Sum("total_amount"))["total"] or 0
        
        today_sales = Order.objects.filter(
            store=store, status="Completed", order_date__date=today
        ).aggregate(total=Sum("total_amount"))["total"] or 0
        
        weekly_sales = Order.objects.filter(
            store=store, status="Completed", order_date__gte=week_ago
        ).aggregate(total=Sum("total_amount"))["total"] or 0
        
        monthly_sales = Order.objects.filter(
            store=store, status="Completed", order_date__gte=month_ago
        ).aggregate(total=Sum("total_amount"))["total"] or 0
        
        yearly_sales = Order.objects.filter(
            store=store, status="Completed", order_date__gte=year_ago
        ).aggregate(total=Sum("total_amount"))["total"] or 0

        # Stock metrics
        total_stocks = Product.objects.filter(store=store).aggregate(
            total=Sum('stock')
        )['total'] or 0
        
        low_stock_products = Product.objects.filter(
            store=store, stock__lt=10, stock__gt=0
        ).count()
        
        # Order metrics
        total_orders = Order.objects.filter(store=store).count()
        completed_orders = Order.objects.filter(store=store, status="Completed").count()
        pending_orders = Order.objects.filter(store=store, status="Pending").count()

        # Weekly sales data for chart
        weekly_sales_data = []
        for i in range(6, -1, -1):
            date = today - timedelta(days=i)
            day_sales = Order.objects.filter(
                store=store, status="Completed", order_date__date=date
            ).aggregate(
                total_sales=Sum('total_amount'),
                order_count=Count('id')
            )
            weekly_sales_data.append({
                'date': date.strftime('%Y-%m-%d'),
                'day': date.strftime('%a'),
                'total_sales': float(day_sales['total_sales'] or 0),
                'order_count': day_sales['order_count'] or 0
            })

        # Top products
        top_products = Product.objects.filter(store=store).annotate(
            total_sold=Count('order'),
            total_revenue=Sum('order__total_amount', filter=Q(order__store=store, order__status='Completed'))
        ).order_by('-total_sold')[:10]

        # Order status distribution
        statuses = ['Pending', 'On Process', 'Delivered', 'Completed', 'Cancelled']
        order_status_data = []
        for status in statuses:
            count = Order.objects.filter(store=store, status=status).count()
            order_status_data.append({'status': status, 'count': count})

        context.update({
            'total_customers': total_customers,
            'new_customers_month': new_customers_month,
            'total_sales': total_sales,
            'today_sales': today_sales,
            'weekly_sales': weekly_sales,
            'monthly_sales': monthly_sales,
            'yearly_sales': yearly_sales,
            'total_stocks': total_stocks,
            'low_stock_products': low_stock_products,
            'total_orders': total_orders,
            'completed_orders': completed_orders,
            'pending_orders': pending_orders,
            'weekly_sales_data': weekly_sales_data,
            'weekly_sales_json': json.dumps(weekly_sales_data),
            'order_status_data': order_status_data,
            'order_status_json': json.dumps(order_status_data),
            'top_products': top_products,
        })

    # ========== MY PURCHASES FROM OTHER STORES ==========
    my_purchases_queryset = Order.objects.filter(
        customer=request.user,
        status="Completed"
    ).select_related('product', 'store')

    # Calculate purchase statistics
    total_purchase_count = my_purchases_queryset.count()
    total_purchase_amount = my_purchases_queryset.aggregate(total=Sum('total_amount'))['total'] or 0
    
    # Unique stores and products
    unique_stores_count = my_purchases_queryset.values('store').distinct().count()
    unique_products_count = my_purchases_queryset.values('product').distinct().count()

    # Get limited purchases for table display
    my_purchases_for_table = my_purchases_queryset[:10]

    # Monthly purchase summary
    monthly_purchases = {}
    for purchase in my_purchases_queryset:
        month_year = purchase.order_date.strftime('%Y-%m')
        month_label = purchase.order_date.strftime('%b %Y')
        if month_year not in monthly_purchases:
            monthly_purchases[month_year] = {
                'month': month_year,
                'month_label': month_label,
                'total_amount': Decimal('0.00'),
                'total_quantity': 0,
                'order_count': 0
            }
        monthly_purchases[month_year]['total_amount'] += purchase.total_amount
        monthly_purchases[month_year]['total_quantity'] += purchase.quantity
        monthly_purchases[month_year]['order_count'] += 1

    # Convert to list for template
    monthly_purchase_list = []
    for month_year, data in monthly_purchases.items():
        monthly_purchase_list.append({
            'month': data['month'],
            'month_label': data['month_label'],
            'total_amount': float(data['total_amount']),
            'total_quantity': data['total_quantity'],
            'order_count': data['order_count']
        })
    
    monthly_purchase_list.sort(key=lambda x: x['month'])

    # Add purchase data to context
    context.update({
        'my_purchases': my_purchases_for_table,
        'total_purchase_count': total_purchase_count,
        'total_purchase_amount': total_purchase_amount,
        'unique_stores_count': unique_stores_count,
        'unique_products_count': unique_products_count,
        'monthly_purchases_json': json.dumps(monthly_purchase_list),
    })

    # ========== USER VISUALIZATION ==========
    
    non_admin_users = users.exclude(role="Admin")
    
    # User statistics by role
    role_distribution = list(non_admin_users.values('role').annotate(
        count=Count('id')
    ).order_by('-count'))

    # Daily user registration data (last 30 days)
    daily_registrations = {}
    for i in range(30):
        date = today - timedelta(days=29-i)
        date_str = date.strftime('%Y-%m-%d')
        daily_registrations[date_str] = {
            'date': date_str,
            'date_label': date.strftime('%b %d'),
            'count': 0,
            'farmers': 0,
            'market_entities': 0
        }

    # Fill with actual data
    for user in non_admin_users.filter(date_joined__date__gte=today-timedelta(days=29)):
        date_str = user.date_joined.strftime('%Y-%m-%d')
        if date_str in daily_registrations:
            daily_registrations[date_str]['count'] += 1
            if user.role == 'Farmer':
                daily_registrations[date_str]['farmers'] += 1
            elif user.role == 'Market-entity':
                daily_registrations[date_str]['market_entities'] += 1

    daily_registration_list = list(daily_registrations.values())
    daily_registration_list.sort(key=lambda x: x['date'])

    context.update({
        'role_distribution': role_distribution,
        'role_distribution_json': json.dumps(role_distribution),
        'daily_registrations_json': json.dumps(daily_registration_list),
        'farmers_count': non_admin_users.filter(role='Farmer').count(),
        'market_entities_count': non_admin_users.filter(role='Market-entity').count(),
    })

    # ========== FARMER'S DATA VISUALIZATION ==========
    
    farmers = CustomUser.objects.filter(role='Farmer', is_deleted=False)
    total_farmers = farmers.count()
    
    # Detection records analysis
    detection_records = DetectionRecord.objects.filter(
        user__role='Farmer'
    ).select_related('user')
    
    total_detections = detection_records.count()
    active_farmers = detection_records.values('user').distinct().count()
    
    # Daily detection activity (last 30 days)
    daily_detection_activity = {}
    start_date = today - timedelta(days=29)
    
    # Initialize all dates
    for i in range(30):
        date = start_date + timedelta(days=i)
        date_str = date.strftime('%Y-%m-%d')
        daily_detection_activity[date_str] = {
            'date': date_str,
            'day': date.strftime('%b %d'),
            'disease_scans': 0,
            'variety_scans': 0,
            'total_scans': 0,
            'unique_farmers': 0
        }
    
    # Fill with actual data
    for detection in detection_records.filter(timestamp__date__gte=start_date):
        date_str = detection.timestamp.strftime('%Y-%m-%d')
        if date_str in daily_detection_activity:
            daily_detection_activity[date_str]['total_scans'] += 1
            if detection.model_type == 'disease':
                daily_detection_activity[date_str]['disease_scans'] += 1
            else:
                daily_detection_activity[date_str]['variety_scans'] += 1
    
    # Count unique farmers per day
    for date_str in daily_detection_activity.keys():
        unique_farmers = detection_records.filter(
            timestamp__date=date_str
        ).values('user').distinct().count()
        daily_detection_activity[date_str]['unique_farmers'] = unique_farmers

    daily_activity_list = list(daily_detection_activity.values())
    daily_activity_list.sort(key=lambda x: x['date'])

    # Top farmers with scan counts
    top_farmers_data = list(farmers.annotate(
        disease_scans=Count('detectionrecord', filter=Q(detectionrecord__model_type='disease')),
        variety_scans=Count('detectionrecord', filter=Q(detectionrecord__model_type='variety')),
        total_scans=Count('detectionrecord')
    ).filter(total_scans__gt=0).order_by('-total_scans')[:10])

    # Add last scan date
    for farmer in top_farmers_data:
        last_scan = DetectionRecord.objects.filter(user=farmer).order_by('-timestamp').first()
        farmer.last_scan = last_scan.timestamp.strftime('%Y-%m-%d') if last_scan else 'Never'

    # Detection summary
    detection_summary = {
        'disease_ratio': round(detection_records.filter(model_type='disease').count() / max(total_detections, 1) * 100, 1),
        'variety_ratio': round(detection_records.filter(model_type='variety').count() / max(total_detections, 1) * 100, 1),
        'avg_confidence_disease': round(detection_records.filter(model_type='disease').aggregate(Avg('confidence'))['confidence__avg'] or 0, 2),
        'avg_confidence_variety': round(detection_records.filter(model_type='variety').aggregate(Avg('confidence'))['confidence__avg'] or 0, 2)
    }

    context.update({
        'total_farmers': total_farmers,
        'active_farmers': active_farmers,
        'total_detections': total_detections,
        'daily_detection_activity_json': json.dumps(daily_activity_list),
        'top_farmers': top_farmers_data,
        'detection_summary': detection_summary
    })

    return render(request, 'escan/Admin/admin_dashboard.html', context)



# # ----------------------------------------------------------------------------


# Admin Side Manage Users
@supabase_login_required
def user_table(request):
    if request.user.role != "Admin":
        return redirect("user_dashboard")  # Restrict non-admins

    users = CustomUser.objects.all()
    userss= users.exclude(role="Admin").order_by("first_name") 
    return render(request, "escan/Admin/user_list/user_table.html", {"userss": userss})

@supabase_login_required
def add_user(request):
    if request.user.role != "Admin":
        return redirect("user_dashboard")

    global last_action

    if request.method == "POST":
        print("🔍 Request Files:", request.FILES)
        form = UserProfileForm(request.POST, request.FILES)
        print("🔍 Form data:", form.data)

        if form.is_valid():
            user = form.cleaned_data.get('username')

            if CustomUser.objects.filter(username=user).exists():
                messages.error(request, "User already exists. Duplicate entries are not allowed.")
            else:
                form = form.save()
                messages.success(request, "User added successfully.")
                last_action = {'type': 'add', 'user_id': user.id}
                return redirect('user_table')
        else:
            messages.error(request, "Form is invalid. Please correct the errors.")
    else:
        form = UserProfileForm()

    users = CustomUser.objects.all()
    return render(request, 'escan/Admin/user_list/user_table.html', {'form': form, 'users': users})

@supabase_login_required
def edit_user(request, user_id):
    if request.user.role != "Admin":
        return redirect("user_dashboard")

    user = get_object_or_404(CustomUser, id=user_id)

    if request.method == "POST":
        form = UserProfileForm(request.POST, request.FILES, instance=user)

        if form.is_valid():
            user_name = form.cleaned_data.get('username')

            # Check if the username already exists (except for the current user)
            if CustomUser.objects.exclude(id=user_id).filter(username=user_name).exists():
                messages.error(request, "Username already exists. Please choose a different one.")
                return redirect('user_table')  # Prevent saving if a duplicate exists

            # Save the form data (user profile)
            form.save()

            # Optionally, track last action in a model or in session data
            # last_action = {'type': 'edit', 'user_id': user.id}

            messages.success(request, "User updated successfully.")
            return redirect('user_table')  # Redirect after successful update

        else:
            messages.error(request, "Form is invalid. Please correct the errors.")

    else:
        form = UserProfileForm(instance=user)

    return render(request, 'escan/Admin/user_list/user_table.html', {'form': form, 'user': user})


@supabase_login_required
def delete_user(request, user_id):
    if request.user.role != "Admin":
        return redirect("login")
    user = get_object_or_404(CustomUser, id=user_id)  # Fixed spacing and typo
    user.soft_delete()  # Assuming you have a soft delete method 
    request.session["deleted_user"] = user.id  # Store in session for undo
    request.session["last_action"] = {"type": "delete", "user_id": user.id} 
    messages.success(request, "User deleted successfully. <a href='/undo_delete/'>Undo</a>", extra_tags="safe")
    return redirect("user_table")

@supabase_login_required
def undo_last_action_user(request):
    global last_action
    if last_action:
        if last_action['type'] == 'delete':
            user = last_action['user']
            user.save()
            messages.success(request, "Undo successful. User restored.")
        elif last_action['type'] == 'add':
            CustomUser.objects.filter(id=last_action['user_id']).delete()
            messages.success(request, "Undo add successful.")
        elif last_action['type'] == 'edit':
            previous_data = last_action['previous_data']
            user = CustomUser.objects.get(id=last_action['user_id'])
            # Restore previous data for user
            user.first_name = previous_data['first_name']
            user.last_name = previous_data['last_name']
            user.username = previous_data['username']
            user.email = previous_data['email']
            # Only update the password if it was modified
            if previous_data['password']:
                user.set_password(previous_data['password'])
            user.image_url = previous_data['image_url']
            user.role = previous_data['role']  # Assuming role is a field of CustomUser
            user.save()
            messages.success(request, "Undo edit successful.")
        last_action = {}
    return redirect('user_table')

@supabase_login_required
def search_users(request):
    query = request.GET.get('query', '').strip()
    if query:
        users = CustomUser.objects.filter(first_name__icontains=query).union(
            CustomUser.objects.filter(last_name__icontains=query),
            CustomUser.objects.filter(username__icontains=query),
            CustomUser.objects.filter(email__icontains=query)
        )
    else:
        users = CustomUser.objects.none()

    results = [
        {
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'first_name': u.first_name,
            'last_name': u.last_name,
            'date_joined': u.date_joined.strftime('%Y-%m-%d'),
            'is_active': u.is_active,
            'role': u.role,
            'image_url': u.image_url.url if u.image_url else None # Supabase URL is already a string
        }
        for u in users
    ]
    return JsonResponse({'results':results})

def user_print(request):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter), rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    elements = []
    styles = getSampleStyleSheet()
    wrap_style = ParagraphStyle(
        name='WrapStyle',
        parent=styles['Normal'],
        fontSize=12,
        leading=12,
        alignment=0,
    )
    # === LOGO IMAGE ===
    logo_path = finders.find("img/PrintLogo.jpg")
    if logo_path and os.path.exists(logo_path):
        logo = Image(logo_path, width=60, height=60)
    else:
        logo = Spacer(1, 60)
    title = Paragraph("<b>BANAe-SCAN STORE USER LIST</b>", styles['Title'])
    header = Table([[logo, title]], colWidths=[70, 450])
    header.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (1, 0), (1, 0), 'LEFT'),
    ]))
    elements.append(header)
    elements.append(Spacer(1, 12))
    date = Paragraph(datetime.now().strftime("%B %d, %Y — %I:%M %p"), styles['Normal'])
    elements.append(date)
    elements.append(Spacer(1, 12))
    # Table headers
    data = [['First Name', 'Last Name', 'Username', 'Email', 'Image','Date Joined', 'Is Active', 'Role']]
    users = CustomUser .objects.exclude(role='Admin')
    for user in users:
        # === Download product image from URL ===
        try:
            response = requests.get(user.image_url)
            if response.status_code == 200:
                img_buffer = io.BytesIO(response.content)
                user_img = Image(img_buffer, width=50, height=50)
            else:
                prod_img = Paragraph("No Image", wrap_style)
        except Exception as e:
            user_img = Paragraph("No Image", wrap_style)

        # Append row
        data.append([
            Paragraph(user.first_name, wrap_style),
            Paragraph(user.last_name, wrap_style),
            Paragraph(user.username, wrap_style),
            Paragraph(user.email,wrap_style),
            user_img,
            Paragraph(user.date_joined.strftime('%Y-%m-%d'), wrap_style),
            Paragraph("Active" if user.is_active else "Inactive", wrap_style),
            Paragraph(user.role, wrap_style),
        ])
    colWidths = [
        1.2* 72,  
        1.2* 72, 
        1.2* 72, 
        1.5* 72,  
        1.2 * 72,  
        1.5 * 72,  
        0.8 * 72,  
        1 * 72,  
    ]

    table = Table(data, colWidths=colWidths, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
    ]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return HttpResponse(buffer, content_type='application/pdf', headers={
        'Content-Disposition': 'attachment; filename="user_list.pdf"'
    })


# Admin Side
def a_setting(request):
    return render(request, "escan/Admin/a_setting.html")

# ----------------------------------------------------------------------------
#Admin/User Side Manage Profile/Settings/Addres

@login_required
def update_profile_ajax(request):
    """
    AJAX endpoint for updating user profile without page redirect
    Works for both admin and regular users
    """
    if request.method == 'POST':
        user = request.user
        form = UserProfileForm(request.POST, request.FILES, instance=user)
        
        if form.is_valid():
            username = form.cleaned_data.get('username')
            email = form.cleaned_data.get('email')
            
            # Check for duplicate username or email from other users
            if CustomUser.objects.exclude(id=user.id).filter(username=username).exists():
                return JsonResponse({
                    'success': False, 
                    'error': 'Username already taken by another user.'
                })
            
            if CustomUser.objects.exclude(id=user.id).filter(email=email).exists():
                return JsonResponse({
                    'success': False, 
                    'error': 'Email already registered with another account.'
                })
            
            # Save the form (this will handle image upload via Supabase)
            form.save()
            
            return JsonResponse({
                'success': True, 
                'message': 'Profile updated successfully.',
                'user_data': {
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'username': user.username,
                    'email': user.email,
                    'image_url': user.image_url.url if user.image_url else None
                }
            })
        else:
            errors = []
            for field, field_errors in form.errors.items():
                for error in field_errors:
                    errors.append(f"{field}: {error}")
            
            return JsonResponse({
                'success': False, 
                'error': 'Form is invalid: ' + ', '.join(errors)
            })
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@login_required 
def update_store_ajax(request):
    """
    AJAX endpoint for updating store information
    """
    if request.method == 'POST':
        try:
            store = Store.objects.get(owner=request.user)
        except Store.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Store not found'})
        
        form = StoreForm(request.POST, request.FILES, instance=store)
        
        if form.is_valid():
            form.save()
            return JsonResponse({
                'success': True, 
                'message': 'Store information updated successfully.',
                'store_data': {
                    'name': store.name,
                    'description': store.description,
                    'address': store.address,
                    'city': store.city,
                    'province': store.province,
                    'logo': store.logo
                }
            })
        else:
            errors = []
            for field, field_errors in form.errors.items():
                for error in field_errors:
                    errors.append(f"{field}: {error}")
            
            return JsonResponse({
                'success': False, 
                'error': 'Form is invalid: ' + ', '.join(errors)
            })
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@login_required
def update_shipping_address_ajax(request):
    """
    AJAX endpoint for updating shipping address
    """
    if request.method == 'POST':
        address_id = request.POST.get('address_id')
        
        if address_id:
            try:
                address = ShippingAddress.objects.get(id=address_id, customer=request.user)
                form = ShippingAddressForm(request.POST, instance=address)
            except ShippingAddress.DoesNotExist:
                return JsonResponse({'success': False, 'error': 'Address not found'})
        else:
            # Create new address
            form = ShippingAddressForm(request.POST)
        
        if form.is_valid():
            shipping_address = form.save(commit=False)
            shipping_address.customer = request.user
            shipping_address.save()
            
            return JsonResponse({
                'success': True, 
                'message': 'Shipping address updated successfully.',
                'address_data': {
                    'id': shipping_address.id,
                    'address': shipping_address.address,
                    'city': shipping_address.city,
                    'province': shipping_address.province,
                    'zipcode': shipping_address.zipcode,
                    'phone_number': shipping_address.phone_number,
                    'is_default': shipping_address.is_default
                }
            })
        else:
            errors = []
            for field, field_errors in form.errors.items():
                for error in field_errors:
                    errors.append(f"{field}: {error}")
            
            return JsonResponse({
                'success': False, 
                'error': 'Form is invalid: ' + ', '.join(errors)
            })
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@login_required
def get_user_data(request):
    """
    Get current user data for populating forms
    """
    user = request.user
    
    # Get store data if exists
    store_data = None
    try:
        store = Store.objects.get(owner=user)
        store_data = {
            'name': store.name,
            'description': store.description,
            'address': store.address,
            'city': store.city,
            'province': store.province,
            'logo': store.logo
        }
    except Store.DoesNotExist:
        pass
    
    # Get shipping addresses
    shipping_addresses = []
    for address in ShippingAddress.objects.filter(customer=user):
        shipping_addresses.append({
            'id': address.id,
            'address': address.address,
            'city': address.city,
            'province': address.province,
            'zipcode': address.zipcode,
            'phone_number': address.phone_number,
            'is_default': address.is_default
        })
    
    return JsonResponse({
        'user_data': {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'username': user.username,
            'email': user.email,
            'image_url': user.image_url.url if user.image_url else None
        },
        'store_data': store_data,
        'shipping_addresses': shipping_addresses
    })

# ----------------------------------------------------------------------------
# Admin Market place 
@login_required
def a_market_place(request):
    cart = Cart.objects.filter(customer=request.user, completed=False).first()
    products = Product.objects.filter(is_deleted=False) 
    return render(request, 'escan/Admin/E-commerce/a_market_place.html', {'products': products, 'cart': cart, 'cart_item_count': cart.get_item_total if cart else 0,})
    
# --------------------------------------------------------------------------------------------
# Admin Side Checkout
@login_required
def checkout_view(request):
    # Determine if this is a direct purchase or cart checkout
    product_id = request.GET.get('product')
    is_direct_checkout = product_id is not None
    
    if is_direct_checkout:
        return handle_direct_checkout(request)
    else:
        return handle_cart_checkout(request)


def handle_direct_checkout(request):
    try:
        product = get_object_or_404(Product, id=request.GET.get('product'))
        store = get_object_or_404(Store, id=request.GET.get('store'))
        quantity = int(request.GET.get('quantity', 1))
        
        # Check stock availability
        if product.stock < quantity:
            messages.error(request, f"Sorry, only {product.stock} items available in stock.")
            return redirect("a_market_place")
        
        # Get the user's default address or the last one
        shipping_address = ShippingAddress.objects.filter(
            customer=request.user, 
            is_default=True
        ).first()
        
        if not shipping_address:
            shipping_address = ShippingAddress.objects.filter(
                customer=request.user
            ).last()
        
        action = request.POST.get("action") if request.method == "POST" else None

        if action == "update_address":
            # Get or create the address
            address_data = {
                "phone_number": request.POST.get("phone_number"),
                "address": request.POST.get("address"),
                "city": request.POST.get("city"),
                "province": request.POST.get("province"),
                "zipcode": request.POST.get("zipcode"),
            }
            
            # Remove empty values to avoid overwriting with empty strings
            address_data = {k: v for k, v in address_data.items() if v}
            
            shipping_address, created = ShippingAddress.objects.update_or_create(
                customer=request.user,
                defaults=address_data
            )
            
            if created:
                messages.success(request, "Shipping address created successfully.")
            else:
                messages.success(request, "Shipping address updated successfully.")
                
            return redirect(f"{reverse('direct_checkout')}?product={product.id}&store={store.id}&quantity={quantity}")

        elif action == "place_order":
            use_existing = request.POST.get("use_existing_address") == "on"
            
            if use_existing and not shipping_address:
                messages.error(request, "No existing address found, please add one.")
                return redirect(f"{reverse('direct_checkout')}?product={product.id}&store={store.id}&quantity={quantity}")
            
            if not use_existing:
                # Create a new address
                address_data = {
                    "phone_number": request.POST.get("phone_number"),
                    "address": request.POST.get("address"),
                    "city": request.POST.get("city"),
                    "province": request.POST.get("province"),
                    "zipcode": request.POST.get("zipcode"),
                }
                
                # Remove empty values
                address_data = {k: v for k, v in address_data.items() if v}
                
                shipping_address = ShippingAddress.objects.create(
                    customer=request.user,
                    **address_data
                )
                
                # Set as default if requested
                if request.POST.get("set_as_default"):
                    shipping_address.is_default = True
                    shipping_address.save()

            # Calculate order totals
            subtotal = product.price * quantity
            shipping_fee = calculate_shipping_fee(store, shipping_address) if shipping_address else Decimal("0.00")
            total_amount = subtotal + shipping_fee
            payment_method = request.POST.get("payment_method", "COD")

            if payment_method == "COD":
                # Use transaction to ensure stock is properly decreased
                with transaction.atomic():
                    # Create the order
                    order = Order.objects.create(
                        customer=request.user,
                        store=store,
                        product=product,
                        shipping_address=shipping_address,
                        quantity=quantity,
                        subtotal=subtotal,
                        shipping_fee=shipping_fee,
                        total_amount=total_amount,
                        payment_method=payment_method,
                        paid=False,
                        status="Pending",
                    )
                    
                    # Decrease product stock
                    product.stock -= quantity
                    product.save()
                
                return redirect("order_confirmation", order_id=order.id)
            else:
                # Handle online payment methods
                request.session['pending_order_data'] = {
                    'store_id': store.id,
                    'product_id': product.id,
                    'shipping_address_id': shipping_address.id,
                    'quantity': quantity,
                    'subtotal': str(subtotal),
                    'shipping_fee': str(shipping_fee),
                    'total_amount': str(total_amount),
                    'payment_method': payment_method,
                }
                return a_initiate_paymongo_checkout(request, product, store, quantity, shipping_address, [payment_method.lower()])

        # GET request - show the form
        subtotal = product.price * quantity
        shipping_fee = a_calculate_shipping_fee(store, shipping_address) if shipping_address else Decimal("0.00")

        context = {
            "is_u_direct_checkouts": True,
            "product": product,
            "store": store,
            "quantity": quantity,
            "shipping_address": shipping_address,
            "shipping_fee": shipping_fee,
            "subtotal": subtotal,
            "total_amount": subtotal + shipping_fee,
            "has_address": shipping_address is not None,
            "PAYMENT_METHOD_CHOICES": Order.PAYMENT_METHOD_CHOICES,
        }
        return render(request, "escan/Admin/E-commerce/amarketplace/checkout.html", context)

    except (Product.DoesNotExist, Store.DoesNotExist, ValueError) as e:
        messages.error(request, f"Invalid product selection: {e}")
        return redirect("a_market_place")
    

def a_initiate_paymongo_checkout(request, product, store, quantity, shipping_address, paymongo_methods):
    subtotal = product.price * quantity
    shipping_fee = a_calculate_shipping_fee(store, shipping_address)
    total_amount = (subtotal + shipping_fee).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    # amount_in_cents = int(total_amount * 100)

    print("✅ Total amount to PayMongo:", total_amount)
    # print("✅ Amount in centavos:", product_amount_cents)

    product_amount_cents = int((product.price * 100).quantize(Decimal("1")))
    shipping_amount_cents = int((shipping_fee * 100).quantize(Decimal("1")))


    payload = {
        "data": {
            "attributes": {
                "line_items": [
                    {
                        "currency": "PHP",
                        "amount": product_amount_cents,
                        "description": (product.description or product.name)[:255],
                        "name": product.name,
                        "quantity": quantity,
                    },
                    {
                        "currency": "PHP",
                        "amount": shipping_amount_cents,
                        "description": "Shipping Fee",
                        "name": "Shipping fee",
                        "quantity": 1,
                    }
                ],
                "payment_method_types": paymongo_methods,
                "redirect": {
                    "success": request.build_absolute_uri(reverse("paymongo_success")) + f"?product_id={product.id}&store_id={store.id}&quantity={quantity}",
                    "failed": request.build_absolute_uri(reverse("paymongo_failed")),
                },
                "metadata": {
                    "user_id": request.user.id,
                },
            }
        }
    }

    headers = {
        "Authorization": f"Basic {base64.b64encode(settings.PAYMONGO_SECRET_API_KEY.encode()).decode()}",
        "Content-Type": "application/json",
    }

    response = requests.post("https://api.paymongo.com/v1/checkout_sessions", headers=headers, json=payload)

    if response.ok:
        checkout_url = response.json()["data"]["attributes"]["checkout_url"]
        return redirect(checkout_url)

    messages.error(request, "Unable to initiate payment.")
    return redirect(f"{reverse('direct_checkout')}?product={product.id}&store={store.id}&quantity={quantity}")

@login_required
def a_paymongo_success(request):
    pending = request.session.get("pending_order_data")
    if not pending:
        messages.error(request, "Payment succeeded but order data was lost.")
        return redirect("a_market_place")

    try:
        store = Store.objects.get(id=pending['store_id'])
        product = Product.objects.get(id=pending['product_id'])
        shipping_address = ShippingAddress.objects.get(id=pending['shipping_address_id'])

        subtotal = Decimal(pending['subtotal'])
        shipping_fee = Decimal(pending['shipping_fee'])
        total_amount = Decimal(pending['total_amount'])
        quantity = int(pending['quantity'])

        order = Order.objects.create(
            customer=request.user,
            store=store,
            product=product,
            shipping_address=shipping_address,
            quantity=quantity,
            subtotal=subtotal,
            shipping_fee=shipping_fee,
            total_amount=total_amount,
            payment_method=pending['payment_method'],
            paid=True,
            status="Completed",
        )

        # Clear session
        del request.session["pending_order_data"]

        messages.success(request, "Payment successful!")
        return redirect("order_confirmation", order_id=order.id)

    except Exception as e:
        print("Error creating order after payment:", e)
        messages.error(request, "Payment succeeded but order creation failed.")
        return redirect("a_market_place")
    
@login_required
def a_paymongo_failed(request):
    order = get_object_or_404(Order, id=request.GET.get("order_id"), customer=request.user)
    order.status = "Cancelled"
    order.save()
    messages.error(request, "Payment failed.")
    return redirect("direct_checkout")

@transaction.atomic
def process_direct_checkout(request, product, store, quantity):
    try:
        payment_method = request.POST.get('payment_method', 'COD')
        total_amount = product.price * quantity

        # Always resolve the shipping address FIRST
        if request.POST.get('use_existing_address') == 'on':
            shipping_address = ShippingAddress.objects.filter(customer=request.user).first()
            if not shipping_address:
                raise ValueError("No existing address found")
        else:
            # If a new address was entered, either update the old one or create a fresh one
            shipping_address, _ = ShippingAddress.objects.update_or_create(
                customer=request.user,
                defaults={
                    "phone_number": request.POST.get("phone_number"),
                    "address": request.POST.get("address"),
                    "city": request.POST.get("city"),
                    "province": request.POST.get("province"),
                    "zipcode": request.POST.get("zipcode"),
                }
            )

        # ✅ Calculate shipping fee only once, using the resolved address
        shipping_fee = a_calculate_shipping_fee(store, shipping_address)
        total_amount += shipping_fee

        # Create the order
        order = Order.objects.create(
            customer=request.user,
            store=store,
            product=product,
            shipping_address=shipping_address,
            quantity=quantity,
            total_amount=total_amount,
            shipping_fee=shipping_fee,
            payment_method=payment_method,
            status='Pending'
        )

        if payment_method != 'COD':
            Payment.objects.create(
                order=order,
                method=payment_method,
                amount_paid=order.total_amount,
                confirmed=False
            )

        # Reduce stock
        product.stock -= quantity
        product.save()

        # Track purchase history
        customer, _ = Customer.objects.get_or_create(user=request.user)
        CustomerPurchase.objects.create(
            customer=customer,
            store=store,
            product=product,
            category=product.category,
            quantity=quantity,
            total_amount=order.total_amount,
            is_completed=True
        )

        customer.stores_purchased_from.add(store)

        return redirect('order_confirmation', order_id=order.id)

    except Exception as e:
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect(request.META.get('HTTP_REFERER', 'checkout'))
    


def a_get_lat_lon_from_address(address):
    """Fetch latitude and longitude from a string address using Nominatim."""
    try:
        url = "https://nominatim.openstreetmap.org/search"
        params = {"q": address, "format": "json"}
        res = requests.get(url, params=params, headers={"User-Agent": "BanaeScanApp"}).json()
        if res:
            return float(res[0]["lat"]), float(res[0]["lon"])
    except Exception as e:
        print("Nominatim error:", e)
    return None, None

def a_calculate_shipping_fee(store, shipping_address):
    try:
        # Get coordinates of buyer based on shipping address (or fallback)
        if shipping_address.latitude and shipping_address.longitude:
            buyer_coords = (shipping_address.latitude, shipping_address.longitude)
        else:
            # Fallback: use PostalCodeLocation by ZIP code
            try:
                buyer_loc = PostalCodeLocation.objects.get(postal_code=shipping_address.zipcode)
                buyer_coords = (buyer_loc.latitude, buyer_loc.longitude)
            except PostalCodeLocation.DoesNotExist:
                # Fallback to Nominatim geolocation service
                geolocator = Nominatim(user_agent="escan")
                location = geolocator.geocode(f"{shipping_address.address}, {shipping_address.city}, {shipping_address.province}, {shipping_address.zipcode}")
                if not location:
                    return Decimal("0.00")  # Return 0 if no location is found
                buyer_coords = (location.latitude, location.longitude)
    except Exception as e:
        print(f"Error getting buyer coordinates: {e}")
        return Decimal("0.00")  # Return 0 if there's any error

    # Get store coordinates (fallback if missing)
    if not (store.latitude and store.longitude):
        print("Store coordinates missing")
        return Decimal("0.00")

    store_coords = (store.latitude, store.longitude)
    print("Buyer coordinates:", buyer_coords)
    print("Store coordinates:", store_coords)

    # Calculate distance in kilometers
    distance_km = geodesic(store_coords, buyer_coords).km

    # Get shipping fee from store's shipping rule
    rule = getattr(store, "shipping_rule", None)
    base_fee = rule.base_fee if rule else Decimal("10.00")
    per_km_rate = rule.per_km_rate if rule else Decimal("5.00")

    # Calculate total shipping fee
    shipping_fee = base_fee + (Decimal(distance_km) * per_km_rate)

    # Return the rounded shipping fee (rounded to 2 decimal places)
    return shipping_fee.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    
@login_required
def a_set_default_address(request, address_id):
    address = get_object_or_404(ShippingAddress, id=address_id, customer=request.user)

    if request.method == 'POST':
        # Set this address as default
        address.is_default = True
        address.save()  # Your model logic will unset others

    return redirect(request.META.get('HTTP_REFERER', 'a_market_place'))


@csrf_exempt
def a_create_gcash_payment(request):
    if request.method == 'POST':
        amount = int(Decimal(request.POST.get('amount')) * 100)  # Convert to centavos
        redirect_url = request.build_absolute_uri('/payment/success/')
        failed_url = request.build_absolute_uri('/payment/failed/')
        reference_id = f"gcash-{uuid.uuid4()}"

        headers = {
            'Authorization': f'Basic {settings.PAYMONGO_SECRET_KEY}',
            'Content-Type': 'application/json'
        }

        payload = {
            "data": {
                "attributes": {
                    "amount": amount,
                    "redirect": {
                        "success": redirect_url,
                        "failed": failed_url
                    },
                    "type": "gcash",
                    "currency": "PHP",
                    "metadata": {
                        "user_id": request.user.id,
                        "reference_id": reference_id
                    }
                }
            }
        }

        response = requests.post(
            "https://api.paymongo.com/v1/checkout_sessions",
            headers=headers,
            json=payload
        )

        if response.status_code == 200:
            gcash_url = response.json()["data"]["attributes"]["checkout_url"]
            return redirect(gcash_url)
        else:
            return render(request, 'payment/error.html', {'error': response.json()})  

def a_payment_success(request):
    return render(request, 'payment/success.html')

def a_payment_failed(request):
    return render(request, 'payment/failed.html')
    


@login_required
def handle_cart_checkout(request):
    cart = Cart.objects.filter(customer=request.user, completed=False).first()
    
    if not cart or not cart.cartitems.exists():
        messages.warning(request, "Your cart is empty")
        return redirect('carts')
    
    cart_items = cart.cartitems.select_related('product').all()
    shipping_address = ShippingAddress.objects.filter(customer=request.user).first()
    
    if request.method == 'POST':
        return process_cart_checkout(request, cart, cart_items)
    
    context = {
        'is_direct_checkout': False,
        'cart_items': cart_items,
        'cart_total': cart.get_cart_total,
        'item_count': cart.get_item_total,
        'shipping_address': shipping_address,
        'has_address': shipping_address is not None,
        'PAYMENT_METHOD_CHOICES': Order.PAYMENT_METHOD_CHOICES,
    }
    return render(request, 'escan/Admin/E-commerce/amarketplace/checkout.html', context)

def process_cart_checkout(request, cart, cart_items):
    try:
        payment_method = request.POST.get('payment_method', 'COD')
        
        # Handle shipping address
        if request.POST.get('use_existing_address') == 'on':
            shipping_address = ShippingAddress.objects.filter(customer=request.user).first()
            if not shipping_address:
                raise ValueError("No existing address found")
        else:
            shipping_address = ShippingAddress.objects.create(
                customer=request.user,
                phone_number=request.POST.get('phone_number'),
                address=request.POST.get('address'),
                city=request.POST.get('city'),
                province=request.POST.get('province'),
                zipcode=request.POST.get('zipcode')
            )
        
        # Create orders for each cart item
        orders = []
        for item in cart_items:
            total_amount = item.get_total
            
            # Create order
            order = Order.objects.create(
                customer=request.user,
                store=item.product.store,
                product=item.product,
                shipping_address=shipping_address,
                quantity=item.quantity,
                total_amount=total_amount,
                payment_method=payment_method,
                status='Pending'
            )
            orders.append(order)
            
            # Create payment record if not COD
            if payment_method != 'COD':
                Payment.objects.create(
                    order=order,
                    method=payment_method,
                    amount_paid=total_amount,
                    confirmed=False
                )
            
            # Update product stock
            item.product.stock -= item.quantity
            item.product.save()
            
            # Add to customer purchase history
            customer, created = Customer.objects.get_or_create(user=request.user)
            CustomerPurchase.objects.create(
                customer=customer,
                store=item.product.store,
                product=item.product,
                category=item.product.category,
                quantity=item.quantity,
                total_amount=total_amount,
                is_completed=True
            )
            
            # Add store to customer's purchased stores
            customer.stores_purchased_from.add(item.product.store)
        
        # Mark cart as completed and clear items
        cart.completed = True
        cart.save()
        
        # Redirect to order confirmation for the first order
        return redirect('order_confirmation', order_id=orders[0].id)
        
    except Exception as e:
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect('checkouts')

@login_required
def direct_item_checkout(request, item_id):
    try:
        cart_item = get_object_or_404(
            Cartitems, 
            id=item_id, 
            cart__customer=request.user,
            cart__completed=False
        )
        
        # Redirect to checkout with this single item
        return redirect(
            reverse('checkouts') + 
            f"?product={cart_item.product.id}&store={cart_item.product.store.id}&quantity={cart_item.quantity}"
        )
        
    except Exception as e:
        messages.error(request, f"Error processing checkout: {str(e)}")
        return redirect('carts')
    
@login_required
def order_confirmation_view(request, order_id):
    order = get_object_or_404(Order, id=order_id, customer=request.user)
    return render(request, 'escan/Admin/E-commerce/amarketplace/order_confirmation.html', {'order': order})
        
# ----------------------------------------------------------------------------------------------
# Admin Side Cart
@login_required
def carts(request):
    cart = Cart.objects.filter(customer=request.user, completed=False).first()
    
    if cart:
        cart_items = cart.cartitems.select_related('product').all()
        cart_total = cart.get_cart_total
        item_count = cart.get_item_total
    else:
        cart_items = []
        cart_total = 0
        item_count = 0
    
    context = {
        'cart_items': cart_items,
        'cart_total': cart_total,
        'item_count': item_count,
    }
    return render(request, 'escan/Admin/E-commerce/amarketplace/carts.html', context)


# In your views.py file

@login_required
@require_POST
@csrf_exempt
def add_to_carts(request, product_id):
    try:
        # Parse JSON data from request body
        data = json.loads(request.body)
        quantity = int(data.get('quantity', 1))
        
        # Validate quantity
        if quantity <= 0:
            return JsonResponse({
                'success': False,
                'error': 'Quantity must be at least 1'
            }, status=400)
        
        # Get product and validate stock
        product = get_object_or_404(Product, id=product_id)
        if quantity > product.stock:
            return JsonResponse({
                'success': False,
                'error': f'Only {product.stock} items available in stock'
            }, status=400)
        
        # Get or create cart for current user - CHANGED FROM user TO customer
        cart, created = Cart.objects.get_or_create(customer=request.user, completed=False)
        
        # Get or create cart item
        cart_item, created = Cartitems.objects.get_or_create(cart=cart, product=product)
        
        # Calculate new quantity
        new_quantity = cart_item.quantity + quantity if not created else quantity
        
        # Validate stock again with new quantity
        if new_quantity > product.stock:
            return JsonResponse({
                'success': False,
                'error': f'Cannot add {quantity} more items (would exceed available stock)'
            }, status=400)
        
        # Update cart item
        cart_item.quantity = new_quantity
        cart_item.save()
        
        # Return success response - Convert Decimal to float for JSON serialization
        return JsonResponse({
            'success': True,
            'item_count': cart.get_item_total,
            'cart_total': float(cart.get_cart_total),  # Convert Decimal to float
            'message': f'{product.name} added to cart successfully!'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
    
@login_required
@require_POST
@csrf_exempt
def update_cart_items(request, item_id):
    try:
        data = json.loads(request.body)
        new_quantity = int(data.get('quantity', 1))
        
        cart_item = get_object_or_404(
            Cartitems, 
            id=item_id, 
            cart__customer=request.user
        )
        
        if new_quantity <= 0:
            cart_item.delete()
            return JsonResponse({
                'success': True,
                'item_count': cart_item.cart.get_item_total,
                'cart_total': cart_item.cart.get_cart_total,
                'message': 'Item removed from cart'
            })
        
        if new_quantity > cart_item.product.stock:
            return JsonResponse({
                'success': False,
                'error': f'Only {cart_item.product.stock} items available in stock'
            }, status=400)
        
        cart_item.quantity = new_quantity
        cart_item.save()
        
        return JsonResponse({
            'success': True,
            'item_count': cart_item.cart.get_item_total,
            'cart_total': cart_item.cart.get_cart_total,
            'item_total': cart_item.get_total,
            'message': 'Cart updated successfully'
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)

@login_required
@require_POST
@csrf_exempt
def remove_from_carts(request, item_id):
    try:
        cart_item = get_object_or_404(
            Cartitems, 
            id=item_id, 
            cart__customer=request.user
        )
        cart = cart_item.cart
        cart_item.delete()
        
        return JsonResponse({
            'success': True,
            'item_count': cart.get_item_total,
            'cart_total': cart.get_cart_total,
            'message': 'Item removed from cart'
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)

#--------------------------------------------
# Admin Side Sign Up
def admin_signup(request):
    if request.method == "POST":
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        role = request.POST.get("role", "Admin")  # Get the selected user role

        # Ensure the username or email is not already taken
        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username is already taken.")
            return redirect("admin_signup")

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email is already registered.")
            return redirect("admin_signup")

        # Create the user
        user = CustomUser.objects.create_user(
            first_name=first_name,
            last_name=last_name,
            username=username,
            email=email,
            password=password,  # Django automatically hashes it
            role=role  # Assign selected role
        )

        messages.success(request, "Account created successfully! Please log in.")
        return redirect("admin_login")  # Redirect to the login page after successful signup

    return render(request, "escan/Admin/admin_signup.html")
# ----------------------------------------------------------------------------
# Admin Side Manage Customers
def customer_table(request):
    # Get the store owned by the currently logged-in user
    try:
        store = Store.objects.get(owner=request.user)
        
        # Get all orders for this store
        store_orders = Order.objects.filter(store=store)
        
        # Get all customers who placed these orders
        customer_ids = store_orders.values_list('customer', flat=True).distinct()
        customers = Customer.objects.filter(id__in=customer_ids).select_related('user')
        
    except Store.DoesNotExist:
        # If the user doesn't have a store, return empty queryset
        customers = Customer.objects.none()
    
    return render(request, 'escan/Admin/E-commerce/customer_list.html', {
        'customers': customers,
    })


# ----------------------------------------------------------------------------
#Admin Side Manage Category
@login_required
def category_list(request):
    # Get categories only for stores owned by the current user
    user_stores = Store.objects.filter(owner=request.user)
    categories = Category.objects.filter(store__in=user_stores).order_by("name")
    return render(request, 'escan/Admin/E-commerce/category_list.html', {'categories': categories})

@csrf_exempt
@login_required
def add_category(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_stores = Store.objects.filter(owner=request.user)
            
            if not user_stores.exists():
                return JsonResponse({"error": "You need to have a store to create categories"}, status=403)
                
            # Use the first store (or you can modify to select specific store)
            store = user_stores.first()
            category = Category.objects.create(
                store=store,
                name=data["name"],
                description=data.get("description", "")
            )
            return JsonResponse({
                "id": category.id, 
                "name": category.name,
                "description": category.description
            }, status=201)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)

@csrf_exempt
@login_required
def edit_category(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    
    # Verify the category belongs to the user's store
    if category.store.owner != request.user:
        return JsonResponse({"error": "Unauthorized"}, status=403)
        
    if request.method == "POST":
        data = json.loads(request.body)
        category.name = data.get("name", category.name)
        category.description = data.get("description", category.description)
        category.save()
        return JsonResponse({
            "id": category.id, 
            "name": category.name,
            "description": category.description
        })

@csrf_exempt
@login_required
def delete_category(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    
    # Verify the category belongs to the user's store
    if category.store.owner != request.user:
        return JsonResponse({"error": "Unauthorized"}, status=403)
        
    category.delete()
    return JsonResponse({"message": "Category deleted successfully"})

# -----------------------------------------------------------------------------------
# Admin Side Store
@login_required
@require_http_methods(["POST"])
def create_store(request):
    try:
        if hasattr(request.user, 'store'):
            return JsonResponse({
                'success': False,
                'message': "You already have a store"
            }, status=400)
        
        # Check store validation status
        try:
            validation = request.user.store_validation
            if validation.status != 'approved':
                return JsonResponse({
                    'success': False,
                    'message': "Your store validation is not approved yet"
                }, status=403)
        except AttributeError:
            return JsonResponse({
                'success': False,
                'message': "You need to complete store validation first"
            }, status=403)

        form = StoreForm(request.POST, request.FILES, request=request)
        if form.is_valid():
            store = form.save()
            return JsonResponse({
                'success': True,
                'message': "Store created successfully!",
                'store_id': store.id
            })
        else:
            return JsonResponse({
                'success': False,
                'message': "Please correct the errors below",
                'errors': dict(form.errors.items())
            }, status=400)
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': "An unexpected error occurred"
        }, status=500)

# @login_required
# @require_http_methods(["POST"])
# def update_store(request):
#     try:
#         if not hasattr(request.user, 'store'):
#             return JsonResponse({
#                 'success': False,
#                 'message': "You don't have a store to update"
#             }, status=404)

#         form = StoreForm(request.POST, request.FILES, instance=request.user.store, request=request)
#         if form.is_valid():
#             store = form.save()
#             return JsonResponse({
#                 'success': True,
#                 'message': "Store updated successfully!",
#                 'latitude': store.latitude,
#                 'longitude': store.longitude,
#             })
#         else:
#             print("Form errors:", form.errors)
#             return JsonResponse({
#                 'success': False,
#                 'message': "Please correct the errors below",
#                 'errors': dict(form.errors.items())
#             }, status=400)
            
#     except Exception as e:
#         import traceback
#         traceback.print_exc()
#         return JsonResponse({
#             'success': False,
#             'message': "An unexpected error occurred"
#         }, status=500)
@login_required
@login_required
@require_POST
def update_store(request):
    """Update existing store information"""
    print(f"\n{'='*50}")
    print(f"UPDATE STORE REQUEST from {request.user.username}")
    print(f"{'='*50}")
    print(f"POST data: {request.POST}")
    print(f"FILES: {request.FILES}")
    
    try:
        if not hasattr(request.user, 'store') or not request.user.store:
            print("❌ User doesn't have a store")
            return JsonResponse({
                'success': False,
                'message': 'You don\'t have a store to update. Please create one first.'
            }, status=400)

        store_instance = request.user.store
        original_logo = store_instance.logo  # Keep original if no new image
        
        # Handle image upload separately if provided
        if 'logo' in request.FILES and request.FILES['logo']:
            print("📸 Logo file detected, uploading to Supabase...")
            logo_file = request.FILES['logo']
            
            try:
                # Generate unique filename
                file_name = f"store-logos/{store_instance.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{logo_file.name}"
                
                supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_API_KEY)
                bucket = supabase.storage.from_('store-logos')  # ✅ Use correct bucket
                
                # Read file content
                logo_file.seek(0)
                file_data = logo_file.read()
                
                print(f"📤 Uploading file: {file_name}")
                print(f"📊 File size: {len(file_data)} bytes")
                
                # Upload file
                upload_response = bucket.upload(file_name, file_data, {
                    "content-type": logo_file.content_type
                })
                
                print(f"✅ Upload response: {upload_response}")
                
                # ✅ Construct the full public URL
                if hasattr(upload_response, 'path') and upload_response.path:
                    # Build the complete Supabase public URL
                    logo_url = f"{settings.SUPABASE_URL}/storage/v1/object/public/store-logos/{file_name}"
                    store_instance.logo = logo_url
                    print(f"✅ Logo URL set: {store_instance.logo}")
                else:
                    print("⚠️ Upload response has no path, keeping original logo")
                    store_instance.logo = original_logo
                    
            except Exception as e:
                print(f"⚠️ Supabase upload error: {e}")
                traceback.print_exc()
                # Continue with original logo
                store_instance.logo = original_logo
        
        # Now update other fields using the form
        form = StoreForm(
            request.POST, 
            request.FILES, 
            request=request, 
            instance=store_instance
        )
        
        print("\n--- Form Validation ---")
        if form.is_valid():
            print("✅ Form is valid")
            try:
                # Save the form
                updated_store = form.save(commit=False)
                
                # Make sure logo URL is preserved
                if store_instance.logo:
                    updated_store.logo = store_instance.logo
                
                updated_store.save()
                
                print(f"✅ Store updated successfully!")
                print(f"Store ID: {updated_store.id}")
                print(f"Store Name: {updated_store.name}")
                print(f"Store Logo: {updated_store.logo}")
                
                return JsonResponse({
                    'success': True,
                    'message': 'Store updated successfully!',
                    'logo_url': str(updated_store.logo) if updated_store.logo else None
                })
            except Exception as e:
                print(f"❌ Error updating store: {e}")
                traceback.print_exc()
                return JsonResponse({
                    'success': False,
                    'message': f'Error updating store: {str(e)}'
                }, status=500)
        else:
            print("❌ Form validation failed")
            print(f"Form errors: {form.errors.as_json()}")
            
            error_dict = {}
            for field, errors in form.errors.items():
                error_dict[field] = [str(error) for error in errors]
            
            return JsonResponse({
                'success': False,
                'message': 'Please correct the errors below',
                'errors': error_dict
            }, status=400)
            
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'message': f'An unexpected error occurred: {str(e)}'
        }, status=500)


# Admin Side 
@login_required
def product_print(request):
    try:
        store = request.user.store
        products = Product.objects.filter(store=store, is_deleted=False).select_related('category')
    except Store.DoesNotExist:
        products = Product.objects.none()
    
    context = {
        'products': products,
        'store': getattr(request.user, 'store', None)
    }
    return render(request, "escan/Admin/E-commerce/product_print.html", context)

# ---------------------------------------------------------------------------------
#Admin Side Manage Products/Stocks
# @login_required
# def product_list(request):
#     try:
#         # Get the user's store if it exists
#         store = request.user.store
#         store.refresh_from_db()
#         products = Product.objects.filter(store=store, is_deleted=False).select_related('category')
#         # Get all categories (shared across all users)
#         categories = Category.objects.filter(store=store)

#     except (Store.DoesNotExist, AttributeError):
#         products = Product.objects.none()
#         categories = Category.objects.none()
#         if not hasattr(request, 'warning_message'):
#             messages.warning(request, "You need to create a store first before adding products")

#     context = {
#         'store': store,
#         'products': products,
#         'categories': categories,
#         'has_store': hasattr(request.user, 'store')
#     }

#     print(f"Store latitude in view: {store.latitude}")
#     print(f"Store longitude in view: {store.longitude}")
#     return render(request, "escan/Admin/E-commerce/product_list.html", context)
@login_required
def product_list(request):
    """
    Display product list for the current user's store.
    Handles cases where user doesn't have a store yet.
    """
    # Initialize all variables first to avoid UnboundLocalError
    store = None
    products = Product.objects.none()
    categories = Category.objects.none()
    has_store = False
    
    try:
        # Check if user has a store
        if hasattr(request.user, 'store') and request.user.store:
            store = request.user.store
            store.refresh_from_db()
            
            # Get products for this store (excluding deleted ones)
            products = Product.objects.filter(
                store=store, 
                is_deleted=False
            ).select_related('category').order_by('-created_at')
            
            # Get categories for this store
            categories = Category.objects.filter(store=store)
            
            has_store = True
            
            # Debug print statements
            print(f"✅ Store found: {store.name} (ID: {store.id})")
            print(f"Store latitude: {store.latitude}")
            print(f"Store longitude: {store.longitude}")
            print(f"Products count: {products.count()}")
            print(f"Categories count: {categories.count()}")
        else:
            # User doesn't have a store
            print(f"⚠️ User {request.user.username} doesn't have a store")
            
            # Check if user is an approved seller
            approved_validation = StoreValidation.objects.filter(
                store_owner=request.user,
                status='approved'
            ).first()
            
            if approved_validation:
                messages.info(request, "You're an approved seller! Create your store to start adding products.")
            else:
                # Check application status
                latest_validation = StoreValidation.objects.filter(
                    store_owner=request.user
                ).order_by('-created_at').first()
                
                if latest_validation:
                    if latest_validation.status == 'pending':
                        messages.info(request, "Your seller application is pending review. You can create a store once approved.")
                    elif latest_validation.status == 'rejected':
                        messages.warning(request, "Your seller application was rejected. You can apply again.")
                else:
                    messages.warning(request, "You need to apply as a seller and get approved before creating a store.")
    
    except Store.DoesNotExist:
        print(f"⚠️ Store.DoesNotExist exception for user {request.user.username}")
        messages.warning(request, "You need to create a store first before adding products.")
    
    except AttributeError as e:
        print(f"⚠️ AttributeError: {e}")
        messages.warning(request, "You need to create a store first before adding products.")
    
    except Exception as e:
        print(f"❌ Unexpected error in product_list: {e}")
        import traceback
        traceback.print_exc()
        messages.error(request, "An error occurred while loading products.")
    
    # Get user's seller application status
    latest_validation = StoreValidation.objects.filter(
        store_owner=request.user
    ).order_by('-created_at').first()
    
    has_seller_application = latest_validation is not None
    is_approved_seller = latest_validation and latest_validation.status == 'approved'
    is_pending_seller = latest_validation and latest_validation.status == 'pending'
    is_rejected_seller = latest_validation and latest_validation.status == 'rejected'
    
    # Prepare context
    context = {
        'store': store,  # Will be None if no store exists
        'products': products,
        'categories': categories,
        'has_store': has_store,
        'has_seller_application': has_seller_application,
        'is_approved_seller': is_approved_seller,
        'is_pending_seller': is_pending_seller,
        'is_rejected_seller': is_rejected_seller,
    }
    
    return render(request, "escan/Admin/E-commerce/product_list.html", context)
@login_required
@transaction.atomic
def add_product(request):
    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES, request=request)
        if form.is_valid():
            try:
                product = form.save(commit=False)
                product.store = request.user.store
                
                # Handle image upload
                if 'image' in request.FILES:
                    image_file = request.FILES['image']
                    # Generate unique filename
                    ext = os.path.splitext(image_file.name)[1]
                    filename = f"{uuid.uuid4()}{ext}"
                    # Save the file
                    file_path = default_storage.save(f'products/{filename}', image_file)
                    product.image = file_path
                
                product.save()
                
                # Save action for undo functionality
                global last_action
                last_action = {
                    'type': 'add',
                    'product_id': product.id,
                    'product_data': {
                        'name': product.name,
                        'category': product.category.id if product.category else None,
                        'description': product.description,
                        'price': product.price,
                        'stock': product.stock,
                        'image': product.image.url if product.image else None
                    }
                }
                
                messages.success(request, "Product added successfully!")
                return redirect('product_list')
            except Exception as e:
                messages.error(request, f"Error adding product: {str(e)}")
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = ProductForm(request=request)
    
    context = {
        'form': form,
        'title': 'Add New Product'
    }
    return render(request, 'escan/Admin/E-commerce/product_list.html', context)

@login_required
@transaction.atomic
def edit_product(request, product_id):
    product = get_object_or_404(Product, id=product_id, store=request.user.store)
    
    if request.method == 'POST':
        form = ProductForm(request.POST, request.FILES, instance=product, request=request)
        if form.is_valid():
            try:
                # Save previous data for undo functionality
                global last_action
                last_action = {
                    'type': 'edit',
                    'product_id': product.id,
                    'previous_data': {
                        'name': product.name,
                        'category': product.category.id if product.category else None,
                        'description': product.description,
                        'price': product.price,
                        'stock': product.stock,
                        'image_url': product.image_url
                    }
                }
                
                form.save()
                messages.success(request, "Product updated successfully!")
                return redirect('product_list')
            except Exception as e:
                messages.error(request, f"Error updating product: {str(e)}")
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = ProductForm(instance=product, request=request)
    
    return redirect('product_list')

@login_required
@require_POST
@transaction.atomic
def delete_product(request, product_id):
    product = get_object_or_404(Product, id=product_id, store=request.user.store)
    
    try:
        global last_action
        last_action = {
            'type': 'delete',
            'product': product
        }
        product.soft_delete()
        messages.success(request, "Product deleted successfully.")
        return JsonResponse({'success': True})
    except Exception as e:
        messages.error(request, f"Error deleting product: {str(e)}")
        return JsonResponse({'success': False, 'message': str(e)}, status=400)

@login_required
@require_POST
def undo_last_action(request):
    global last_action
    if not last_action:
        return JsonResponse({'success': False, 'message': 'No action to undo'})
    
    try:
        if last_action['type'] == 'delete':
            product = last_action['product']
            product.restore()
            message = "Product restoration successful"
        elif last_action['type'] == 'add':
            Product.objects.filter(id=last_action['product_id']).delete()
            message = "Product creation undone"
        elif last_action['type'] == 'edit':
            product = Product.objects.get(id=last_action['product_id'])
            previous_data = last_action['previous_data']
            product.name = previous_data['name']
            product.category_id = previous_data['category']
            product.description = previous_data['description']
            product.price = previous_data['price']
            product.stock = previous_data['stock']
            product.image_url = previous_data['image_url']
            product.save()
            message = "Product edit undone"
        
        last_action = None
        messages.success(request, message)
        return JsonResponse({'success': True, 'message': message})
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=400)

@login_required
def search_products(request):
    query = request.GET.get('query', '').strip()
    if not query:
        return JsonResponse({'results': []})
    
    try:
        store = request.user.store
        products = Product.objects.filter(
            store=store,
            is_deleted=False
        ).filter(
            models.Q(name__icontains=query) |
            models.Q(category__name__icontains=query) |
            models.Q(description__icontains=query)
        ).select_related('category')
        
        results = [
            {
                'id': p.id,
                'name': p.name,
                'category': p.category.name if p.category else 'No Category',
                'description': p.description or '',
                'price': str(p.price),
                'stock': p.stock,
                'image_url': p.image_url if p.image_url else ''
            }
            for p in products
        ]
        return JsonResponse({'results': results})
    except Store.DoesNotExist:
        return JsonResponse({'results': []})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
    
# --------------------------------------------------------------------------
#Admin Side Manage Oders
import calendar
from datetime import datetime
import calendar
from .models import Order

# Admin side  
@login_required
def update_order_status(request, order_id):
    if request.method == "POST":
        order = get_object_or_404(Order, id=order_id)
        new_status = request.POST.get('status')
        
        # Check if user has permission to update this order
        if (hasattr(request.user, 'store_owner') and order.store == request.user.store_owner) or \
           (hasattr(request.user, 'store') and order.store == request.user.store):
            order.status = new_status
            order.save()
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': True})
        
        return redirect('orders_part')

@login_required
def set_order_schedule(request):
    if request.method == "POST":
        order_id = request.POST.get('order_id')
        schedule_type = request.POST.get('schedule_type')
        order = get_object_or_404(Order, id=order_id)
        
        # Check permission
        if not ((hasattr(request.user, 'store_owner') and order.store == request.user.store_owner) or \
                (hasattr(request.user, 'store') and order.store == request.user.store)):
            return redirect('orders_part')
        
        if schedule_type == "process":
            start_date = request.POST.get('start_date')
            end_date = request.POST.get('end_date')
            if start_date and end_date:
                order.process_start = start_date
                order.process_end = end_date
                order.save()
        
        elif schedule_type == "delivery":
            start_date = request.POST.get('start_date')
            end_date = request.POST.get('end_date')
            if start_date and end_date:
                order.delivery_start = start_date
                order.delivery_end = end_date
                order.save()
        
        elif schedule_type == "completion":
            single_date = request.POST.get('single_date')
            if single_date:
                order.completion_date = single_date
                order.save()
        
        return redirect('orders_part')

@login_required
def add_review(request):
    if request.method == 'POST':
        order_id = request.POST.get('order_id')
        product_id = request.POST.get('product_id')
        rating = request.POST.get('rating')
        comment = request.POST.get('comment', '')
        
        # Validate rating
        if not rating or not rating.isdigit():
            return JsonResponse({'error': 'Invalid rating'}, status=400)
            
        rating = int(rating)
        
        if rating < 1 or rating > 5:
            return JsonResponse({'error': 'Rating must be between 1 and 5'}, status=400)
        
        order = get_object_or_404(Order, id=order_id, customer=request.user)
        product = get_object_or_404(Product, id=product_id)
        
        # Check if order is completed
        if order.status != 'Completed':
            return JsonResponse({'error': 'You can only review completed orders'}, status=400)
        
        # Check if review already exists
        existing_review = Review.objects.filter(
            product=product,
            customer=request.user,
            order=order
        ).first()
        
        if existing_review:
            # Update existing review
            existing_review.rating = rating
            existing_review.comment = comment
            existing_review.save()
        else:
            # Create new review
            Review.objects.create(
                product=product,
                customer=request.user,
                order=order,
                rating=rating,
                comment=comment,
                is_approved=False
            )
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'success': True})
        
        return redirect('orders_part')
    
    return redirect('orders_part')

# Admin Side 
@login_required
def orders_part(request):
    # --- Store detection ---
    admin_store = None
    if hasattr(request.user, 'store_owner'):
        admin_store = request.user.store_owner
    elif hasattr(request.user, 'store'):
        admin_store = request.user.store
    elif hasattr(request.user, 'stores') and request.user.stores.exists():
        admin_store = request.user.stores.first()

    # --- Filters ---
    today = datetime.today()
    month = int(request.GET.get("month", today.month))
    year = int(request.GET.get("year", today.year))

    # --- Base queries ---
    new_orders = Order.objects.filter(customer=request.user, status='Pending')
    total_orders = Order.objects.filter(customer=request.user).exclude(status='Pending')
    if admin_store:
        customer_orders = Order.objects.filter(store=admin_store).exclude(customer=request.user)
    else:
        customer_orders = Order.objects.none()

    # --- Calendar grid for the month ---
    cal = calendar.Calendar(firstweekday=6)  # Sunday start
    month_days = cal.monthdatescalendar(year, month)  # 2D weeks grid

    calendar_data = []
    if admin_store:
        orders = Order.objects.filter(store=admin_store)

        # Top offsets for each status
        status_top_map = {
            "Pending": 5,
            "On Process": 30,
            "Delivered": 55,
            "Completed": 80,
        }

        for week in month_days:
            week_data = []
            bars = []

            # Map day -> column index (1..7 for CSS grid)
            day_to_col = {day: idx + 1 for idx, day in enumerate(week)}

            # --- Bars for orders ---
            for order in orders:
                top_offset = 0

                # Pending = single day
                if order.status == "Pending" and order.order_date:
                    top_offset = status_top_map["Pending"]
                    if order.order_date.date() in week:
                        col = day_to_col[order.order_date.date()]
                        bars.append({
                            "type": "pending",
                            "label": f"#{order.id}",
                            "start_col": col,
                            "end_col": col + 1,
                            "top": top_offset
                        })

                # On Process = range (process_start → process_end)
                elif order.status == "On Process" and order.process_start and order.process_end:
                    top_offset = status_top_map["On Process"]
                    start = max(order.process_start.date(), week[0])
                    end = min(order.process_end.date(), week[-1])
                    if start <= end:
                        bars.append({
                            "type": "process",
                            "label": f"#{order.id}",
                            "start_col": day_to_col[start],
                            "end_col": day_to_col[end] + 1,
                            "top": top_offset
                        })

                # Delivered = range (delivery_start → delivery_end)
                elif order.status == "Delivered" and order.delivery_start and order.delivery_end:
                    top_offset = status_top_map["Delivered"]
                    start = max(order.delivery_start.date(), week[0])
                    end = min(order.delivery_end.date(), week[-1])
                    if start <= end:
                        bars.append({
                            "type": "delivery",
                            "label": f"#{order.id}",
                            "start_col": day_to_col[start],
                            "end_col": day_to_col[end] + 1,
                            "top": top_offset
                        })

                # Completed = single day
                elif order.status == "Completed" and order.completion_date:
                    top_offset = status_top_map["Completed"]
                    if order.completion_date.date() in week:
                        col = day_to_col[order.completion_date.date()]
                        bars.append({
                            "type": "completed",
                            "label": f"#{order.id}",
                            "start_col": col,
                            "end_col": col + 1,
                            "top": top_offset
                        })

            # --- Day data for this week ---
            for day in week:
                day_data = {
                    "date": day,
                    "is_current_month": (day.month == month)
                }
                week_data.append(day_data)

            # Push week into calendar_data
            calendar_data.append({
                "days": week_data,
                "bars": bars
            })

    context = {
        "new_orders": new_orders,
        "total_orders": total_orders,
        "customer_orders": customer_orders,
        "calendar_data": calendar_data,   # each week has days + bars
        "current_month": month,
        "current_year": year,
        "now": today,
    }
    return render(request, "escan/Admin/E-commerce/orders_part.html", context)


from collections import Counter
import calendar
from .models import Order
from django.utils.dateparse import parse_datetime

@login_required
def set_order_schedule(request):
    if request.method == "POST":
        order_id = request.POST.get("order_id")
        schedule_type = request.POST.get("schedule_type")
        order = get_object_or_404(Order, id=order_id)

        if schedule_type in ["process", "delivery"]:
            start_date = parse_datetime(request.POST.get("start_date"))
            end_date = parse_datetime(request.POST.get("end_date"))
            if start_date and end_date:
                if schedule_type == "process":
                    order.process_start = start_date
                    order.process_end = end_date
                elif schedule_type == "delivery":
                    order.delivery_start = start_date
                    order.delivery_end = end_date
        elif schedule_type == "completion":
            single_date = parse_datetime(request.POST.get("single_date"))
            if single_date:
                order.completion_date = single_date

        order.save()
        return redirect("orders_part")






@login_required
def update_order_status(request, order_id):
    if request.method == 'POST':
        new_status = request.POST.get('status')
        order = get_object_or_404(Order, pk=order_id)
        
        # Check if the user has permission to update this order
        admin_store = None
        if hasattr(request.user, 'store_owner'):
            admin_store = request.user.store_owner
        elif hasattr(request.user, 'store'):
            admin_store = request.user.store
        elif hasattr(request.user, 'stores') and request.user.stores.exists():
            admin_store = request.user.stores.first()
        
        if order.store == admin_store or order.customer == request.user:
            order.status = new_status
            order.save()
            
            # Create CustomerPurchase record when order is completed
            if new_status == 'Completed' and not order.paid:
                customer, created = Customer.objects.get_or_create(user=order.customer)
                CustomerPurchase.objects.create(
                    customer=customer,
                    store=order.store,
                    product=order.product,
                    category=order.product.category,
                    quantity=order.quantity,
                    total_amount=order.total_amount,
                    is_completed=True
                )
                order.paid = True
                order.save()
        
        return redirect('orders_part')
  

@login_required
def set_delivery_schedule(request):
    if request.method == 'POST':
        order_id = request.POST.get('order_id')
        delivery_schedule = request.POST.get('delivery_schedule')
        
        order = get_object_or_404(Order, id=order_id)
        
        # Check if user has permission to update this order
        if request.user == order.store.owner or request.user == order.store.admin:
            order.delivery_schedule = delivery_schedule
            order.save()
            messages.success(request, 'Delivery schedule updated successfully')
        else:
            messages.error(request, 'You do not have permission to update this order')
        
        return redirect('orders_part')
    
    return redirect('orders_part')






# -----------------------------------------------------------------------
#Admin Side User Graphs
def user_graph_view(request):
    # Fetch users with the role 'User '
    users = CustomUser .objects.filter(role='User ').values('first_name', 'date_joined')
    
    # Convert the queryset to a list of dictionaries
    user_data = [{'first_name': user['first_name'], 'date_joined': user['date_joined']} for user in users]
    
    return render(request, 'escan/Admin/E-commerce/product_list.html', {'users': user_data}) 

#-------------------------------------------------------
# Admin Scan Side
def a_scan(request):
    avarieties = BananaVariety.objects.filter(is_deleted=False) 
    knowledges = KnowledgeBase.objects.filter(is_deleted=False) 
    return render(request, "escan/Admin/A_Scan/scan.html", {'knowledges':  knowledges, 'avarieties': avarieties })


def a_banana_disease(request):
    model = load_disease_model()
    class_names = ['Banana Anthracnose Fruit disease', 'Banana Bract Mosaic Virus Disease', 'Banana Cordana Leaf Disease',
                   'Banana Fusarium Wilt Tree Disease', 'Banana Insect Pest Disease', 'Banana Naturally Leaf Dead',
                   'Banana Panama Leaf Disease', 'Banana Pestalotiopsis Disease', 'Banana Rhizome Root Tree Disease',
                   'Banana Sigatoka Leaf Disease']
    class_descriptions = {
       'Banana Anthracnose Fruit Disease': {
        'description': 'A fungal infection caused by (Colletotrichum musae), primarily affecting banana fruits during ripening, causing dark sunken spots and post-harvest rot.',
        'symptoms': 'Small, water-soaked spots on fruit skin that enlarge, turning black and sunken with possible pinkish spore masses in humid conditions.',
        'management': 'Post-harvest fungicide dips, careful handling during harvest and transport, removal of infected plant debris, and maintaining orchard sanitation.',
        'prevention': 'Use disease-free planting material, regular pruning to improve air circulation, and protective fungicide sprays pre- and post-harvest.'
    },
    'Banana Bract Mosaic Virus Disease': {
        'description': 'A viral disease transmitted by aphids causing mosaic patterns on banana bracts, leaves, and fruit peels, affecting plant growth and yield.',
        'symptoms': 'Chlorotic or dark green streaks and mosaic patterns on bracts and petioles, distorted fruits, and leaf deformation.',
        'management': 'Use of virus-free suckers, removal of infected plants, and control of aphid vectors using insecticides or biological agents.',
        'prevention': 'Implement strict quarantine measures, monitor aphid populations, and avoid planting near infected fields.'
    },
    'Banana Cordana Leaf Disease': {
        'description': 'A fungal disease caused by *Cordana musae* that primarily affects banana leaves, reducing photosynthesis and leading to premature leaf death.',
        'symptoms': 'Small oval to elliptical brown spots with yellow halos on leaves, coalescing into large necrotic patches.',
        'management': 'Pruning of affected leaves, application of protective fungicides, and improving field drainage.',
        'prevention': 'Regular monitoring, use of resistant varieties where available, and proper spacing to avoid dense foliage.'
    },
    'Banana Fusarium Wilt Tree Disease': {
        'description': 'Also known as Panama disease, caused by *Fusarium oxysporum f.sp. cubense*, it’s a serious soil-borne fungal disease attacking the plant’s vascular system.',
        'symptoms': 'Yellowing of older leaves, wilting, splitting of the pseudostem base, and brown vascular discoloration in rhizomes.',
        'management': 'Uprooting and burning infected plants, soil solarization, and using disease-resistant banana cultivars.',
        'prevention': 'Avoid contaminated soil and tools, use clean planting material, and implement crop rotation with non-host crops.'
    },
    'Banana Insect Pest Disease': {
        'description': 'A collective term for damage caused by various banana insect pests such as banana weevils and aphids, affecting plant health and fruit yield.',
        'symptoms': 'Presence of boreholes in pseudostem, yellowing leaves, stunted growth, and distorted fruits.',
        'management': 'Use of pheromone traps, biological control agents, and selective insecticide applications.',
        'prevention': 'Field sanitation, removal of plant residues, regular monitoring, and planting pest-resistant varieties.'
    },
    'Banana Naturally Leaf Dead': {
        'description': 'A natural physiological process where older banana leaves die off as new leaves emerge, typically harmless unless excessive.',
        'symptoms': 'Gradual yellowing, drying, and death of lower leaves starting from the tip towards the base.',
        'management': 'Regular removal of dead leaves to reduce pest and disease harboring.',
        'prevention': 'Ensure balanced fertilization, adequate water, and healthy plant care to minimize premature leaf death.'
    },
    'Banana Panama Leaf Disease': {
        'description': 'Another form of Fusarium Wilt, it specifically affects banana leaves, leading to characteristic yellowing and eventual death of leaves.',
        'symptoms': 'Chlorosis starting from older leaves, progressing to wilting and drooping, with reddish-brown vascular discoloration.',
        'management': 'Immediate removal of infected plants, soil treatment, and application of biological control agents.',
        'prevention': 'Use of resistant cultivars and maintaining strict field hygiene and quarantine protocols.'
    },
    'Banana Pestalotiopsis Disease': {
        'description': 'A fungal leaf spot disease caused by (Pestalotiopsis spp.), affecting banana leaves and reducing photosynthetic efficiency.',
        'symptoms': 'Small, dark brown spots with concentric rings on leaves, which enlarge and merge into necrotic areas.',
        'management': 'Prune and destroy affected leaves, improve air circulation, and apply appropriate fungicides.',
        'prevention': 'Avoid overhead irrigation, practice crop rotation, and ensure optimal plant spacing.'
    },
    'Banana Rhizome Root Tree Disease': {
        'description': 'A disease affecting the rhizome and roots of banana plants, often caused by fungal pathogens like *Fusarium* or bacterial soft rot.',
        'symptoms': 'Wilting of leaves, reduced plant vigor, softening and discoloration of rhizomes, and root decay.',
        'management': 'Use of clean planting material, removal of infected plants, and soil sterilization if feasible.',
        'prevention': 'Implement good drainage, avoid waterlogging, and maintain field sanitation.'
    },
    'Banana Sigatoka Leaf Disease': {
        'description': 'A widespread fungal disease caused by "Mycosphaerella musicola" (Yellow Sigatoka) or "Mycosphaerella fijiensis" (Black Sigatoka) affecting banana leaves.',
        'symptoms': 'Small yellowish streaks on leaves developing into large necrotic areas, leading to premature leaf death.',
        'management': 'Regular removal of infected leaves, fungicide applications, and use of resistant cultivars.',
        'prevention': 'Maintain adequate plant spacing, improve drainage, and avoid overhead irrigation.'
    }
        
    }

    result = None
    confidence = None
    prediction_time = None
    image_url = None
    disease_info = None

    if request.method == 'POST':
        form = ImageUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                image = form.cleaned_data['image']
                
                # Use PIL to open the image
                from PIL import Image
                img = Image.open(image).convert('RGB')
                
                # Rest of your image processing code
                img_tensor = transforms.Compose([
                    transforms.Resize(256),
                    transforms.CenterCrop(224),
                    transforms.ToTensor(),
                    transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
                ])(img).unsqueeze(0)

                with torch.no_grad():
                    output = model(img_tensor)
                    probabilities = torch.nn.functional.softmax(output[0], dim=0)
                    confidence = torch.max(probabilities).item() * 100
                    _, predicted = torch.max(output, 1)
                    result = class_names[predicted.item()]
                    prediction_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    disease_info = class_descriptions.get(result)

                # Upload to Supabase
                user = request.user
                image.seek(0)
                file_data = image.read()
                file_name = f"{user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{image.name}"
                
                supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_ROLE_KEY)
                bucket = supabase.storage.from_('a-detection-images')

                try:
                    upload_response = bucket.upload(file_name, file_data, {
                        "content-type": image.content_type
                    })
                    
                    if hasattr(upload_response, 'path') and upload_response.path:
                        image_url = f"{settings.SUPABASE_URL}/storage/v1/object/public/a-detection-images/{upload_response.path}"
                        DetectionRecord.objects.create(
                            user=user,
                            prediction=result,
                            confidence=confidence,
                            image_url=image_url,
                            model_type='disease'
                        )
                    else:
                        print("Upload error: No path in response")

                except Exception as e:
                    print(f"Supabase upload error: {e}")

                return render(request, 'escan/Admin/A_Scan/a_banana_disease_result.html', {
                    'result': result,
                    'confidence': confidence,
                    'prediction_time': prediction_time,
                    'image_url': image_url,
                    'disease_info': disease_info,
                })

            except Exception as e:
                print(f"Error processing image: {e}")
                # Handle error appropriately
                return render(request, 'escan/Admin/A_Scan/a_banana_disease.html', {
                    'form': form,
                    'error': f"Failed to process image: {str(e)}"
                })

    else:
        form = ImageUploadForm()

    # Get all records for admin view (not filtered by user)
    records = DetectionRecord.objects.filter(model_type='disease').order_by('-timestamp')[:10]

    return render(request, 'escan/Admin/A_Scan/a_banana_disease.html', {
        'form': form,
        'records': records
    })

def a_predict_from_camera(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid method'}, status=405)

    try:
        print("Request.FILES:", request.FILES)
        print("Request.POST:", request.POST)

        image_file = request.FILES.get('image')
        preview = request.POST.get('preview', 'false') == 'true'

        if not image_file:
            return JsonResponse({'error': 'No image uploaded'}, status=400)

        image = Image.open(image_file).convert('RGB')
        print("Image opened successfully")

        # --- model prediction ---
        model = load_disease_model()
        class_names = [
            'Banana Anthracnose Fruit disease',
            'Banana Bract Mosaic Virus Disease',
            'Banana Cordana Leaf Disease',
            'Banana Fusarium Wilt Tree Disease',
            'Banana Insect Pest Leaf Disease',
            'Banana Naturally Leaf Dead',
            'Banana Panama Leaf Disease',
            'Banana Pestalotiopsis Leaf Disease',
            'Banana Rhizome Root Tree Disease',
            'Banana Sigatoka Leaf Disease',
            'Unknowmn'
        ]
        transform = transforms.Compose([
            transforms.Resize(256),
            transforms.CenterCrop(224),
            transforms.ToTensor(),
            transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
        ])
        input_tensor = transform(image).unsqueeze(0)

        with torch.no_grad():
            output = model(input_tensor)
            probs = torch.nn.functional.softmax(output[0], dim=0)
            confidence = torch.max(probs).item() * 100
            _, predicted = torch.max(output, 1)
            result = class_names[predicted.item()]

        if preview:
            return JsonResponse({'result': result, 'confidence': confidence})

        # --- capture mode: save image and redirect ---
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({'error': 'Authentication required'}, status=401)

        file_name = f"{user.id}_{datetime.now():%Y%m%d_%H%M%S}_capture.jpg"
        supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_ROLE_KEY)
        bucket = supabase.storage.from_('detection-images')

        buffer = BytesIO()
        image.save(buffer, format='JPEG')
        buffer.seek(0)
        upload_response = bucket.upload(file_name, buffer.read(), {"content-type": "image/jpeg"})

        # Debug upload response
        print("Upload response:", upload_response)

        image_url = f"{settings.SUPABASE_URL}/storage/v1/object/public/detection-images/{file_name}"

        record = DetectionRecord.objects.create(
            user=user,
            prediction=result,
            confidence=confidence,
            image_url=image_url,
            model_type='disease'
        )
        redirect_url = reverse('a_view_scan_result', kwargs={'record_id': record.id})
        return JsonResponse({'redirect_url': redirect_url})

    except Exception as e:
        print("Exception during predict_from_camera:", e)
        return JsonResponse({'error': f'Unexpected error: {str(e)}'}, status=500)




#banana variety model
def load_variety_model():
    # Load the variety model (Replace with your actual model loading code)
    model = models.resnet18(weights=None)  # Example, change to your model
    num_ftrs = model.fc.in_features
    model.fc = torch.nn.Linear(num_ftrs, 8)  # number of classes in your variety model
    model.load_state_dict(torch.load('escan/model/banana_variety_resnet_state_dict'))
    model.eval().pth
    return model

def a_banana_variety(request):
    model = load_variety_model()
    class_names = ['Anaji', 'Banana Lady Finger ( Señorita )', 'Banana Red', 'Bichi', 'Canvendish(Bungulan)', 'Lakatan', 'Saba', 'Sabri Kola']
    class_descriptions = {
        'Anaji': {
        'description': 'Anaji is a local banana variety known for its medium-sized fruits, thick peel, and mild sweet flavor. It is typically grown in certain regional areas.',
        'Classification': 'Dessert banana, medium-sized variety.',
        'Origin': 'Commonly cultivated in parts of Southeast Asia, particularly in the Philippines and neighboring countries.',
        'HarvestPeriod': '10-12 months after planting.'
    },
    'Banana Lady Finger ( Señorita )': {
        'description': 'Lady Finger or Señorita bananas are small, sweet, and slender bananas with thin yellow skin when ripe.',
        'Classification': 'Dessert banana, small-sized premium variety.',
        'Origin': 'Popular in the Philippines and tropical countries for its extra-sweet taste and attractive small size.',
        'HarvestPeriod': '9-10 months after planting.'
    },
    'Banana Red': {
        'description': 'Banana Red is a distinctive variety with reddish-purple skin and cream to light pink flesh, offering a unique, sweet taste.',
        'Classification': 'Dessert banana, colored variety.',
        'Origin': 'Cultivated in India, East Africa, and the Philippines; considered a specialty banana.',
        'HarvestPeriod': '12-14 months after planting.'
    },
    'Bichi': {
        'description': 'Bichi is a hardy, local banana variety often cultivated for its resilience in varying climate conditions and multipurpose use.',
        'Classification': 'Plantain-type banana for both raw and cooked uses.',
        'Origin': 'Native to rural agricultural areas in South Asia and Southeast Asia.',
        'HarvestPeriod': '11-13 months after planting.'
    },
    'Canvendish (Bungulan)': {
        'description': 'Cavendish, locally known as Bungulan in the Philippines, is the most commercially grown banana variety worldwide.',
        'Classification': 'Dessert banana, export-grade variety.',
        'Origin': 'Originated from China and popularized globally, particularly in the Philippines for export markets.',
        'HarvestPeriod': '9-10 months after planting.'
    },
    'Lakatan': {
        'description': 'Lakatan is a premium banana variety prized for its bright yellow skin and rich, sweet taste, preferred in many tropical countries.',
        'Classification': 'Dessert banana, premium variety.',
        'Origin': 'A favorite in the Philippines and neighboring countries; commonly sold in local markets and supermarkets.',
        'HarvestPeriod': '8-10 months after planting.'
    },
    'Saba': {
        'description': 'Saba is a large, firm banana primarily used for cooking but also eaten ripe. It is valued for its versatility and durability.',
        'Classification': 'Cooking banana (plantain-type).',
        'Origin': 'Widely grown in the Philippines and other Southeast Asian countries; essential in native dishes.',
        'HarvestPeriod': '12-14 months after planting.'
    },
    'Sabri Kola': {
        'description': 'Sabri Kola is a lesser-known variety with medium to large fruits, slightly starchy texture, and mild sweetness when ripe.',
        'Classification': 'Dual-purpose banana, suitable for cooking and eating ripe.',
        'Origin': 'Cultivated in parts of Bangladesh, India, and select Southeast Asian regions.',
        'HarvestPeriod': '11-13 months after planting.'
    }
    }

    result = None
    confidence = None
    prediction_time = None
    image_url = None
    disease_info = None

    if request.method == 'POST':
        form = ImageUploadForm(request.POST, request.FILES)
        if form.is_valid():
            image = form.cleaned_data['image']
            img = Image.open(image).convert('RGB')
            img_tensor = transforms.Compose([
                transforms.Resize(256),
                transforms.CenterCrop(224),
                transforms.ToTensor(),
                transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
            ])(img).unsqueeze(0)

            with torch.no_grad():
                output = model(img_tensor)
                probabilities = torch.nn.functional.softmax(output[0], dim=0)
                confidence = torch.max(probabilities).item() * 100
                _, predicted = torch.max(output, 1)
                result = class_names[predicted.item()]
                prediction_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                disease_info = class_descriptions.get(result)

            # 🔼 Upload image to Supabase
            user = request.user
            image.seek(0)  # Reset pointer
            file_data = image.read()
            file_name = f"{user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{image.name}"
            
            supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_ROLE_KEY)
            bucket = supabase.storage.from_('detection-images')

            try:
                # Upload image with correct content type
                upload_response = bucket.upload(file_name, file_data, {
                    "content-type": image.content_type
                })
                print("🔍 Response from Supabase:", upload_response)

                # If response has 'path' attribute, use it to get the public URL
                if hasattr(upload_response, 'path') and upload_response.path:
                    # Construct public URL from response
                    image_url = f"{settings.SUPABASE_URL}/storage/v1/object/public/detection-images/{upload_response.path}"

                    # Save to DB
                    DetectionRecord.objects.create(
                        user=user,
                        prediction=result,
                        confidence=confidence,
                        image_url=image_url,
                        model_type='variety'
                    )
                    print("✅ Detection record saved successfully")
                else:
                    print("❌ Upload error: No path in response")

            except Exception as e:
                print(f"⚠️ Supabase upload error: {e}")

            return render(request, 'escan/Admin/A_Scan/banana_variety_result.html', {
                'result': result,
                'confidence': confidence,
                'prediction_time': prediction_time,
                'image_url': image_url,
                'disease_info': disease_info,
            })

    else:
        form = ImageUploadForm()

    # user_records = DetectionRecord.objects.filter(user=request.user).order_by('-timestamp')[:4]

    return render(request, 'escan/Admin/A_Scan/a_banana_variety.html', {'form': form})

@login_required
def a_disease_scan_history(request):
    user_recordss = DetectionRecord.objects.filter(
        user=request.user, model_type='disease'
    ).order_by('-timestamp')
    return render(request, 'escan/Admin/A_Scan/a_disease_scan_records.html', {'user_recordss': user_recordss})

@login_required
def a_variety_scan_history(request):
    user_records = DetectionRecord.objects.filter(
        user=request.user, model_type='variety'
    ).order_by('-timestamp')
    return render(request, 'escan/Admin/A_Scan/a_variety_scan_records.html', {'user_records': user_records})

# Admin side Side
def a_predict_variety_from_camera(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid method'}, status=405)

    try:
        print("Request.FILES:", request.FILES)
        print("Request.POST:", request.POST)

        image_file = request.FILES.get('image')
        preview = request.POST.get('preview', 'false') == 'true'

        if not image_file:
            return JsonResponse({'error': 'No image uploaded'}, status=400)

        image = Image.open(image_file).convert('RGB')
        print("Image opened successfully")

        # --- model prediction ---
        model = load_variety_model()
        class_names = [
            'Anaji1', 
            'Banana Lady Finger (Señorita)', 
            'Banana Red', 
            'Bichi', 
            'Canvendish(Bungulan)', 
            'Lakatan', 
            'Saba', 
            'Sabri Kola',
            'Unknown Data'
        ]
        
        transform = transforms.Compose([
            transforms.Resize(256),
            transforms.CenterCrop(224),
            transforms.ToTensor(),
            transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
        ])
        input_tensor = transform(image).unsqueeze(0)

        with torch.no_grad():
            output = model(input_tensor)
            probs = torch.nn.functional.softmax(output[0], dim=0)
            confidence = torch.max(probs).item() * 100
            _, predicted = torch.max(output, 1)
            result = class_names[predicted.item()]

        if preview:
            return JsonResponse({'result': result, 'confidence': confidence})

        # --- capture mode: save image and redirect ---
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({'error': 'Authentication required'}, status=401)

        file_name = f"{user.id}_{datetime.now():%Y%m%d_%H%M%S}_capture.jpg"
        supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_ROLE_KEY)
        bucket = supabase.storage.from_('detection-images')

        buffer = BytesIO()
        image.save(buffer, format='JPEG')
        buffer.seek(0)
        upload_response = bucket.upload(file_name, buffer.read(), {"content-type": "image/jpeg"})

        # Debug upload response
        print("Upload response:", upload_response)

        image_url = f"{settings.SUPABASE_URL}/storage/v1/object/public/detection-images/{file_name}"

        record = DetectionRecord.objects.create(
            user=user,
            prediction=result,
            confidence=confidence,
            image_url=image_url,
            model_type='variety'
        )
        redirect_url = reverse('view_scan_result', kwargs={'record_id': record.id})
        return JsonResponse({'redirect_url': redirect_url})

    except Exception as e:
        print("Exception during a_predic_varietyt_from_camera:", e)
        return JsonResponse({'error': f'Unexpected error: {str(e)}'}, status=500)


@login_required
def a_view_scan_result(request, record_id):
    record = get_object_or_404(DetectionRecord, pk=record_id, user=request.user)

    # Use the model_type to determine which result template to render
    template = 'escan/Admin/A_Scan/a_banana_disease_result.html' if record.model_type == 'disease' else 'escan/User/Scan/a_banana_variety_result.html'

     # Disease Descriptions
    disease_descriptions = {
        'Anaji': {
        'description': 'Anaji is a local banana variety known for its medium-sized fruits, thick peel, and mild sweet flavor. It is typically grown in certain regional areas.',
        'Classification': 'Dessert banana, medium-sized variety.',
        'Origin': 'Commonly cultivated in parts of Southeast Asia, particularly in the Philippines and neighboring countries.',
        'HarvestPeriod': '10-12 months after planting.'
    },
    'Banana Lady Finger ( Señorita )': {
        'description': 'Lady Finger or Señorita bananas are small, sweet, and slender bananas with thin yellow skin when ripe.',
        'Classification': 'Dessert banana, small-sized premium variety.',
        'Origin': 'Popular in the Philippines and tropical countries for its extra-sweet taste and attractive small size.',
        'HarvestPeriod': '9-10 months after planting.'
    },
    'Banana Red': {
        'description': 'Banana Red is a distinctive variety with reddish-purple skin and cream to light pink flesh, offering a unique, sweet taste.',
        'Classification': 'Dessert banana, colored variety.',
        'Origin': 'Cultivated in India, East Africa, and the Philippines; considered a specialty banana.',
        'HarvestPeriod': '12-14 months after planting.'
    },
    'Bichi': {
        'description': 'Bichi is a hardy, local banana variety often cultivated for its resilience in varying climate conditions and multipurpose use.',
        'Classification': 'Plantain-type banana for both raw and cooked uses.',
        'Origin': 'Native to rural agricultural areas in South Asia and Southeast Asia.',
        'HarvestPeriod': '11-13 months after planting.'
    },
    'Canvendish (Bungulan)': {
        'description': 'Cavendish, locally known as Bungulan in the Philippines, is the most commercially grown banana variety worldwide.',
        'Classification': 'Dessert banana, export-grade variety.',
        'Origin': 'Originated from China and popularized globally, particularly in the Philippines for export markets.',
        'HarvestPeriod': '9-10 months after planting.'
    },
    'Lakatan': {
        'description': 'Lakatan is a premium banana variety prized for its bright yellow skin and rich, sweet taste, preferred in many tropical countries.',
        'Classification': 'Dessert banana, premium variety.',
        'Origin': 'A favorite in the Philippines and neighboring countries; commonly sold in local markets and supermarkets.',
        'HarvestPeriod': '8-10 months after planting.'
    },
    'Saba': {
        'description': 'Saba is a large, firm banana primarily used for cooking but also eaten ripe. It is valued for its versatility and durability.',
        'Classification': 'Cooking banana (plantain-type).',
        'Origin': 'Widely grown in the Philippines and other Southeast Asian countries; essential in native dishes.',
        'HarvestPeriod': '12-14 months after planting.'
    },
    'Sabri Kola': {
        'description': 'Sabri Kola is a lesser-known variety with medium to large fruits, slightly starchy texture, and mild sweetness when ripe.',
        'Classification': 'Dual-purpose banana, suitable for cooking and eating ripe.',
        'Origin': 'Cultivated in parts of Bangladesh, India, and select Southeast Asian regions.',
        'HarvestPeriod': '11-13 months after planting.'
    }
    }

    # Variety Descriptions
    variety_descriptions = {
        'Anaji': {
            'description': 'Description of Anaji...',
            'symptoms': 'Symptoms of Anaji...',
            'management': 'Management of Anaji...',
            'prevention': 'Prevention of Anaji...'
        },
        'Banana Lady Finger ( Señorita )': {
            'description': 'Description of Señorita...',
            'symptoms': 'N/A',
            'management': 'N/A',
            'prevention': 'N/A'
        },
        # Add all other variety info...
    }

    prediction_key = record.prediction.strip()

    if record.model_type == 'disease':
        disease_info = disease_descriptions.get(prediction_key, {})
    elif record.model_type == 'variety':
        disease_info = variety_descriptions.get(prediction_key, {})
    else:
        disease_info = {}

    return render(request, template, {
        'result': record.prediction,
        'confidence': record.confidence,
        'prediction_time': record.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'image_url': record.image_url,
        'disease_info': disease_info
    })


# -------------------------------------------
# Scan Farmer Side
# Allow loading of ResNet model class
torch.serialization.add_safe_globals({
    'torchvision.models.resnet.ResNet': models.ResNet
})

#banana disease model
def load_disease_model():
    # Load the disease model (Replace with your actual model loading code)
    model = models.resnet18(weights=None)  # Example, change to your model
    num_ftrs = model.fc.in_features
    model.fc = torch.nn.Linear(num_ftrs, 11)  # number of classes in your disease model
    model.load_state_dict(torch.load('escan/model/banana_disease(F)_resnet_state_dict.pth'))
    model.eval()
    return model

def banana_disease(request):
    model = load_disease_model()
    class_names = ['Banana Anthracnose Disease', 'Banana Bract Mosaic Virus Disease', 
 'Banana Cordana Leaf Disease', 'Banana Healthy',
 'Banana Naturally Leaf Dead', 'Banana Panama Leaf Disease', 
 'Banana Panama Tree Disease', 'Banana Pestalotiopsis Disease', 
 'Banana Rhizome Root Tree Disease', 'Banana Sigatoka Leaf Disease', 
 'Unknow Data']
    class_descriptions = {
'Banana Anthracnose Disease': {
        'description': 'Isang fungal infection na dulot ng *Colletotrichum musae*, karaniwang umaatake sa bunga ng saging habang hinog, nagdudulot ng maiitim na bilog at pagkabulok pagkatapos anihin.',
        'symptoms': 'Maliit na mamasa-masang batik sa balat ng bunga na lumalaki, nagiging itim at lumulubog, minsan may kulay rosas na spores kapag mahalumigmig.',
        'management': 'Paggamit ng fungicide pagkatapos anihin, maingat na pag-aani at paghawak, pagtanggal ng nahawaang bahagi ng halaman, at pagpapanatili ng kalinisan sa taniman.',
        'prevention': 'Paggamit ng malulusog na suwi, regular na pagputol ng dahon para sa magandang sirkulasyon ng hangin, at pag-spray ng proteksiyon na fungicide bago at pagkatapos anihin.'
    },
    'Banana Bract Mosaic Virus Disease': {
        'description': 'Isang sakit na dulot ng virus na ikinakalat ng dapulak (aphids), nagdudulot ng mosaic o batik-batik na guhit sa mga bracts, dahon, at balat ng bunga ng saging.',
        'symptoms': 'Paglitaw ng dilaw o matingkad na berdeng guhit at mosaic patterns sa bracts at petioles, kasama ang deformed o baluktot na bunga at dahon.',
        'management': 'Paggamit ng virus-free na suwi, pagtanggal ng mga nahawaang halaman, at pagkontrol sa dapulak gamit ang insecticide o natural na predator.',
        'prevention': 'Mahigpit na quarantine, regular na pagmamanman sa dapulak, at pag-iwas sa pagtatanim malapit sa kontaminadong bukirin.'
    },
    'Banana Cordana Leaf Disease': {
        'description': 'Isang fungal disease na dulot ng *Cordana musae* na pangunahing umaatake sa dahon ng saging, nagbabawas sa kakayahang mag-photosynthesis at nagdudulot ng maagang pagkamatay ng dahon.',
        'symptoms': 'Maliit na oblong o bilugang kayumangging batik na may dilaw na palibot sa dahon na maaaring magsanib at lumaki.',
        'management': 'Pagputol ng apektadong dahon, pag-spray ng fungicide, at pagpapabuti ng drainage sa bukirin.',
        'prevention': 'Regular na pagmamanman, paggamit ng resistant na barayti kung meron, at tamang agwat ng pagtatanim para maiwasan ang masyadong siksik na dahon.'
    },
    'Banana Healthy': {
        'description': 'Ipinapakita na ang halamang saging ay nasa maayos na kalagayan, walang nakikitang peste, sakit, o kakulangan sa sustansya.',
        'symptoms': 'Luntian at makinis na dahon, normal na paglaki ng bunga, at malusog na puno.',
        'management': 'Pagpapatuloy ng tamang pangangalaga tulad ng regular na dilig, abono, at pagtanggal ng damo.',
        'prevention': 'Pagsunod sa tamang gawain sa pagsasaka, paggamit ng malulusog na suwi, at regular na pagmamanman ng halaman.'
    },
    'Banana Naturally Leaf Dead': {
        'description': 'Isang normal na proseso kung saan ang matatandang dahon ng saging ay unti-unting namamatay habang tumutubo ang mga bagong dahon.',
        'symptoms': 'Unti-unting paninilaw, pagkatuyo, at pagkamatay ng mga dahon sa ibabang bahagi simula sa dulo hanggang sa puno.',
        'management': 'Regular na pagtanggal ng tuyong dahon upang hindi pamugaran ng peste at sakit.',
        'prevention': 'Pagbibigay ng sapat na abono at tubig, at tamang pangangalaga upang hindi mapabilis ang maagang pagkamatay ng dahon.'
    },
    'Banana Panama Leaf Disease': {
        'description': 'Isang uri ng Fusarium Wilt na pangunahing nakakaapekto sa dahon ng saging, nagdudulot ng paninilaw at tuluyang pagkamatay ng dahon.',
        'symptoms': 'Pagdilaw ng matatandang dahon, pagkalanta at pagbagsak, at pagkakaroon ng pulang kayumangging kulay sa loob ng halaman.',
        'management': 'Agarang pagtanggal ng nahawaang halaman, paggamot ng lupa, at paggamit ng biological control agents.',
        'prevention': 'Paggamit ng resistant na barayti at pagpapanatili ng malinis na bukirin.'
    },
    'Banana Panama Tree Disease': {
        'description': 'Kilala rin bilang Fusarium Wilt o Panama Disease, dulot ng *Fusarium oxysporum f.sp. cubense*, isang sakit na galing sa lupa na sumisira sa ugat at vascular system ng saging.',
        'symptoms': 'Pagdilaw ng matatandang dahon, pagkalanta, pagkabiyak ng pseudostem, at pagkakaroon ng kayumangging kulay sa rhizome.',
        'management': 'Pagbunot at pagsunog ng nahawaang halaman, crop rotation, at paggamit ng resistant na barayti.',
        'prevention': 'Iwasan ang kontaminadong lupa at kagamitan, gumamit ng malinis na suwi, at panatilihin ang sanitation ng bukirin.'
    },
    'Banana Pestalotiopsis Disease': {
        'description': 'Isang fungal leaf spot disease na dulot ng *Pestalotiopsis spp.*, na nakakaapekto sa dahon at nagpapababa sa kakayahang mag-photosynthesis.',
        'symptoms': 'Maliit na kayumangging batik na may bilog-bilog na pattern sa dahon, lumalaki at nagsasanib para maging malalaking tuyong bahagi.',
        'management': 'Pagputol at pagsira ng apektadong dahon, pagpapabuti ng bentilasyon, at pag-spray ng fungicide.',
        'prevention': 'Iwasan ang overhead irrigation, mag-rotate ng pananim, at magbigay ng tamang agwat ng pagtatanim.'
    },
    'Banana Rhizome Root Tree Disease': {
        'description': 'Isang sakit na nakakaapekto sa rhizome at ugat ng saging, karaniwang dulot ng fungal pathogens tulad ng *Fusarium* o bacterial soft rot.',
        'symptoms': 'Pagkalanta ng dahon, panghihina ng halaman, paglambot at pagkaitim ng rhizome, at pagkabulok ng ugat.',
        'management': 'Paggamit ng malinis na suwi, pagtanggal ng nahawaang halaman, at soil sterilization kung posible.',
        'prevention': 'Pagpapanatili ng maayos na drainage, pag-iwas sa sobrang tubig, at pagpapanatili ng kalinisan sa bukirin.'
    },
    'Banana Sigatoka Leaf Disease': {
        'description': 'Isang karaniwang fungal disease na dulot ng *Mycosphaerella musicola* (Yellow Sigatoka) o *Mycosphaerella fijiensis* (Black Sigatoka) na umaatake sa dahon ng saging.',
        'symptoms': 'Maliit na dilaw na guhit sa dahon na lumalaki at nagiging tuyong bahagi, nagdudulot ng maagang pagkamatay ng dahon.',
        'management': 'Regular na pagtanggal ng apektadong dahon, pag-spray ng fungicide, at paggamit ng resistant na barayti.',
        'prevention': 'Tamang agwat ng pagtatanim, maayos na drainage, at pag-iwas sa overhead irrigation.'
    },
    'Unknow Data': {
        'description': 'Kategorya para sa datos o larawan ng saging na hindi matukoy kung anong sakit o kung ito ay malusog.',
        'symptoms': 'Hindi malinaw o hindi tumutugma ang sintomas sa mga kilalang sakit ng saging.',
        'management': 'Kinakailangan ng karagdagang pagsusuri ng eksperto o laboratory test upang makilala ang sanhi.',
        'prevention': 'Siguruhing tama ang pagkolekta ng datos, malinaw ang kuha ng larawan, at regular ang pagmamanman para mabawasan ang hindi matukoy na kaso.'
    }
        
    }

    result = None
    confidence = None
    prediction_time = None
    image_url = None
    disease_info = None

    if request.method == 'POST':
        form = ImageUploadForm(request.POST, request.FILES)
        if form.is_valid():
            image = form.cleaned_data['image']
            img = PILImage.open(image).convert('RGB')
            img_tensor = transforms.Compose([
                transforms.Resize(256),
                transforms.CenterCrop(224),
                transforms.ToTensor(),
                transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
            ])(img).unsqueeze(0)

            with torch.no_grad():
                output = model(img_tensor)
                probabilities = torch.nn.functional.softmax(output[0], dim=0)
                confidence = torch.max(probabilities).item() * 100
                _, predicted = torch.max(output, 1)
                result = class_names[predicted.item()]
                prediction_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                disease_info = class_descriptions.get(result)

            # 🔼 Upload image to Supabase
            user = request.user
            image.seek(0)  # Reset pointer
            file_data = image.read()
            file_name = f"{user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{image.name}"
            
            supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_ROLE_KEY)
            bucket = supabase.storage.from_('detection-images')

            try:
                # Upload image with correct content type
                upload_response = bucket.upload(file_name, file_data, {
                    "content-type": image.content_type
                })
                print("🔍 Response from Supabase:", upload_response)

                # If response has 'path' attribute, use it to get the public URL
                if hasattr(upload_response, 'path') and upload_response.path:
                    # Construct public URL from response
                    image_url = f"{settings.SUPABASE_URL}/storage/v1/object/public/detection-images/{upload_response.path}"

                    # Save to DB
                    DetectionRecord.objects.create(
                        user=user,
                        prediction=result,
                        confidence=confidence,
                        image_url=image_url,
                        model_type='disease'
                    )
                    print("✅ Detection record saved successfully")
                else:
                    print("❌ Upload error: No path in response")

            except Exception as e:
                print(f"⚠️ Supabase upload error: {e}")

            return render(request, 'escan/Farmer/Scan/banana_disease_result.html', {
                'result': result,
                'confidence': confidence,
                'prediction_time': prediction_time,
                'image_url': image_url,
                'disease_info': disease_info,
            })

    else:
        form = ImageUploadForm()

    # Get current user's past records (most recent first)
    # user_records = DetectionRecord.objects.filter(user=request.user).order_by('-timestamp')[:4]

    # return render(request, 'escan/User/Scan/banana_disease.html', {'form': form, 'user_records': user_records})
    return render(request, 'escan/Farmer/Scan/banana_disease.html', {'form': form})

from PIL import Image

def predict_from_camera(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid method'}, status=405)

    try:
        print("Request.FILES:", request.FILES)
        print("Request.POST:", request.POST)

        image_file = request.FILES.get('image')
        preview = request.POST.get('preview', 'false') == 'true'

        if not image_file:
            return JsonResponse({'error': 'No image uploaded'}, status=400)

        image = Image.open(image_file).convert('RGB')
        print("Image opened successfully")

        # --- model prediction ---
        model = load_disease_model()
        class_names = [
            'Banana Anthracnose Disease', 
            'Banana Bract Mosaic Virus Disease', 
            'Banana Cordana Leaf Disease', 
            'Banana Healthy',
            'Banana Naturally Leaf Dead', 
            'Banana Panama Leaf Disease', 
            'Banana Panama Tree Disease',
            'Banana Pestalotiopsis Disease', 
            'Banana Rhizome Root Tree Disease', 
            'Banana Sigatoka Le7af Disease', 
            'Unknow Data'
        ]
        transform = transforms.Compose([
            transforms.Resize(256),
            transforms.CenterCrop(224),
            transforms.ToTensor(),
            transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
        ])
        input_tensor = transform(image).unsqueeze(0)

        with torch.no_grad():
            output = model(input_tensor)
            probs = torch.nn.functional.softmax(output[0], dim=0)
            confidence = torch.max(probs).item() * 100
            _, predicted = torch.max(output, 1)
            result = class_names[predicted.item()]

        if preview:
            return JsonResponse({'result': result, 'confidence': confidence})

        # --- capture mode: save image and redirect ---
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({'error': 'Authentication required'}, status=401)

        file_name = f"{user.id}_{datetime.now():%Y%m%d_%H%M%S}_capture.jpg"
        supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_ROLE_KEY)
        bucket = supabase.storage.from_('detection-images')

        buffer = BytesIO()
        image.save(buffer, format='JPEG')
        buffer.seek(0)
        upload_response = bucket.upload(file_name, buffer.read(), {"content-type": "image/jpeg"})

        # Debug upload response
        print("Upload response:", upload_response)

        image_url = f"{settings.SUPABASE_URL}/storage/v1/object/public/detection-images/{file_name}"

        record = DetectionRecord.objects.create(
            user=user,
            prediction=result,
            confidence=confidence,
            image_url=image_url,
            model_type='disease'
        )
        redirect_url = reverse('view_scan_result', kwargs={'record_id': record.id})
        return JsonResponse({'redirect_url': redirect_url})

    except Exception as e:
        print("Exception during predict_from_camera:", e)
        return JsonResponse({'error': f'Unexpected error: {str(e)}'}, status=500)


#Farmer Side banana variety model
def load_variety_model():
    # Load the variety model (Replace with your actual model loading code)
    model = models.resnet18(weights=None)  # Example, change to your model
    num_ftrs = model.fc.in_features
    model.fc = torch.nn.Linear(num_ftrs, 9)  # number of classes in your variety model
    model.load_state_dict(torch.load('escan/model/banana_variety_resnet_state_dict.pth'))
    model.eval()
    return model

def banana_variety(request):
    model = load_variety_model()
    class_names = ['Anaji1', 'Banana Lady Finger ( Señorita )', 'Banana Red', 'Bichi', 'Canvendish(Bungulan)', 'Lakatan', 'Saba', 'Sabri Kola', 'Unknow Data']
    class_descriptions = {
    'Anaji1': {
        'description': 'Ang Anaji ay isang lokal na barayti ng saging na kilala sa katamtamang laki ng bunga, makapal na balat, at banayad na tamis ng lasa. Karaniwang itinatanim sa piling rehiyon.',
        'Classification': 'Panghimagas na saging, katamtamang laki.',
        'Origin': 'Karaniwang itinatanim sa ilang bahagi ng Timog-Silangang Asya, partikular sa Pilipinas at kalapit bansa.',
        'HarvestPeriod': '10-12 buwan matapos itanim.'
    },
    'Banana Lady Finger ( Señorita )': {
        'description': 'Ang Señorita o Lady Finger ay maliliit na saging na matamis, manipis ang balat kapag hinog, at kilala sa masarap na lasa.',
        'Classification': 'Panghimagas na saging, maliit na premium variety.',
        'Origin': 'Sikat sa Pilipinas at mga tropikal na bansa dahil sa labis na tamis at kaakit-akit na maliit na sukat.',
        'HarvestPeriod': '9-10 buwan matapos itanim.'
    },
    'Banana Red': {
        'description': 'Ang Banana Red ay natatangi dahil sa mapula-pulang balat at laman na kulay krema hanggang rosas na may kakaibang tamis.',
        'Classification': 'Panghimagas na saging, may kulay na variety.',
        'Origin': 'Itinatanim sa India, East Africa, at Pilipinas; itinuturing na espesyal na barayti.',
        'HarvestPeriod': '12-14 buwan matapos itanim.'
    },
    'Bichi': {
        'description': 'Ang Bichi ay isang matibay na lokal na barayti ng saging na kilala sa kakayahang tumubo sa iba’t ibang klima at maraming gamit.',
        'Classification': 'Plantain-type na saging, maaaring kainin nang hilaw o luto.',
        'Origin': 'Katutubong itinatanim sa mga kanayunan ng South Asia at Timog-Silangang Asya.',
        'HarvestPeriod': '11-13 buwan matapos itanim.'
    },
    'Canvendish (Bungulan)': {
        'description': 'Ang Cavendish, na lokal na tinatawag na Bungulan sa Pilipinas, ang pinakapangunahing komersyal na barayti ng saging sa buong mundo.',
        'Classification': 'Panghimagas na saging, export-grade variety.',
        'Origin': 'Nagmula sa China at naging tanyag sa buong mundo, partikular sa Pilipinas bilang pangunahing panluwas.',
        'HarvestPeriod': '9-10 buwan matapos itanim.'
    },
    'Lakatan': {
        'description': 'Ang Lakatan ay isang premium na saging na tanyag dahil sa matingkad na dilaw na balat at mayamang tamis, paborito sa maraming tropikal na bansa.',
        'Classification': 'Panghimagas na saging, premium variety.',
        'Origin': 'Paborito sa Pilipinas at kalapit bansa; karaniwang makikita sa mga pamilihan at supermarket.',
        'HarvestPeriod': '8-10 buwan matapos itanim.'
    },
    'Saba': {
        'description': 'Ang Saba ay malaking uri ng saging na matibay at madalas ginagamit sa pagluluto ngunit maaari ring kainin kapag hinog. Pinahahalagahan dahil sa pagiging maraming gamit.',
        'Classification': 'Saging na pangluto (plantain-type).',
        'Origin': 'Malawakang itinatanim sa Pilipinas at iba pang bansa sa Timog-Silangang Asya; mahalaga sa mga katutubong putahe.',
        'HarvestPeriod': '12-14 buwan matapos itanim.'
    },
    'Sabri Kola': {
        'description': 'Ang Sabri Kola ay hindi gaanong kilalang barayti na may katamtaman hanggang malaking bunga, bahagyang malapot ang laman, at banayad ang tamis kapag hinog.',
        'Classification': 'Dual-purpose na saging, puwedeng lutuin o kainin nang hinog.',
        'Origin': 'Itinatanim sa ilang bahagi ng Bangladesh, India, at piling rehiyon ng Timog-Silangang Asya.',
        'HarvestPeriod': '11-13 buwan matapos itanim.'
    },
    'Unknow Data': {
        'description': 'Limitado pa ang impormasyon tungkol sa barayting ito ng saging at hindi pa dokumentado nang maayos. Kinakailangan ng karagdagang pag-aaral o field validation.',
        'Classification': 'Hindi pa nakikilala-hindi pa tiyak ang gamit at layunin.',
        'Origin': 'Hindi pa natutukoy; maaaring mag-iba depende sa lugar ng pagtatanim.',
        'HarvestPeriod': 'Hindi pa matukoy; kailangan ng dagdag na datos upang malaman ang takdang panahon ng ani.'
    }
}

    result = None
    confidence = None
    prediction_time = None
    image_url = None
    variety_info = None

    if request.method == 'POST':
        form = ImageUploadForm(request.POST, request.FILES)
        if form.is_valid():
            image = form.cleaned_data['image']
            img = Image.open(image).convert('RGB')
            img_tensor = transforms.Compose([
                transforms.Resize(256),
                transforms.CenterCrop(224),
                transforms.ToTensor(),
                transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
            ])(img).unsqueeze(0)

            with torch.no_grad():
                output = model(img_tensor)
                probabilities = torch.nn.functional.softmax(output[0], dim=0)
                confidence = torch.max(probabilities).item() * 100
                _, predicted = torch.max(output, 1)
                result = class_names[predicted.item()]
                prediction_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                variety_info = class_descriptions.get(result)

            # 🔼 Upload image to Supabase
            user = request.user
            image.seek(0)  # Reset pointer
            file_data = image.read()
            file_name = f"{user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{image.name}"
            
            supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_ROLE_KEY)
            bucket = supabase.storage.from_('detection-images')

            try:
                # Upload image with correct content type
                upload_response = bucket.upload(file_name, file_data, {
                    "content-type": image.content_type
                })
                print("🔍 Response from Supabase:", upload_response)

                # If response has 'path' attribute, use it to get the public URL
                if hasattr(upload_response, 'path') and upload_response.path:
                    # Construct public URL from response
                    image_url = f"{settings.SUPABASE_URL}/storage/v1/object/public/detection-images/{upload_response.path}"

                    # Save to DB
                    DetectionRecord.objects.create(
                        user=user,
                        prediction=result,
                        confidence=confidence,
                        image_url=image_url,
                        model_type='variety'
                    )
                    print("✅ Detection record saved successfully")
                else:
                    print("❌ Upload error: No path in response")

            except Exception as e:
                print(f"⚠️ Supabase upload error: {e}")

            return render(request, 'escan/Farmer/Scan/banana_variety_result.html', {
                'result': result,
                'confidence': confidence,
                'prediction_time': prediction_time,
                'image_url': image_url,
                'variety_info': variety_info,
            })

    else:
        form = ImageUploadForm()

    # user_records = DetectionRecord.objects.filter(user=request.user).order_by('-timestamp')[:4]

    return render(request, 'escan/Farmer/Scan/banana_variety.html', {'form': form})
# Farmer Side
def predict_variety_from_camera(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid method'}, status=405)

    try:
        print("Request.FILES:", request.FILES)
        print("Request.POST:", request.POST)

        image_file = request.FILES.get('image')
        preview = request.POST.get('preview', 'false') == 'true'

        if not image_file:
            return JsonResponse({'error': 'No image uploaded'}, status=400)

        image = Image.open(image_file).convert('RGB')
        print("Image opened successfully")

        # --- model prediction ---
        model = load_variety_model()
        class_names = [
            'Anaji1', 
            'Banana Lady Finger (Señorita)', 
            'Banana Red', 
            'Bichi', 
            'Canvendish(Bungulan)', 
            'Lakatan', 
            'Saba', 
            'Sabri Kola',
            'Unknown Data'
        ]
        
        transform = transforms.Compose([
            transforms.Resize(256),
            transforms.CenterCrop(224),
            transforms.ToTensor(),
            transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
        ])
        input_tensor = transform(image).unsqueeze(0)

        with torch.no_grad():
            output = model(input_tensor)
            probs = torch.nn.functional.softmax(output[0], dim=0)
            confidence = torch.max(probs).item() * 100
            _, predicted = torch.max(output, 1)
            result = class_names[predicted.item()]

        if preview:
            return JsonResponse({'result': result, 'confidence': confidence})

        # --- capture mode: save image and redirect ---
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({'error': 'Authentication required'}, status=401)

        file_name = f"{user.id}_{datetime.now():%Y%m%d_%H%M%S}_capture.jpg"
        supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_ROLE_KEY)
        bucket = supabase.storage.from_('detection-images')

        buffer = BytesIO()
        image.save(buffer, format='JPEG')
        buffer.seek(0)
        upload_response = bucket.upload(file_name, buffer.read(), {"content-type": "image/jpeg"})

        # Debug upload response
        print("Upload response:", upload_response)

        image_url = f"{settings.SUPABASE_URL}/storage/v1/object/public/detection-images/{file_name}"

        record = DetectionRecord.objects.create(
            user=user,
            prediction=result,
            confidence=confidence,
            image_url=image_url,
            model_type='variety'
        )
        redirect_url = reverse('a_view_scan_result', kwargs={'record_id': record.id})
        return JsonResponse({'redirect_url': redirect_url})

    except Exception as e:
        print("Exception during predic_varietyt_from_camera:", e)
        return JsonResponse({'error': f'Unexpected error: {str(e)}'}, status=500)

@login_required
def disease_scan_history(request):
    user_recordss = DetectionRecord.objects.filter(
        user=request.user, model_type='disease'
    ).order_by('-timestamp')
    return render(request, 'escan/Farmer/Scan/disease_scan_records.html', {'user_recordss': user_recordss})

@login_required
def variety_scan_history(request):
    variety_user_records = DetectionRecord.objects.filter(
        user=request.user, model_type='variety'
    ).order_by('-timestamp')
    return render(request, 'escan/Farmer/Scan/variety_scan_records.html', {'variety_user_records':variety_user_records})



@login_required
def view_scan_result(request, record_id):
    record = get_object_or_404(DetectionRecord, pk=record_id, user=request.user)

    # Variety Descriptions
    variety_descriptions = {
        'Anaji': {
            'description': 'Anaji is a local banana variety known for its medium-sized fruits, thick peel, and mild sweet flavor. It is typically grown in certain regional areas.',
            'Classification': 'Dessert banana, medium-sized variety.',
            'Origin': 'Commonly cultivated in parts of Southeast Asia, particularly in the Philippines and neighboring countries.',
            'HarvestPeriod': '10-12 months after planting.'
        },
        'Banana Lady Finger ( Señorita )': {
            'description': 'Lady Finger or Señorita bananas are small, sweet, and slender bananas with thin yellow skin when ripe.',
            'Classification': 'Dessert banana, small-sized premium variety.',
            'Origin': 'Popular in the Philippines and tropical countries for its extra-sweet taste and attractive small size.',
            'HarvestPeriod': '9-10 months after planting.'
        },
        'Banana Red': {
            'description': 'Banana Red is a distinctive variety with reddish-purple skin and cream to light pink flesh, offering a unique, sweet taste.',
            'Classification': 'Dessert banana, colored variety.',
            'Origin': 'Cultivated in India, East Africa, and the Philippines; considered a specialty banana.',
            'HarvestPeriod': '12-14 months after planting.'
        },
        'Bichi': {
            'description': 'Bichi is a hardy, local banana variety often cultivated for its resilience in varying climate conditions and multipurpose use.',
            'Classification': 'Plantain-type banana for both raw and cooked uses.',
            'Origin': 'Native to rural agricultural areas in South Asia and Southeast Asia.',
            'HarvestPeriod': '11-13 months after planting.'
        },
        'Canvendish (Bungulan)': {
            'description': 'Cavendish, locally known as Bungulan in the Philippines, is the most commercially grown banana variety worldwide.',
            'Classification': 'Dessert banana, export-grade variety.',
            'Origin': 'Originated from China and popularized globally, particularly in the Philippines for export markets.',
            'HarvestPeriod': '9-10 months after planting.'
        },
        'Lakatan': {
            'description': 'Lakatan is a premium banana variety prized for its bright yellow skin and rich, sweet taste, preferred in many tropical countries.',
            'Classification': 'Dessert banana, premium variety.',
            'Origin': 'A favorite in the Philippines and neighboring countries; commonly sold in local markets and supermarkets.',
            'HarvestPeriod': '8-10 months after planting.'
        },
        'Saba': {
            'description': 'Saba is a large, firm banana primarily used for cooking but also eaten ripe. It is valued for its versatility and durability.',
            'Classification': 'Cooking banana (plantain-type).',
            'Origin': 'Widely grown in the Philippines and other Southeast Asian countries; essential in native dishes.',
            'HarvestPeriod': '12-14 months after planting.'
        },
        'Sabri Kola': {
            'description': 'Sabri Kola is a lesser-known variety with medium to large fruits, slightly starchy texture, and mild sweetness when ripe.',
            'Classification': 'Dual-purpose banana, suitable for cooking and eating ripe.',
            'Origin': 'Cultivated in parts of Bangladesh, India, and select Southeast Asian regions.',
            'HarvestPeriod': '11-13 months after planting.'
        },
        'Unknown Data': {
            'description': 'Information about this banana variety is currently limited and not well-documented. Further research or field validation is required to identify its physical traits and characteristics.',
            'Classification': 'Unclassified – potential use and purpose not yet verified.',
            'Origin': 'Origin is not yet established; may vary depending on local cultivation.',
            'HarvestPeriod': 'Undetermined; more data needed to confirm growth and harvest cycle.'
        },
    }

    # Disease Descriptions
    disease_descriptions = {
        'Banana Anthracnose Disease': {
            'description': 'A fungal infection caused by (Colletotrichum musae), primarily affecting banana fruits during ripening, causing dark sunken spots and post-harvest rot.',
            'symptoms': 'Small, water-soaked spots on fruit skin that enlarge, turning black and sunken with possible pinkish spore masses in humid conditions.',
            'management': 'Post-harvest fungicide dips, careful handling during harvest and transport, removal of infected plant debris, and maintaining orchard sanitation.',
            'prevention': 'Use disease-free planting material, regular pruning to improve air circulation, and protective fungicide sprays pre- and post-harvest.'
        },
        'Banana Bract Mosaic Virus Disease': {
            'description': 'A viral disease transmitted by aphids causing mosaic patterns on banana bracts, leaves, and fruit peels, affecting plant growth and yield.',
            'symptoms': 'Chlorotic or dark green streaks and mosaic patterns on bracts and petioles, distorted fruits, and leaf deformation.',
            'management': 'Use of virus-free suckers, removal of infected plants, and control of aphid vectors using insecticides or biological agents.',
            'prevention': 'Implement strict quarantine measures, monitor aphid populations, and avoid planting near infected fields.'
        },
        'Banana Cordana Leaf Disease': {
            'description': 'A fungal disease caused by *Cordana musae* that primarily affects banana leaves, reducing photosynthesis and leading to premature leaf death.',
            'symptoms': 'Small oval to elliptical brown spots with yellow halos on leaves, coalescing into large necrotic patches.',
            'management': 'Pruning of affected leaves, application of protective fungicides, and improving field drainage.',
            'prevention': 'Regular monitoring, use of resistant varieties where available, and proper spacing to avoid dense foliage.'
        },
        'Banana Fusarium Wilt Tree Disease': {
            'description': 'Also known as Panama disease, caused by *Fusarium oxysporum f.sp. cubense*, it\'s a serious soil-borne fungal disease attacking the plant\'s vascular system.',
            'symptoms': 'Yellowing of older leaves, wilting, splitting of the pseudostem base, and brown vascular discoloration in rhizomes.',
            'management': 'Uprooting and burning infected plants, soil solarization, and using disease-resistant banana cultivars.',
            'prevention': 'Avoid contaminated soil and tools, use clean planting material, and implement crop rotation with non-host crops.'
        },
        'Banana Insect Pest Disease': {
            'description': 'A collective term for damage caused by various banana insect pests such as banana weevils and aphids, affecting plant health and fruit yield.',
            'symptoms': 'Presence of boreholes in pseudostem, yellowing leaves, stunted growth, and distorted fruits.',
            'management': 'Use of pheromone traps, biological control agents, and selective insecticide applications.',
            'prevention': 'Field sanitation, removal of plant residues, regular monitoring, and planting pest-resistant varieties.'
        },
        'Banana Naturally Leaf Dead': {
            'description': 'A natural physiological process where older banana leaves die off as new leaves emerge, typically harmless unless excessive.',
            'symptoms': 'Gradual yellowing, drying, and death of lower leaves starting from the tip towards the base.',
            'management': 'Regular removal of dead leaves to reduce pest and disease harboring.',
            'prevention': 'Ensure balanced fertilization, adequate water, and healthy plant care to minimize premature leaf death.'
        },
        'Banana Panama Leaf Disease': {
            'description': 'Another form of Fusarium Wilt, it specifically affects banana leaves, leading to characteristic yellowing and eventual death of leaves.',
            'symptoms': 'Chlorosis starting from older leaves, progressing to wilting and drooping, with reddish-brown vascular discoloration.',
            'management': 'Immediate removal of infected plants, soil treatment, and application of biological control agents.',
            'prevention': 'Use of resistant cultivars and maintaining strict field hygiene and quarantine protocols.'
        },
        'Banana Pestalotiopsis Disease': {
            'description': 'A fungal leaf spot disease caused by (Pestalotiopsis spp.), affecting banana leaves and reducing photosynthetic efficiency.',
            'symptoms': 'Small, dark brown spots with concentric rings on leaves, which enlarge and merge into necrotic areas.',
            'management': 'Prune and destroy affected leaves, improve air circulation, and apply appropriate fungicides.',
            'prevention': 'Avoid overhead irrigation, practice crop rotation, and ensure optimal plant spacing.'
        },
        'Banana Rhizome Root Tree Disease': {
            'description': 'A disease affecting the rhizome and roots of banana plants, often caused by fungal pathogens like *Fusarium* or bacterial soft rot.',
            'symptoms': 'Wilting of leaves, reduced plant vigor, softening and discoloration of rhizomes, and root decay.',
            'management': 'Use of clean planting material, removal of infected plants, and soil sterilization if feasible.',
            'prevention': 'Implement good drainage, avoid waterlogging, and maintain field sanitation.'
        },
        'Banana Sigatoka Leaf Disease': {
            'description': 'A widespread fungal disease caused by "Mycosphaerella musicola" (Yellow Sigatoka) or "Mycosphaerella fijiensis" (Black Sigatoka) affecting banana leaves.',
            'symptoms': 'Small yellowish streaks on leaves developing into large necrotic areas, leading to premature leaf death.',
            'management': 'Regular removal of infected leaves, fungicide applications, and use of resistant cultivars.',
            'prevention': 'Maintain adequate plant spacing, improve drainage, and avoid overhead irrigation.'
        },
         'Unknown Data': {
            'description': 'Information about this banana variety is currently limited and not well-documented. Further research or field validation is required to identify its physical traits and characteristics.',
            'Classification': 'Unclassified – potential use and purpose not yet verified.',
            'Origin': 'Origin is not yet established; may vary depending on local cultivation.',
            'HarvestPeriod': 'Undetermined; more data needed to confirm growth and harvest cycle.'
        },
    }

    prediction_key = record.prediction.strip()

    # Determine which template and data to use based on model_type
    if record.model_type == 'disease':
        template = 'escan/Farmer/Scan/banana_disease_result.html'
        context_data = {
            'result': record.prediction,
            'confidence': record.confidence,
            'prediction_time': record.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'image_url': record.image_url,
            'disease_info': disease_descriptions.get(prediction_key, {})
        }
    elif record.model_type == 'variety':
        template = 'escan/Farmer/Scan/banana_variety_result.html'
        context_data = {
            'result': record.prediction,
            'confidence': record.confidence,
            'prediction_time': record.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'image_url': record.image_url,
            'variety_info': variety_descriptions.get(prediction_key, {})
        }
    else:
        # Fallback for unknown model types
        template = 'escan/Farmer/Scan/banana_disease_result.html'
        context_data = {
            'result': record.prediction,
            'confidence': record.confidence,
            'prediction_time': record.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'image_url': record.image_url,
            'disease_info': {}
        }

    return render(request, template, context_data)

# Famer Side Dashboard
from django.db.models import Count, Q, Avg

@login_required
def farmer_dashboard(request):
    """Render the farmer dashboard page with comprehensive context"""
    user = request.user
    
    # Get basic scan counts
    user_records = DetectionRecord.objects.filter(user=user)
    total_scans = user_records.count()
    disease_scans = user_records.filter(model_type='disease').count()
    variety_scans = user_records.filter(model_type='variety').count()
    today_scans = user_records.filter(timestamp__date=timezone.now().date()).count()
    
    # Calculate week and month scans
    week_start = timezone.now().date() - timedelta(days=timezone.now().date().weekday())
    month_start = timezone.now().date().replace(day=1)
    
    week_scans = user_records.filter(timestamp__date__gte=week_start).count()
    month_scans = user_records.filter(timestamp__date__gte=month_start).count()
    
    # Get weather data
    weather_data = get_weather_context(request)
    
    # Get scanning tip
    scanning_tip = get_scanning_tip(
        weather_data.get('condition', '').lower(),
        weather_data.get('temperature', 0),
        weather_data.get('humidity', 0)
    ) if weather_data else "Check local conditions for optimal scanning"
    
    # Get most recent scans for display
    recent_records = user_records.order_by('-timestamp')[:5]
    
    # Get analytics data for charts
    disease_analytics = dict(
        user_records.filter(model_type='disease')
        .values('prediction')
        .annotate(count=Count('prediction'))
        .values_list('prediction', 'count')
    )
    
    variety_analytics = dict(
        user_records.filter(model_type='variety')
        .values('prediction')
        .annotate(count=Count('prediction'))
        .values_list('prediction', 'count')
    )
    
    # Most scanned items
    most_scanned_disease = (
        user_records.filter(model_type='disease')
        .values('prediction')
        .annotate(count=Count('prediction'))
        .order_by('-count')
        .first()
    )
    
    most_scanned_variety = (
        user_records.filter(model_type='variety')
        .values('prediction')
        .annotate(count=Count('prediction'))
        .order_by('-count')
        .first()
    )
    
    # Confidence statistics
    disease_avg_confidence = user_records.filter(model_type='disease').aggregate(
        avg_confidence=Avg('confidence')
    )['avg_confidence'] or 0
    
    variety_avg_confidence = user_records.filter(model_type='variety').aggregate(
        avg_confidence=Avg('confidence')
    )['avg_confidence'] or 0
    
    high_confidence_count = user_records.filter(confidence__gte=0.8).count()
    low_confidence_count = user_records.filter(confidence__lt=0.6).count()
    
    # Unique predictions count
    unique_diseases = user_records.filter(model_type='disease').values('prediction').distinct().count()
    unique_varieties = user_records.filter(model_type='variety').values('prediction').distinct().count()
    
    # Trends data (last 30 days)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    trends_data = {}
    
    for i in range(30):
        date = (thirty_days_ago + timedelta(days=i)).date()
        date_str = date.strftime('%m-%d')
        
        day_records = user_records.filter(timestamp__date=date)
        trends_data[date_str] = {
            'disease': day_records.filter(model_type='disease').count(),
            'variety': day_records.filter(model_type='variety').count(),
            'total': day_records.count()
        }
    
    # Prepare recent records data
    recent_records_data = []
    for record in recent_records:
        recent_records_data.append({
            'id': record.id,
            'prediction': record.prediction,
            'model_type': record.model_type,
            'confidence': round(record.confidence * 1, 1),
            'timestamp': record.timestamp.isoformat(),
            'formatted_timestamp': record.timestamp.strftime('%Y-%m-%d %H:%M'),
            'image_url': record.image_url or '/static/img/default-plant.png'
        })
    
    # Prepare context
    context = {
        # Basic counts
        'total_scan': total_scans,
        'total_disease_scan': disease_scans,
        'total_variety_scan': variety_scans,
        'total_today_scan': today_scans,
        'total_week_scan': week_scans,
        'total_month_scan': month_scans,
        
        # Weather data
        'weather_data': weather_data,
        'scanning_tip': scanning_tip,
        
        # Analytics data
        'disease_analytics': disease_analytics,
        'variety_analytics': variety_analytics,
        
        # Most scanned items
        'most_scanned': {
            'disease': most_scanned_disease['prediction'] if most_scanned_disease else 'None',
            'disease_count': most_scanned_disease['count'] if most_scanned_disease else 0,
            'variety': most_scanned_variety['prediction'] if most_scanned_variety else 'None',
            'variety_count': most_scanned_variety['count'] if most_scanned_variety else 0
        },
        
        # Confidence statistics
        'confidence_stats': {
            'disease_avg': round(disease_avg_confidence * 1, 1) if disease_avg_confidence else 0,
            'variety_avg': round(variety_avg_confidence * 1, 1) if variety_avg_confidence else 0,
            'high_confidence_count': high_confidence_count,
            'low_confidence_count': low_confidence_count
        },
        
        # Diversity statistics
        'diversity_stats': {
            'unique_diseases': unique_diseases,
            'unique_varieties': unique_varieties
        },
        
        # Trends and records
        'trends_data': trends_data,
        'recent_records': recent_records_data,
        'user_name': user.get_full_name() or user.username,
    }
    
    return render(request, 'escan/Farmer/farmer_dashboard.html', context)

@login_required
def farmer_dashboard_data(request):
    """API endpoint to fetch dashboard data for logged-in user (for AJAX updates)"""
    try:
        user = request.user
        
        # Get all records for the current user
        user_records = DetectionRecord.objects.filter(user=user)
        
        # Calculate KPIs
        total_scans = user_records.count()
        disease_scans = user_records.filter(model_type='disease').count()
        variety_scans = user_records.filter(model_type='variety').count()
        
        # Today's scans
        today = timezone.now().date()
        today_scans = user_records.filter(timestamp__date=today).count()
        
        # This week's scans
        week_start = today - timedelta(days=today.weekday())
        week_scans = user_records.filter(timestamp__date__gte=week_start).count()
        
        # This month's scans
        month_start = today.replace(day=1)
        month_scans = user_records.filter(timestamp__date__gte=month_start).count()
        
        # Disease analytics - group by prediction with counts
        disease_analytics = dict(
            user_records.filter(model_type='disease')
            .values('prediction')
            .annotate(count=Count('prediction'))
            .values_list('prediction', 'count')
        )
        
        # Variety analytics - group by prediction with counts
        variety_analytics = dict(
            user_records.filter(model_type='variety')
            .values('prediction')
            .annotate(count=Count('prediction'))
            .values_list('prediction', 'count')
        )
        
        # Most scanned items
        most_scanned_disease = (
            user_records.filter(model_type='disease')
            .values('prediction')
            .annotate(count=Count('prediction'))
            .order_by('-count')
            .first()
        )
        
        most_scanned_variety = (
            user_records.filter(model_type='variety')
            .values('prediction')
            .annotate(count=Count('prediction'))
            .order_by('-count')
            .first()
        )
        
        # Average confidence scores
        disease_avg_confidence = user_records.filter(model_type='disease').aggregate(
            avg_confidence=Avg('confidence')
        )['avg_confidence'] or 0
        
        variety_avg_confidence = user_records.filter(model_type='variety').aggregate(
            avg_confidence=Avg('confidence')
        )['avg_confidence'] or 0
        
        # Trends data (last 30 days)
        thirty_days_ago = timezone.now() - timedelta(days=30)
        trends_data = {}
        
        for i in range(30):
            date = (thirty_days_ago + timedelta(days=i)).date()
            date_str = date.strftime('%m-%d')
            
            day_records = user_records.filter(timestamp__date=date)
            trends_data[date_str] = {
                'disease': day_records.filter(model_type='disease').count(),
                'variety': day_records.filter(model_type='variety').count(),
                'total': day_records.count()
            }
        
        # Recent records (last 20 for better display)
        recent_records = []
        for record in user_records.order_by('-timestamp')[:20]:
            recent_records.append({
                'id': record.id,
                'prediction': record.prediction,
                'model_type': record.model_type,
                'confidence': round(record.confidence * 1, 1),
                'timestamp': record.timestamp.isoformat(),
                'formatted_timestamp': record.timestamp.strftime('%Y-%m-%d %H:%M'),
                'image_url': record.image_url or '/static/img/default-plant.png'
            })
        
        # High confidence scans (>80%)
        high_confidence_count = user_records.filter(confidence__gte=0.8).count()
        
        # Low confidence scans (<60%)
        low_confidence_count = user_records.filter(confidence__lt=0.6).count()
        
        # Unique predictions count
        unique_diseases = user_records.filter(model_type='disease').values('prediction').distinct().count()
        unique_varieties = user_records.filter(model_type='variety').values('prediction').distinct().count()
        
        return JsonResponse({
            'success': True,
            'total_scans': total_scans,
            'disease_scans': disease_scans,
            'variety_scans': variety_scans,
            'today_scans': today_scans,
            'week_scans': week_scans,
            'month_scans': month_scans,
            'disease_analytics': disease_analytics,
            'variety_analytics': variety_analytics,
            'most_scanned': {
                'disease': most_scanned_disease['prediction'] if most_scanned_disease else 'None',
                'disease_count': most_scanned_disease['count'] if most_scanned_disease else 0,
                'variety': most_scanned_variety['prediction'] if most_scanned_variety else 'None',
                'variety_count': most_scanned_variety['count'] if most_scanned_variety else 0
            },
            'confidence_stats': {
                'disease_avg': round(disease_avg_confidence * 10, 1) if disease_avg_confidence else 0,
                'variety_avg': round(variety_avg_confidence * 10, 1) if variety_avg_confidence else 0,
                'high_confidence_count': high_confidence_count,
                'low_confidence_count': low_confidence_count
            },
            'diversity_stats': {
                'unique_diseases': unique_diseases,
                'unique_varieties': unique_varieties
            },
            'trends_data': trends_data,
            'recent_records': recent_records,
            'user_name': user.get_full_name() or user.username
        })
        
    except Exception as e:
        logger.error(f"Error fetching dashboard data: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to fetch dashboard data'
        }, status=500)

def get_weather_context(request):
    """Helper function to get weather data for template context"""
    lat = request.GET.get('lat')
    lon = request.GET.get('lon')
    api_key = getattr(settings, 'OPENWEATHER_API_KEY', '')
    
    try:
        if lat and lon and lat != 'null' and lon != 'null':
            url = f"https://api.openweathermap.org/data/2.5/weather?lat={lat}&lon={lon}&appid={api_key}&units=metric"
        else:
            try:
                ip_response = requests.get('https://ipapi.co/json/', timeout=5)
                if ip_response.status_code == 200:
                    ip_data = ip_response.json()
                    detected_lat = ip_data.get('latitude')
                    detected_lon = ip_data.get('longitude')
                    if detected_lat and detected_lon:
                        url = f"http://api.openweathermap.org/data/2.5/weather?lat={detected_lat}&lon={detected_lon}&appid={api_key}&units=metric"
                    else:
                        raise Exception("No coordinates from IP service")
                else:
                    raise Exception("IP service unavailable")
            except:
                url = f"http://api.openweathermap.org/data/2.5/weather?q=Oriental Mindoro,PH&appid={api_key}&units=metric"
        
        weather_response = requests.get(url, timeout=10)
        
        if weather_response.status_code == 200:
            weather_data = weather_response.json()
            condition = weather_data['weather'][0]['main'].lower()
            
            return {
                'location': f"{weather_data['name']}, {weather_data['sys']['country']}",
                'temperature': round(weather_data['main']['temp']),
                'condition': weather_data['weather'][0]['main'],
                'description': weather_data['weather'][0]['description'].title(),
                'humidity': weather_data['main']['humidity'],
                'feels_like': round(weather_data['main']['feels_like']),
                'wind_speed': weather_data['wind'].get('speed', 0),
                'weather_icon': get_weather_icon(condition),
                'coordinates': {
                    'lat': weather_data['coord']['lat'],
                    'lon': weather_data['coord']['lon']
                }
            }
    except Exception as e:
        logger.error(f"Weather API error: {str(e)}")
    
    return {
        'location': 'Location Unknown',
        'temperature': '--',
        'condition': 'Unknown',
        'description': 'Weather data unavailable',
        'humidity': 0,
        'feels_like': '--',
        'wind_speed': 0,
        'weather_icon': 'fas fa-question-circle',
    }

def get_scanning_tip(condition, temperature, humidity):
    """Generate detailed scanning tip based on weather conditions"""
    tips = {
        'clear': f'Perfect conditions for outdoor scanning! Clear skies provide excellent natural lighting.',
        'clouds': f'Good diffused lighting for accurate scans. Cloudy conditions reduce harsh shadows.',
        'rain': f'Indoor scanning recommended. High humidity ({humidity}%) may affect equipment.',
        'drizzle': f'Light rain detected. Consider indoor scanning for equipment protection.',
        'thunderstorm': f'Severe weather - stay indoors and scan stored samples safely.',
        'snow': f'Cold weather ({temperature}°C) - protect equipment and consider indoor scanning.',
        'mist': f'Reduced visibility. Use additional artificial lighting for clear scans.',
        'fog': f'Poor visibility conditions. Wait for clearer weather or use controlled lighting.',
        'haze': f'Hazy conditions may affect image quality. Ensure good lighting setup.'
    }
    
    base_tip = tips.get(condition, 'Moderate scanning conditions')
    
    # Add temperature-specific advice
    if temperature > 35:
        base_tip += f' High temperature ({temperature}°C) - protect equipment from overheating.'
    elif temperature < 10:
        base_tip += f' Cold temperature ({temperature}°C) - allow equipment to acclimate.'
    
    # Add humidity-specific advice
    if humidity > 80:
        base_tip += f' High humidity ({humidity}%) - watch for condensation on lens.'
    elif humidity < 30:
        base_tip += f' Low humidity ({humidity}%) - good conditions for equipment.'
    
    return base_tip

def get_weather_icon(condition):
    """Get appropriate Font Awesome icon for weather condition"""
    icons = {
        'clear': 'fas fa-sun',
        'clouds': 'fas fa-cloud',
        'rain': 'fas fa-cloud-rain',
        'drizzle': 'fas fa-cloud-drizzle',
        'thunderstorm': 'fas fa-bolt',
        'snow': 'fas fa-snowflake',
        'mist': 'fas fa-smog',
        'fog': 'fas fa-smog',
        'haze': 'fas fa-smog'
    }
    return icons.get(condition, 'fas fa-cloud')

@login_required
def export_dashboard_data(request):
    """Export user's scan data as JSON"""
    try:
        user = request.user
        user_records = DetectionRecord.objects.filter(user=user)
        
        export_data = []
        for record in user_records:
            export_data.append({
                'prediction': record.prediction,
                'model_type': record.model_type,
                'confidence': record.confidence,
                'timestamp': record.timestamp.isoformat(),
                'image_url': record.image_url
            })
        
        response = JsonResponse({
            'success': True,
            'user': user.username,
            'export_date': timezone.now().isoformat(),
            'total_records': len(export_data),
            'records': export_data
        })
        
        # Set filename for download
        response['Content-Disposition'] = f'attachment; filename="scan_data_{user.username}_{timezone.now().strftime("%Y%m%d")}.json"'
        
        return response
        
    except Exception as e:
        logger.error(f"Export error: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to export data'
        }, status=500)
    
def scan(request):
    fvarieties = BananaVariety.objects.filter(is_deleted=False) 
    knowledges = KnowledgeBase.objects.filter(is_deleted=False) 
    return render(request, 'escan/Farmer/Scan/scan.html', {'knowledges':  knowledges, 'fvarieties': fvarieties })
  
# Farmer Side
def f_setting(request):
    return render(request, "escan/Farmer/Settings/f_setting.html")



@login_required
def a_market_place(request):
    cart = Cart.objects.filter(customer=request.user, completed=False).first()
    products = Product.objects.filter(is_deleted=False) 
    return render(request, 'escan/Admin/E-commerce/a_market_place.html', {'products': products, 'cart': cart, 'cart_item_count': cart.get_item_total if cart else 0,})
  