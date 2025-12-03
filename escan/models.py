from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models
from django.contrib.auth.models import User
# from django.contrib.auth.models import 
from django.db.models import Count
from django.conf import settings
from django.utils import timezone
from decimal import Decimal
import uuid
import os

import math
import requests
from geopy.distance import geodesic
from geopy.geocoders import Nominatim

class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('Admin', 'Admin'),
        ('Farmer', 'Farmer'),
        ('Market-entity', 'Market-entity'),
    ]

    id = models.AutoField(primary_key=True)  # Unique ID for each user
    first_name = models.CharField(max_length=50)  # First name field
    last_name = models.CharField(max_length=50)  # Last name field
    username = models.CharField(max_length=50, unique=True)  # Unique username
    email = models.EmailField(unique=True)  # Unique email
    image_url = models.ImageField(max_length=500, blank=True, null=True)  # Store image URL from Supabase
    password = models.CharField(max_length=255)  # Hashed password storage
    is_deleted = models.BooleanField(default=False)  # Soft delete field
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='Farmer')

    def soft_delete(self):
        self.is_deleted = True
        self.save()

    def restore(self):
        self.is_deleted = False
        self.save()

    class meta:
        db_table = 'user_account'
        

class PasswordReset(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    reset_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_when = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Password reset for {self.user.username} at {self.created_when}"
    
    class Meta:
        app_label = 'escan'


class StoreValidation(models.Model):
    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'

    STATUS_CHOICES = [
        (PENDING, 'Pending'),
        (APPROVED, 'Approved'),
        (REJECTED, 'Rejected'),
    ]

    # Changed from OneToOneField to ForeignKey to allow multiple applications
    store_owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='store_validations'  # Changed to plural
    ) 
    first_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100, null=True, blank=True)
    phone_number = models.CharField(max_length=20)
    address = models.CharField(max_length=255, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    province = models.CharField(max_length=100, null=True, blank=True)
    id_picture = models.ImageField(max_length=500, blank=True, null=True)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_validations'
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.get_status_display()})"

    class Meta:
        db_table = 'banaescan_store_validation'
        verbose_name = 'Store Validation'
        verbose_name_plural = 'Store Validations'
        ordering = ['-created_at']  # Most recent first
        
    # Helper method to get user's latest validation
    @classmethod
    def get_latest_for_user(cls, user):
        """Get the most recent validation for a user"""
        return cls.objects.filter(store_owner=user).order_by('-created_at').first()
    
    # Helper method to check if user has approved validation
    @classmethod
    def user_is_approved(cls, user):
        """Check if user has an approved validation"""
        return cls.objects.filter(store_owner=user, status='approved').exists()

class Store(models.Model):
    owner = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='store'
    )
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    logo = models.URLField(max_length=500, blank=True, null=True)
    address = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    province = models.CharField(max_length=100, blank=True, null=True)
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        old_instance = None
        if self.pk:
            try:
                old_instance = Store.objects.get(pk=self.pk)
            except Store.DoesNotExist:
                pass

        # Check if address fields changed
        address_changed = (
            not old_instance or
            self.address != old_instance.address or
            self.city != old_instance.city or
            self.province != old_instance.province
        )

        # Update coordinates only if:
        # - address changed, OR
        # - lat/lon are missing
        if (address_changed or self.latitude in [None, 0.0] or self.longitude in [None, 0.0]) \
                and self.address and self.city and self.province:

            full_address = f"{self.address}, {self.city}, {self.province}, Philippines"
            try:
                url = "https://nominatim.openstreetmap.org/search"
                params = {"q": full_address, "format": "json", "limit": 1, "addressdetails": 1}
                res = requests.get(url, params=params, headers={"User-Agent": "escan"}).json()
                print(f"Querying: {full_address}")
                print(f"Nominatim Response: {res}")
                if res:
                    self.latitude = float(res[0]["lat"])
                    self.longitude = float(res[0]["lon"])
            except Exception as e:
                print("Geocoding failed:", e)

        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

    class Meta:
        db_table = 'banaescan_store'
        verbose_name = 'Store'
        verbose_name_plural = 'Stores'



class Category(models.Model):
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name='categories')
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL,on_delete=models.SET_NULL,null=True,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Categories"
        db_table = 'banaescan_category'

# Product model
class Product(models.Model):
    store = models.ForeignKey(Store, on_delete=models.PROTECT, related_name='products')
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    price = models.DecimalField(default=0, max_digits=10, decimal_places=2)
    stock = models.PositiveIntegerField(default=0)
    image_url = models.ImageField(max_length=500, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def clean(self):
    # Ensure price is positive
        if self.price and self.price <= 0:
            raise ValidationError({'price': 'Price must be greater than 0'})

        # Ensure stock is not negative
        if self.stock < 0:
            raise ValidationError({'stock': 'Stock cannot be negative'})
    
    def soft_delete(self):
        self.is_deleted = True
        self.save()

    def restore(self):
        self.is_deleted = False
        self.save()

    def save(self, *args, **kwargs):
        # Check if the price has changed
        if self.pk:
            original = Product.objects.get(pk=self.pk)
            price_changed = original.price != self.price
        else:
            price_changed = False

        super().save(*args, **kwargs)

        if price_changed:
            from escan.models import Cartitems, Cart  # Avoid circular import if needed

            # Get all non-completed cart items for this product
            cart_items = Cartitems.objects.filter(
                product=self,
                cart__completed=False
            )

            for item in cart_items:
                item.price_at_addition = self.price
                item.total_price = Decimal(item.quantity) * self.price
                item.save(update_fields=["price_at_addition", "total_price"])

    def __str__(self):
        return f"{self.name} ({self.store.name})"

    class Meta:
        db_table = 'banaescan_product'
        verbose_name = 'Product'
        verbose_name_plural = 'Products'
        unique_together = ['store', 'name']  
        

class Customer(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,related_name='customer_profile')
    stores_purchased_from = models.ManyToManyField(Store, through='CustomerPurchase', related_name='customers')
    class Meta:
        db_table = 'banaescan_customer'
    def __str__(self):
        return self.user.first_name + " " + self.user.last_name

class CustomerPurchase(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name='purchases')
    store = models.ForeignKey(Store, on_delete=models.CASCADE, related_name='store_purchases')
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='product_purchases')
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    quantity = models.PositiveIntegerField(default=1)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    purchase_date = models.DateTimeField(auto_now_add=True)
    is_completed = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'banaescan_customer_purchase'
        ordering = ['-purchase_date']
        verbose_name = 'Customer Purchase'
        verbose_name_plural = 'Customer Purchases'
        
    def __str__(self):
        return f"{self.customer.user.username} purchased {self.product.name} from {self.store.name}"

    

class Cart(models.Model):
    customer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='carts')
    completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def get_subtotal(self):
        # return sum(item.get_subtotal for item in self.cartitems.all())
        from decimal import Decimal
        subtotal = Decimal('0.00')
        for item in self.cartitems.all():
            subtotal += Decimal(str(item.get_subtotal))
        return subtotal
    
    @property
    def get_shipping_fee(self):
        return sum(item.shipping_fee for item in self.cartitems.all())

    @property
    def get_cart_total(self):
        # return sum(item.get_total for item in self.cartitems.all())
        from decimal import Decimal
        shipping_fee = Decimal('0.00')
        for item in self.cartitems.all():
            shipping_fee += Decimal(str(item.shipping_fee))
        return shipping_fee
    
    @property
    def get_item_total(self):
        return sum(item.quantity for item in self.cartitems.all())

    def __str__(self):
        return f"Cart {self.id} for {self.customer.username}"

    class Meta:
        db_table = 'banaescan_cart'

class Cartitems(models.Model):
    cart = models.ForeignKey('Cart', on_delete=models.CASCADE, related_name='cartitems')
    product = models.ForeignKey('Product', on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)

    # Save product price at the time item is added
    product_price_at_addition = models.DecimalField(max_digits=10, decimal_places=2)
    shipping_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    total_price = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    def save(self, *args, **kwargs):
        # Always get the current price of the product
        # self.product_price_at_addition = self.product.price
        # self.total_price = (self.product_price_at_addition * self.quantity) + self.shipping_fee
        # super().save(*args, **kwargs)
        from decimal import Decimal
        self.product_price_at_addition = self.product.price
        # Convert to Decimal for proper calculation
        self.total_price = (Decimal(str(self.product_price_at_addition)) * self.quantity) + Decimal(str(self.shipping_fee))
        super().save(*args, **kwargs)

    @property
    def get_subtotal(self):
        from decimal import Decimal
        return self.product_price_at_addition * self.quantity

    @property
    def get_total(self):
        # return self.get_subtotal + self.shipping_fee
        from decimal import Decimal
        # return self.get_subtotal + Decimal(str(self.shipping_fee))
        return Decimal(str(self.product_price_at_addition)) * self.quantity

    def __str__(self):
        return f"{self.product.name} (x{self.quantity})"

    class Meta:
        db_table = 'banaescan_cartitem'


class ShippingFee(models.Model):
    store = models.ForeignKey('Store', on_delete=models.CASCADE, related_name='shipping_fees')
    base_fee = models.DecimalField(max_digits=10, decimal_places=2, default=10.00)
    per_km_rate = models.DecimalField(max_digits=10, decimal_places=2, default=5.00)
    max_distance_km = models.PositiveIntegerField(default=100)  # max range
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = 'Shipping Fee'
        verbose_name_plural = 'Shipping Fees'

    def __str__(self):
        return f"{self.store.name} - Base ₱{self.base_fee} + ₱{self.per_km_rate}/km"

class ShippingAddress(models.Model):
    customer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shipping_addresses')
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    province = models.CharField(max_length=100)
    zipcode = models.CharField(max_length=10, null=True)
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    is_default = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        old_instance = None
        if self.pk:
            try:
                old_instance = ShippingAddress.objects.get(pk=self.pk)
                address_changed = (
                    self.address != old_instance.address or
                    self.city != old_instance.city or
                    self.province != old_instance.province or
                    self.zipcode != old_instance.zipcode
                )
            except ShippingAddress.DoesNotExist:
                address_changed = True
        else:
            address_changed = True
        
        # Only geocode if address changed or coordinates are missing
        if (address_changed or not self.latitude or not self.longitude) and self.address and self.city:
            try:
                # Build address string
                parts = [self.address, self.city, self.province, "Philippines"]
                if self.zipcode:
                    parts.append(self.zipcode)
                full_address = ", ".join([p for p in parts if p])
                
                # Geocode using Nominatim
                url = "https://nominatim.openstreetmap.org/search"
                params = {"q": full_address, "format": "json", "limit": 1}
                headers = {"User-Agent": "escan-app/1.0"}
                
                res = requests.get(url, params=params, headers=headers, timeout=10)
                res.raise_for_status()
                data = res.json()
                
                if data:
                    self.latitude = float(data[0]["lat"])
                    self.longitude = float(data[0]["lon"])
                    print(f"Geocoding successful: {self.latitude}, {self.longitude}")
                else:
                    # Fallback to city-level geocoding
                    simple_address = f"{self.city}, {self.province}, Philippines"
                    params = {"q": simple_address, "format": "json", "limit": 1}
                    res = requests.get(url, params=params, headers=headers, timeout=10)
                    data = res.json()
                    
                    if data:
                        self.latitude = float(data[0]["lat"])
                        self.longitude = float(data[0]["lon"])
                        print(f"Fallback geocoding successful: {self.latitude}, {self.longitude}")
                    else:
                        print("Geocoding failed for both full and simple address")
            except Exception as e:
                print(f"Geocoding error: {e}")
                # Don't fail the save if geocoding fails
        
        # Handle default address logic
        if self.is_default:
            ShippingAddress.objects.filter(
                customer=self.customer,
                is_default=True
            ).exclude(pk=self.pk).update(is_default=False)
        
        # Call the parent save method
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.address}, {self.city}, {self.province}"
    


class Order(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('On Process', 'On Process'),
        ('Delivered', 'Delivered'),
        ('Cancelled', 'Cancelled'),
        ('Completed', 'Completed'),
    ]

    PAYMENT_METHOD_CHOICES = [
        ('COD', 'Cash on Delivery'),
        ('GCASH', 'GCash'),
        # ('PAYPAL', 'PayPal'),
        # ('CARD', 'Credit/Debit Card'),
    ]

    customer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='orders')
    store = models.ForeignKey('Store', on_delete=models.CASCADE, related_name='store_orders')
    product = models.ForeignKey('Product', on_delete=models.CASCADE)
    shipping_address = models.ForeignKey('ShippingAddress', on_delete=models.CASCADE)
    subtotal = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    shipping_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    quantity_surcharge = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    quantity = models.PositiveIntegerField()
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHOD_CHOICES, default='COD')
    paid = models.BooleanField(default=False)
    order_date = models.DateTimeField(auto_now_add=True)

    # ⬇️ New estimated schedule fields
    process_start = models.DateTimeField(null=True, blank=True)
    process_end = models.DateTimeField(null=True, blank=True)
    delivery_start = models.DateTimeField(null=True, blank=True)
    delivery_end = models.DateTimeField(null=True, blank=True)
    completion_date = models.DateTimeField(null=True, blank=True)
 
    def calculate_shipping_fee(self):
            try:
                # ✅ Prefer lat/lon from ShippingAddress if available
                if self.shipping_address.latitude and self.shipping_address.longitude:
                    buyer_coords = (self.shipping_address.latitude, self.shipping_address.longitude)
                else:
                    # 🔁 Fallback: use PostalCodeLocation by ZIP code
                    try:
                        buyer_loc = PostalCodeLocation.objects.get(postal_code=self.shipping_address.zipcode)
                        buyer_coords = (buyer_loc.latitude, buyer_loc.longitude)
                    except PostalCodeLocation.DoesNotExist:
                        # 🔁 Fallback to Nominatim
                        geolocator = Nominatim(user_agent="escan")
                        location = geolocator.geocode(
                            f"{self.shipping_address.address}, {self.shipping_address.city}, "
                            f"{self.shipping_address.province}, {self.shipping_address.zipcode}"
                        )
                        if not location:
                            return Decimal("0.00")
                        buyer_coords = (location.latitude, location.longitude)
            except Exception as e:
                print(f"Error getting buyer coordinates: {e}")
                return Decimal("0.00")

            if not (self.store.latitude and self.store.longitude):
                print("Store coordinates missing")
                return Decimal("0.00")

            store_coords = (self.store.latitude, self.store.longitude)
            print("Buyer coordinates:", buyer_coords)
            print("Store coordinates:", store_coords)

            distance_km = geodesic(store_coords, buyer_coords).km

            rule = getattr(self.store, "shipping_rule", None)
            base_fee = rule.base_fee if rule else Decimal("5.00")
            per_km_rate = rule.per_km_rate if rule else Decimal("2.00")

            return (base_fee + (Decimal(distance_km) * per_km_rate)).quantize(Decimal("0.01"))


    def save(self, *args, **kwargs):
        self.subtotal = self.product.price * self.quantity
        self.quantity_surcharge = max(0, (self.quantity - 10)) * Decimal("10.00")
        self.shipping_fee = self.calculate_shipping_fee()
        self.total_amount = self.subtotal + self.shipping_fee + self.quantity_surcharge
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Order #{self.id} by {self.customer.username}"


    class Meta:
        db_table = 'banaescan_order'
        ordering = ['-order_date']
        verbose_name = 'Order'
        verbose_name_plural = 'Orders'


class PostalCodeLocation(models.Model):
    postal_code = models.CharField(max_length=10, unique=True)
    city = models.CharField(max_length=100)
    region = models.CharField(max_length=100)
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)

    def save(self, *args, **kwargs):
        if self.latitude is None or self.longitude is None:
            query = f"{self.postal_code}, {self.city}, {self.region}"
            try:
                url = "https://nominatim.openstreetmap.org/search"
                params = {"q": query, "format": "json"}
                res = requests.get(url, params=params, headers={"User-Agent": "escan"}).json()
                if res:
                    self.latitude = float(res[0]["lat"])
                    self.longitude = float(res[0]["lon"])
            except Exception:
                pass
        super().save(*args, **kwargs)


class ShippingRule(models.Model):
    store = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="shipping_rules"
    )
    base_fee = models.DecimalField(max_digits=10, decimal_places=2, default=5.0)
    rate_per_km = models.DecimalField(max_digits=10, decimal_places=2, default=5.0)

    def __str__(self):
        return f"ShippingRule for {self.store}"


# Payment model for transaction logs
class Payment(models.Model):
    order = models.OneToOneField(Order, on_delete=models.CASCADE, related_name='payment')
    method = models.CharField(max_length=20, choices=Order.PAYMENT_METHOD_CHOICES)
    transaction_id = models.CharField(max_length=100, blank=True, null=True)
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2)
    paid_on = models.DateTimeField(auto_now_add=True)
    confirmed = models.BooleanField(default=False)

    def __str__(self):
        return f"Payment for Order #{self.order.id}"

    class Meta:
        db_table = 'banaescan_payment'

class DeliverySchedule(models.Model):
    order = models.OneToOneField(Order, on_delete=models.CASCADE, related_name='delivery_schedule')
    scheduled_date = models.DateField()
    delivered_date = models.DateField(null=True, blank=True)
    notes = models.TextField(blank=True)
    is_delivered = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Delivery for Order #{self.order.id}"

    class Meta:
        db_table = 'banaescan_deliveryschedule'
        verbose_name = 'Delivery Schedule'
        verbose_name_plural = 'Delivery Schedules'

# Review model
class Review(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='reviews')
    customer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='reviews')
    rating = models.IntegerField(choices=[(i, f"{i} Star") for i in range(1, 6)])
    comment = models.TextField(blank=True, null=True)
    review_date = models.DateTimeField(auto_now_add=True)
    is_approved = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.rating} star review for {self.product.name} by {self.customer.username}"

    class Meta:
        db_table = 'banaescan_review'
        ordering = ['-review_date']
        unique_together = ['product', 'customer']

#MESSAGES/INBOX MODEL
class Thread(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='threads')
    admin = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='admin_threads')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Thread between {self.user.username} and {self.admin.username}"

class Message(models.Model):
    thread = models.ForeignKey('Thread', related_name='messages', on_delete=models.CASCADE)
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='received_messages', null=True)
    content = models.TextField()
    # subject = models.CharField(max_length=255, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"Message from {self.sender.username} at {self.timestamp}"




class KnowledgeBase(models.Model):
    title = models.CharField(max_length=255)
    img = models.ImageField(max_length=500, blank=True, null=True)
    definition = models.TextField()
    control_prevention = models.TextField()
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'escan_knowledge_base'
        verbose_name = 'Knowledge Base Entry'
        verbose_name_plural = 'Knowledge Base Entries'

    def soft_delete(self):
        """Mark record as deleted instead of removing it from DB"""
        if not self.is_deleted:
            self.is_deleted = True
            self.deleted_at = timezone.now()
            self.save()

            # Save deleted record to file
            file_path = os.path.join("deleted_records.txt")
            with open(file_path, "a", encoding="utf-8") as f:
                f.write(
                    f"Deleted at {self.deleted_at}: {self.title}\n"
                    f"Definition: {self.definition}\n"
                    f"Control/Prevention: {self.control_prevention}\n\n"
                )

    def restore(self):
        """Restore soft-deleted record"""
        if self.is_deleted:
            self.is_deleted = False
            self.deleted_at = None
            self.save()

    def __str__(self):
        return self.title

class DetectionRecord(models.Model):
    MODEL_CHOICES = [
        ('disease', 'Disease'),
        ('variety', 'Variety'),
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    prediction = models.CharField(max_length=255)
    confidence = models.FloatField()
    timestamp = models.DateTimeField(auto_now_add=True)
    image_url = models.URLField(max_length=500)
    model_type = models.CharField(max_length=50, choices=MODEL_CHOICES, default=None,)

class BananaVariety(models.Model):
    title = models.CharField(max_length=255)
    img = models.ImageField(max_length=500, blank=True, null=True)
    description = models.TextField(help_text="Detailed description of the variety")
    classification = models.CharField(max_length=255, blank=True, null=True, help_text="Type or classification of the banana")
    origin = models.CharField(max_length=255, blank=True, null=True, help_text="Geographical origin")
    harvest_period = models.CharField(max_length=255, blank=True, null=True, help_text="Approximate harvest period")
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'escan_banana_varieties'
        verbose_name = 'Banana Variety'
        verbose_name_plural = 'Banana Varieties'

    def soft_delete(self):
        """Mark record as deleted instead of removing it from DB"""
        if not self.is_deleted:
            self.is_deleted = True
            self.deleted_at = timezone.now()
            self.save()

            # Save deleted record to file
            file_path = os.path.join("deleted_varieties.txt")
            with open(file_path, "a", encoding="utf-8") as f:
                f.write(
                    f"Deleted at {self.deleted_at}: {self.title}\n"
                    f"Description: {self.description}\n"
                    f"Classification: {self.classification}\n"
                    f"Origin: {self.origin}\n"
                    f"Harvest Period: {self.harvest_period}\n\n"
                )

    def restore(self):
        """Restore soft-deleted record"""
        if self.is_deleted:
            self.is_deleted = False
            self.deleted_at = None
            self.save()

    def __str__(self):
        return self.title