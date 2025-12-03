from django.contrib import admin
from django import forms
from .models import CustomUser, Product, Customer, Category,Order, ShippingFee

admin.site.register(CustomUser)
admin.site.register(Category)
admin.site.register(Customer)
admin.site.register(Order)
admin.site.register(Product)
admin.register(ShippingFee)
class ShippingFeeAdmin(admin.ModelAdmin):
    list_display = ('store', 'zip_code', 'fee', 'is_active')
    list_filter = ('store', 'is_active')
    search_fields = ('zip_code', 'store__name')