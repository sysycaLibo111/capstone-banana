# signals.py
from django.db.models.signals import pre_save
from django.dispatch import receiver
from .models import Store, ShippingAddress
import requests

# Signal to update latitude, longitude, and postal code before saving the store
@receiver(pre_save, sender=Store)
def update_store_location(sender, instance, **kwargs):
    if instance.address and instance.city and instance.province:
        full_address = f"{instance.address}, {instance.city}, {instance.province}, Philippines"
        
        # Check if latitude, longitude, or postal code need to be updated
        if not instance.latitude or not instance.longitude:
            try:
                # Request to Nominatim API for geocoding
                url = "https://nominatim.openstreetmap.org/search"
                params = {"q": full_address, "format": "json"}
                res = requests.get(url, params=params, headers={"User-Agent": "escan"}).json()

                if res:
                    instance.latitude = float(res[0]["lat"])
                    instance.longitude = float(res[0]["lon"])
                    instance.postal_code = res[0].get("address", {}).get("postcode", "")
            except Exception as e:
                print(f"Error updating location for store {instance.name}: {e}")

# Signal to update latitude, longitude, and postal code before saving shipping address
@receiver(pre_save, sender=ShippingAddress)
def update_shipping_address_location(sender, instance, **kwargs):
    if instance.address and instance.city and instance.province:
        full_address = f"{instance.address}, {instance.city}, {instance.province}, Philippines"
        
        # Check if latitude, longitude, or postal code need to be updated
        if not instance.latitude or not instance.longitude:
            try:
                # Request to Nominatim API for geocoding
                url = "https://nominatim.openstreetmap.org/search"
                params = {"q": full_address, "format": "json"}
                res = requests.get(url, params=params, headers={"User-Agent": "escan"}).json()

                if res:
                    instance.latitude = float(res[0]["lat"])
                    instance.longitude = float(res[0]["lon"])
                    instance.postal_code = res[0].get("address", {}).get("postcode", "")
            except Exception as e:
                print(f"Error updating location for shipping address {instance.address}: {e}")
