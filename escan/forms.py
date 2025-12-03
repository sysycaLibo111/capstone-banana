from django import forms
from jsonschema import ValidationError
from .models import  Store, Category, Product, CustomUser, ShippingAddress, StoreValidation
from .supabase_helper import upload_image_to_supabase
import logging
from django.core.exceptions import ValidationError
from supabase import create_client
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserChangeForm
from .models import Message
from .models import ShippingFee

import uuid  
import os

logger = logging.getLogger(__name__)

# class CategoryForm(forms.ModelForm):
#     class Meta:
#         model = Category
#         fields = ['name', 'description']
class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ['name', 'description']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['name'].widget.attrs.update({'class': 'form-control'})
        self.fields['description'].widget.attrs.update({'class': 'form-control'})
        
        # Add required attribute and labels
        self.fields['name'].required = True
        self.fields['name'].label = "Category Name"
        self.fields['description'].label = "Description"
        self.fields['description'].required = False
    
    def clean_name(self):
        name = self.cleaned_data.get('name')
        if self.instance and self.instance.pk:
            if Category.objects.filter(name=name).exclude(pk=self.instance.pk).exists():
                raise forms.ValidationError("A category with this name already exists.")
        else:
            if Category.objects.filter(name=name).exists():
                raise forms.ValidationError("A category with this name already exists.")
        return name

class UserProfileForm(forms.ModelForm):
    """
    Form for updating user profile information
    """
    password = forms.CharField(
        widget=forms.PasswordInput(), 
        required=False,
        help_text="Leave blank if you don't want to change password"
    )
    
    class Meta:
        model = CustomUser    
        fields = ['first_name', 'last_name', 'username', 'email', 'password', 'image_url','role']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'username': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'role': forms.EmailInput(attrs={'class': 'form-control'}),
            'image_url': forms.FileInput(attrs={'class': 'form-control', 'accept': 'image/*'}),
        }

    def save(self, commit=True):
        user = super().save(commit=False)

        password = self.cleaned_data.get('password')
        if password:
            user.set_password(password)  # Hash the password only if it's provided

        if commit:
            user.save()

        # Handle image upload to Supabase
        image_file = self.cleaned_data.get('image_url')
        if image_file:
            print("🔍 Image File Found:", image_file.name)
            print(f"🔍 Image File Size Before Reading: {image_file.size} bytes")

            if image_file.size > 0:
                image_file.seek(0)
                file_data = image_file.read()
                print(f"🔍 File Size Before Upload: {len(file_data)} bytes")

                supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_ROLE_KEY)
                bucket_name = "profile-images"
                file_name = f"{user.id}_{image_file.name}"

                try:
                    # Delete old image if exists
                    try:
                        supabase.storage.from_(bucket_name).remove([f"{user.id}_*"])
                    except:
                        pass  # Ignore if no old image exists
                    
                    response = supabase.storage.from_(bucket_name).upload(file_name, file_data)

                    if hasattr(response, 'full_path') and response.full_path:
                        public_url = f"{settings.SUPABASE_URL}/storage/v1/object/public/{response.full_path}"
                        user.image_url = public_url
                        user.save()
                        print("✅ Image Uploaded Successfully:", public_url)
                    else:
                        print("❌ Error Uploading Image:", response)

                except Exception as e:
                    print(f"⚠️ Exception in upload: {e}")
            else:
                print("❌ File has 0 size, cannot upload image")

        return user


class ShippingAddressForm(forms.ModelForm):
    """
    Form for updating shipping address
    """
    class Meta:
        model = ShippingAddress
        fields = ['phone_number', 'address', 'city', 'province', 'zipcode', 'is_default']
        widgets = {
            'phone_number': forms.TextInput(attrs={'class': 'form-control'}),
            'address': forms.TextInput(attrs={'class': 'form-control'}),
            'city': forms.TextInput(attrs={'class': 'form-control'}),
            'province': forms.TextInput(attrs={'class': 'form-control'}),
            'zipcode': forms.TextInput(attrs={'class': 'form-control'}),
            'is_default': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

class EditProfileForm(UserChangeForm):
    """
    Alternative form using UserChangeForm (if needed)
    """
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'username', 'email', 'password', 'image_url']

    def save(self, commit=True):
        user = super().save(commit=False)
        
        # If password is changed, hash it
        if self.cleaned_data.get('password'):
            user.set_password(self.cleaned_data['password'])

        if commit:
            user.save()

        # Handle image upload to Supabase
        image_file = self.cleaned_data.get('image_url')
        if image_file:
            print("🔍 Image File Found:", image_file.name)
            print(f"🔍 Image File Size Before Reading: {image_file.size} bytes")

            if image_file.size > 0:
                image_file.seek(0)
                file_data = image_file.read()
                print(f"🔍 File Size Before Upload: {len(file_data)} bytes")

                supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_ROLE_KEY)
                bucket_name = "profile-images"
                file_name = f"{user.id}_{image_file.name}"

                try:
                    response = supabase.storage.from_(bucket_name).upload(file_name, file_data)

                    if hasattr(response, 'full_path') and response.full_path:
                        public_url = f"{settings.SUPABASE_URL}/storage/v1/object/public/{response.full_path}"
                        user.image_url = public_url
                        user.save()
                        print("✅ Image Uploaded Successfully:", public_url)
                    else:
                        print("❌ Error Uploading Image:", response)

                except Exception as e:
                    print(f"⚠️ Exception in upload: {e}")
            else:
                print("❌ File has 0 size, cannot upload image")

        return user
    


    
class ProductForm(forms.ModelForm):
    class Meta:
        model = Product
        fields = ['name', 'category', 'description', 'price', 'stock', 'image_url']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
            'category': forms.Select(attrs={'class': 'form-control'}),
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'price': forms.NumberInput(attrs={'class': 'form-control'}),
            'stock': forms.NumberInput(attrs={'class': 'form-control'}),
            'image_url': forms.FileInput(attrs={'class': 'form-control'}),
        }
    
    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)
        
        # Make fields required except image
        self.fields['category'].required = True
        self.fields['name'].required = True
        self.fields['price'].required = True
        self.fields['stock'].required = True
        self.fields['image_url'].required = False
        
        # Filter categories if needed
        self.fields['category'].queryset = Category.objects.all()
    
    def clean_price(self):
        price = self.cleaned_data.get('price')
        if price is not None and price <= 0:
            raise ValidationError("Price must be greater than 0")
        return price
    
    def clean_stock(self):
        stock = self.cleaned_data.get('stock')
        if stock is not None and stock < 0:
            raise ValidationError("Stock cannot be negative")
        return stock
    
    def clean_name(self):
        name = self.cleaned_data.get('name')
        
        # Safe check for request and user
        if not self.request or not hasattr(self.request, 'user') or not self.request.user.is_authenticated:
            raise ValidationError("User authentication required to validate product name.")
        
        # Check if user has a store
        if not hasattr(self.request.user, 'store'):
            raise ValidationError("User store not found.")
        
        store = self.request.user.store
        
        if self.instance.pk:  # Editing existing product
            if Product.objects.exclude(pk=self.instance.pk).filter(
                store=store, 
                name=name
            ).exists():
                raise ValidationError("A product with this name already exists in your store.")
        else:  # Creating new product
            if Product.objects.filter(
                store=store, 
                name=name
            ).exists():
                raise ValidationError("A product with this name already exists in your store.")
        return name
    
    def save(self, commit=True):
        product = super().save(commit=False)
        
        # Only process image if a new one was uploaded
        if 'image_url' in self.changed_data:
            image_file = self.cleaned_data.get('image_url')
            if image_file:
                # Delete old image if exists
                if self.instance and self.instance.image_url:
                    try:
                        # Extract filename from URL
                        old_file_path = self.instance.image_url.split('/')[-1]
                        delete_image_from_supabase(old_file_path)
                    except Exception as e:
                        print(f"Error deleting old image: {e}")
                
                # Upload new image
                try:
                    supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_ROLE_KEY)
                    bucket_name = "product-images"
                    file_name = f"{uuid.uuid4()}_{image_file.name}"
                    
                    # Read file data
                    image_file.seek(0)
                    file_data = image_file.read()
                    
                    # Upload to Supabase
                    response = supabase.storage.from_(bucket_name).upload(file_name, file_data)
                    
                    if response:
                        # Construct public URL
                        public_url = f"{settings.SUPABASE_URL}/storage/v1/object/public/{bucket_name}/{file_name}"
                        product.image_url = public_url
                except Exception as e:
                    print(f"Error uploading image: {e}")
                    raise forms.ValidationError("Error uploading product image")
        
        if commit:
            product.save()
            self.save_m2m()
        
        return product

class StoreValidationForm(forms.ModelForm):
    id_picture = forms.ImageField(
        required=True,
        widget=forms.FileInput(attrs={'class': 'form-control'})
    )

    class Meta:
        model = StoreValidation
        fields = [
            'first_name',
            'last_name',
            'phone_number',
            'address',
            'city',
            'province',
            'id_picture',
        ]
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'phone_number': forms.TextInput(attrs={'class': 'form-control'}),
            'address': forms.TextInput(attrs={'class': 'form-control'}),
            'city': forms.TextInput(attrs={'class': 'form-control'}),
            'province': forms.TextInput(attrs={'class': 'form-control'}),
        }

    def clean_phone_number(self):
        phone_number = self.cleaned_data.get('phone_number')
        # Allow phone numbers with +, -, spaces, and digits
        cleaned = ''.join(filter(str.isdigit, phone_number))
        if len(cleaned) < 10:
            raise ValidationError("Phone number must be at least 10 digits.")
        return phone_number

    def save(self, commit=True, user=None):
        instance = super().save(commit=False)
        
        # Set the user if provided
        if user:
            instance.store_owner = user
        
        id_picture = self.cleaned_data.get('id_picture')

        if id_picture:
            try:
                supabase = create_client(
                    settings.SUPABASE_URL,
                    settings.SUPABASE_ROLE_KEY
                )
                bucket_name = "id-pictures"

                # Generate unique filename
                file_ext = os.path.splitext(id_picture.name)[1]
                user_id = user.id if user else 'unknown'
                file_name = f"id_{user_id}_{uuid.uuid4()}{file_ext}"

                # Read file data
                id_picture.seek(0)
                file_data = id_picture.read()

                # Upload to Supabase
                result = supabase.storage.from_(bucket_name).upload(
                    path=file_name,
                    file=file_data,
                    file_options={"content-type": id_picture.content_type}
                )

                print("Upload Response:", result)

                # Get public URL
                public_url = (
                    f"{settings.SUPABASE_URL}/storage/v1/object/public/"
                    f"{bucket_name}/{file_name}"
                )
                print("✅ Public URL:", public_url)
                instance.id_picture = public_url

            except Exception as e:
                print(f"Error uploading ID picture: {str(e)}")
                raise ValidationError(f"Error uploading ID picture: {str(e)}")

        if commit:
            instance.save()
        return instance



from django import forms
from django.core.exceptions import ValidationError
import os
import uuid
import traceback
from supabase import create_client
from django.conf import settings
from .models import Store
class StoreForm(forms.ModelForm):
    logo_clear = forms.BooleanField(required=False, label='Remove logo')
    
    class Meta:
        model = Store
        fields = ['name', 'description', 'logo', 'address', 'city', 'province', 'latitude', 'longitude']
        widgets = {
            'latitude': forms.HiddenInput(),
            'longitude': forms.HiddenInput(),
        }
    
    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)
        self.fields['logo'].required = False
    
    def clean_logo(self):
        logo = self.cleaned_data.get('logo')
        
        if logo and hasattr(logo, 'size'):
            # Check file size (max 5MB)
            if logo.size > 5 * 1024 * 1024:
                raise ValidationError("Logo file size must be less than 5MB.")
            
            # Check file type
            valid_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
            ext = os.path.splitext(logo.name)[1].lower()
            if ext not in valid_extensions:
                raise ValidationError("Please upload a valid image file (JPG, PNG, GIF, or WEBP).")
        
        return logo
    
    def save(self, commit=True):
        store = super().save(commit=False)
        
        # Set owner if new store
        if not store.owner_id and self.request:
            store.owner = self.request.user
        
        logo_file = self.cleaned_data.get('logo')
        logo_clear = self.cleaned_data.get('logo_clear', False)
        
        print(f"DEBUG - Logo file provided: {'Yes' if logo_file else 'No'}")
        print(f"DEBUG - Clear logo requested: {logo_clear}")
        
        # Handle logo removal
        if logo_clear:
            if self.instance and self.instance.logo:
                self._delete_logo_from_supabase(self.instance.logo)
            store.logo = None
        # Handle new logo upload
        elif logo_file and hasattr(logo_file, 'file'):
            # Delete old logo if exists
            if self.instance and self.instance.logo:
                self._delete_logo_from_supabase(self.instance.logo)
            
            # Upload new logo
            try:
                store.logo = self._upload_logo_to_supabase(logo_file)
                print(f"DEBUG - New logo URL: {store.logo}")
            except Exception as e:
                print(f"Error uploading logo: {e}")
                # Preserve existing logo on error
                if self.instance and self.instance.logo:
                    store.logo = self.instance.logo
        # No changes to logo
        else:
            if self.instance:
                store.logo = self.instance.logo
        
        if commit:
            store.save()
            print(f"DEBUG - Store saved with logo: {store.logo}")
        
        return store
    
    def _delete_logo_from_supabase(self, logo_url):
        """Delete logo from Supabase storage"""
        try:
            supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_ROLE_KEY)
            bucket_name = "store-logos"
            
            # Extract filename from URL
            if 'store-logos/' in logo_url:
                file_name = logo_url.split('store-logos/')[-1]
                print(f"DEBUG - Deleting logo: {file_name}")
                result = supabase.storage.from_(bucket_name).remove([file_name])
                print(f"DEBUG - Delete result: {result}")
        except Exception as e:
            print(f"Warning: Could not delete old logo: {e}")
    
    def _upload_logo_to_supabase(self, logo_file):
        """Upload logo to Supabase storage"""
        try:
            supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_ROLE_KEY)
            bucket_name = "store-logos"
            
            # Generate unique filename
            file_ext = os.path.splitext(logo_file.name)[1].lower()
            file_name = f"logo_{uuid.uuid4()}{file_ext}"
            
            print(f"DEBUG - Uploading file: {file_name}")
            
            # Read file content
            logo_file.seek(0)
            file_content = logo_file.read()
            
            print(f"DEBUG - File size: {len(file_content)} bytes")
            
            # Upload to Supabase
            response = supabase.storage.from_(bucket_name).upload(
                file_name,
                file_content,
                {"content-type": logo_file.content_type}
            )
            
            print(f"DEBUG - Upload response: {response}")
            
            # Get public URL
            public_url = f"{settings.SUPABASE_URL}/storage/v1/object/public/{bucket_name}/{file_name}"
            print(f"DEBUG - Generated public URL: {public_url}")
            
            # Verify the file exists
            try:
                check = supabase.storage.from_(bucket_name).list()
                print(f"DEBUG - Files in bucket: {check}")
            except Exception as e:
                print(f"DEBUG - Could not list bucket: {e}")
            
            return public_url
            
        except Exception as e:
            print(f"Error uploading logo: {e}")
            raise ValidationError(f"Error uploading logo: {str(e)}")
class StoreForm(forms.ModelForm):
    logo_clear = forms.BooleanField(required=False, label='Remove logo')
    
    class Meta:
        model = Store
        fields = ['name', 'description', 'logo', 'address', 'city', 'province', 'latitude', 'longitude']
        widgets = {
            'latitude': forms.HiddenInput(),
            'longitude': forms.HiddenInput(),
        }
    
    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)
        self.fields['logo'].required = False
        
        # Add debugging info
        print("\n" + "="*50)
        print("STORE FORM INITIALIZATION")
        print("="*50)
        if self.instance and self.instance.pk:
            print(f"Editing existing store: {self.instance.name}")
            print(f"Current logo URL: {self.instance.logo}")
        else:
            print("Creating new store")
    
    def clean_logo(self):
        logo = self.cleaned_data.get('logo')
        print(f"\nCLEAN_LOGO called:")
        print(f"  Logo file: {logo}")
        if logo:
            print(f"  File name: {logo.name}")
            print(f"  File size: {logo.size}")
            print(f"  File type: {logo.content_type}")
        
        if logo and hasattr(logo, 'size'):
            # Check file size (max 5MB)
            if logo.size > 5 * 1024 * 1024:
                raise ValidationError("Logo file size must be less than 5MB.")
            
            # Check file type
            valid_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
            if hasattr(logo, 'name'):
                ext = os.path.splitext(logo.name)[1].lower()
                if ext not in valid_extensions:
                    raise ValidationError("Please upload a valid image file (JPG, PNG, GIF, or WEBP).")
        
        return logo
    
    def save(self, commit=True):
        print(f"\n" + "="*50)
        print("STORE FORM SAVE METHOD")
        print("="*50)
        print(f"Commit parameter: {commit}")
        
        store = super().save(commit=False)
        
        # Set owner if new store
        if not store.owner_id and self.request:
            store.owner = self.request.user
            print(f"Setting owner: {store.owner}")
        
        logo_file = self.cleaned_data.get('logo')
        logo_clear = self.cleaned_data.get('logo_clear', False)
        
        print(f"\nLOGO HANDLING:")
        print(f"  Logo file in cleaned_data: {'YES' if logo_file else 'NO'}")
        print(f"  Logo clear checkbox: {logo_clear}")
        print(f"  Has file attribute: {'YES' if logo_file and hasattr(logo_file, 'file') else 'NO'}")
        
        if logo_file:
            print(f"  File details:")
            print(f"    Name: {getattr(logo_file, 'name', 'N/A')}")
            print(f"    Size: {getattr(logo_file, 'size', 'N/A')}")
            print(f"    Content type: {getattr(logo_file, 'content_type', 'N/A')}")
        
        # Handle logo removal
        if logo_clear:
            print("Processing logo removal...")
            if self.instance and self.instance.logo:
                print(f"Deleting existing logo: {self.instance.logo}")
                self._delete_logo_from_supabase(self.instance.logo)
            store.logo = None
            print("Logo set to None")
        
        # Handle new logo upload
        elif logo_file and logo_file not in ['', None]:
            print("Processing new logo upload...")
            
            # Delete old logo if exists
            if self.instance and self.instance.logo:
                print(f"Deleting old logo: {self.instance.logo}")
                self._delete_logo_from_supabase(self.instance.logo)
            
            # Upload new logo
            try:
                print("Attempting to upload to Supabase...")
                new_logo_url = self._upload_logo_to_supabase(logo_file)
                store.logo = new_logo_url
                print(f"Success! New logo URL: {store.logo}")
            except Exception as e:
                print(f"Error uploading logo: {e}")
                print("Preserving existing logo...")
                # Preserve existing logo on error
                if self.instance and self.instance.logo:
                    store.logo = self.instance.logo
                else:
                    store.logo = None
        
        # No changes to logo
        else:
            print("No logo changes detected")
            if self.instance:
                store.logo = self.instance.logo
                print(f"Keeping existing logo: {store.logo}")
            else:
                store.logo = None
        
        if commit:
            print("\nCommitting to database...")
            store.save()
            print(f"Store saved with logo: {store.logo}")
        
        return store
    
    def _delete_logo_from_supabase(self, logo_url):
        """Delete logo from Supabase storage"""
        try:
            supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_ROLE_KEY)
            bucket_name = "store-logos"
            
            # Extract filename from URL
            if 'store-logos/' in logo_url:
                file_name = logo_url.split('store-logos/')[-1]
                print(f"  Deleting from Supabase: {file_name}")
                result = supabase.storage.from_(bucket_name).remove([file_name])
                print(f"  Delete result: {result}")
            else:
                print(f"  Could not parse filename from URL: {logo_url}")
        except Exception as e:
            print(f"  Warning: Could not delete old logo: {e}")
    
    def _upload_logo_to_supabase(self, logo_file):
        """Upload logo to Supabase storage"""
        print(f"\n  UPLOADING LOGO TO SUPABASE")
        print(f"  File name: {logo_file.name}")
        print(f"  File size: {logo_file.size}")
        
        try:
            supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_ROLE_KEY)
            bucket_name = "store-logos"
            
            print(f"  Supabase URL: {settings.SUPABASE_URL}")
            print(f"  Bucket name: {bucket_name}")
            
            # Generate unique filename
            file_ext = os.path.splitext(logo_file.name)[1].lower()
            file_name = f"logo_{uuid.uuid4()}{file_ext}"
            
            print(f"  Generated filename: {file_name}")
            
            # Read file content
            print("  Reading file content...")
            logo_file.seek(0)
            file_content = logo_file.read()
            
            print(f"  File content size: {len(file_content)} bytes")
            
            # Upload to Supabase
            print("  Uploading to Supabase...")
            response = supabase.storage.from_(bucket_name).upload(
                file_name,
                file_content,
                {"content-type": logo_file.content_type}
            )
            
            print(f"  Upload response: {response}")
            
            # Get public URL
            public_url = f"{settings.SUPABASE_URL}/storage/v1/object/public/{bucket_name}/{file_name}"
            print(f"  Generated public URL: {public_url}")
            
            # Verify upload
            print("  Verifying upload...")
            try:
                # List files to verify
                files = supabase.storage.from_(bucket_name).list()
                print(f"  Files in bucket after upload: {len(files)} files")
                
                # Try to get the file info
                file_info = supabase.storage.from_(bucket_name).get_public_url(file_name)
                print(f"  File info: {file_info}")
                
            except Exception as e:
                print(f"  Verification error (non-critical): {e}")
            
            return public_url
            
        except Exception as e:
            print(f"  ERROR uploading logo: {str(e)}")
            import traceback
            traceback.print_exc()
            raise ValidationError(f"Error uploading logo: {str(e)}")
        
class MessageForm(forms.ModelForm):
    class Meta:
        model = Message
        fields = ['receiver', 'content']

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)  # Accept 'user' as an argument
        super().__init__(*args, **kwargs)

        if user:
            opposite_role = 'Admin' if user.role == 'User' else 'User'
            self.fields['receiver'].queryset = CustomUser.objects.filter(role=opposite_role, is_deleted=False)
        else:
            self.fields['receiver'].queryset = CustomUser.objects.none()  # Fallback if no user provided


class ImageUploadForm(forms.Form):
    image = forms.ImageField()

# class ImageUploadForm(forms.Form):
#     image = forms.ImageField()
#     model_type = forms.ChoiceField(choices=[('disease', 'Banana Disease Detection'), ('variety', 'Banana Variety Classification')])
