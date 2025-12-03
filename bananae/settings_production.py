from .settings import *

DEBUG = False
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1,.onrender.com').split(',')

# Static files
STATIC_ROOT = BASE_DIR / 'staticfiles'
MEDIA_ROOT = BASE_DIR / 'media'
MEDIA_URL = f'https://{SUPABASE_BUCKET}.supabase.co/storage/v1/object/public/'

# Database (use env or keep Supabase config)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv('POSTGRES_DB', 'postgres'),
        'USER': os.getenv('POSTGRES_USER', 'postgres'),
        'PASSWORD': os.getenv('POSTGRES_PASSWORD', ''),
        'HOST': os.getenv('POSTGRES_HOST', ''),
        'PORT': os.getenv('POSTGRES_PORT', '5432'),
        'OPTIONS': {'sslmode': 'require'},
    }
}
