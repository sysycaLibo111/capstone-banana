# escan/management/commands/reset_migrations.py
from django.core.management.base import BaseCommand
from django.db import connection

class Command(BaseCommand):
    help = 'Resets migration history'

    def handle(self, *args, **options):
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM django_migrations")
        self.stdout.write(self.style.SUCCESS('Cleared all migration history'))