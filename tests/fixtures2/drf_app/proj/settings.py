ROOT_URLCONF = "proj.urls"
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
}
DATABASES = {"default": {"ENGINE": "django.db.backends.postgresql"}}
