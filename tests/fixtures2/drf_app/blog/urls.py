from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import HealthView, PostViewSet, StatsView

router = DefaultRouter()
router.register(r"posts", PostViewSet, basename="post")

urlpatterns = [
    path("", include(router.urls)),
    path("health/", HealthView.as_view()),
    path("stats/", StatsView.as_view()),
]
