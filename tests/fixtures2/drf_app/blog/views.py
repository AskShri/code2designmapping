from rest_framework import generics, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.views import APIView
from .models import Post


class PostViewSet(viewsets.ModelViewSet):
    queryset = Post.objects.all()

    @action(detail=True, methods=["post"])
    def publish(self, request, pk=None):
        Post.objects.filter(pk=pk).update(title="x")


class HealthView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return None


class StatsView(generics.ListAPIView):
    permission_classes = [IsAdminUser]

    def get_queryset(self):
        return Post.objects.all()
