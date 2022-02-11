# API
from django.contrib.auth.models import User

from tasks.models import Task, History

from rest_framework.views import APIView
from rest_framework.response import Response

from rest_framework.serializers import ModelSerializer

from rest_framework.viewsets import ModelViewSet

from rest_framework.permissions import IsAuthenticated


class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "username"]


class TaskSerializer(ModelSerializer):

    user = UserSerializer(read_only=True)

    class Meta:
        model = Task
        fields = ["title", "description", "completed", "user", "status", "id"]


class TaskViewSet(ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer

    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return Task.objects.filter(user=self.request.user, deleted=False)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class TaskListAPI(APIView):
    def get(self, request):
        tasks = Task.objects.filter(deleted=False)
        data = TaskSerializer(tasks, many=True).data
        return Response(data)


# django filters
from django_filters.rest_framework import (
    DjangoFilterBackend,
    FilterSet,
    CharFilter,
    ChoiceFilter,
    BooleanFilter,
    ModelChoiceFilter,
    DateFromToRangeFilter,
    DateTimeFilter,
)


class CompletedTaskViewSet(ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer

    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return Task.objects.filter(
            user=self.request.user, deleted=False, completed=True
        )

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


STATUS_CHOICES = (
    ("PENDING", "PENDING"),
    ("IN_PROGRESS", "IN_PROGRESS"),
    ("COMPLETED", "COMPLETED"),
    ("CANCELLED", "CANCELLED"),
)


class TaskFilter(FilterSet):
    title = CharFilter(lookup_expr="icontains")
    status = ChoiceFilter(choices=STATUS_CHOICES)
    completed = BooleanFilter()


class TaskViewSet(ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer

    permission_classes = (IsAuthenticated,)

    filter_backends = (DjangoFilterBackend,)
    filterset_class = TaskFilter

    # for tracking status changes
    def perform_update(self, serializer):
        id = self.get_object().id
        status = self.get_object().status
        new_status = serializer.validated_data.get("status")

        if new_status != status:
            task = Task.objects.filter(id=id).get()
            History.objects.create(task=task, prev=status, new=new_status)
            serializer.save(status=new_status)
        else:
            serializer.save()


# Task Status History Section


class HistorySerializer(ModelSerializer):
    class Meta:
        model = History
        fields = "__all__"


class HistoryFilter(FilterSet):
    task = ModelChoiceFilter(queryset=Task.objects.filter(deleted=False))
    time = DateFromToRangeFilter()
    prev = ChoiceFilter(choices=STATUS_CHOICES)
    new = ChoiceFilter(choices=STATUS_CHOICES)


from rest_framework import mixins
from rest_framework.viewsets import GenericViewSet


class TaskHistoryApiViewset(
    mixins.DestroyModelMixin,
    mixins.RetrieveModelMixin,
    mixins.ListModelMixin,
    GenericViewSet,
):
    permission_classes = [IsAuthenticated]
    serializer_class = HistorySerializer

    filter_backends = [DjangoFilterBackend]
    filterset_class = HistoryFilter

    def get_queryset(self):
        return History.objects.all()


# class to view history of status
class TaskHistoryFilter(FilterSet):
    task = CharFilter()
    prev = ChoiceFilter(lookup_expr="icontains", choices=STATUS_CHOICES)
    new = ChoiceFilter(lookup_expr="icontains", choices=STATUS_CHOICES)
    time = DateTimeFilter(lookup_expr="icontains")


class TaskHistorySerializer(ModelSerializer):
    class Meta:
        model = History
        fields = "__all__"


class TaskHistoryViewSet(ModelViewSet):
    queryset = History.objects.all()
    serializer_class = TaskHistorySerializer

    permission_classes = (IsAuthenticated,)

    filter_backends = (DjangoFilterBackend,)
    filterset_class = TaskHistoryFilter
