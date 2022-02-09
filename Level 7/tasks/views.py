from random import choices
from re import search
from django.forms import DateTimeField, ModelForm
from django.http import HttpResponseRedirect
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from django.views.generic.list import ListView
from django.contrib.auth.mixins import LoginRequiredMixin
from matplotlib.pyplot import hist

from tasks.models import Task

from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.views import LoginView

# API start
from django.forms import ModelChoiceField
from django.views import View

from django.contrib.auth.models import User

from django.http.response import JsonResponse

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
        task = Task.objects.filter(id=id).get()
        History.objects.create(task=task, prev=status, new=new_status)
        serializer.save(status=new_status)


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
        return History.objects.filter(task__user=self.request.user)


# redirect to login page whenever the server is restarted
def redirect(request):
    return HttpResponseRedirect("/user/login")


# cascade priority
def cascade(priority, user):
    if Task.objects.filter(
        user=user, completed=False, deleted=False, priority=priority
    ).exists():
        p = priority

        # saving all data in variable: "data"
        data = (
            Task.objects.select_for_update()
            .filter(deleted=False, user=user, completed=False, priority__gte=priority)
            .order_by("priority")
        )
        current = p

        updated = []

        for task in data:
            if task.priority == current:
                task.priority = current + 1
                current += 1
                updated.append(task)
            else:
                break
        Task.objects.bulk_update(updated, ["priority"])


class AuthorisedTaskManager(LoginRequiredMixin):
    def get_queryset(self):
        return Task.objects.filter(deleted=False, user=self.request.user)


class UserLoginView(LoginView):
    template_name = "login.html"
    success_url = "/home/all"


class UserCreateView(CreateView):
    form_class = UserCreationForm
    template_name = "signup.html"
    success_url = "/user/login"


class TaskCreateForm(ModelForm):
    class Meta:
        model = Task
        fields = ["title", "description", "completed", "priority"]


class GenericTaskDeleteView(AuthorisedTaskManager, DeleteView):
    model = Task
    template_name = "task_delete.html"
    success_url = "/home/all"


class GenericTaskDetailView(AuthorisedTaskManager, DetailView):
    model = Task
    template_name = "task_detail.html"


def status_update(task, prev_status, status):
    History.objects.create(task=task, prev=prev_status, new=status)


class GenericTaskUpdateView(AuthorisedTaskManager, UpdateView):
    model = Task
    form_class = TaskCreateForm
    template_name = "task_update.html"
    success_url = "/home/all"

    def form_valid(self, form):
        task = Task.objects.get(id=self.object.id)
        new_priority = form.cleaned_data.get("priority")
        if task.priority != new_priority:
            cascade(new_priority, self.request.user)

        form.save()
        self.object = form.save()
        self.object.user = self.request.user
        self.object.save()
        return HttpResponseRedirect("/home/all")


# class to view history of status
class TaskHistoryFilter(FilterSet):
    task = CharFilter()
    prev = ChoiceFilter(lookup_expr="icontains", choices=STATUS_CHOICES)
    new = ChoiceFilter(lookup_expr="icontains", choices=STATUS_CHOICES)
    time = DateFromToRangeFilter(lookup_expr="icontains")


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


class GenericTaskCreateView(AuthorisedTaskManager, CreateView):
    form_class = TaskCreateForm
    template_name = "task_create.html"
    success_url = "/home/all"

    def form_valid(self, form):
        new_priority = form.cleaned_data.get("priority")
        cascade(new_priority, self.request.user)
        form.save()
        self.object = form.save()
        self.object.user = self.request.user
        self.object.save()
        return HttpResponseRedirect("/home/all")


# pending tasks
class GenericTaskViewPend(ListView):
    queryset = Task.objects.filter(deleted=False)
    template_name = "pend.html"
    context_object_name = "tasks"

    def get_queryset(self):
        search_term = self.request.GET.get("search")
        tasks = Task.objects.filter(
            deleted=False, user=self.request.user, completed=False
        )
        if search_term:
            tasks = Task.objects.filter(title__icontains=search_term)
        return tasks

    def get_context_data(self, **kwargs):
        completed = Task.objects.filter(
            deleted=False, user=self.request.user, completed=True
        ).count()
        total = Task.objects.filter(deleted=False, user=self.request.user).count()
        context = super(ListView, self).get_context_data(**kwargs)
        context["completed"] = completed
        context["total"] = total
        return context


# completed tasks
class GenericTaskViewComp(ListView):
    queryset = Task.objects.filter(deleted=False)
    template_name = "comp.html"
    context_object_name = "tasks"

    def get_queryset(self):
        search_term = self.request.GET.get("search")
        tasks = Task.objects.filter(
            deleted=False, user=self.request.user, completed=True
        )
        if search_term:
            tasks = Task.objects.filter(title__icontains=search_term)
        return tasks

    def get_context_data(self, **kwargs):
        completed = Task.objects.filter(
            deleted=False, user=self.request.user, completed=True
        ).count()
        total = Task.objects.filter(deleted=False, user=self.request.user).count()
        context = super(ListView, self).get_context_data(**kwargs)
        context["completed"] = completed
        context["total"] = total
        return context


# all
class GenericTaskViewAll(ListView):
    queryset = Task.objects.filter(deleted=False)
    template_name = "all.html"
    context_object_name = "tasks"

    def get_queryset(self):
        search_term = self.request.GET.get("search")
        tasks = Task.objects.filter(deleted=False, user=self.request.user)
        if search_term:
            tasks = Task.objects.filter(title__icontains=search_term)
        return tasks

    def get_context_data(self, **kwargs):
        completed = Task.objects.filter(
            deleted=False, user=self.request.user, completed=True
        ).count()
        total = Task.objects.filter(deleted=False, user=self.request.user).count()
        context = super(ListView, self).get_context_data(**kwargs)
        context["completed"] = completed
        context["total"] = total

        return context
