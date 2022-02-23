from django.forms import ModelForm
from django.http import HttpResponseRedirect
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from django.views.generic.list import ListView
from django.contrib.auth.mixins import LoginRequiredMixin

# from django.contrib.auth.models import User

from tasks.models import Task, Report

from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.views import LoginView


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

    def form_valid(self, form):
        self.object = form.save()
        Report.objects.create(user=self.object)
        return HttpResponseRedirect(self.get_success_url())


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
class GenericTaskViewPend(LoginRequiredMixin, ListView):
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
class GenericTaskViewComp(LoginRequiredMixin, ListView):
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
class GenericTaskViewAll(LoginRequiredMixin, ListView):
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

    # redirect to login page not working
    def test_func(self):
        if self.request.user.is_anonymous:
            return HttpResponseRedirect("/user/login")

    def handle_no_permission(self):
        if self.request.user.is_anonymous:
            return HttpResponseRedirect("/user/login")


class EmailTaskForm(ModelForm):
    class Meta:
        model = Report
        fields = ["time", "disabled"]


class EmailTaskView(AuthorisedTaskManager, CreateView):
    model = Report
    form_class = EmailTaskForm
    template_name = "report_email.html"
    success_url = "/home/all"

    def form_valid(self, form):
        form.save()
        self.object = form.save()
        self.object.save()
        return HttpResponseRedirect("/home/all")
