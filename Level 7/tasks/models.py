from django.db import models

from django.contrib.auth.models import User

STATUS_CHOICES = (
    ("PENDING", "PENDING"),
    ("IN_PROGRESS", "IN_PROGRESS"),
    ("COMPLETED", "COMPLETED"),
    ("CANCELLED", "CANCELLED"),
)


# adding signals
from django.db.models.signals import pre_save
from django.dispatch import receiver


class Task(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    completed = models.BooleanField(default=False)
    created_date = models.DateTimeField(auto_now=True)
    deleted = models.BooleanField(default=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    priority = models.IntegerField(default=1)
    status = models.CharField(
        max_length=100, choices=STATUS_CHOICES, default=STATUS_CHOICES[0][0]
    )

    def __str__(self):
        return self.title

    def pretty_date(self):
        return self.created_date.strftime("%a %d %b")


class History(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE)
    prev = models.CharField(max_length=100, choices=STATUS_CHOICES, null=True)
    new = models.CharField(max_length=100, choices=STATUS_CHOICES, null=True)
    time = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.created_date.strftme("%a %d %b")

@receiver(pre_save, sender=Task)
def addHistory(sender, instance, **kwargs):
    previous = Task.objects.get(pk=instance.id)
    if previous.status != instance.status:
        History.objects.create(
            task=instance, prev=previous.status, new=sender.status
        ).save()
        print("History record added")
    else:
        print("History record not created")

    