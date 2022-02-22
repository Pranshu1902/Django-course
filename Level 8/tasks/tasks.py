from django.core.mail import send_mail
from tasks.models import Task, Report
from datetime import datetime, timedelta, timezone

from celery.decorators import periodic_task


@periodic_task(run_every=timedelta(minutes=1))
def send_email_reminder():
    print("Processing emails")

    previous_day = datetime.now(timezone.utc) - timedelta(days=1)

    reports = Report.objects.filter(last_emailed__lte=previous_day, disabled=False)

    for report in reports:
        pending_tasks = Task.objects.filter(
            user=report.user, completed=False, deleted=False
        )
        email_content = f"You have {pending_tasks.count()} Pending Tasks\n\n"
        i = 1
        for task in pending_tasks:
            email_content += f"" + str(i) + ". {task.title} \n"
            i += 1
        send_mail(
            "Daily Report",
            email_content,
            "tasks@taskmanager.org",
            [report.user.email],
        )

        # updating the last_emailed field
        report.last_emailed = datetime.now(timezone.utc).replace(
            hour=report.time.hour, minute=report.time.minute, second=report.time.second
        )
        report.save()
        print(f"Completed Processing User {report.user.id}")
