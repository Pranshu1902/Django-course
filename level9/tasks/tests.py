from django.contrib.auth.models import User
from django.test import TestCase
from tasks.models import Task
from datetime import datetime, timezone
from tasks.tasks import send_email_reminder
from tasks.views import cascade


class Testing(TestCase):
    def setUp(self):
        # creating a user
        self.user = User.objects.create(username="user1902", email="test@user.com")
        self.user.set_password("testforuser12345")
        self.user.save()

        self.user1 = User.objects.create(username="ironman", email="iron@man.com")
        self.user1.set_password("pranshu1920")
        self.user1.save()

        self.user2 = User.objects.create(username="taskmanager", email="iron@man.com")
        self.user2.set_password("pranshu1920")
        self.user2.save()

        # logging in
        # self.client.login(username="user1902", password="testforuser12345")

    def test_view_user_login(self):
        response = self.client.get("/user/login")
        self.assertEqual(response.status_code, 200)

    def test_view_user_signup(self):
        response = self.client.get("/user/signup")
        self.assertEqual(response.status_code, 200)

    def test_detail_view(self):
        self.client.get(
            "/user/login", {"username": "user1902", "password": "testforuser12345"}
        )
        self.client.get(
            "/create-task",
            {
                "title": "Task1",
                "description": "Desc1",
                "completed": "False",
                "priority": 1,
            },
        )
        response = self.client.get("/detail-task/1")
        self.assertEqual(response.status_code, 302)

    def test_status_history_api_view(self):
        self.client.get(
            "/user/login", {"username": "user1902", "password": "testforuser12345"}
        )
        self.client.get(
            "/create-task",
            {
                "title": "Task1",
                "description": "Desc1",
                "completed": "False",
                "priority": 1,
            },
        )
        response = self.client.get("/api/status_history")
        self.assertEqual(response.status_code, 301)

    def test_login_required_all(self):
        response = self.client.get("/home/all")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/user/login")

    def test_redirect(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)

    def test_logout(self):
        self.client.get(
            "/user/login", {"username": "user1902", "password": "testforuser12345"}
        )
        response = self.client.get("/user/logout")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/user/login")

    def test_login_required_pending(self):
        response = self.client.get("/home/pending")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/user/login?next=/home/pending")

    def test_login_required_complete(self):
        response = self.client.get("/home/complete")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/user/login?next=/home/complete")

    def test_create(self):
        response = self.client.get(
            "/create-task",
            {
                "title": "Task1",
                "description": "Desc1",
                "completed": "False",
                "priority": 1,
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_delete(self):
        self.client.get(
            "/create-task",
            {
                "title": "Task1",
                "description": "Desc1",
                "completed": "False",
                "priority": 1,
            },
        )
        response = self.client.get("/delete-task/1")
        self.assertEqual(response.status_code, 302)

    def test_update(self):
        self.client.get(
            "/create-task",
            {
                "title": "Task1",
                "description": "Desc1",
                "completed": "False",
                "priority": 1,
            },
        )
        response = self.client.get("/update-task/1", {"title": "Task2"})
        self.assertEqual(response.status_code, 301)

    def test_detail(self):
        self.client.get(
            "/create-task",
            {
                "title": "Task1",
                "description": "Desc1",
                "completed": "False",
                "priority": 1,
            },
        )
        response = self.client.get("/detail-task/1")
        self.assertEqual(response.status_code, 302)

    def test_api(self):
        response = self.client.get("/api/tasks")
        self.assertEqual(response.status_code, 301)

    def test_api_history(self):
        response = self.client.get("/api/history")
        self.assertEqual(response.status_code, 301)

    def test_email_page(self):
        response = self.client.get("/email")
        self.assertEqual(response.status_code, 302)

    def test_email_send(self):
        response = self.client.post(
            "/email", {"time": datetime.now(timezone.utc), "diabled": "False"}
        )
        self.assertEqual(response.status_code, 302)

    def test_api_detail(self):
        self.client.get(
            "/user/login", {"username": "user1902", "password": "testforuser12345"}
        )
        self.client.get(
            "/create-task",
            {
                "title": "Task1",
                "description": "Desc1",
                "completed": "False",
                "priority": 1,
            },
        )
        response = self.client.get("/api/history/1")
        self.assertEqual(response.status_code, 301)

    def test_email_content(self):
        self.client.get(
            "/user/login",
            {
                "username": "user1902",
                "password": "testforuser12345",
            },
        )
        Task.objects.create(
            title="email",
            description="Desc1",
            completed=False,
            priority=10,
        )
        self.client.post(
            "/email", {"time": datetime.now(timezone.utc), "diabled": "False"}
        )
        resp = send_email_reminder()
        self.assertTrue("You have 1 Pending Tasks" in resp, msg="Email sent")

    def test_alltask_authorzation(self):
        self.client.get(
            "/user/login",
            {
                "username": "ironman",
                "password": "pranshu1920",
            },
        )
        self.client.get(
            "/create-task",
            {
                "title": "Authorization",
                "description": "Desc1",
                "completed": "False",
                "priority": 1,
            },
        )
        self.assertEqual(Task.objects.filter(user=self.user1).count(), 1)

    def test_cascade(self):
        self.client.get(
            "/user/login/", {"username": "taskmanager", "password": "pranshu1920"}
        )
        task = Task.objects.create(
            title="cascade1",
            description="Desc1",
            completed=False,
            priority=10,
        )
        task.save()
        task1 = Task.objects.create(
            title="Task2",
            description="Desc2",
            completed=False,
            priority=10,
            user=self.user,
        )
        task1.save()
        # cascade(10, self.user1)
        self.assertEqual(task.priority, 2)
