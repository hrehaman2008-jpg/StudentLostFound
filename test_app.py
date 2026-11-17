r"""
Automated tests for the Student Lost and Found Portal.

Phase 2 (authentication + database), Phase 3 (item reports),
Phase 4 (search, filters and marking items as returned) and
Phase 6 (editing and deleting your own reports).

Run from the project folder on Windows:

    venv\Scripts\activate
    python -m unittest -v test_app

Every test uses a temporary SQLite file, so the real database in
instance/lost_found.db is never modified or deleted.
"""

import os
import re
import shutil
import tempfile
import unittest
from io import BytesIO

from app import Claim, ItemReport, Notification, User, create_app, db
from werkzeug.security import check_password_hash, generate_password_hash

CSRF_RE = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')

VALID_REPORT = {
    "title": "Black wireless earbuds",
    "report_type": "Lost",
    "category": "Electronics",
    "description": "Small charging case, slight scratch on the lid.",
    "location": "Library, 2nd floor",
    "date_lost_found": "2026-10-20",
}


class PortalTestBase(unittest.TestCase):
    """Shared setup: a fresh temporary database per test."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(self.db_path)
        # Uploaded photographs go to a throw-away folder, never static/uploads.
        self.upload_dir = tempfile.mkdtemp(suffix="-uploads")

        self.app = create_app(
            {
                "TESTING": True,
                "SQLALCHEMY_DATABASE_URI": "sqlite://" + "/" + self.db_path.replace("\\", "/"),
                "UPLOAD_FOLDER": self.upload_dir,
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.engine.dispose()
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)
        shutil.rmtree(self.upload_dir, ignore_errors=True)

    # --- helpers ------------------------------------------------------

    def csrf(self, path=None):
        """Fetch a page and pull its CSRF token out of the HTML."""
        html = self.client.get(path or "/login").get_data(as_text=True)
        match = CSRF_RE.search(html)
        self.assertIsNotNone(match, f"No CSRF token found on {path}")
        return match.group(1)

    def register(self, name="Test Student", email="student@college.edu",
                 password="secret123", confirm="secret123", follow_redirects=False):
        token = self.csrf("/register")
        return self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "name": name,
                "email": email,
                "password": password,
                "confirm_password": confirm,
            },
            follow_redirects=follow_redirects,
        )

    def login(self, email="student@college.edu", password="secret123",
              follow_redirects=False):
        token = self.csrf("/login")
        return self.client.post(
            "/login",
            data={"csrf_token": token, "email": email, "password": password},
            follow_redirects=follow_redirects,
        )

    def logout(self):
        token = CSRF_RE.search(self.client.get("/").get_data(as_text=True)).group(1)
        return self.client.post("/logout", data={"csrf_token": token})

    def post_report(self, **overrides):
        """Submit a report (defaults to a valid Lost report)."""
        data = dict(VALID_REPORT)
        data.update(overrides)
        data["csrf_token"] = self.csrf("/report")
        return self.client.post("/report", data=data)

    def start_report(self, **overrides):
        """Register + log in, then submit a report."""
        self.register()
        self.login()
        return self.post_report(**overrides)

    def restart_app(self):
        """Simulate an application restart on the same database file."""
        return create_app(
            {
                "TESTING": True,
                "SQLALCHEMY_DATABASE_URI": "sqlite://" + "/" + self.db_path.replace("\\", "/"),
            }
        )


class Phase2AuthTests(PortalTestBase):
    """End-to-end checks for registration, login, logout and the dashboard."""

    # --- 1 & 2: the app starts and the pages render -------------------

    def test_app_starts_and_pages_render(self):
        self.assertIsNotNone(self.app)
        for path, marker in (
            ("/", "Student Lost & Found Portal"),
            ("/login", "Welcome back"),
            ("/register", "Create your account"),
            ("/browse", "Browse reports"),
        ):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, f"{path} did not render")
            self.assertIn(marker, response.get_data(as_text=True))

    # --- 3: registration works ----------------------------------------

    def test_registration_succeeds_and_redirects_to_login(self):
        response = self.register()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/login"))

        page = self.client.get("/login", follow_redirects=True).get_data(as_text=True)
        self.assertIn("Your account has been created", page)

    def test_registration_validates_fields(self):
        token = self.csrf("/register")

        response = self.client.post(
            "/register",
            data={"csrf_token": token, "name": "A", "email": "a@b.edu",
                  "password": "short", "confirm_password": "short"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("at least 8 characters", response.get_data(as_text=True))

        response = self.client.post(
            "/register",
            data={"csrf_token": token, "name": "A", "email": "a@b.edu",
                  "password": "longenough1", "confirm_password": "different1"},
        )
        self.assertIn("passwords do not match", response.get_data(as_text=True))

        response = self.client.post(
            "/register",
            data={"csrf_token": token, "name": "A", "email": "not-an-email",
                  "password": "longenough1", "confirm_password": "longenough1"},
        )
        self.assertIn("does not look valid", response.get_data(as_text=True))

        response = self.client.post(
            "/register",
            data={"csrf_token": token, "name": "", "email": "a@b.edu",
                  "password": "longenough1", "confirm_password": "longenough1"},
        )
        self.assertIn("full name", response.get_data(as_text=True))

    # --- 4: duplicate email rejected ----------------------------------

    def test_duplicate_email_is_rejected(self):
        self.register()
        response = self.register(follow_redirects=True)
        body = response.get_data(as_text=True)
        self.assertIn("already exists", body)

        with self.app.app_context():
            self.assertEqual(User.query.count(), 1)

    # --- 5: the stored password is hashed -----------------------------

    def test_password_is_stored_hashed_not_plaintext(self):
        self.register()

        with self.app.app_context():
            user = User.query.filter_by(email="student@college.edu").one()
            self.assertNotIn("secret123", user.password_hash)
            self.assertFalse(user.password_hash.startswith("secret123"))
            self.assertTrue(
                check_password_hash(user.password_hash, "secret123"),
                "Hash does not verify the original password",
            )

    # --- 6: correct credentials log in --------------------------------

    def test_correct_credentials_log_in(self):
        self.register()
        response = self.login()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/dashboard"))

        page = self.client.get("/dashboard")
        self.assertEqual(page.status_code, 200)
        body = page.get_data(as_text=True)
        self.assertIn("Welcome, Test Student!", body)
        self.assertIn("Total Reports", body)

    # --- 7: wrong credentials rejected --------------------------------

    def test_wrong_credentials_are_rejected(self):
        self.register()
        response = self.login(password="wrongpass1")
        body = response.get_data(as_text=True)
        self.assertIn("Incorrect email or password", body)

        self.assertEqual(self.client.get("/dashboard").status_code, 302)

        response = self.login(email="nobody@college.edu", password="whatever1")
        self.assertIn("Incorrect email or password", response.get_data(as_text=True))

    # --- 8: the dashboard requires login ------------------------------

    def test_dashboard_requires_login(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

        followed = self.client.get("/dashboard", follow_redirects=True)
        self.assertEqual(followed.status_code, 200)
        self.assertIn("Please log in", followed.get_data(as_text=True))

    # --- 9: logout works and the dashboard is protected again ---------

    def test_logout_works_and_dashboard_is_protected_again(self):
        self.register()
        self.login()

        response = self.logout()
        self.assertEqual(response.status_code, 302)

        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    # --- 10: CSRF protection is active --------------------------------

    def test_csrf_protection_is_active(self):
        response = self.client.post(
            "/login", data={"email": "student@college.edu", "password": "secret123"}
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            "/register",
            data={"name": "X", "email": "x@y.edu", "password": "secret123",
                  "confirm_password": "secret123"},
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post("/logout")
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            "/login",
            data={"csrf_token": "wrong-token", "email": "a@b.edu", "password": "x"},
        )
        self.assertEqual(response.status_code, 400)

    # --- 11: the account survives an application restart ---------------

    def test_account_persists_after_restart(self):
        self.register()

        restarted = create_app(
            {
                "TESTING": True,
                "SQLALCHEMY_DATABASE_URI": "sqlite://" + "/" + self.db_path.replace("\\", "/"),
            }
        )
        with restarted.app_context():
            self.assertEqual(User.query.count(), 1)

        fresh_client = restarted.test_client()
        token = CSRF_RE.search(
            fresh_client.get("/login").get_data(as_text=True)
        ).group(1)
        response = fresh_client.post(
            "/login",
            data={"csrf_token": token, "email": "student@college.edu",
                  "password": "secret123"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/dashboard"))

        with restarted.app_context():
            db.session.remove()
            db.engine.dispose()


class Phase3ReportTests(PortalTestBase):
    """Checks for reporting, browsing, my-reports and dashboard counters."""

    # --- 1: existing registration and login still work ----------------

    def test_registration_and_login_still_work(self):
        self.assertEqual(self.register().status_code, 302)
        self.assertEqual(self.login().status_code, 302)
        body = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn("Welcome, Test Student!", body)

    # --- 2: unauthenticated users are blocked -------------------------

    def test_unauthenticated_cannot_report_or_open_my_reports(self):
        # GET pages redirect to login.
        for path in ("/report", "/my-reports"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302, f"{path} was not protected")
            self.assertIn("/login", response.headers["Location"])

        # A POST with a valid token still cannot create a report.
        token = self.csrf("/login")
        response = self.client.post("/report", data=dict(VALID_REPORT, csrf_token=token))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

        with self.app.app_context():
            self.assertEqual(ItemReport.query.count(), 0)

    # --- 3: a logged-in student can submit a Lost report ---------------

    def test_lost_report_can_be_submitted(self):
        self.start_report()

        with self.app.app_context():
            item = ItemReport.query.one()
            self.assertEqual(item.report_type, "Lost")
            self.assertEqual(item.status, "Active")
            self.assertEqual(item.category, "Electronics")
            self.assertEqual(item.date_lost_found.isoformat(), "2026-10-20")
            self.assertEqual(item.author.email, "student@college.edu")

        # It lands on the browse page and is visible there.
        page = self.client.get("/browse").get_data(as_text=True)
        self.assertIn("Black wireless earbuds", page)
        self.assertIn("Reported by Test Student", page)

    # --- 4: a logged-in student can submit a Found report --------------

    def test_found_report_can_be_submitted(self):
        self.start_report(
            title="Blue water bottle",
            report_type="Found",
            category="Other",
            description="Metal bottle with a campus sticker.",
            location="Sports complex",
            date_lost_found="2026-10-25",
        )

        with self.app.app_context():
            item = ItemReport.query.one()
            self.assertEqual(item.report_type, "Found")
            self.assertEqual(item.title, "Blue water bottle")

        page = self.client.get("/browse").get_data(as_text=True)
        self.assertIn("Blue water bottle", page)

    # --- 5: reports persist after a restart ----------------------------

    def test_reports_persist_after_restart(self):
        self.start_report()

        restarted = self.restart_app()
        with restarted.app_context():
            self.assertEqual(ItemReport.query.count(), 1)
            self.assertEqual(User.query.count(), 1)
            db.session.remove()
            db.engine.dispose()

    # --- 6: browse shows reports from different users ------------------

    def test_browse_shows_reports_from_different_users(self):
        # Student A posts.
        self.start_report(title="Student A calculator")

        # Student B posts.
        self.logout()
        self.register(name="Second Student", email="second@college.edu")
        self.login(email="second@college.edu")
        self.post_report(
            title="Student B notebook",
            report_type="Found",
            category="Books",
            location="Canteen",
            date_lost_found="2026-10-28",
        )

        body = self.client.get("/browse").get_data(as_text=True)
        self.assertIn("Student A calculator", body)
        self.assertIn("Student B notebook", body)
        self.assertIn("Reported by Test Student", body)
        self.assertIn("Reported by Second Student", body)

    # --- 7: my reports shows only the current user's reports -----------

    def test_my_reports_shows_only_current_users_reports(self):
        self.start_report(title="Only mine, please")

        self.logout()
        self.register(name="Second Student", email="second@college.edu")
        self.login(email="second@college.edu")
        self.post_report(title="Someone else report")

        body = self.client.get("/my-reports").get_data(as_text=True)
        self.assertIn("Someone else report", body)
        self.assertNotIn("Only mine, please", body)

        # Logging back in as the first student flips the result.
        self.logout()
        self.login(email="student@college.edu")
        body = self.client.get("/my-reports").get_data(as_text=True)
        self.assertIn("Only mine, please", body)
        self.assertNotIn("Someone else report", body)

    # --- 8: dashboard counts reflect the current user ------------------

    def test_dashboard_counts_reflect_the_current_user(self):
        self.start_report(title="Lost one")
        self.post_report(title="Lost two")
        self.post_report(title="Found one", report_type="Found")

        body = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn("<h2 class=\"h4 fw-bold mt-3 mb-0\">3</h2>", body)   # total
        self.assertIn("<h2 class=\"h4 fw-bold mt-3 mb-0\">2</h2>", body)   # lost
        self.assertIn("<h2 class=\"h4 fw-bold mt-3 mb-0\">1</h2>", body)   # found
        self.assertIn("<h2 class=\"h4 fw-bold mt-3 mb-0\">0</h2>", body)   # returned

        # A different student sees their own (empty) counters, not these.
        self.logout()
        self.register(name="Second Student", email="second@college.edu")
        self.login(email="second@college.edu")
        body = self.client.get("/dashboard").get_data(as_text=True)
        self.assertNotIn("Lost one", body)
        self.assertIn("0", body)

    # --- 9: invalid form values are rejected ---------------------------

    def test_invalid_report_values_are_rejected(self):
        self.start_report()
        token = self.csrf("/report")

        cases = [
            ({"report_type": "Stolen"}, "Lost or Found"),
            ({"category": "Jewellery"}, "allowed categories"),
            ({"title": ""}, "item name"),
            ({"description": ""}, "describe the item"),
            ({"location": ""}, "lost or found"),
            ({"date_lost_found": "not-a-date"}, "valid date"),
            ({"date_lost_found": ""}, "Please enter the date"),
        ]
        for overrides, marker in cases:
            data = dict(VALID_REPORT)
            data.update(overrides)
            data["csrf_token"] = token
            response = self.client.post("/report", data=data)
            self.assertEqual(response.status_code, 200, f"Case {overrides} not re-rendered")
            self.assertIn(marker, response.get_data(as_text=True),
                          f"Missing message for {overrides}")

        # Nothing extra was stored.
        with self.app.app_context():
            self.assertEqual(ItemReport.query.count(), 1)

    # --- 10: CSRF protection remains active ----------------------------

    def test_report_form_requires_csrf(self):
        self.register()
        self.login()

        response = self.client.post("/report", data=dict(VALID_REPORT))
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            "/report", data=dict(VALID_REPORT, csrf_token="wrong-token")
        )
        self.assertEqual(response.status_code, 400)

        with self.app.app_context():
            self.assertEqual(ItemReport.query.count(), 0)

    # --- 11: existing account data is preserved ------------------------

    def test_existing_account_data_is_preserved(self):
        self.register()

        # New table is created on top of the existing one.
        with self.app.app_context():
            db.create_all()
            self.assertEqual(User.query.count(), 1)
            user = User.query.one()
            self.assertEqual(user.email, "student@college.edu")
            self.assertTrue(check_password_hash(user.password_hash, "secret123"))

        # And after a restart.
        restarted = self.restart_app()
        with restarted.app_context():
            self.assertEqual(User.query.count(), 1)
            self.assertTrue(
                check_password_hash(User.query.one().password_hash, "secret123")
            )
            db.session.remove()
            db.engine.dispose()


class Phase4SearchAndReturnTests(PortalTestBase):
    """Phase 4: search, filtering and the owner-only mark-as-returned action."""

    REPORTS = [
        dict(
            title="Silver Calculator",
            report_type="Lost",
            category="Electronics",
            description="Scientific calculator with a cracked screen cover.",
            location="Library 2nd floor",
            date_lost_found="2026-10-10",
        ),
        dict(
            title="Blue Umbrella",
            report_type="Found",
            category="Accessories",
            description="Compact foldable umbrella with a navy handle.",
            location="Canteen near the counter",
            date_lost_found="2026-10-12",
        ),
        dict(
            title="ID card holder",
            report_type="Lost",
            category="ID Card",
            description="Transparent plastic holder with a lanyard attached.",
            location="Main gate security desk",
            date_lost_found="2026-10-14",
        ),
    ]

    def setUp(self):
        super().setUp()
        self.register()
        self.login()
        for report in self.REPORTS:
            self.post_report(**report)

    # --- helpers ------------------------------------------------------

    def browse(self, **params):
        response = self.client.get("/browse", query_string=params)
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def report_id(self, title):
        with self.app.app_context():
            return ItemReport.query.filter_by(title=title).one().id

    def status_of(self, title):
        with self.app.app_context():
            return ItemReport.query.filter_by(title=title).one().status

    def mark_returned(self, report_id, next_url="/my-reports", token=None):
        data = {"next": next_url}
        # /login always renders a CSRF token (it is session-bound, not form-bound).
        token = self.csrf("/login") if token is None else token
        if token:
            data["csrf_token"] = token
        return self.client.post(f"/reports/{report_id}/return", data=data)

    def dashboard_counters(self):
        """Return [total, lost, found, returned] from the dashboard page."""
        html = self.client.get("/dashboard").get_data(as_text=True)
        numbers = re.findall(r'<h2 class="h4 fw-bold mt-3 mb-0">(\d+)</h2>', html)
        self.assertEqual(len(numbers), 4, "dashboard counters not found")
        return [int(n) for n in numbers]

    # --- 1-3: search by title, description and location ---------------

    def test_search_by_title(self):
        html = self.browse(q="calculator")
        self.assertIn("Silver Calculator", html)
        self.assertNotIn("Blue Umbrella", html)
        self.assertNotIn("ID card holder", html)

    def test_search_by_description(self):
        html = self.browse(q="lanyard")
        self.assertIn("ID card holder", html)
        self.assertNotIn("Silver Calculator", html)
        self.assertNotIn("Blue Umbrella", html)

    def test_search_by_location(self):
        html = self.browse(q="canteen")
        self.assertIn("Blue Umbrella", html)
        self.assertNotIn("Silver Calculator", html)
        self.assertNotIn("ID card holder", html)

    def test_search_is_case_insensitive(self):
        self.assertIn("Silver Calculator", self.browse(q="CALCULATOR"))
        self.assertIn("Blue Umbrella", self.browse(q="uMbReLlA"))
        self.assertIn("ID card holder", self.browse(q="MAIN GATE"))

    # --- 4-6: type, category and status filters ------------------------

    def test_filter_by_report_type(self):
        found = self.browse(report_type="Found")
        self.assertIn("Blue Umbrella", found)
        self.assertNotIn("Silver Calculator", found)

        lost = self.browse(report_type="Lost")
        self.assertIn("Silver Calculator", lost)
        self.assertIn("ID card holder", lost)
        self.assertNotIn("Blue Umbrella", lost)

    def test_filter_by_category(self):
        id_cards = self.browse(category="ID Card")
        self.assertIn("ID card holder", id_cards)
        self.assertNotIn("Silver Calculator", id_cards)

        electronics = self.browse(category="Electronics")
        self.assertIn("Silver Calculator", electronics)
        self.assertNotIn("Blue Umbrella", electronics)

        none_in_category = self.browse(category="Books")
        self.assertNotIn("Silver Calculator", none_in_category)
        self.assertIn("No reports match your search", none_in_category)

    def test_filter_by_status_active_and_returned(self):
        # Nothing is returned yet.
        self.assertNotIn("Silver Calculator", self.browse(status="Returned"))

        self.mark_returned(self.report_id("Silver Calculator"))

        returned = self.browse(status="Returned")
        self.assertIn("Silver Calculator", returned)
        self.assertNotIn("Blue Umbrella", returned)

        active = self.browse(status="Active")
        self.assertIn("Blue Umbrella", active)
        self.assertNotIn("Silver Calculator", active)

        everything = self.browse(status="All")
        self.assertIn("Silver Calculator", everything)
        self.assertIn("Blue Umbrella", everything)

        # Default browse page still hides returned reports.
        self.assertNotIn("Silver Calculator", self.browse())

    # --- 7: search and filters combined --------------------------------

    def test_search_and_filters_combine(self):
        html = self.browse(q="calculator", report_type="Lost", category="Electronics")
        self.assertIn("Silver Calculator", html)
        self.assertNotIn("Blue Umbrella", html)

        # Each filter stays in the form so the choice is visible and shareable.
        self.assertIn('value="calculator"', html)

        mismatch = self.browse(q="calculator", category="Books")
        self.assertNotIn("Silver Calculator", mismatch)
        self.assertIn("No reports match your search", mismatch)

        returned_state = self.browse(q="lanyard", status="Active", category="ID Card")
        self.assertIn("ID card holder", returned_state)
        self.assertNotIn("Blue Umbrella", returned_state)

    def test_invalid_filter_values_fall_back_safely(self):
        html = self.browse(report_type="Bogus", category="Nonsense", status="Whatever")

        # The bogus values never reach the form controls or the query.
        self.assertNotIn('value="Bogus"', html)
        self.assertNotIn("selected>Bogus", html)
        self.assertNotIn("selected>Nonsense", html)
        self.assertNotIn("selected>Whatever", html)

        # Unknown values behave like "All", so every active report is listed.
        self.assertIn("Blue Umbrella", html)
        self.assertIn("Silver Calculator", html)
        self.assertIn("<option value=\"All\" selected>All</option>", html)

    # --- 8: clearing the filters ---------------------------------------

    def test_clear_filters_restores_full_list(self):
        self.assertNotIn("Blue Umbrella", self.browse(q="calculator", report_type="Lost"))

        cleared = self.browse()
        for report in self.REPORTS:
            self.assertIn(report["title"], cleared)
        self.assertIn('href="/browse"', cleared)
        self.assertIn("No reports match your search", self.browse(q="nothing-matches-this"))

    # --- 9-11: marking a report as returned ----------------------------

    def test_owner_can_mark_report_returned(self):
        item_id = self.report_id("Blue Umbrella")
        response = self.mark_returned(item_id, next_url="/my-reports")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/my-reports"))
        self.assertEqual(self.status_of("Blue Umbrella"), "Returned")

        page = self.client.get("/my-reports").get_data(as_text=True)
        self.assertIn("marked as returned", page)
        self.assertIn("Returned", page)

    def test_other_student_cannot_mark_report_returned(self):
        item_id = self.report_id("Blue Umbrella")

        self.logout()
        self.register(name="Other Student", email="other@college.edu")
        self.login(email="other@college.edu")

        response = self.mark_returned(item_id, next_url="/browse")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.status_of("Blue Umbrella"), "Active")

        page = self.client.get("/browse").get_data(as_text=True)
        self.assertIn("only update your own reports", page)
        # The button is not offered on someone else's card.
        self.assertNotIn("Mark as Returned", page)

    def test_returned_report_stays_returned(self):
        item_id = self.report_id("ID card holder")
        self.mark_returned(item_id)
        self.assertEqual(self.status_of("ID card holder"), "Returned")

        # A second attempt cannot flip it back to Active.
        self.mark_returned(item_id)
        self.assertEqual(self.status_of("ID card holder"), "Returned")

        # And it survives an application restart.
        restarted = self.restart_app()
        with restarted.app_context():
            item = db.session.get(ItemReport, item_id)
            self.assertEqual(item.status, "Returned")
            db.session.remove()
            db.engine.dispose()

    def test_button_only_visible_to_the_owner(self):
        self.assertIn("Mark as Returned", self.client.get("/browse").get_data(as_text=True))

        self.mark_returned(self.report_id("Blue Umbrella"))
        my_page = self.client.get("/my-reports").get_data(as_text=True)
        # Returned cards no longer offer the button, active ones still do.
        self.assertEqual(my_page.count("Mark as Returned"), 2)

        self.logout()
        self.assertNotIn("Mark as Returned", self.browse())

    def test_marking_unknown_report_is_handled(self):
        response = self.mark_returned(9999)
        self.assertEqual(response.status_code, 302)
        page = self.client.get(response.headers["Location"]).get_data(as_text=True)
        self.assertIn("could not be found", page)

    # --- 12: dashboard counters ---------------------------------------

    def test_dashboard_counters_update_after_return(self):
        self.assertEqual(self.dashboard_counters(), [3, 2, 1, 0])

        self.mark_returned(self.report_id("Silver Calculator"))
        self.assertEqual(self.dashboard_counters(), [3, 2, 1, 1])

        self.mark_returned(self.report_id("Blue Umbrella"))
        self.assertEqual(self.dashboard_counters(), [3, 2, 1, 2])

        # Another student's counters are unaffected.
        self.logout()
        self.register(name="Other Student", email="other@college.edu")
        self.login(email="other@college.edu")
        self.assertEqual(self.dashboard_counters(), [0, 0, 0, 0])

    def test_dashboard_cards_link_to_filtered_lists(self):
        html = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn('href="/my-reports"', html)
        self.assertIn('href="/my-reports?report_type=Lost"', html)
        self.assertIn('href="/my-reports?report_type=Found"', html)
        self.assertIn('href="/my-reports?status=Returned"', html)

        lost = self.client.get("/my-reports?report_type=Lost").get_data(as_text=True)
        self.assertIn("Silver Calculator", lost)
        self.assertNotIn("Blue Umbrella", lost)

    # --- 13: CSRF protection on the status update ----------------------

    def test_mark_returned_requires_csrf(self):
        item_id = self.report_id("Silver Calculator")
        response = self.client.post(f"/reports/{item_id}/return", data={"next": "/my-reports"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.status_of("Silver Calculator"), "Active")

        response = self.client.post(
            f"/reports/{item_id}/return",
            data={"csrf_token": "not-a-real-token", "next": "/my-reports"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.status_of("Silver Calculator"), "Active")

    def test_mark_returned_requires_login(self):
        item_id = self.report_id("Silver Calculator")
        self.logout()

        response = self.mark_returned(item_id)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        self.assertEqual(self.status_of("Silver Calculator"), "Active")

    def test_mark_returned_rejects_external_next_url(self):
        item_id = self.report_id("Blue Umbrella")
        response = self.mark_returned(item_id, next_url="https://example.com/phish")
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("example.com", response.headers["Location"])
        self.assertEqual(self.status_of("Blue Umbrella"), "Returned")


UPDATED_REPORT = {
    "title": "Navy water bottle",
    "report_type": "Found",
    "category": "Accessories",
    "description": "Steel bottle with a navy cap and a small dent near the base.",
    "location": "Canteen, table 4",
    "date_lost_found": "2026-11-05",
}


class Phase6EditDeleteTests(PortalTestBase):
    """Phase 6: the owner can edit and delete their own reports."""

    def setUp(self):
        super().setUp()
        self.register()
        self.login()
        self.post_report()
        with self.app.app_context():
            self.item_id = ItemReport.query.one().id

    # --- helpers ------------------------------------------------------

    def snapshot(self, item_id=None):
        """Plain dict of the stored report, or None when it no longer exists."""
        with self.app.app_context():
            item = db.session.get(
                ItemReport, item_id if item_id is not None else self.item_id
            )
            if item is None:
                return None
            return {
                "title": item.title,
                "description": item.description,
                "category": item.category,
                "report_type": item.report_type,
                "location": item.location,
                "date": item.date_lost_found.isoformat(),
                "status": item.status,
                "user_id": item.user_id,
            }

    def count(self):
        with self.app.app_context():
            return ItemReport.query.count()

    def token(self):
        """A valid CSRF token for the current session (logged in or not)."""
        page = self.client.get("/report")
        if page.status_code != 200:
            page = self.client.get("/login")
        return CSRF_RE.search(page.get_data(as_text=True)).group(1)

    def edit(self, token=None, **overrides):
        data = dict(VALID_REPORT)
        data.update(overrides)
        token = self.token() if token is None else token
        if token:
            data["csrf_token"] = token
        return self.client.post(f"/reports/{self.item_id}/edit", data=data)

    def delete(self, token=None):
        data = {}
        token = self.token() if token is None else token
        if token:
            data["csrf_token"] = token
        return self.client.post(f"/reports/{self.item_id}/delete", data=data)

    def become_other_student(self):
        self.logout()
        self.register(name="Other Student", email="other@college.edu")
        self.login(email="other@college.edu")

    def assert_card_absent(self, html, title):
        """The report card heading is gone (the flash message may still name it)."""
        self.assertNotIn(f'<h3 class="h5 fw-bold mb-0">{title}</h3>', html)

    # --- 1: the edit page opens with the current values ---------------

    def test_edit_page_is_prefilled_with_the_report(self):
        page = self.client.get(f"/reports/{self.item_id}/edit")
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)

        self.assertIn("Edit report", html)
        self.assertIn('value="Black wireless earbuds"', html)
        self.assertIn("Small charging case, slight scratch on the lid.", html)
        self.assertIn('value="Library, 2nd floor"', html)
        self.assertIn('value="2026-10-20"', html)
        self.assertIn('value="Electronics" selected', html)
        self.assertIn('value="Lost"', html)
        self.assertEqual(html.count("checked"), 1, "exactly one report type is selected")

    # --- 2-3: a valid edit saves everywhere ----------------------------

    def test_owner_can_edit_their_report(self):
        response = self.edit(**UPDATED_REPORT)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/my-reports"))

        stored = self.snapshot()
        self.assertEqual(stored["title"], UPDATED_REPORT["title"])
        self.assertEqual(stored["description"], UPDATED_REPORT["description"])
        self.assertEqual(stored["category"], UPDATED_REPORT["category"])
        self.assertEqual(stored["report_type"], UPDATED_REPORT["report_type"])
        self.assertEqual(stored["location"], UPDATED_REPORT["location"])
        self.assertEqual(stored["date"], UPDATED_REPORT["date_lost_found"])

        page = self.client.get("/my-reports").get_data(as_text=True)
        self.assertIn("has been updated", page)
        self.assertIn("Navy water bottle", page)

    def test_edited_report_appears_in_browse_and_my_reports(self):
        self.edit(**UPDATED_REPORT)

        browse_all = self.client.get("/browse").get_data(as_text=True)
        self.assertIn("Navy water bottle", browse_all)
        self.assertNotIn("Black wireless earbuds", browse_all)

        browse_search = self.client.get("/browse?q=navy+water").get_data(as_text=True)
        self.assertIn("Navy water bottle", browse_search)

        mine = self.client.get("/my-reports").get_data(as_text=True)
        self.assertIn("Navy water bottle", mine)
        self.assertNotIn("Black wireless earbuds", mine)

    # --- 4: editing never changes status or ownership ------------------

    def test_edit_preserves_status_and_owner(self):
        self.client.post(
            f"/reports/{self.item_id}/return", data={"csrf_token": self.token()}
        )
        before = self.snapshot()
        self.assertEqual(before["status"], "Returned")

        self.edit(**UPDATED_REPORT)

        after = self.snapshot()
        self.assertEqual(after["status"], "Returned", "status must not be reset")
        self.assertEqual(after["user_id"], before["user_id"], "owner must not change")
        self.assertEqual(after["title"], UPDATED_REPORT["title"])

    # --- 5: invalid edits are rejected ---------------------------------

    def test_invalid_edits_are_rejected(self):
        before = self.snapshot()

        cases = (
            (dict(title="   "), "Please enter the item name."),
            (dict(description=""), "Please describe the item."),
            (dict(location=""), "Please tell us where the item was lost or found."),
            (dict(report_type="Maybe"), "Please choose whether the item is Lost or Found."),
            (dict(category="Spaceships"), "Please choose one of the allowed categories."),
            (dict(date_lost_found=""), "Please enter the date the item was lost or found."),
            (dict(date_lost_found="2026-13-45"), "Please enter a valid date"),
        )
        for overrides, message in cases:
            with self.subTest(overrides=overrides):
                response = self.edit(**overrides)
                self.assertEqual(response.status_code, 200)
                self.assertIn(message, response.get_data(as_text=True))
                self.assertEqual(self.snapshot(), before, "the stored report must not change")

        self.assertEqual(self.count(), 1)

    # --- 6-7: only the owner may edit, and only when logged in ----------

    def test_another_student_cannot_edit_the_report(self):
        self.become_other_student()
        before = self.snapshot()

        page = self.client.get(f"/reports/{self.item_id}/edit")
        self.assertEqual(page.status_code, 302)
        self.assertTrue(page.headers["Location"].endswith("/browse"))

        response = self.edit(**UPDATED_REPORT)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.snapshot(), before)

        browse = self.client.get("/browse").get_data(as_text=True)
        self.assertIn("You can only edit your own reports.", browse)

    def test_edit_requires_login(self):
        self.logout()
        before = self.snapshot()

        page = self.client.get(f"/reports/{self.item_id}/edit")
        self.assertEqual(page.status_code, 302)
        self.assertIn("/login", page.headers["Location"])

        response = self.edit(**UPDATED_REPORT)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        self.assertEqual(self.snapshot(), before)

    # --- 8-9: deleting a report ----------------------------------------

    def test_owner_can_delete_their_report(self):
        title = self.snapshot()["title"]

        response = self.delete()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/my-reports"))

        self.assertIsNone(self.snapshot())
        self.assertEqual(self.count(), 0)

        page = self.client.get("/my-reports").get_data(as_text=True)
        self.assertIn("has been deleted", page)
        self.assert_card_absent(page, title)
        self.assertNotIn(f"/reports/{self.item_id}", page)

    def test_deletion_removes_the_report_from_browse(self):
        self.assertIn(
            "Black wireless earbuds", self.client.get("/browse").get_data(as_text=True)
        )

        self.delete()

        for url in ("/browse", "/browse?status=All", "/browse?q=earbuds"):
            html = self.client.get(url).get_data(as_text=True)
            self.assert_card_absent(html, "Black wireless earbuds")
            self.assertNotIn(f"/reports/{self.item_id}", html, url)

    # --- 10-11: other students and logged-out visitors cannot delete ----

    def test_another_student_cannot_delete_the_report(self):
        self.become_other_student()
        before = self.snapshot()

        response = self.delete()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/browse"))

        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.count(), 1)
        page = self.client.get("/browse").get_data(as_text=True)
        self.assertIn("You can only delete your own reports.", page)

    def test_delete_requires_login(self):
        self.logout()

        response = self.delete()
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        self.assertEqual(self.count(), 1)

    # --- 12: CSRF protection on both actions ---------------------------

    def test_edit_and_delete_require_csrf(self):
        before = self.snapshot()

        response = self.edit(token="")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.snapshot(), before)

        response = self.delete(token="")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.snapshot(), before)

        response = self.edit(token="forged-token")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.snapshot(), before)

        response = self.delete(token="forged-token")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.snapshot(), before)

    # --- 13: unknown report ids are handled politely --------------------

    def test_unknown_report_id_is_handled(self):
        page = self.client.get("/reports/9999/edit")
        self.assertEqual(page.status_code, 302)
        self.assertIn(
            "could not be found", self.client.get("/my-reports").get_data(as_text=True)
        )

        response = self.client.post(
            "/reports/9999/delete", data={"csrf_token": self.token()}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.count(), 1)

    # --- 14: the buttons are only shown to the owner --------------------

    def test_edit_and_delete_buttons_only_for_the_owner(self):
        mine = self.client.get("/my-reports").get_data(as_text=True)
        self.assertIn(f"/reports/{self.item_id}/edit", mine)
        self.assertIn(f"/reports/{self.item_id}/delete", mine)
        self.assertIn("Edit", mine)
        self.assertIn("Delete", mine)
        self.assertIn("onsubmit=\"return confirm(", mine, "delete asks for confirmation")

        # A different student sees the card without any owner buttons.
        self.become_other_student()
        other = self.client.get("/browse").get_data(as_text=True)
        self.assertIn("Black wireless earbuds", other)
        self.assertNotIn(f"/reports/{self.item_id}/edit", other)
        self.assertNotIn(f"/reports/{self.item_id}/delete", other)

        # Logged-out visitors never get the buttons either.
        self.logout()
        public = self.client.get("/browse").get_data(as_text=True)
        self.assertNotIn(f"/reports/{self.item_id}/edit", public)
        self.assertNotIn(f"/reports/{self.item_id}/delete", public)


# --- Tiny fake image files (only the signatures matter to the app) ------
JPEG_BYTES = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xdb\x00C\x00" + b"\x08" * 64 + b"\xff\xd9"
)
PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
    b"\x1f\x15\xc4\x89"
    b"\x00\x00\x00\x0aIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)
WEBP_BYTES = b"RIFF" + (64).to_bytes(4, "little") + b"WEBPVP8 " + b"\x00" * 56


class Phase7ImageUploadTests(PortalTestBase):
    """Phase 7: optional photographs on reports."""

    def setUp(self):
        super().setUp()
        self.register()
        self.login()

    # --- helpers ------------------------------------------------------

    def upload(self, filename, payload, **overrides):
        """Post a new report with a photograph attached."""
        data = dict(VALID_REPORT)
        data.update(overrides)
        data["csrf_token"] = self.csrf("/report")
        data["image"] = (BytesIO(payload), filename)
        return self.client.post("/report", data=data, content_type="multipart/form-data")

    def edit_with_image(self, item_id, filename, payload, **overrides):
        data = dict(VALID_REPORT)
        data.update(overrides)
        data["csrf_token"] = self.csrf(f"/reports/{item_id}/edit")
        data["image"] = (BytesIO(payload), filename)
        return self.client.post(
            f"/reports/{item_id}/edit", data=data, content_type="multipart/form-data"
        )

    def newest_id(self):
        with self.app.app_context():
            return ItemReport.query.order_by(ItemReport.id.desc()).first().id

    def stored_photo(self, item_id=None):
        with self.app.app_context():
            item = db.session.get(
                ItemReport, item_id if item_id is not None else self.newest_id()
            )
            return None if item is None else item.image_filename

    def report_count(self):
        with self.app.app_context():
            return ItemReport.query.count()

    def uploaded_files(self):
        return sorted(os.listdir(self.upload_dir))

    def become_other_student(self):
        self.logout()
        self.register(name="Other Student", email="other@college.edu")
        self.login(email="other@college.edu")

    # --- 1: a report with no image still works -------------------------

    def test_create_report_without_image(self):
        response = self.post_report()
        self.assertEqual(response.status_code, 302)

        self.assertIsNone(self.stored_photo())
        self.assertEqual(self.uploaded_files(), [])

        html = self.client.get("/browse").get_data(as_text=True)
        self.assertIn("No photograph", html)
        self.assertIn("report-photo-placeholder", html)

    # --- 2: a valid JPEG is stored and shown on the card ---------------

    def test_create_report_with_jpeg_shows_it_on_the_card(self):
        response = self.upload("my holiday photo.jpg", JPEG_BYTES)
        self.assertEqual(response.status_code, 302)

        filename = self.stored_photo()
        self.assertIsNotNone(filename)
        self.assertTrue(filename.endswith(".jpg"))
        self.assertIn(filename, self.uploaded_files())
        # The student's own file name is never used on disk.
        self.assertNotIn("holiday", filename)

        html = self.client.get("/browse").get_data(as_text=True)
        self.assertIn(f'src="/static/uploads/reports/{filename}"', html)
        self.assertIn('alt="Photograph of Black wireless earbuds"', html)
        self.assertIn("report-photo", html)

    # --- 3: PNG and WEBP are accepted too ------------------------------

    def test_create_report_with_png_and_webp(self):
        self.upload("photo.png", PNG_BYTES)
        png_name = self.stored_photo()
        self.assertTrue(png_name.endswith(".png"))

        self.upload("photo.webp", WEBP_BYTES, title="Navy water bottle")
        webp_name = self.stored_photo()
        self.assertTrue(webp_name.endswith(".webp"))

        self.assertEqual(self.report_count(), 2)
        self.assertEqual(sorted(self.uploaded_files()), sorted([png_name, webp_name]))

    # --- 4: two reports never share a file name -------------------------

    def test_image_filenames_are_unique(self):
        self.upload("same-photo.jpg", JPEG_BYTES)
        first = self.stored_photo()

        self.upload("same-photo.jpg", JPEG_BYTES, title="Second earbuds case")
        second = self.stored_photo()

        self.assertNotEqual(first, second)
        self.assertEqual(len(self.uploaded_files()), 2)

    # --- 5: unsupported / unsafe extensions are refused -----------------

    def test_reject_unsupported_extensions(self):
        cases = (
            ("photo.gif", PNG_BYTES),
            ("drawing.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'),
            ("page.html", b"<html><body>not an image</body></html>"),
            ("program.exe", b"MZ\x90\x00rule"),
            ("notes.txt", JPEG_BYTES),
        )
        for filename, payload in cases:
            with self.subTest(filename=filename):
                response = self.upload(filename, payload)
                self.assertEqual(response.status_code, 200)
                self.assertIn(
                    "That file type is not supported", response.get_data(as_text=True)
                )
                self.assertEqual(self.report_count(), 0, f"{filename} must not create a report")
                self.assertEqual(self.uploaded_files(), [])

    # --- 6: a renamed text file is refused ------------------------------

    def test_reject_invalid_image_content(self):
        response = self.upload("fake.jpg", b"this is just text, not a photograph")
        self.assertEqual(response.status_code, 200)
        self.assertIn("does not look like a real image", response.get_data(as_text=True))
        self.assertEqual(self.report_count(), 0)
        self.assertEqual(self.uploaded_files(), [])

    # --- 7: the 5 MB limit is enforced on the server --------------------

    def test_reject_file_larger_than_five_megabytes(self):
        oversized = JPEG_BYTES + b"\x00" * (5 * 1024 * 1024)
        self.assertGreater(len(oversized), 5 * 1024 * 1024)

        response = self.upload("huge.jpg", oversized)
        self.assertEqual(response.status_code, 200)
        self.assertIn("larger than 5 MB", response.get_data(as_text=True))
        self.assertEqual(self.report_count(), 0)
        self.assertEqual(self.uploaded_files(), [])

    # --- 8: the edit page shows the current photograph ------------------

    def test_edit_page_shows_current_photo(self):
        self.upload("photo.jpg", JPEG_BYTES)
        item_id = self.newest_id()
        filename = self.stored_photo()

        html = self.client.get(f"/reports/{item_id}/edit").get_data(as_text=True)
        self.assertIn("Current photograph", html)
        self.assertIn(f'src="/static/uploads/reports/{filename}"', html)

    # --- 9: editing other fields keeps the photo ------------------------

    def test_edit_without_replacement_keeps_photo(self):
        self.upload("photo.jpg", JPEG_BYTES)
        item_id = self.newest_id()
        original = self.stored_photo()

        data = dict(VALID_REPORT)
        data["csrf_token"] = self.csrf(f"/reports/{item_id}/edit")
        data["location"] = "Library, 3rd floor"
        response = self.client.post(f"/reports/{item_id}/edit", data=data)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.stored_photo(item_id), original)
        self.assertIn(original, self.uploaded_files())
        with self.app.app_context():
            self.assertEqual(
                db.session.get(ItemReport, item_id).location, "Library, 3rd floor"
            )

    # --- 10-11: replacing a photo --------------------------------------

    def test_replace_photo(self):
        self.upload("photo.jpg", JPEG_BYTES)
        item_id = self.newest_id()
        old_name = self.stored_photo()

        response = self.edit_with_image(item_id, "replacement.png", PNG_BYTES)
        self.assertEqual(response.status_code, 302)

        new_name = self.stored_photo(item_id)
        self.assertNotEqual(new_name, old_name)
        self.assertTrue(new_name.endswith(".png"))
        self.assertIn(new_name, self.uploaded_files())

        html = self.client.get("/browse").get_data(as_text=True)
        self.assertIn(f'src="/static/uploads/reports/{new_name}"', html)
        self.assertNotIn(old_name, html)

    # --- 11: the replaced file is removed from disk ---------------------

    def test_replace_removes_the_old_file(self):
        self.upload("photo.jpg", JPEG_BYTES)
        item_id = self.newest_id()
        old_name = self.stored_photo()

        self.edit_with_image(item_id, "replacement.webp", WEBP_BYTES)

        files = self.uploaded_files()
        self.assertNotIn(old_name, files, "the replaced photograph must be deleted")
        self.assertEqual(files, [self.stored_photo(item_id)])

    # --- 12: a failed replacement changes nothing ----------------------

    def test_failed_replacement_keeps_the_old_photo(self):
        self.upload("photo.jpg", JPEG_BYTES)
        item_id = self.newest_id()
        original = self.stored_photo()

        response = self.edit_with_image(item_id, "broken.jpg", b"not really a photo")
        self.assertEqual(response.status_code, 200)
        self.assertIn("does not look like a real image", response.get_data(as_text=True))

        self.assertEqual(self.stored_photo(item_id), original)
        self.assertEqual(self.uploaded_files(), [original])

    # --- 13: deleting a report deletes its photo -----------------------

    def test_delete_report_removes_its_photo(self):
        self.upload("photo.jpg", JPEG_BYTES)
        item_id = self.newest_id()
        filename = self.stored_photo()
        self.assertIn(filename, self.uploaded_files())

        response = self.client.post(
            f"/reports/{item_id}/delete", data={"csrf_token": self.csrf("/my-reports")}
        )
        self.assertEqual(response.status_code, 302)

        self.assertEqual(self.report_count(), 0)
        self.assertEqual(self.uploaded_files(), [])

    # --- 14: anonymous visitors cannot upload --------------------------

    def test_upload_requires_login(self):
        self.logout()

        data = dict(VALID_REPORT)
        data["csrf_token"] = self.csrf("/login")
        data["image"] = (BytesIO(JPEG_BYTES), "photo.jpg")
        response = self.client.post(
            "/report", data=data, content_type="multipart/form-data"
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        self.assertEqual(self.report_count(), 0)
        self.assertEqual(self.uploaded_files(), [])

    # --- 15: another student cannot touch the photo --------------------

    def test_other_student_cannot_replace_or_delete_photo(self):
        self.upload("photo.jpg", JPEG_BYTES)
        item_id = self.newest_id()
        original = self.stored_photo()

        self.become_other_student()

        # The edit page itself is refused, so the other student has no form;
        # they can still try the POST directly, with a token from their own page.
        blocked = self.client.get(f"/reports/{item_id}/edit")
        self.assertEqual(blocked.status_code, 302)

        data = dict(VALID_REPORT)
        data["csrf_token"] = self.csrf("/browse")
        data["image"] = (BytesIO(PNG_BYTES), "evil.png")
        response = self.client.post(
            f"/reports/{item_id}/edit", data=data, content_type="multipart/form-data"
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.stored_photo(item_id), original)
        self.assertEqual(self.uploaded_files(), [original])

        response = self.client.post(
            f"/reports/{item_id}/delete", data={"csrf_token": self.csrf("/browse")}
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.report_count(), 1)
        self.assertEqual(self.uploaded_files(), [original])

    # --- 16: reports saved before the column existed keep working ------

    def test_legacy_report_without_photo_and_idempotent_migration(self):
        self.post_report()
        with self.app.app_context():
            self.assertIsNone(ItemReport.query.one().image_filename)

        # Starting the app again must not add the column a second time.
        restarted = self.restart_app()
        with restarted.app_context():
            columns = [
                row[1]
                for row in db.session.execute(
                    db.text("PRAGMA table_info(item_report)")
                ).fetchall()
            ]
            self.assertEqual(columns.count("image_filename"), 1)
            self.assertEqual(ItemReport.query.count(), 1)
            db.session.remove()
            db.engine.dispose()

        html = self.client.get("/browse").get_data(as_text=True)
        self.assertIn("Black wireless earbuds", html)
        self.assertIn("No photograph", html)


class Phase8ClaimTests(PortalTestBase):
    """Phase 8: claiming found items and the owner's handover decisions."""

    def setUp(self):
        super().setUp()
        self.register()  # Student A owns the reports
        self.login()
        self.found_id = self.create_report("Blue water bottle", "Found", "Other")

    # --- helpers ------------------------------------------------------

    def create_report(self, title, report_type="Found", category="Other", **extra):
        """Post a report as the signed-in student and return its id."""
        data = dict(VALID_REPORT)
        data.update({"title": title, "report_type": report_type, "category": category})
        data.update(extra)
        data["csrf_token"] = self.csrf("/report")
        self.client.post("/report", data=data)
        with self.app.app_context():
            return (
                ItemReport.query.filter_by(title=title)
                .order_by(ItemReport.id.desc())
                .first()
                .id
            )

    def token(self):
        """A valid CSRF token for the current session (signed in or not)."""
        page = self.client.get("/report")
        if page.status_code != 200:
            page = self.client.get("/login")
        return CSRF_RE.search(page.get_data(as_text=True)).group(1)

    def sign_in_as(self, name, email):
        """Create the account if needed and sign in as that student."""
        if self.client.get("/dashboard").status_code == 200:
            self.logout()
        self.register(name=name, email=email)
        self.login(email=email)

    def switch_back_to_owner(self):
        """Sign back in as the existing Student A."""
        if self.client.get("/dashboard").status_code == 200:
            self.logout()
        self.login()

    def claim(self, item_id=None, message="I lost this bottle in the canteen; it has a dent.", token=None):
        item_id = self.found_id if item_id is None else item_id
        data = {"message": message}
        token = self.token() if token is None else token
        if token:
            data["csrf_token"] = token
        return self.client.post(f"/reports/{item_id}/claim", data=data)

    def decide(self, claim_id, action, token=None):
        data = {}
        token = self.token() if token is None else token
        if token:
            data["csrf_token"] = token
        return self.client.post(f"/claims/{claim_id}/{action}", data=data)

    def claim_for(self, report_id, email="b@college.edu"):
        with self.app.app_context():
            user = User.query.filter_by(email=email).one()
            return (
                Claim.query.filter_by(report_id=report_id, claimant_id=user.id)
                .order_by(Claim.id.desc())
                .first()
            )

    def claim_id_for(self, report_id, email="b@college.edu"):
        with self.app.app_context():
            user = User.query.filter_by(email=email).one()
            return Claim.query.filter_by(
                report_id=report_id, claimant_id=user.id
            ).one().id

    def claim_status(self, claim_id):
        with self.app.app_context():
            return db.session.get(Claim, claim_id).status

    def report_status(self, item_id=None):
        with self.app.app_context():
            return db.session.get(ItemReport, item_id or self.found_id).status

    def claim_count(self):
        with self.app.app_context():
            return Claim.query.count()

    # --- 1: a student can claim someone else's found item --------------
    def test_claim_submission_succeeds(self):
        self.sign_in_as("Student B", "b@college.edu")
        response = self.claim(message="It has my name written under the cap.")

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/my-claims"))

        with self.app.app_context():
            stored = Claim.query.one()
            self.assertEqual(stored.report_id, self.found_id)
            self.assertEqual(stored.message, "It has my name written under the cap.")
            self.assertEqual(stored.status, "Pending")
            self.assertEqual(stored.claimant.email, "b@college.edu")

        page = self.client.get("/my-claims").get_data(as_text=True)
        self.assertIn("Blue water bottle", page)
        self.assertIn("Pending", page)
        self.assertIn("has been sent to the owner", page)

    # --- 2: authentication is required ---------------------------------

    def test_claim_requires_login(self):
        self.logout()

        page = self.client.get(f"/reports/{self.found_id}/claim")
        self.assertEqual(page.status_code, 302)
        self.assertIn("/login", page.headers["Location"])

        response = self.claim()
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        self.assertEqual(self.claim_count(), 0)

    # --- 3: no self-claims ---------------------------------------------

    def test_cannot_claim_own_report(self):
        response = self.claim(message="This is my own report, but I will try anyway.")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.claim_count(), 0)

        page = self.client.get("/browse").get_data(as_text=True)
        self.assertIn("You cannot claim your own report.", page)

        page = self.client.get(f"/reports/{self.found_id}/claim")
        self.assertEqual(page.status_code, 302)

    # --- 4: only Found reports can be claimed --------------------------

    def test_cannot_claim_lost_report(self):
        lost_id = self.create_report("Lost wallet", "Lost", "Accessories")
        self.sign_in_as("Student B", "b@college.edu")

        response = self.claim(item_id=lost_id)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.claim_count(), 0)

        page = self.client.get("/browse", query_string={"status": "All"}).get_data(as_text=True)
        self.assertIn("Only found items can be claimed", page)

    # --- 5: returned reports cannot be claimed -------------------------

    def test_cannot_claim_returned_report(self):
        self.client.post(
            f"/reports/{self.found_id}/return", data={"csrf_token": self.token()}
        )
        self.assertEqual(self.report_status(), "Returned")

        self.sign_in_as("Student B", "b@college.edu")
        response = self.claim()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.claim_count(), 0)
        page = self.client.get("/browse", query_string={"status": "All"}).get_data(as_text=True)
        self.assertIn("already been returned", page)

    # --- 6: one claim per student per report ---------------------------

    def test_duplicate_claim_prevented(self):
        self.sign_in_as("Student B", "b@college.edu")

        self.claim()
        response = self.claim(message="Second attempt with a different story entirely.")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.claim_count(), 1)

        page = self.client.get("/browse").get_data(as_text=True)
        self.assertIn("already claimed this item", page)

    # --- 7: the explanation is validated -------------------------------

    def test_invalid_explanation_is_rejected(self):
        self.sign_in_as("Student B", "b@college.edu")

        cases = (
            ("", "Please explain why you believe this item is yours."),
            ("    ", "Please explain why you believe this item is yours."),
            ("too short", "at least 10 characters"),
            ("x" * 501, "under 500 characters"),
        )
        for message, expected in cases:
            with self.subTest(message=message[:20]):
                response = self.claim(message=message)
                self.assertEqual(response.status_code, 200)
                self.assertIn(expected, response.get_data(as_text=True))
                self.assertEqual(self.claim_count(), 0)

    # --- 8: the owner sees incoming claims -----------------------------

    def test_owner_sees_incoming_claims(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim(message="There is a sticker with my initials on the base.")
        self.switch_back_to_owner()

        page = self.client.get("/incoming-claims")
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)

        self.assertIn("Blue water bottle", html)
        self.assertIn("Student B", html)
        self.assertIn("There is a sticker with my initials on the base.", html)
        self.assertIn("Pending", html)
        self.assertIn("Approve", html)
        self.assertIn("Reject", html)

    # --- 9: unrelated students cannot see someone else's claims --------

    def test_non_owner_cannot_see_incoming_claims(self):
        secret = "My locker number is written on the bottom."
        self.sign_in_as("Student B", "b@college.edu")
        self.claim(message=secret)

        # Student B owns no reports, so their incoming queue is empty.
        html = self.client.get("/incoming-claims").get_data(as_text=True)
        self.assertIn("No claims yet", html)
        self.assertNotIn(secret, html)

        self.logout()
        page = self.client.get("/incoming-claims")
        self.assertEqual(page.status_code, 302)
        self.assertIn("/login", page.headers["Location"])

    # --- 10-11: approving a claim --------------------------------------

    def test_owner_can_approve_claim(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        claim_id = self.claim_id_for(self.found_id)
        self.switch_back_to_owner()

        response = self.decide(claim_id, "approve")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/incoming-claims"))

        self.assertEqual(self.claim_status(claim_id), "Approved")
        page = self.client.get("/incoming-claims").get_data(as_text=True)
        self.assertIn("approved", page)

    def test_approval_marks_report_returned(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        claim_id = self.claim_id_for(self.found_id)
        self.switch_back_to_owner()

        self.decide(claim_id, "approve")

        self.assertEqual(self.report_status(), "Returned")
        default_browse = self.client.get("/browse").get_data(as_text=True)
        # The success flash quotes the title, so check the card itself is gone.
        self.assertNotIn('<h3 class="h5 fw-bold mb-0">Blue water bottle</h3>', default_browse)
        returned = self.client.get("/browse", query_string={"status": "Returned"}).get_data(as_text=True)
        self.assertIn("Blue water bottle", returned)

    # --- 12: approving closes the other pending claims -----------------

    def test_approval_rejects_other_pending_claims(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        b_claim = self.claim_id_for(self.found_id)

        self.sign_in_as("Student C", "c@college.edu")
        self.claim(message="Actually it is mine, I left it after football practice.")
        c_claim = self.claim_id_for(self.found_id, "c@college.edu")

        self.switch_back_to_owner()
        self.decide(b_claim, "approve")

        self.assertEqual(self.claim_status(b_claim), "Approved")
        self.assertEqual(self.claim_status(c_claim), "Rejected")
        self.assertEqual(self.report_status(), "Returned")

    # --- 13-14: rejecting a claim --------------------------------------

    def test_owner_can_reject_claim(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        claim_id = self.claim_id_for(self.found_id)
        self.switch_back_to_owner()

        response = self.decide(claim_id, "reject")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.claim_status(claim_id), "Rejected")

        page = self.client.get("/incoming-claims").get_data(as_text=True)
        self.assertIn("rejected", page)

    def test_rejection_keeps_report_active(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        claim_id = self.claim_id_for(self.found_id)

        self.switch_back_to_owner()
        self.decide(claim_id, "reject")
        self.assertEqual(self.report_status(), "Active")

        # Another student may still claim the item afterwards.
        self.sign_in_as("Student C", "c@college.edu")
        self.claim(message="I think this is mine, my initials are on the lid.")
        self.assertEqual(self.claim_count(), 2)
        c_claim = self.claim_id_for(self.found_id, "c@college.edu")
        self.assertEqual(self.claim_status(c_claim), "Pending")

    # --- 15: only the report owner may decide ---------------------------

    def test_unauthorized_decisions_are_refused(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        claim_id = self.claim_id_for(self.found_id)

        # The claimant is not the owner.
        response = self.decide(claim_id, "approve")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/browse"))
        self.assertEqual(self.claim_status(claim_id), "Pending")

        self.decide(claim_id, "reject")
        self.assertEqual(self.claim_status(claim_id), "Pending")

        # A logged-out visitor cannot decide either.
        self.logout()
        self.decide(claim_id, "approve")
        self.assertEqual(self.claim_status(claim_id), "Pending")
        self.assertEqual(self.report_status(), "Active")

    # --- 16: a decided claim cannot be decided again --------------------

    def test_decisions_on_processed_claims_are_blocked(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        claim_id = self.claim_id_for(self.found_id)
        self.switch_back_to_owner()

        self.decide(claim_id, "approve")
        self.decide(claim_id, "reject")

        self.assertEqual(self.claim_status(claim_id), "Approved")
        self.assertEqual(self.report_status(), "Returned")
        page = self.client.get("/incoming-claims").get_data(as_text=True)
        self.assertIn("already been decided", page)

    # --- 17: no new claims once the item is returned --------------------

    def test_no_claims_after_approval(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        claim_id = self.claim_id_for(self.found_id)
        self.switch_back_to_owner()
        self.decide(claim_id, "approve")

        self.sign_in_as("Student C", "c@college.edu")
        response = self.claim(message="I would like to claim this too, it is mine.")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.claim_count(), 1)
        page = self.client.get("/browse", query_string={"status": "All"}).get_data(as_text=True)
        self.assertIn("already been returned", page)

    # --- 18: CSRF protection on claims and decisions --------------------

    def test_claim_and_decision_require_csrf(self):
        self.sign_in_as("Student B", "b@college.edu")

        response = self.claim(token="")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.claim_count(), 0)

        self.claim()
        claim_id = self.claim_id_for(self.found_id)
        self.switch_back_to_owner()

        self.assertEqual(self.decide(claim_id, "approve", token="").status_code, 400)
        self.assertEqual(self.claim_status(claim_id), "Pending")

        self.assertEqual(self.decide(claim_id, "reject", token="forged").status_code, 400)
        self.assertEqual(self.claim_status(claim_id), "Pending")
        self.assertEqual(self.report_status(), "Active")

    # --- 19: the migration keeps reports and photographs ----------------

    def test_migration_keeps_reports_and_images(self):
        data = dict(VALID_REPORT)
        data.update({"title": "Umbrella with photo", "report_type": "Found"})
        data["csrf_token"] = self.csrf("/report")
        data["image"] = (BytesIO(JPEG_BYTES), "umbrella.jpg")
        self.client.post("/report", data=data, content_type="multipart/form-data")

        with self.app.app_context():
            photo = ItemReport.query.filter_by(title="Umbrella with photo").one().image_filename
            reports_before = ItemReport.query.count()
        self.assertIsNotNone(photo)
        self.assertTrue(os.path.isfile(os.path.join(self.upload_dir, photo)))

        # Starting the app again re-runs the Phase 7 and Phase 8 migrations.
        restarted = self.restart_app()
        with restarted.app_context():
            tables = [
                row[0]
                for row in db.session.execute(
                    db.text("SELECT name FROM sqlite_master WHERE type='table'")
                ).fetchall()
            ]
            self.assertEqual(tables.count("claim"), 1)
            columns = [
                row[1]
                for row in db.session.execute(db.text("PRAGMA table_info(claim)")).fetchall()
            ]
            for expected in ("id", "report_id", "claimant_id", "message", "status", "created_at"):
                self.assertIn(expected, columns)
            self.assertEqual(ItemReport.query.count(), reports_before)
            self.assertEqual(
                ItemReport.query.filter_by(title="Umbrella with photo").one().image_filename,
                photo,
            )
            db.session.remove()
            db.engine.dispose()

        self.assertTrue(os.path.isfile(os.path.join(self.upload_dir, photo)))

    # --- 20: My Claims shows every status -------------------------------

    def test_my_claims_shows_all_statuses(self):
        first = self.create_report("Steel bottle", "Found", "Other")
        second = self.create_report("Grey hoodie", "Found", "Accessories")
        third = self.create_report("USB drive", "Found", "Electronics")

        self.sign_in_as("Student B", "b@college.edu")
        for report_id, message in (
            (first, "My bottle has a blue cap and a dent."),
            (second, "My hoodie has my name inside the collar."),
            (third, "My drive has a red sticker on it."),
        ):
            self.claim(item_id=report_id, message=message)

        self.switch_back_to_owner()
        self.decide(self.claim_id_for(first), "approve")
        self.decide(self.claim_id_for(second), "reject")

        self.sign_in_as("Student B", "b@college.edu")
        html = self.client.get("/my-claims").get_data(as_text=True)

        for title in ("Steel bottle", "Grey hoodie", "USB drive"):
            self.assertIn(title, html)
        self.assertIn("Approved", html)
        self.assertIn("Rejected", html)
        self.assertIn("Pending", html)
        self.assertIn("The owner approved your claim", html)
        self.assertIn("The owner rejected this claim", html)


class Phase9NotificationTests(PortalTestBase):
    """Phase 9: the notification centre and the bell counter."""

    def setUp(self):
        super().setUp()
        self.register()  # Student A owns the report
        self.login()
        self.found_id = self.create_report("Blue water bottle")

    # --- helpers ------------------------------------------------------

    def create_report(self, title, report_type="Found", category="Other", **extra):
        data = dict(VALID_REPORT)
        data.update({"title": title, "report_type": report_type, "category": category})
        data.update(extra)
        data["csrf_token"] = self.csrf("/report")
        self.client.post("/report", data=data)
        with self.app.app_context():
            return (
                ItemReport.query.filter_by(title=title)
                .order_by(ItemReport.id.desc())
                .first()
                .id
            )

    def token(self):
        page = self.client.get("/report")
        if page.status_code != 200:
            page = self.client.get("/login")
        return CSRF_RE.search(page.get_data(as_text=True)).group(1)

    def sign_in_as(self, name, email):
        if self.client.get("/dashboard").status_code == 200:
            self.logout()
        self.register(name=name, email=email)
        self.login(email=email)

    def switch_back_to_owner(self):
        if self.client.get("/dashboard").status_code == 200:
            self.logout()
        self.login()

    def claim(self, item_id=None, message="It has my initials written on the base.", token=None):
        item_id = self.found_id if item_id is None else item_id
        data = {"message": message}
        token = self.token() if token is None else token
        if token:
            data["csrf_token"] = token
        return self.client.post(f"/reports/{item_id}/claim", data=data)

    def decide(self, claim_id, action):
        return self.client.post(
            f"/claims/{claim_id}/{action}", data={"csrf_token": self.token()}
        )

    def claim_id_for(self, email="b@college.edu"):
        with self.app.app_context():
            user = User.query.filter_by(email=email).one()
            return Claim.query.filter_by(
                report_id=self.found_id, claimant_id=user.id
            ).one().id

    def notes(self, email):
        """Plain dicts so nothing touches a closed session."""
        with self.app.app_context():
            user = User.query.filter_by(email=email).one()
            rows = (
                Notification.query.filter_by(user_id=user.id)
                .order_by(Notification.id)
                .all()
            )
            return [
                {
                    "id": note.id,
                    "title": note.title,
                    "message": note.message,
                    "type": note.notification_type,
                    "is_read": note.is_read,
                    "claim_id": note.claim_id,
                    "report_id": note.report_id,
                }
                for note in rows
            ]

    def note_count(self):
        with self.app.app_context():
            return Notification.query.count()

    def badge(self):
        """The navbar unread number, or None when the badge is hidden."""
        html = self.client.get("/browse").get_data(as_text=True)
        match = re.search(r'notification-count">(\d+)<', html)
        return match.group(1) if match else None

    # --- 1-2: a claim notifies the owner exactly once -------------------

    def test_claim_notifies_the_owner(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim(message="There is a sticker with my initials on the base.")

        notes = self.notes("student@college.edu")
        self.assertEqual(len(notes), 1)
        note = notes[0]

        self.assertEqual(note["type"], "claim_received")
        self.assertIn("Student B", note["message"])
        self.assertIn("Blue water bottle", note["message"])
        self.assertEqual(note["report_id"], self.found_id)
        self.assertEqual(note["claim_id"], self.claim_id_for("b@college.edu"))
        self.assertFalse(note["is_read"])

    def test_refreshing_pages_does_not_duplicate_notifications(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        self.switch_back_to_owner()

        for _ in range(3):
            self.client.get("/notifications")
            self.client.get("/incoming-claims")

        self.assertEqual(self.note_count(), 1)

    # --- 3-4: decisions notify the claimant ----------------------------

    def test_approval_notifies_the_claimant(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        claim_id = self.claim_id_for()
        self.switch_back_to_owner()
        self.decide(claim_id, "approve")

        notes = self.notes("b@college.edu")
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["type"], "claim_approved")
        self.assertIn("approved", notes[0]["message"])
        self.assertIn("Blue water bottle", notes[0]["message"])
        self.assertEqual(notes[0]["claim_id"], claim_id)
        self.assertFalse(notes[0]["is_read"])

    def test_rejection_notifies_the_claimant(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        claim_id = self.claim_id_for()
        self.switch_back_to_owner()
        self.decide(claim_id, "reject")

        notes = self.notes("b@college.edu")
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["type"], "claim_rejected")
        self.assertIn("rejected", notes[0]["message"])
        self.assertIn("still available", notes[0]["message"])

    # --- 5: automatic rejections notify their claimants ----------------

    def test_auto_rejection_notifies_the_other_claimant(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        b_claim = self.claim_id_for("b@college.edu")

        self.sign_in_as("Student C", "c@college.edu")
        self.claim(message="Actually it is mine, I left it after practice.")

        self.switch_back_to_owner()
        self.decide(b_claim, "approve")

        c_notes = self.notes("c@college.edu")
        self.assertEqual(len(c_notes), 1)
        self.assertEqual(c_notes[0]["type"], "claim_rejected_auto")
        self.assertIn("approved", c_notes[0]["message"])
        with self.app.app_context():
            c_user = User.query.filter_by(email="c@college.edu").one()
            c_claim = Claim.query.filter_by(claimant_id=c_user.id).one()
            self.assertEqual(c_claim.status, "Rejected")

    def test_owner_is_not_notified_of_their_own_decisions(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        claim_id = self.claim_id_for()
        self.switch_back_to_owner()
        self.decide(claim_id, "approve")

        owner_notes = self.notes("student@college.edu")
        self.assertEqual(len(owner_notes), 1)
        self.assertEqual(owner_notes[0]["type"], "claim_received")

    # --- 6-7: the centre page, ordering and the bell --------------------

    def test_notifications_are_listed_newest_first(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim(message="First claim from B about the bottle.")
        self.sign_in_as("Student C", "c@college.edu")
        self.claim(message="Second claim from C about the bottle.")

        self.switch_back_to_owner()
        html = self.client.get("/notifications").get_data(as_text=True)
        self.assertLess(
            html.index("Student C claimed"),
            html.index("Student B claimed"),
            "the newest notification must come first",
        )

    def test_unread_counter_shows_and_hides(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        self.switch_back_to_owner()

        html = self.client.get("/browse").get_data(as_text=True)
        self.assertIn("bi-bell", html)
        self.assertEqual(self.badge(), "1")

        note_id = self.notes("student@college.edu")[0]["id"]
        self.client.post(
            f"/notifications/{note_id}/read", data={"csrf_token": self.token()}
        )
        self.assertIsNone(self.badge())

    def test_page_shows_item_title_and_links(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        claim_id = self.claim_id_for()
        self.switch_back_to_owner()

        html = self.client.get("/notifications").get_data(as_text=True)
        self.assertIn("Blue water bottle", html)
        self.assertIn('href="/incoming-claims"', html)
        self.assertIn("Review the claim", html)
        self.assertIn("New", html)

        self.decide(claim_id, "approve")
        self.sign_in_as("Student B", "b@college.edu")
        html = self.client.get("/notifications").get_data(as_text=True)
        self.assertIn('href="/my-claims"', html)
        self.assertIn("View my claims", html)
        self.assertIn("Your claim was approved", html)

    # --- 8-9: marking notifications as read ----------------------------

    def test_mark_one_notification_as_read(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        self.switch_back_to_owner()
        note_id = self.notes("student@college.edu")[0]["id"]

        response = self.client.post(
            f"/notifications/{note_id}/read", data={"csrf_token": self.token()}
        )
        self.assertEqual(response.status_code, 302)

        self.assertTrue(self.notes("student@college.edu")[0]["is_read"])
        html = self.client.get("/notifications").get_data(as_text=True)
        self.assertIn("New claim on your found item", html)
        self.assertIn("notification-read", html)

    def test_mark_all_notifications_as_read(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim(message="Claim from B with a longer explanation.")
        self.sign_in_as("Student C", "c@college.edu")
        self.claim(message="Claim from C with a longer explanation.")
        self.switch_back_to_owner()
        self.assertEqual(self.badge(), "2")

        response = self.client.post(
            "/notifications/read-all", data={"csrf_token": self.token()}
        )
        self.assertEqual(response.status_code, 302)

        # Read the flash first: badge() renders a page and would consume it.
        page = self.client.get("/notifications").get_data(as_text=True)
        self.assertIn("marked as read", page)

        unread = [note for note in self.notes("student@college.edu") if not note["is_read"]]
        self.assertEqual(unread, [])
        self.assertIsNone(self.badge())

    # --- 10-11: privacy and login --------------------------------------

    def test_cannot_mark_another_users_notification(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        owner_note = self.notes("student@college.edu")[0]["id"]

        # B is still signed in and must not be able to touch A's notification.
        response = self.client.post(
            f"/notifications/{owner_note}/read", data={"csrf_token": self.token()}
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(self.notes("student@college.edu")[0]["is_read"])

        page = self.client.get("/notifications").get_data(as_text=True)
        self.assertIn("could not be found", page)

    def test_notifications_require_login(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        owner_note = self.notes("student@college.edu")[0]["id"]
        self.logout()

        response = self.client.get("/notifications")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

        # A valid token is needed so login_required (not CSRF) answers.
        response = self.client.post(
            "/notifications/read-all", data={"csrf_token": self.token()}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

        response = self.client.post(
            f"/notifications/{owner_note}/read", data={"csrf_token": self.token()}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        self.assertFalse(self.notes("student@college.edu")[0]["is_read"])

    # --- 12: CSRF protection -------------------------------------------

    def test_marking_read_requires_csrf(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        self.switch_back_to_owner()
        note_id = self.notes("student@college.edu")[0]["id"]

        self.assertEqual(
            self.client.post(f"/notifications/{note_id}/read").status_code, 400
        )
        self.assertEqual(self.client.post("/notifications/read-all").status_code, 400)
        self.assertFalse(self.notes("student@college.edu")[0]["is_read"])

    # --- 13-15: empty state, cleanup and the migration -----------------

    def test_empty_state(self):
        self.sign_in_as("Student C", "c@college.edu")
        html = self.client.get("/notifications").get_data(as_text=True)
        self.assertIn("No notifications yet", html)
        self.assertIsNone(self.badge())

    def test_deleting_a_report_removes_its_notifications(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        self.switch_back_to_owner()
        self.assertEqual(self.note_count(), 1)

        self.client.post(
            f"/reports/{self.found_id}/delete", data={"csrf_token": self.token()}
        )

        self.assertEqual(self.note_count(), 0)
        with self.app.app_context():
            self.assertEqual(Claim.query.count(), 0)

    def test_migration_is_idempotent_and_preserves_data(self):
        self.sign_in_as("Student B", "b@college.edu")
        self.claim()
        self.assertEqual(self.note_count(), 1)

        restarted = self.restart_app()
        with restarted.app_context():
            tables = [
                row[0]
                for row in db.session.execute(
                    db.text("SELECT name FROM sqlite_master WHERE type='table'")
                ).fetchall()
            ]
            self.assertEqual(tables.count("notification"), 1)
            columns = [
                row[1]
                for row in db.session.execute(
                    db.text("PRAGMA table_info(notification)")
                ).fetchall()
            ]
            for expected in (
                "id",
                "user_id",
                "claim_id",
                "report_id",
                "title",
                "message",
                "notification_type",
                "is_read",
                "created_at",
            ):
                self.assertIn(expected, columns)
            self.assertEqual(User.query.count(), 2)
            self.assertEqual(ItemReport.query.count(), 1)
            self.assertEqual(Claim.query.count(), 1)
            self.assertEqual(Notification.query.count(), 1)
            db.session.remove()
            db.engine.dispose()


class Phase10AdminTests(PortalTestBase):
    """Phase 10: administrator role, moderation and oversight."""

    def setUp(self):
        super().setUp()
        self.register()  # Student A, the report owner
        self.login()
        self.found_id = self.create_report("Blue water bottle", "Found")

    # --- helpers ------------------------------------------------------

    def create_report(self, title, report_type="Found", category="Other", image=False):
        data = dict(VALID_REPORT)
        data.update({"title": title, "report_type": report_type, "category": category})
        data["csrf_token"] = self.csrf("/report")
        if image:
            data["image"] = (BytesIO(JPEG_BYTES), "photo.jpg")
            self.client.post("/report", data=data, content_type="multipart/form-data")
        else:
            self.client.post("/report", data=data)
        with self.app.app_context():
            return (
                ItemReport.query.filter_by(title=title)
                .order_by(ItemReport.id.desc())
                .first()
                .id
            )

    def add_student(self, name, email, admin=False, active=True, password="secret123"):
        """Create an account directly, without touching the current session."""
        with self.app.app_context():
            db.session.add(
                User(
                    name=name,
                    email=email,
                    password_hash=generate_password_hash(password),
                    is_admin=admin,
                    is_active=active,
                )
            )
            db.session.commit()

    def promote(self, email="student@college.edu"):
        with self.app.app_context():
            account = User.query.filter_by(email=email).one()
            account.is_admin = True
            db.session.commit()

    def flag(self, email, field):
        with self.app.app_context():
            return getattr(User.query.filter_by(email=email).one(), field)

    def user_id(self, email):
        with self.app.app_context():
            return User.query.filter_by(email=email).one().id

    def token(self):
        page = self.client.get("/report")
        if page.status_code != 200:
            page = self.client.get("/login")
        return CSRF_RE.search(page.get_data(as_text=True)).group(1)

    def login_as(self, email, password="secret123"):
        if self.client.get("/dashboard").status_code == 200:
            self.logout()
        return self.login(email=email, password=password)

    def back_to_owner(self):
        self.login_as("student@college.edu")

    def claim_as(self, email, item_id, message="It is mine, my initials are on it."):
        self.login_as(email)
        self.client.post(
            f"/reports/{item_id}/claim",
            data={"csrf_token": self.token(), "message": message},
        )

    def stats(self):
        html = self.client.get("/admin").get_data(as_text=True)
        numbers = re.findall(r'<h2 class="h4 fw-bold mt-3 mb-0">(\d+)</h2>', html)
        self.assertEqual(len(numbers), 8, numbers)
        return [int(value) for value in numbers]

    # --- 1-3: migration and the promotion command -----------------------

    def test_existing_users_stay_ordinary_students_after_migration(self):
        self.assertFalse(self.flag("student@college.edu", "is_admin"))
        self.assertTrue(self.flag("student@college.edu", "is_active"))

        restarted = self.restart_app()
        with restarted.app_context():
            account = User.query.one()
            self.assertFalse(account.is_admin, "the migration must never promote anyone")
            self.assertTrue(account.is_active)
            db.session.remove()
            db.engine.dispose()

    def test_migration_is_idempotent(self):
        first = self.restart_app()
        second = self.restart_app()
        # Dispose both engines, otherwise Windows keeps the temp file locked.
        with first.app_context():
            db.session.remove()
            db.engine.dispose()
        with second.app_context():
            columns = [
                row[1]
                for row in db.session.execute(db.text("PRAGMA table_info(user)")).fetchall()
            ]
            self.assertEqual(columns.count("is_admin"), 1)
            self.assertEqual(columns.count("is_active"), 1)
            self.assertEqual(User.query.count(), 1)
            self.assertEqual(ItemReport.query.count(), 1)
            db.session.remove()
            db.engine.dispose()

    def test_cli_promotes_an_existing_account(self):
        runner = self.app.test_cli_runner()

        result = runner.invoke(args=["promote-admin", "student@college.edu"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("now an administrator", result.output)
        self.assertTrue(self.flag("student@college.edu", "is_admin"))

        again = runner.invoke(args=["promote-admin", "student@college.edu"])
        self.assertIn("already an administrator", again.output)

        missing = runner.invoke(args=["promote-admin", "nobody@college.edu"])
        self.assertIn("No account found", missing.output)

    # --- 4-6: access control and statistics -----------------------------

    def test_admin_can_open_the_dashboard(self):
        self.promote()
        page = self.client.get("/admin")
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)
        self.assertIn("Admin overview", html)
        self.assertIn("Total students", html)
        self.assertIn("Pending claims", html)
        self.assertIn("Newest reports", html)

    def test_student_cannot_open_the_dashboard(self):
        page = self.client.get("/admin")
        self.assertEqual(page.status_code, 302)
        self.assertTrue(page.headers["Location"].endswith("/dashboard"))

        html = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn("Administrator access is required", html)

    def test_anonymous_visitor_is_redirected_to_login(self):
        self.logout()
        page = self.client.get("/admin")
        self.assertEqual(page.status_code, 302)
        self.assertIn("/login", page.headers["Location"])

    def test_statistics_reflect_real_records(self):
        self.add_student("Student B", "b@college.edu")
        self.create_report("Lost wallet", "Lost", "Accessories")
        self.claim_as("b@college.edu", self.found_id)
        self.back_to_owner()
        self.promote()

        # students, lost, found, active, returned, claims, pending, notifications
        self.assertEqual(self.stats(), [2, 1, 1, 2, 0, 1, 1, 1])

        with self.app.app_context():
            claim_id = Claim.query.one().id
        self.client.post(
            f"/claims/{claim_id}/approve", data={"csrf_token": self.token()}
        )
        self.assertEqual(self.stats(), [2, 1, 1, 1, 1, 1, 0, 2])

    # --- 7-13: user management ------------------------------------------

    def test_admin_can_view_user_management(self):
        self.add_student("Student B", "b@college.edu")
        self.promote()

        html = self.client.get("/admin/users").get_data(as_text=True)
        self.assertIn("student@college.edu", html)
        self.assertIn("b@college.edu", html)
        self.assertIn("Administrator", html)
        self.assertIn("Student", html)
        self.assertIn("Active", html)

    def test_admin_can_deactivate_another_student(self):
        self.add_student("Student B", "b@college.edu")
        self.promote()
        b_id = self.user_id("b@college.edu")

        response = self.client.post(
            f"/admin/users/{b_id}/toggle", data={"csrf_token": self.token()}
        )
        self.assertEqual(response.status_code, 302)

        self.assertFalse(self.flag("b@college.edu", "is_active"))
        html = self.client.get("/admin/users").get_data(as_text=True)
        self.assertIn("Deactivated", html)
        self.assertIn("reactivated" if False else "deactivated", html)

    def test_deactivated_user_cannot_log_in(self):
        self.add_student("Student B", "b@college.edu")
        self.promote()
        self.client.post(
            f"/admin/users/{self.user_id('b@college.edu')}/toggle",
            data={"csrf_token": self.token()},
        )

        # An existing session is dropped on the next request too.
        other = self.app.test_client()
        other.post(
            "/login",
            data={
                "csrf_token": CSRF_RE.search(
                    other.get("/login").get_data(as_text=True)
                ).group(1),
                "email": "b@college.edu",
                "password": "secret123",
            },
        )
        self.assertEqual(other.get("/dashboard").status_code, 302)

        self.logout()
        page = self.login(email="b@college.edu")
        self.assertEqual(page.status_code, 200)
        self.assertIn("deactivated", page.get_data(as_text=True))
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_admin_can_reactivate_a_student(self):
        self.add_student("Student B", "b@college.edu")
        self.promote()
        b_id = self.user_id("b@college.edu")

        self.client.post(f"/admin/users/{b_id}/toggle", data={"csrf_token": self.token()})
        self.assertFalse(self.flag("b@college.edu", "is_active"))

        self.client.post(f"/admin/users/{b_id}/toggle", data={"csrf_token": self.token()})
        self.assertTrue(self.flag("b@college.edu", "is_active"))

        response = self.login_as("b@college.edu")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/dashboard"))

    def test_admin_cannot_deactivate_themselves(self):
        self.add_student("Second Admin", "admin2@college.edu", admin=True)
        self.promote()

        response = self.client.post(
            f"/admin/users/{self.user_id('student@college.edu')}/toggle",
            data={"csrf_token": self.token()},
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(self.flag("student@college.edu", "is_active"))

        html = self.client.get("/admin/users").get_data(as_text=True)
        self.assertIn("You cannot deactivate your own account.", html)

    def test_last_active_administrator_cannot_be_deactivated(self):
        self.add_student("Second Admin", "admin2@college.edu", admin=True, active=False)
        self.promote()

        response = self.client.post(
            f"/admin/users/{self.user_id('student@college.edu')}/toggle",
            data={"csrf_token": self.token()},
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(self.flag("student@college.edu", "is_active"))
        self.assertTrue(self.flag("student@college.edu", "is_admin"))

        html = self.client.get("/admin/users").get_data(as_text=True)
        self.assertIn("last active administrator", html)

    # --- 14-18: report moderation ---------------------------------------

    def test_admin_can_view_reports_for_moderation(self):
        self.promote()
        html = self.client.get("/admin/reports").get_data(as_text=True)
        self.assertIn("Report moderation", html)
        self.assertIn("Blue water bottle", html)
        self.assertIn("Test Student", html)
        self.assertIn("Remove", html)

    def test_admin_can_remove_a_report(self):
        self.promote()
        response = self.client.post(
            f"/admin/reports/{self.found_id}/delete", data={"csrf_token": self.token()}
        )
        self.assertEqual(response.status_code, 302)

        with self.app.app_context():
            self.assertEqual(ItemReport.query.count(), 0)
        html = self.client.get("/admin/reports").get_data(as_text=True)
        self.assertIn("removed from the portal", html)

    def test_removal_handles_claims_and_notifications(self):
        self.add_student("Student B", "b@college.edu")
        self.claim_as("b@college.edu", self.found_id)
        self.back_to_owner()
        self.promote()

        with self.app.app_context():
            self.assertEqual(Claim.query.count(), 1)
            self.assertEqual(Notification.query.count(), 1)

        self.client.post(
            f"/admin/reports/{self.found_id}/delete", data={"csrf_token": self.token()}
        )

        with self.app.app_context():
            self.assertEqual(ItemReport.query.count(), 0)
            self.assertEqual(Claim.query.count(), 0)
            self.assertEqual(Notification.query.count(), 0)

    def test_removal_deletes_the_photograph(self):
        self.promote()
        item_id = self.create_report("Umbrella with photo", "Found", image=True)
        with self.app.app_context():
            photo = db.session.get(ItemReport, item_id).image_filename
        self.assertTrue(os.path.isfile(os.path.join(self.upload_dir, photo)))

        self.client.post(
            f"/admin/reports/{item_id}/delete", data={"csrf_token": self.token()}
        )

        self.assertFalse(os.path.isfile(os.path.join(self.upload_dir, photo)))
        with self.app.app_context():
            self.assertIsNone(db.session.get(ItemReport, item_id))

    def test_students_cannot_access_moderation(self):
        page = self.client.get("/admin/reports")
        self.assertEqual(page.status_code, 302)
        self.assertTrue(page.headers["Location"].endswith("/dashboard"))

        response = self.client.post(
            f"/admin/reports/{self.found_id}/delete", data={"csrf_token": self.token()}
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            self.assertEqual(ItemReport.query.count(), 1)

    # --- 18-20: claim oversight -----------------------------------------

    def test_admin_can_view_all_claims(self):
        self.add_student("Student B", "b@college.edu")
        self.add_student("Student C", "c@college.edu")
        hoodie = self.create_report("Grey hoodie", "Found", "Accessories")
        self.claim_as("b@college.edu", self.found_id)
        self.claim_as("c@college.edu", hoodie)
        self.back_to_owner()
        self.promote()

        html = self.client.get("/admin/claims").get_data(as_text=True)
        self.assertIn("Blue water bottle", html)
        self.assertIn("Grey hoodie", html)
        self.assertIn("Student B", html)
        self.assertIn("Student C", html)
        self.assertIn("Pending", html)

    def test_claim_filters_work(self):
        self.add_student("Student B", "b@college.edu")
        hoodie = self.create_report("Grey hoodie", "Found", "Accessories")
        drive = self.create_report("USB drive", "Found", "Electronics")
        self.claim_as("b@college.edu", self.found_id)
        self.claim_as("b@college.edu", hoodie)
        self.claim_as("b@college.edu", drive)
        self.back_to_owner()

        with self.app.app_context():
            ids = {
                report.title: claim.id
                for report, claim in [
                    (c.report, c) for c in Claim.query.all()
                ]
            }
        self.client.post(
            f"/claims/{ids['Blue water bottle']}/approve",
            data={"csrf_token": self.token()},
        )
        self.client.post(
            f"/claims/{ids['Grey hoodie']}/reject", data={"csrf_token": self.token()}
        )
        self.promote()

        approved = self.client.get(
            "/admin/claims", query_string={"status": "Approved"}
        ).get_data(as_text=True)
        self.assertIn("Blue water bottle", approved)
        self.assertNotIn("Grey hoodie", approved)

        rejected = self.client.get(
            "/admin/claims", query_string={"status": "Rejected"}
        ).get_data(as_text=True)
        self.assertIn("Grey hoodie", rejected)
        self.assertNotIn("USB drive", rejected)

        pending = self.client.get(
            "/admin/claims", query_string={"status": "Pending"}
        ).get_data(as_text=True)
        self.assertIn("USB drive", pending)
        self.assertNotIn("Blue water bottle", pending)

        everything = self.client.get(
            "/admin/claims", query_string={"status": "Bogus"}
        ).get_data(as_text=True)
        for title in ("Blue water bottle", "Grey hoodie", "USB drive"):
            self.assertIn(title, everything)

    def test_admin_cannot_decide_claims(self):
        self.add_student("Student B", "b@college.edu")
        self.add_student("Admin Three", "admin3@college.edu", admin=True)
        self.claim_as("b@college.edu", self.found_id)

        with self.app.app_context():
            claim_id = Claim.query.one().id

        self.login_as("admin3@college.edu")
        page = self.client.get("/admin/claims").get_data(as_text=True)
        self.assertNotIn(f"/claims/{claim_id}/approve", page)
        self.assertNotIn(f"/claims/{claim_id}/reject", page)

        response = self.client.post(
            f"/claims/{claim_id}/approve", data={"csrf_token": self.token()}
        )
        self.assertEqual(response.status_code, 302)

        with self.app.app_context():
            self.assertEqual(db.session.get(Claim, claim_id).status, "Pending")
            self.assertEqual(
                db.session.get(ItemReport, self.found_id).status, "Active"
            )

    # --- 21-23: CSRF, navigation and student features -------------------

    def test_admin_mutations_require_csrf(self):
        self.add_student("Student B", "b@college.edu")
        self.promote()
        b_id = self.user_id("b@college.edu")

        self.assertEqual(
            self.client.post(f"/admin/users/{b_id}/toggle").status_code, 400
        )
        self.assertTrue(self.flag("b@college.edu", "is_active"))

        self.assertEqual(
            self.client.post(f"/admin/reports/{self.found_id}/delete").status_code, 400
        )
        with self.app.app_context():
            self.assertEqual(ItemReport.query.count(), 1)

    def test_admin_link_is_only_shown_to_administrators(self):
        html = self.client.get("/browse").get_data(as_text=True)
        self.assertNotIn('href="/admin"', html)

        self.promote()
        html = self.client.get("/browse").get_data(as_text=True)
        self.assertIn('href="/admin"', html)

    def test_student_features_still_work(self):
        """A quick end-to-end smoke test next to the 109 existing tests."""
        self.add_student("Student B", "b@college.edu")
        self.claim_as("b@college.edu", self.found_id)
        self.back_to_owner()

        with self.app.app_context():
            claim_id = Claim.query.one().id
        self.client.post(
            f"/claims/{claim_id}/approve", data={"csrf_token": self.token()}
        )

        self.login_as("b@college.edu")
        html = self.client.get("/my-claims").get_data(as_text=True)
        self.assertIn("Approved", html)
        self.assertIn("Your claim was approved", self.client.get("/notifications").get_data(as_text=True))

        # And an ordinary student still posts a report with a photo.
        data = dict(VALID_REPORT)
        data.update({"title": "Student photo report", "report_type": "Found"})
        data["csrf_token"] = self.token()
        data["image"] = (BytesIO(JPEG_BYTES), "photo.jpg")
        response = self.client.post(
            "/report", data=data, content_type="multipart/form-data"
        )
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            self.assertIsNotNone(
                ItemReport.query.filter_by(title="Student photo report").one().image_filename
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)