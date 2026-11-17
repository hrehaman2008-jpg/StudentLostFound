# Student Lost & Found Portal

A small web application for a college campus. Students create an account, report
items they lost or found, search and filter every report, and mark their own
items as returned once they are back with their owner.

It is a **college demonstration project**: everything runs locally with one
Python command, the data lives in a single SQLite file, and there are no
external services to sign up for.

> **Current status — Phase 10 (Secure Admin Dashboard)**
> Students can register, log in and log out; post lost and found reports with
> an optional photograph; search and filter every report; see only their own
> reports; **edit or delete** their own reports; **claim** a found item that
> belongs to them; and follow the outcome through the **notification centre**
> and its unread bell. An optional **administrator** account gets real
> statistics, user management, report moderation and read-only claim
> oversight. Everything is stored in SQLite (`instance/lost_found.db`) and the
> photographs in `static/uploads/reports/`.

---

## Technologies used

| Layer | Technology |
|-------|------------|
| Language | Python 3 |
| Web framework | Flask (application factory, Jinja2 templates) |
| Database | SQLite via Flask-SQLAlchemy |
| Login / sessions | Flask-Login |
| Forms & security | Flask-WTF (`CSRFProtect`), Werkzeug password hashing |
| Front end | HTML, Bootstrap 5.3 + Bootstrap Icons (CDN), one custom stylesheet |

No JavaScript framework, no build step, no blueprints — just a few small files
that are easy to read and explain.

---

## Main features

1. **Student accounts** — register with name, college email and password
   (checked on the server, stored only as a Werkzeug hash), then log in and out.
2. **Protected dashboard** — shows only your own numbers: Total Reports,
   Lost Items, Found Items and Returned Items. Each counter is a link that
   opens the matching list.
3. **Report an item** — item name, Lost/Found, category (Electronics,
   ID Card, Books, Accessories, Keys, Other), description, location and date.
4. **Browse reports** — every student's reports as cards with a Lost/Found
   badge, an Active/Returned badge, category, description, location, date and
   who reported it. Public, so visitors can look before signing up.
5. **Search and filters** — one search box matches the item title, description
   or location (case-insensitive); filters for type (All/Lost/Found), category
   and status (All/Active/Returned). Search and filters combine, live in the
   URL (so a filtered view can be shared or refreshed) and have a Clear button.
6. **My reports** — only the reports you created.
7. **Mark as Returned** — the owner of an *active* report gets a button on the
   card. It is a CSRF-protected POST, ownership is checked on the server, and a
   returned report can never be switched back to Active.
8. **Edit a report** — the owner sees an **Edit** button on their own cards
   (Browse and My Reports). The edit page is the report form pre-filled with
   the current values, so the title, description, category, type, location and
   date can be corrected. Everything is validated again on the server, and the
   owner and the Active/Returned status are never changed by an edit.
9. **Delete a report** — the owner sees a **Delete** button next to Edit. It
   asks for confirmation, submits a CSRF-protected POST, and returns to My
   Reports with a success message. Other students can do neither.
10. **Friendly empty states** — separate messages for "nothing posted yet" and
   "nothing matches your search".

**Photographs** — every report may have one optional photograph. Accepted
formats are **JPG, JPEG, PNG and WEBP**, up to **5 MB**. The file is checked on
the server (extension *and* the file's own signature, so a renamed script or
SVG is refused), saved under a random name, and shown on the report card. A
placeholder appears when there is no photo. Replacing a photo deletes the old
file; deleting the report deletes its photo too.

**Claims and handover** — a logged-in student who did **not** post a Found
report can open its card and choose **Claim Item**, explaining why the item is
theirs. The owner reviews every claim on **Incoming Claims** (claimant name,
explanation, date, status) and approves or rejects it.

* **Approve** — the claim becomes Approved, the report becomes Returned, every
  other pending claim on that report is rejected, and no further claims are
  accepted.
* **Reject** — the claim becomes Rejected, the report stays Active, and other
  students may still claim it.

The student tracks their own claims on **My Claims**, with Pending (blue),
Approved (green) and Rejected (red) badges. Own reports, Lost reports and
returned reports cannot be claimed, and a student may claim a given report only
once (enforced by a unique database constraint).

**Notifications** — the navbar bell shows how many notifications are unread.
The centre at `/notifications` lists them newest first with a title, message,
date and time, the related item, and a link to the claim. They are created
automatically when someone claims your found item, when your own claim is
approved or rejected, and when your pending claim is closed because another
claim was approved first. Each one can be marked as read individually, or all
at once, and only its recipient can read or change it.

**Administrator dashboard** — an account with `is_admin` gets an **Admin**
link and four protected pages:

* **Overview** (`/admin`) — live totals for students, Lost/Found reports,
  active and returned reports, claims, pending claims and notifications, plus
  the newest students, reports and claims.
* **Users** (`/admin/users`) — every account with its role and status, and
  deactivate/reactivate buttons. Deactivation never deletes data, and an
  administrator can neither deactivate themselves nor the last active
  administrator.
* **Reports** (`/admin/reports`) — moderation list with the photograph and a
  confirmed **Remove** action that also deletes the photo, claims and
  notifications belonging to that report.
* **Claims** (`/admin/claims`) — read-only oversight with Pending / Approved /
  Rejected filters. Only the report owner can approve or reject.

Administrators are created only by an explicit local command — there is no
registration page and nobody is promoted automatically.

**Deliberately not included** (out of scope): email or push notifications,
chat, AI matching and payments.

---

## Project structure

```
StudentLostFound/
├── app.py                  # App factory, models, validation, all routes
├── vercel.json             # Vercel Python function settings
├── .vercelignore           # Excludes local/runtime-only files from builds
├── requirements.txt        # Python dependencies
├── test_app.py             # Automated tests (42 tests)
├── README.md               # This file
├── .gitignore
├── instance/
│   ├── .gitkeep
│   └── lost_found.db       # SQLite database (created on first run)
├── static/
│   ├── css/
│   │   └── style.css       # Navy + gold campus theme
│   └── uploads/
│       └── reports/        # Uploaded item photographs (created at runtime)
└── templates/
    ├── base.html           # Shared layout: navbar, flash messages, footer
    ├── index.html          # Home page
    ├── login.html          # Login form
    ├── register.html       # Registration form
    ├── dashboard.html      # Student dashboard with counters
    ├── report.html         # Report an item form
    ├── edit_report.html    # Edit form (same design, pre-filled)
    ├── browse.html         # Search bar, filters and report cards
    ├── my_reports.html     # The logged-in student's own reports
    ├── claim_form.html     # Claim request form for a found item
    ├── my_claims.html      # Claims this student has sent
    ├── incoming_claims.html # Claims on this student's own reports
    ├── notifications.html  # Notification centre with read/unread states
    ├── admin_dashboard.html # Admin overview: statistics and recent activity
    ├── admin_users.html    # Admin user management
    ├── admin_reports.html  # Admin report moderation
    ├── admin_claims.html   # Admin read-only claim oversight
    ├── _admin_tabs.html    # Shared admin tab navigation
    ├── _claim_badge.html   # Pending / Approved / Rejected badge
    └── _report_card.html   # Shared card partial used by both list pages
```

---

## Installation (Windows)

Open **Command Prompt** or **PowerShell** in the project folder.

1. Create a virtual environment (first time only):

   ```bat
   py -m venv venv
   ```

2. Activate it:

   ```bat
   venv\Scripts\activate
   ```

   PowerShell: `venv\Scripts\Activate.ps1`

3. Install the dependencies:

   ```bat
   pip install -r requirements.txt
   ```

4. (Optional) set your own secret key:

   ```bat
   set SECRET_KEY=any-long-random-string
   ```

   PowerShell: `$env:SECRET_KEY = "any-long-random-string"`

   If you skip this, `app.py` falls back to a development-only key. That is
   fine for a demo on your own laptop — never use it on a real website.

---

## How to run the application

```bat
python app.py
```

Then open <http://127.0.0.1:5000/> in your browser. The database file and its
tables are created automatically the first time the app starts. Press
`Ctrl + C` in the terminal to stop the server.

> The app runs with Flask's debug mode on, which is convenient while
> demonstrating (changes reload instantly). Turn it off before showing the app
> to anyone outside your machine.

---

## Deploying on Vercel

The root `app.py` exports the Flask application Vercel detects. Import this
GitHub repository in Vercel with the project root left at the repository root;
no custom build command or output directory is needed.

Set `SECRET_KEY` in Vercel's environment variables before the first deployment.
The app refuses to start on Vercel without it. For data that must survive
deployments and function restarts, also set `DATABASE_URL` to a PostgreSQL
database. The included PostgreSQL driver supports `postgres://` and
`postgresql://` URLs.

If `DATABASE_URL` is omitted, Vercel uses SQLite in `/tmp` for a short demo.
That database is temporary and may reset between function instances. Uploaded
photos also use `/tmp` on Vercel, so they are temporary. Use durable object
storage for photos before relying on the portal for real campus reports.

---

## Administrator setup (Phase 10)

Administrator rights are never granted automatically, and there is no admin
registration page. Promote one existing account from a terminal on the machine
that runs the app:

```bat
venv\Scripts\activate
flask --app app promote-admin you@college.edu
```

* The account must already exist — register it through the normal Register page
  first.
* The command only sets that account's `is_admin` flag. It never creates an
  account, never sets a password and never prints credentials.
* Running it twice is harmless: the second run answers
  “already an administrator”.
* To undo it, set `is_admin = 0` for that row in SQLite.
* Existing students (including Hinata Shoyo and Kageyama Tobio) stay ordinary
  students unless you deliberately run the command for their email.

Only administrators see the **Admin** link in the navbar. Every admin route
re-checks `is_admin` on the server, so a student who types the URL is sent back
to their dashboard and an anonymous visitor is sent to the login page.

---

## Main application routes

| Route | Method | Login | What it does |
|-------|--------|-------|--------------|
| `/` | GET | No | Home page with intro and call-to-action buttons |
| `/register` | GET, POST | No | Create a student account |
| `/login` | GET, POST | No | Sign in |
| `/logout` | POST | No | Sign out (CSRF protected) |
| `/dashboard` | GET | Yes | Your report counters and quick actions |
| `/report` | GET, POST | Yes | Post a lost or found item |
| `/browse` | GET | No | All reports + search & filters (`?q=&report_type=&category=&status=`) |
| `/my-reports` | GET | Yes | Only your own reports |
| `/reports/<id>/return` | POST | Yes, owner | Mark one of your active reports as Returned |
| `/reports/<id>/edit` | GET, POST | Yes, owner | Edit one of your own reports |
| `/reports/<id>/delete` | POST | Yes, owner | Delete one of your own reports |
| `/reports/<id>/claim` | GET, POST | Yes | Claim someone else's active Found report |
| `/my-claims` | GET | Yes | Claims you have sent, with their status |
| `/incoming-claims` | GET | Yes | Claims other students sent for your reports |
| `/claims/<id>/approve` | POST | Yes, report owner | Approve a claim, mark the item returned, close the others |
| `/claims/<id>/reject` | POST | Yes, report owner | Reject a claim; the item stays active |
| `/notifications` | GET | Yes | Your notification centre, newest first |
| `/notifications/<id>/read` | POST | Yes, owner | Mark one of your notifications as read |
| `/notifications/read-all` | POST | Yes, owner | Mark all of your notifications as read |
| `/admin` | GET | Admin | Live portal statistics and recent activity |
| `/admin/users` | GET | Admin | User management with roles and status |
| `/admin/users/<id>/toggle` | POST | Admin | Deactivate or reactivate an account |
| `/admin/reports` | GET | Admin | Report moderation list |
| `/admin/reports/<id>/delete` | POST | Admin | Remove a report with its photo, claims and notifications |
| `/admin/claims` | GET | Admin | Read-only claim oversight (`?status=Pending|Approved|Rejected`) |

Example filtered URLs:

```
/browse?q=id+card
/browse?report_type=Lost
/browse?category=Keys&status=Active
/browse?q=bottle&report_type=Found&status=All
```

---

## Database

* **Engine:** SQLite (a single file, no server to install)
* **File:** `instance/lost_found.db`, built from the project folder path
* **Created automatically** on first start; existing tables and rows are never
  dropped or reset.

Two tables:

| Table | Columns |
|-------|---------|
| `user` | `id`, `name`, `email` (unique), `password_hash`, `is_admin` (Phase 10), `is_active` (Phase 10), `created_at` |
| `item_report` | `id`, `user_id` (FK → `user.id`), `title`, `description`, `category`, `report_type` (Lost/Found), `location`, `date_lost_found`, `status` (Active/Returned), `image_filename` (optional, Phase 7), `created_at` |
| `claim` | `id`, `report_id` (FK → `item_report.id`), `claimant_id` (FK → `user.id`), `message`, `status` (Pending/Approved/Rejected), `created_at`, `updated_at` — with a unique constraint on (`report_id`, `claimant_id`) |
| `notification` | `id`, `user_id` (recipient FK → `user.id`), `claim_id` (optional FK), `report_id` (optional FK), `title`, `message`, `notification_type`, `is_read`, `created_at` |

Passwords are stored only as Werkzeug hashes, never as plain text.

### Schema migration (Phase 7)

Phase 7 adds one nullable column, `image_filename`. `db.create_all()` only
creates missing *tables*, so `app.py` calls `_ensure_image_column()` on every
start: it reads `PRAGMA table_info(item_report)` and issues
`ALTER TABLE item_report ADD COLUMN image_filename VARCHAR(120)` only when the
column is really missing. That makes the migration idempotent — restarting the
app never adds it twice — and existing reports simply keep `NULL` (no
photograph) and continue to work.

### Schema migration (Phase 8)

Phase 8 adds a whole new table, so `db.create_all()` creates `claim` on the
next start. `_ensure_claim_schema()` then double-checks it: if the table is
missing it is created, and the function always runs
`CREATE UNIQUE INDEX IF NOT EXISTS uq_claim_report_claimant ON claim
(report_id, claimant_id)`, so one student can never claim the same report
twice. Both steps are safe to repeat, and existing users, reports and
photographs are never touched.

### Schema migration (Phase 9)

Phase 9 adds the `notification` table, which `db.create_all()` creates on the
next start. `_ensure_notification_schema()` then confirms the table exists and
runs `CREATE INDEX IF NOT EXISTS ix_notification_user_unread ON notification
(user_id, is_read)` so the bell counter stays fast. Both operations are
idempotent, so restarting the app repeatedly is harmless and no existing row
is ever modified by the migration.

### Schema migration (Phase 10)

Phase 10 adds two columns to the existing `user` table:

```sql
ALTER TABLE user ADD COLUMN is_admin  BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE user ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT 1;
```

`_ensure_user_columns()` checks `PRAGMA table_info(user)` and only runs each
statement when its column is missing, so starting the app repeatedly never
duplicates a column. Every existing student is left as an ordinary, active
account (`is_admin = 0`, `is_active = 1`); nothing is promoted by the
migration, and no report, claim, notification or photograph is touched.

---

## Testing instructions

```bat
python -m unittest -v test_app
```

All 133 tests run against **temporary** databases and **temporary upload
folders**, so your real `instance/lost_found.db` and `static/uploads/reports/`
are never modified. They cover:

* **Phase 2 (11 tests)** — pages render, registration and its validation,
  duplicate emails, password hashing, login/logout, protected pages and the
  "next" redirect, CSRF rejection.
* **Phase 3 (11 tests)** — reporting Lost and Found items, server-side
  validation, persistence after restart, Browse showing everyone, My Reports
  showing only your own, dashboard counters, existing accounts preserved.
* **Phase 4 (20 tests)** — search by title/description/location
  (case-insensitive), type/category/status filters, combined search + filters,
  invalid filter values, clearing filters, owner marking a report returned,
  another student being refused, returned staying returned after restart,
  dashboard counters updating, CSRF on the status update, login required,
  the button only showing to the owner, unknown IDs and unsafe `next` URLs.
* **Phase 6 (14 tests)** — the edit page pre-fills the report, a valid edit
  updates every field and shows up in Browse and My Reports, edits keep the
  owner and the Returned status, invalid edits are rejected without saving,
  another student cannot edit or delete, logged-out visitors are sent to
  login, the owner can delete (gone from Browse and My Reports), CSRF is
  required on both actions, unknown IDs are handled, and the Edit/Delete
  buttons only appear for the owner.
* **Phase 7 (16 tests)** — creating a report with no image, with a JPEG, with
  a PNG and a WEBP; unique file names; rejection of GIF/SVG/HTML/EXE/TXT
  uploads; rejection of renamed text files; the 5 MB server-side limit; the
  photo showing on the card (src and alt text); the edit page showing the
  current photo; editing other fields without losing the photo; replacing a
  photo and deleting the old file; a failed replacement keeping the old file;
  deleting a report deleting its photo; anonymous uploads refused; another
  student unable to replace or delete a photo; and a report saved without a
  photo still working after the migration runs again.
* **Phase 8 (20 tests)** — submitting a claim, claiming while signed out,
  self-claims, claiming Lost or Returned reports, duplicate claims, invalid or
  empty explanations, the owner's Incoming Claims page, non-owners seeing no
  claims there, approval (claim Approved, report Returned, other pending
  claims rejected), rejection (report stays Active and another student can
  then claim), unauthorised approve/reject, decisions on already decided
  claims, claims blocked once returned, CSRF on both actions, My Claims status
  badges, and the migration keeping reports and photographs intact.
* **Phase 9 (17 tests)** — a claim notifying the owner with the claimant's name
  and item title, no duplicates from page refreshes, approval and rejection
  notifications for the claimant, automatic-rejection notifications for the
  other claimants, the owner never being told about their own decision, newest
  first ordering, the bell counter appearing and hiding, marking one or all as
  read, another student being unable to mark your notification, login and CSRF
  requirements, the empty state, report deletion clearing its notifications,
  and the idempotent notification migration.
* **Phase 10 (24 tests)** — existing students staying non-admin after the
  migration, the migration running twice safely, the promotion command,
  admin-only access to every admin page, anonymous visitors being sent to
  login, real statistics (checked before and after an approval), user
  management, deactivating and reactivating students, deactivated users being
  refused at login and dropped from an existing session, self-deactivation
  being blocked, the last active administrator being protected, moderation and
  removal (including claims, notifications and the stored photograph), students
  being denied moderation, claim oversight with working filters, administrators
  being unable to decide claims, CSRF on admin mutations, the admin-only nav
  link, and a final student-feature smoke test.

---

## Creating demo data for the presentation

The existing database already holds two demo students (Hinata Shoyo and
Kageyama Tobio) and two "volley ball" reports — one Lost, one Found. If you
know those passwords, you can use them as they are. If not, register fresh
accounts instead: **never** delete or reset the database to start over, and
create everything through the normal Register and Report pages so it looks
real.

1. Start the app (`python app.py`) and open <http://127.0.0.1:5000/>.
2. Click **Register** and create Student A:
   * Name: `Aditi Sharma`
   * Email: `aditi@college.edu`
   * Password: `demo1234` (confirm it)
3. Log in as Aditi, click **Report an Item** and add two Lost reports, e.g.
   * `College ID card` · Lost · ID Card · "Student ID card in a blue lanyard,
     name Aditi Sharma." · `Library 2nd floor` · a recent date
   * `Scientific calculator` · Lost · Electronics · "Grey Casio calculator,
     my roll number is written on the back." · `Physics lab`
4. Add one **Found** report as Aditi (so Lost and Found both appear):
   `Blue water bottle` · Found · Other · "Steel bottle with a blue cap, left
   after the morning lecture." · `Canteen table 4`
5. Log out (**Logout** in the navbar) and click **Register** again for
   Student B:
   * Name: `Rahul Verma`
   * Email: `rahul@college.edu`
   * Password: `demo1234`
6. Log in as Rahul and post one report, e.g.
   `Black umbrella` · Lost · Accessories · "Folding umbrella with a broken
   strap." · `Main gate`
7. Leave one of Rahul's reports **Active** and later mark it **Returned**
   during the demo to show the status change and the updated dashboard count.

Suggested demo sequence (about 5 minutes):

1. Home page → point out the two calls to action.
2. Register a new account live, or log in as Student A.
3. Dashboard → show the four counters and click one to jump to the list.
4. Report an item → submit a Lost report, attaching a photo so the preview
   appears before saving; the card then shows the photograph.
5. Browse → show both students' cards, then type a search, change the
   Type/Category/Status filters, and click **Clear**.
6. My Reports → show that only your own reports appear, then click **Edit**,
   change the location or description, save, and show the updated card.
7. Click **Mark as Returned** on your own card → explain the badge change,
   then return to Dashboard to show the Returned counter increased.
8. *(Claims)* As Student B, open a **Found** card belonging to Student A and
   click **Claim Item**, write a short explanation and send it. The card now
   shows “Your claim is pending”, and **My Claims** lists it.
9. As Student A, the **bell** in the navbar shows an unread badge. Open
   **Notifications** to read “Student B claimed …”, then open **Incoming
   Claims** and **Approve** it: the item is marked Returned and any other
   pending claims are rejected automatically (their claimants get their own
   notification). Use **Reject** on another claim to show the item staying
   Active and other students still being able to claim it.
10. As Student B, the bell shows the decision and **My Claims** shows the
    Pending (blue), Approved (green) and Rejected (red) badges. Mark one
    notification as read to watch the counter drop, then use **Mark all as
    read** to clear the rest.
11. *(Admin)* Promote one account (see **Administrator setup**), log in as it
    and open **Admin**: show the live totals, then **Users** (deactivate a test
    account, show that it can no longer sign in, reactivate it), **Reports**
    (remove a test report and show its photo leaving
    `static/uploads/reports/`) and **Claims** (filter Pending / Approved /
    Rejected — note there are no approve or reject buttons here).
12. Finish with the test suite: `python -m unittest -v test_app` → 133 tests, OK.

---

## Image uploads

| Item | Detail |
|------|--------|
| Accepted formats | JPG, JPEG, PNG, WEBP (extension and real file signature both checked) |
| Maximum size | 5 MB per image, enforced on the server (the form also warns in JavaScript) |
| Required? | No — a report without a photograph shows a tidy placeholder |
| Stored where | `static/uploads/reports/` inside the project |
| File names | Random UUID names such as `4f1c...9d.jpg`; the student's file name is never used |
| Replacing | `edit` accepts a new photo, saves it, then deletes the previous file |
| Deleting | Deleting a report also deletes its photograph |
| Missing files | If a file disappears from disk the card simply shows the placeholder |

Unsafe formats such as SVG, HTML or executables are rejected with a clear
message, and the request-size cap (6 MB) stops oversized uploads before they
are read.

---

## Known limitations

* Only the student who posted a report can edit or delete it, and the status
  can only move from Active to Returned — never back.
* One photograph per report, no gallery, no cropping or resizing — large
  photos are stored as uploaded (within the 5 MB limit).
* Notifications are in-app only: nothing is emailed, texted or pushed, and
  the bell refreshes when a page loads. The owner still has to open
  **Incoming Claims** to review a request.
* Administrator rights can only be granted from the machine running the app
  (`flask --app app promote-admin <email>`); there is no in-app role editor,
  no admin registration page and no audit log of admin actions.
* Deactivating an account signs it out on its next request; existing sessions
  are not terminated instantly at the database level.
* There is no password reset, email verification or rate limiting — this stays
  a local college demonstration, with the development secret key unless you set
  `SECRET_KEY`.
* No messaging or chat.
* Claims are decided one at a time by the report owner; there is no admin
  override and no undo once a claim has been approved or rejected.
* Search is a simple case-insensitive `LIKE` match — no fuzzy or typo
  tolerance, no pagination.
* Everyone who can reach the site can read the Browse page; there is no
  college-email verification or password reset.
* The secret key falls back to a development value if `SECRET_KEY` is unset,
  and debug mode is on — fine for a local demo, not for a real deployment.
