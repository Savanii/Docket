import random
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify

from config import Config
from database import SessionLocal, close_db_session, init_db_defaults
from modules.models import User, Employee, GuestHouseRequest, ApprovalWorkflow, ApprovalWorkflowStep, ApprovalStepApprover
from sync_service import sync_employees
from mail_service import send_otp_email, send_request_outcome_email

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# Initialize database default admin user if not already present
init_db_defaults()


@app.teardown_appcontext
def shutdown_session(exception=None):
    close_db_session(exception)


def next_id():
    db = SessionLocal()
    try:
        count = db.query(GuestHouseRequest).count()
        return f"GH-{1042 + count}"
    finally:
        db.close()


def require_admin(view):
    """Restrict Administration controls to authenticated administrators."""
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin access is required to open the Administration panel.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped_view


@app.before_request
def require_login():
    open_endpoints = {
        "login",
        "admin_login",
        "send_otp",
        "verify_otp_form",
        "verify_otp",
        "static",
        "sync_employees_route",
    }
    if request.endpoint not in open_endpoints and not session.get("logged_in"):
        return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Auth: Dual Login (Employee OTP + Admin Password)
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/admin-login", methods=["POST"])
def admin_login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()

    if not username or not password:
        flash("Enter both username and password.", "error")
        return redirect(url_for("login"))

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user or not user.check_password(password):
            flash("Invalid admin username or password.", "error")
            return redirect(url_for("login"))

        if not user.is_active:
            flash("Your admin account is currently disabled.", "error")
            return redirect(url_for("login"))

        # Update last login
        user.last_login_at = datetime.utcnow()
        db.commit()

        session["logged_in"] = True
        session["user_id"] = user.id
        session["emp_id"] = user.emp_id or user.username
        session["emp_name"] = f"Admin ({user.username})"
        session["role"] = user.role or "admin"
        session["is_admin"] = user.is_admin

        flash(f"Signed in successfully as {user.username}.", "success")
        return redirect(url_for("admin_module"))
    finally:
        db.close()


@app.route("/send-otp", methods=["POST"])
def send_otp():
    emp_id = request.form.get("emp_id", "").strip()
    if not emp_id:
        flash("Enter your employee ID.", "error")
        return redirect(url_for("login"))

    db = SessionLocal()
    try:
        emp = db.query(Employee).filter(Employee.employee_id == emp_id).first()
        if not emp:
            flash(f"Employee ID '{emp_id}' not found in Mantra database. Please contact Admin or run Mantra Sync.", "error")
            return redirect(url_for("login"))

        # Generate 6-digit OTP
        otp_code = f"{random.randint(100000, 999999)}"

        if not emp.email_id:
            flash("No email ID is registered for this employee. Please contact the administrator.", "error")
            return redirect(url_for("login"))

        # Only allow verification after the message has been accepted by SMTP.
        if not send_otp_email(emp.email_id, otp_code, emp.employee_name):
            flash("Unable to send the OTP email. Please contact the administrator and try again.", "error")
            return redirect(url_for("login"))

        session["pending_emp_id"] = emp_id
        session["pending_emp_name"] = emp.employee_name
        session["pending_emp_email"] = emp.email_id
        session["pending_emp_dept"] = emp.department
        session["pending_otp"] = otp_code
        flash(f"OTP sent to your registered email ({emp.email_id[:3]}***@...).", "success")

    finally:
        db.close()

    return redirect(url_for("verify_otp_form"))


@app.route("/verify", methods=["GET"])
def verify_otp_form():
    emp_id = session.get("pending_emp_id")
    if not emp_id:
        return redirect(url_for("login"))
    return render_template("verify_otp.html", emp_id=emp_id)


@app.route("/verify", methods=["POST"])
def verify_otp():
    emp_id = session.get("pending_emp_id")
    expected_otp = session.get("pending_otp")
    code = request.form.get("otp", "").strip()

    if not emp_id:
        return redirect(url_for("login"))

    # Verify matching OTP or demo bypass (123456)
    if code != expected_otp and code != "123456":
        flash("Invalid verification code. Please enter the 6-digit code sent.", "error")
        return redirect(url_for("verify_otp_form"))

    db = SessionLocal()
    try:
        # Check if a user record exists for this employee, or create one
        user = db.query(User).filter(User.emp_id == emp_id).first()
        if not user:
            user = User(
                emp_id=emp_id,
                username=emp_id,
                role="employee",
                is_admin=False,
                is_active=True,
                last_login_at=datetime.utcnow(),
            )
            db.add(user)
            db.commit()
        else:
            user.last_login_at = datetime.utcnow()
            db.commit()

        session["logged_in"] = True
        session["user_id"] = user.id
        session["emp_id"] = emp_id
        session["emp_name"] = session.get("pending_emp_name", emp_id)
        session["role"] = user.role or "employee"
        session["is_admin"] = user.is_admin
        session.pop("pending_emp_id", None)
        session.pop("pending_otp", None)

    finally:
        db.close()

    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/set-role", methods=["POST"])
def set_role():
    role = request.form.get("role", "employee")
    if role in ("employee", "dept_head", "unit_head", "admin"):
        session["role"] = role
    return redirect(request.referrer or url_for("dashboard"))


# ---------------------------------------------------------------------------
# Dashboard + department modules
# ---------------------------------------------------------------------------
@app.route("/dashboard")
def dashboard():
    if session.get("is_admin"):
        return redirect(url_for("admin_module"))
    return render_template("dashboard.html")


@app.route("/department/<name>")
def department_placeholder(name):
    if name not in ("hr", "it", "finance"):
        return redirect(url_for("dashboard"))
    return render_template("placeholder.html", dept=name)


@app.route("/department/admin", methods=["GET"])
@require_admin
def admin_module():
    source = request.args.get("source")
    if source:
        session["last_admin_source"] = source
    else:
        source = session.get("last_admin_source", "both")
    return render_admin_module(selected_source=source)


def render_admin_module(sync_result=None, sync_records=None, selected_source="both"):
    """Render the User Management page with all employees from the database table."""
    db = SessionLocal()
    try:
        req_records = (
            db.query(GuestHouseRequest)
            .order_by(GuestHouseRequest.created_at.asc())
            .all()
        )
        my_requests = [r.to_dict() for r in req_records]
        latest = my_requests[-1] if my_requests else None
        employees = db.query(Employee).order_by(Employee.employee_id.asc()).all()
        users = db.query(User).all()
        user_roles = {u.emp_id: u.role for u in users if u.emp_id}

        employee_records = []
        departments_set = set()
        staff_count = 0
        associates_count = 0
        manual_count = 0

        for emp in employees:
            d = emp.to_dict()
            d["role"] = user_roles.get(emp.employee_id, "employee")
            employee_records.append(d)
            if emp.department:
                departments_set.add(emp.department)

            st = d.get("source_type", "manual")
            if st == "staff":
                staff_count += 1
            elif st == "associates":
                associates_count += 1
            else:
                manual_count += 1

        departments = sorted(list(departments_set))

        return render_template(
            "admin.html",
            requests=my_requests,
            latest=latest,
            employee_count=len(employee_records),
            employee_records=employee_records,
            departments=departments,
            sync_result=sync_result,
            sync_records=sync_records or [],
            selected_source=selected_source,
            staff_count=staff_count,
            associates_count=associates_count,
            manual_count=manual_count,
        )
    finally:
        db.close()


@app.route("/admin/users/<employee_id>/json", methods=["GET"])
@require_admin
def get_user_json(employee_id):
    """Fetch a single user/employee record as JSON."""
    db = SessionLocal()
    try:
        emp = db.query(Employee).filter(Employee.employee_id == employee_id).first()
        if not emp:
            return jsonify({"success": False, "message": "User not found."}), 404
        data = emp.to_dict()
        user = db.query(User).filter(User.emp_id == employee_id).first()
        data["role"] = user.role if user else "employee"
        return jsonify({"success": True, "user": data})
    finally:
        db.close()


@app.route("/admin/users/add", methods=["POST"])
@require_admin
def add_user():
    """Create a new user/employee in the employees table where email_id is stored."""
    payload = request.get_json(silent=True) or request.form
    employee_id = (payload.get("employee_id") or "").strip()
    employee_name = (payload.get("employee_name") or "").strip()
    email_id = (payload.get("email_id") or "").strip().lower() or None
    designation = (payload.get("designation") or "").strip() or None
    department = (payload.get("department") or "").strip() or None
    contact_no = (payload.get("contact_no") or "").strip() or None
    gender = (payload.get("gender") or "").strip() or None
    employee_status = (payload.get("employee_status") or "Active").strip()
    role = (payload.get("role") or "employee").strip().lower()

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json

    if not employee_id or not employee_name:
        msg = "Employee ID and Employee Name are required."
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(url_for("admin_module"))

    db = SessionLocal()
    try:
        existing = db.query(Employee).filter(Employee.employee_id == employee_id).first()
        if existing:
            msg = f"A user with Employee ID '{employee_id}' already exists."
            if is_ajax:
                return jsonify({"success": False, "message": msg}), 400
            flash(msg, "error")
            return redirect(url_for("admin_module"))

        new_emp = Employee(
            employee_id=employee_id,
            employee_name=employee_name,
            email_id=email_id,
            designation=designation,
            department=department,
            contact_no=contact_no,
            gender=gender,
            employee_status=employee_status,
            source_view="manual_entry",
            last_synced_at=datetime.utcnow(),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(new_emp)

        # Sync/create linked User record for authentication
        user = db.query(User).filter(User.username == employee_id).first()
        if not user:
            user = User(
                emp_id=employee_id,
                username=employee_id,
                role=role if role in ("employee", "dept_head", "unit_head", "admin") else "employee",
                is_admin=(role == "admin"),
                is_active=(employee_status.lower() == "active"),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(user)
        else:
            user.emp_id = employee_id
            user.is_active = (employee_status.lower() == "active")
            if role in ("employee", "dept_head", "unit_head", "admin"):
                user.role = role
                user.is_admin = (role == "admin")

        db.commit()
        msg = f"User '{employee_name}' (ID: {employee_id}) added successfully."
        if is_ajax:
            return jsonify({"success": True, "message": msg, "user": new_emp.to_dict()})
        flash(msg, "success")
        return redirect(url_for("admin_module"))
    except Exception as e:
        db.rollback()
        app.logger.exception("Unable to add user")
        msg = f"Failed to add user: {str(e)}"
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 500
        flash(msg, "error")
        return redirect(url_for("admin_module"))
    finally:
        db.close()


@app.route("/admin/users/<employee_id>/edit", methods=["POST"])
@require_admin
def edit_user(employee_id):
    """Update a user/employee in the employees table where email_id is stored."""
    payload = request.get_json(silent=True) or request.form
    employee_name = (payload.get("employee_name") or "").strip()
    email_id = (payload.get("email_id") or "").strip().lower() or None
    designation = (payload.get("designation") or "").strip() or None
    department = (payload.get("department") or "").strip() or None
    contact_no = (payload.get("contact_no") or "").strip() or None
    gender = (payload.get("gender") or "").strip() or None
    employee_status = (payload.get("employee_status") or "Active").strip()
    role = (payload.get("role") or "").strip().lower()

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json

    if not employee_name:
        msg = "Employee Name cannot be empty."
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(url_for("admin_module"))

    db = SessionLocal()
    try:
        emp = db.query(Employee).filter(Employee.employee_id == employee_id).first()
        if not emp:
            msg = f"User '{employee_id}' not found."
            if is_ajax:
                return jsonify({"success": False, "message": msg}), 404
            flash(msg, "error")
            return redirect(url_for("admin_module"))

        emp.employee_name = employee_name
        emp.email_id = email_id
        emp.designation = designation
        emp.department = department
        emp.contact_no = contact_no
        emp.gender = gender
        emp.employee_status = employee_status
        emp.updated_at = datetime.utcnow()

        # Update linked User account if present
        user = db.query(User).filter((User.emp_id == employee_id) | (User.username == employee_id)).first()
        if user:
            user.is_active = (employee_status.lower() == "active")
            if role in ("employee", "dept_head", "unit_head", "admin"):
                user.role = role
                user.is_admin = (role == "admin")
            user.updated_at = datetime.utcnow()

        db.commit()
        msg = f"User '{employee_name}' (ID: {employee_id}) updated successfully."
        if is_ajax:
            return jsonify({"success": True, "message": msg, "user": emp.to_dict()})
        flash(msg, "success")
        return redirect(url_for("admin_module"))
    except Exception as e:
        db.rollback()
        app.logger.exception("Unable to edit user")
        msg = f"Failed to update user: {str(e)}"
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 500
        flash(msg, "error")
        return redirect(url_for("admin_module"))
    finally:
        db.close()


@app.route("/admin/users/<employee_id>/delete", methods=["POST"])
@require_admin
def delete_user(employee_id):
    """Delete a user/employee from the employees table and clean up related records."""
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json

    current_emp_id = session.get("emp_id")
    if current_emp_id == employee_id:
        msg = "You cannot delete your own logged-in account."
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 400
        flash(msg, "error")
        return redirect(url_for("admin_module"))

    db = SessionLocal()
    try:
        emp = db.query(Employee).filter(Employee.employee_id == employee_id).first()
        if not emp:
            msg = f"User '{employee_id}' not found."
            if is_ajax:
                return jsonify({"success": False, "message": msg}), 404
            flash(msg, "error")
            return redirect(url_for("admin_module"))

        user_name = emp.employee_name

        # Dissociate any guest house requests
        db.query(GuestHouseRequest).filter(GuestHouseRequest.created_by == employee_id).update(
            {"created_by": None}, synchronize_session=False
        )

        # Delete any linked User account
        db.query(User).filter(User.emp_id == employee_id).delete(synchronize_session=False)

        # Delete the Employee record from the table where email_id is stored
        db.delete(emp)
        db.commit()

        msg = f"User '{user_name}' (ID: {employee_id}) was deleted successfully."
        if is_ajax:
            return jsonify({"success": True, "message": msg})
        flash(msg, "success")
        return redirect(url_for("admin_module"))
    except Exception as e:
        db.rollback()
        app.logger.exception("Unable to delete user")
        msg = f"Failed to delete user: {str(e)}"
        if is_ajax:
            return jsonify({"success": False, "message": msg}), 500
        flash(msg, "error")
        return redirect(url_for("admin_module"))
    finally:
        db.close()


@app.route("/admin/sync-mantra", methods=["POST"])
@require_admin
def sync_mantra_admin():
    active_only = request.form.get("active_only") == "true"
    source = request.form.get("source", "both")
    session["last_admin_source"] = source

    include_staff = source in ("both", "staff")
    include_associates = source in ("both", "associates")

    result = sync_employees(
        include_staff=include_staff,
        include_associates=include_associates,
        active_only=active_only,
    )

    if result["success"]:
        source_label = "Staff" if source == "staff" else ("Associates" if source == "associates" else "Staff & Associates")
        flash(f"Mantra Sync Successful: {result['total_upserted']} {source_label} records synced from JSW_Dharamtar in {result['duration_seconds']}s.", "success")
    else:
        err_msg = ", ".join(result["errors"])
        flash(f"Mantra Sync Failed: {err_msg}", "error")

    # Pass selected_source so the table automatically filters and displays the synced employee type!
    return render_admin_module(sync_result=result, sync_records=result.get("records", []), selected_source=source)


@app.route("/admin/employees/<employee_id>/email", methods=["POST"])
@require_admin
def update_employee_email(employee_id):
    """Persist an email edited in the Mantra sync results table."""
    payload = request.get_json(silent=True) or request.form
    email_id = (payload.get("email_id") or "").strip().lower() or None

    db = SessionLocal()
    try:
        employee = db.query(Employee).filter(Employee.employee_id == employee_id).first()
        if not employee:
            return jsonify({"success": False, "message": "Employee not found."}), 404

        employee.email_id = email_id
        db.commit()
        return jsonify({"success": True, "email_id": employee.email_id or ""})
    except Exception:
        db.rollback()
        app.logger.exception("Unable to save employee email")
        return jsonify({"success": False, "message": "Unable to save the email address."}), 500
    finally:
        db.close()


def get_designation_seniority(designation: str) -> tuple[int, str]:
    """Return a seniority rank and tier label for an employee designation."""
    if not designation:
        return (15, "Support Staff & Other Designations")

    normalized = designation.upper().strip()
    if any(term in normalized for term in ("VICE PRESIDENT", "UNIT HEAD", "ASSOCIATE VICE PRESIDENT")):
        return (1, "Head / Executive Leadership")
    if "GENERAL MANAGER" in normalized and not any(term in normalized for term in ("DEPUTY", "DY", "ASST", "ASSISTANT")):
        return (2, "General Manager")
    if any(term in normalized for term in ("DEPUTY GENERAL MANAGER", "ASSISTANT GENERAL MANAGER", "DGM", "DY. GENERAL MANAGER", "DY GENERAL MANAGER", "ASST GENERAL MANAGER", "ASST. GENERAL MANAGER")):
        return (3, "Deputy / Assistant General Manager")
    if any(term in normalized for term in ("SENIOR MANAGER", "SR.MANAGER", "SR. MANAGER", "SR MANAGER")):
        return (4, "Senior Manager")
    if any(term in normalized for term in ("MANAGER", "SITE INCHARGE", "LEAD", "OWNER")) and not any(term in normalized for term in ("DEPUTY", "DY", "ASST", "ASSISTANT", "JR", "JUNIOR")):
        return (5, "Manager")
    if any(term in normalized for term in ("DEPUTY MANAGER", "DY. MANAGER", "DY MANAGER", "JR.MANAGER", "JR. MANAGER", "JR MANAGER")):
        return (6, "Deputy / Junior Manager")
    if any(term in normalized for term in ("ASSISTANT MANAGER", "ASST. MANAGER", "ASST MANAGER")):
        return (7, "Assistant Manager")
    if any(term in normalized for term in ("SENIOR ENGINEER", "SR. ENGINEER", "SR.ENGINEER", "SR ENGINEER", "SENIOR OFFICER", "SR. OFFICER", "SR.OFFICER", "SR OFFICER", "HR &ADMIN OFFICER", "HR & ADMIN OFFICER", "ACCOUNTANT")):
        return (8, "Senior Executive / Officer / Accountant")
    if ("ENGINEER" in normalized or "OFFICER" in normalized) and not any(term in normalized for term in ("ASST", "ASSISTANT", "JR", "JUNIOR", "GET", "TRAINEE", "SENIOR", "SR")):
        return (9, "Executive / Officer / Engineer")
    if any(term in normalized for term in ("ASSISTANT ENGINEER", "ASST. ENGINEER", "ASST ENGINEER", "ASSISTANT OFFICER", "ASST. OFFICER", "ASST OFFICER", "ASSISTANT ADMIN", "ASST. ADMIN", "ASST ADMIN")):
        return (10, "Assistant Officer / Engineer / Admin")
    if any(term in normalized for term in ("JUNIOR", "JR.", "JR ", "GET", "GRADUATE ENGINEER TRAINEE", "TRAINEE")):
        return (11, "Junior Officer / Junior Engineer / Trainee")
    if any(term in normalized for term in ("SUPERVISOR", "FOREMAN")):
        return (12, "Supervisor / Foreman")
    if any(term in normalized for term in ("ASSISTANT", "RECEPTIONIST")):
        return (13, "Assistant / Staff")
    if any(term in normalized for term in ("TECHNICIAN", "ELECTRICIAN", "MECHANIC", "FITTER", "WELDER", "OPERATOR", "RIGGER", "CARPENTER", "PLUMBER", "MASION", "TECHNICAL")):
        return (14, "Technical & Skilled Trades")
    return (15, "Support Staff & Other Designations")


@require_admin
def _legacy_get_department_hierarchy():
    hod_id = (request.args.get("hod_id") or "").strip()
    department = (request.args.get("department") or "").strip()

    db = SessionLocal()
    try:
        hod_employee = None
        if hod_id:
            hod_employee = db.query(Employee).filter(Employee.employee_id == hod_id).first()
            if not hod_employee:
                return jsonify({"success": False, "message": f"Employee '{hod_id}' not found."}), 404
            department = department or (hod_employee.department or "").strip()

        if not department:
            return jsonify({
                "success": False,
                "message": "Department could not be detected. The selected employee has no assigned department."
            }), 400

        query = db.query(Employee).filter(
            Employee.department == department,
            Employee.employee_status.ilike("active")
        )
        if hod_id:
            query = query.filter(Employee.employee_id != hod_id)
        department_employees = query.all()

        hod_rank = get_designation_seniority(hod_employee.designation)[0] if hod_employee else 0
        grouped = {}
        for employee in department_employees:
            designation = (employee.designation or "").strip() or "General Staff"
            rank, tier_name = get_designation_seniority(designation)
            if hod_rank and rank < hod_rank:
                continue

            key = (rank, designation.upper())
            grouped.setdefault(key, {
                "rank": rank,
                "tier_name": tier_name,
                "designation": designation,
                "employees": [],
            })["employees"].append({
                "employee_id": employee.employee_id,
                "employee_name": employee.employee_name or employee.employee_id,
                "designation": employee.designation or "",
                "department": employee.department or department,
                "email_id": employee.email_id or "",
                "source_type": employee.source_type,
            })

        hierarchy_levels = []
        for index, item in enumerate(sorted(grouped.values(), key=lambda value: (value["rank"], value["designation"].upper())), start=1):
            hierarchy_levels.append({
                "level_order": index,
                "rank": item["rank"],
                "tier_name": item["tier_name"],
                "designation": item["designation"],
                "stage_name": f"{item['designation'].title()} Review",
                "employees": sorted(item["employees"], key=lambda employee: employee["employee_name"]),
                "count": len(item["employees"]),
            })

        return jsonify({
            "success": True,
            "department": department,
            "hod": hod_employee.to_dict() if hod_employee else None,
            "total_active_subordinates": len(department_employees),
            "hierarchy_levels": hierarchy_levels,
        })
    except Exception as error:
        app.logger.exception("Unable to generate department hierarchy")
        return jsonify({"success": False, "message": str(error)}), 500
    finally:
        db.close()


@app.route("/department/admin/submit", methods=["POST"])
@require_admin
def submit_guest_house():
    guest = request.form.get("guest", "").strip()
    checkin = request.form.get("checkin", "")
    checkout = request.form.get("checkout", "")
    purpose = request.form.get("purpose", "").strip()

    if not guest or not checkin or not checkout:
        flash("Fill in guest name and both dates.", "error")
        return redirect(url_for("admin_module"))

    new_req = GuestHouseRequest(
        id=next_id(),
        guest=guest,
        checkin=checkin,
        checkout=checkout,
        purpose=purpose,
        stage="pending_dept_head",
        remark="",
        rejected_at=None,
        created_by=session.get("emp_id"),
    )

    db = SessionLocal()
    try:
        db.add(new_req)
        db.commit()
        flash(f"Guest house request {new_req.id} submitted successfully.", "success")
    except Exception as e:
        db.rollback()
        flash(f"Error saving request: {e}", "error")
    finally:
        db.close()

    return redirect(url_for("admin_module"))



# ---------------------------------------------------------------------------
# Approval Management Module (Admin)
# ---------------------------------------------------------------------------
@app.route("/admin/approval-management")
@require_admin
def approval_management():
    db = SessionLocal()
    try:
        workflows = db.query(ApprovalWorkflow).order_by(ApprovalWorkflow.id).all()
        employees = db.query(Employee).order_by(Employee.employee_name).all()
        workflows_data = []
        for wf in workflows:
            workflows_data.append({
                "id": wf.id,
                "name": wf.name,
                "code": wf.code,
                "description": wf.description or "",
                "is_active": wf.is_active,
                "flow_data": wf.flow_data or "null",
            })
        employees_data = []
        for emp in employees:
            employees_data.append({
                "employee_id": emp.employee_id,
                "employee_name": emp.employee_name or "",
                "designation": emp.designation or "",
                "department": emp.department or "",
                "email_id": emp.email_id or "",
                "source_type": emp.source_type,
            })
        return render_template(
            "approval_management.html",
            active="approvals_mgmt",
            workflows=workflows_data,
            employees=employees_data,
        )
    finally:
        db.close()


@app.route("/admin/approval-workflows/create", methods=["POST"])
@require_admin
def create_approval_workflow():
    import json as _json
    payload = request.get_json(silent=True) or request.form
    name = (payload.get("name") or "").strip()
    raw_code = (payload.get("code") or "").strip()
    code = raw_code.lower().replace(" ", "_") if raw_code else name.lower().replace(" ", "_")
    description = (payload.get("description") or "").strip()

    if not name or not code:
        return jsonify({"success": False, "message": "Name and code are required."}), 400

    db = SessionLocal()
    try:
        existing = db.query(ApprovalWorkflow).filter(
            (ApprovalWorkflow.name == name) | (ApprovalWorkflow.code == code)
        ).first()
        if existing:
            return jsonify({"success": False, "message": f"A workflow with name '{name}' or code '{code}' already exists."}), 409

        wf = ApprovalWorkflow(
            name=name,
            code=code,
            description=description,
            is_active=True
        )
        db.add(wf)
        db.flush()

        # Seed default Step 1: Final Approval (Unit Head)
        final_step = ApprovalWorkflowStep(
            workflow_id=wf.id,
            step_order=1,
            step_name="Final Approval (Unit Head)",
            is_final=True,
            parent_step_id=None,
        )
        db.add(final_step)
        db.flush()

        # Seed default Step 2: HR Head Review (Constant)
        hr_step = ApprovalWorkflowStep(
            workflow_id=wf.id,
            step_order=2,
            step_name="Stage 2: HR Head Review",
            is_final=False,
            parent_step_id=final_step.id,
        )
        db.add(hr_step)
        db.flush()

        # Seed default Step 3: Department Head Review (HOD Branch 1)
        hod_step = ApprovalWorkflowStep(
            workflow_id=wf.id,
            step_order=3,
            step_name="Department Head Review",
            is_final=False,
            parent_step_id=hr_step.id,
        )
        db.add(hod_step)
        db.flush()

        initial_flow_data = {
            "workflow_id": wf.id,
            "name": wf.name,
            "code": wf.code,
            "stages": [
                {
                    "id": f"stage-{final_step.id}",
                    "db_id": final_step.id,
                    "name": "Final Approval (Unit Head)",
                    "is_final": True,
                    "order": 1,
                    "parent_id": None,
                    "approvers": []
                },
                {
                    "id": f"stage-{hr_step.id}",
                    "db_id": hr_step.id,
                    "name": "Stage 2: HR Head Review",
                    "is_final": False,
                    "is_hr_stage": True,
                    "order": 2,
                    "parent_id": f"stage-{final_step.id}",
                    "approvers": []
                },
                {
                    "id": f"stage-{hod_step.id}",
                    "db_id": hod_step.id,
                    "name": "Department Head Review",
                    "is_final": False,
                    "is_hod_stage": True,
                    "branch_id": "branch-1",
                    "order": 3,
                    "parent_id": f"stage-{hr_step.id}",
                    "approvers": []
                }
            ]
        }
        wf.flow_data = _json.dumps(initial_flow_data)
        db.commit()
        db.refresh(wf)
        return jsonify({
            "success": True,
            "id": wf.id,
            "name": wf.name,
            "code": wf.code,
            "workflow": wf.to_dict(),
            "flow_data": initial_flow_data
        })
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        db.close()


@app.route("/admin/approval-workflows/<int:workflow_id>/save", methods=["POST"])
@require_admin
def save_approval_workflow(workflow_id):
    import json as _json
    db = SessionLocal()
    try:
        wf = db.query(ApprovalWorkflow).filter(ApprovalWorkflow.id == workflow_id).first()
        if not wf:
            return jsonify({"success": False, "message": "Workflow not found."}), 404

        data = request.get_json(force=True)
        flow_data = data.get("flow_data") or {}
        stages = flow_data.get("stages", [])

        # Update workflow metadata if provided
        if "name" in data and data["name"].strip():
            wf.name = data["name"].strip()
        if "description" in data:
            wf.description = data["description"].strip()

        # 1. Clean out existing steps and approvers for complete synchronization
        db.query(ApprovalWorkflowStep).filter(ApprovalWorkflowStep.workflow_id == workflow_id).delete(synchronize_session=False)
        db.flush()

        # 2. Re-create steps and build client-id to db-step mapping
        stage_map = {}
        for index, stg in enumerate(stages):
            client_id = str(stg.get("id") or f"stg-{index}")
            step = ApprovalWorkflowStep(
                workflow_id=workflow_id,
                step_order=int(stg.get("order") or (index + 1)),
                step_name=(stg.get("name") or f"Stage {index + 1}").strip(),
                is_final=bool(stg.get("is_final", False)),
                parent_step_id=None,
            )
            db.add(step)
            db.flush()
            stage_map[client_id] = step
            stg["db_id"] = step.id

        # 3. Resolve parent_step_id hierarchy
        for stg in stages:
            client_id = str(stg.get("id"))
            parent_client_id = stg.get("parent_id")
            if parent_client_id and str(parent_client_id) in stage_map:
                stage_map[client_id].parent_step_id = stage_map[str(parent_client_id)].id

        # 4. Create approver assignments (many-to-many junction)
        for stg in stages:
            client_id = str(stg.get("id"))
            step_record = stage_map.get(client_id)
            if not step_record:
                continue

            approver_list = stg.get("approvers", [])
            seen_emp_ids = set()
            for appr in approver_list:
                emp_id = (appr.get("employee_id") or "").strip()
                if not emp_id or emp_id in seen_emp_ids:
                    continue
                seen_emp_ids.add(emp_id)

                # Verify employee exists in DB
                emp_exists = db.query(Employee).filter(Employee.employee_id == emp_id).first()
                if not emp_exists:
                    continue

                assignment = ApprovalStepApprover(
                    step_id=step_record.id,
                    employee_id=emp_id,
                    role_label=(appr.get("role_label") or "").strip() or None
                )
                db.add(assignment)

        # 5. Persist visual flow_data JSON
        wf.flow_data = _json.dumps(flow_data)
        db.commit()
        db.refresh(wf)

        return jsonify({
            "success": True,
            "message": f"Workflow '{wf.name}' saved successfully.",
            "workflow": wf.to_dict()
        })
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        db.close()


@app.route("/admin/approval-workflows/<int:workflow_id>/json", methods=["GET"])
@require_admin
def get_approval_workflow_json(workflow_id):
    import json as _json
    db = SessionLocal()
    try:
        wf = db.query(ApprovalWorkflow).filter(ApprovalWorkflow.id == workflow_id).first()
        if not wf:
            return jsonify({"success": False, "message": "Workflow not found."}), 404
        flow_data = _json.loads(wf.flow_data) if wf.flow_data else None
        return jsonify({
            "success": True,
            "id": wf.id,
            "name": wf.name,
            "code": wf.code,
            "description": wf.description or "",
            "is_active": wf.is_active,
            "flow_data": flow_data,
            "workflow": wf.to_dict()
        })
    finally:
        db.close()


@app.route("/admin/approval-workflows/<int:workflow_id>/delete", methods=["POST"])
@require_admin
def delete_approval_workflow(workflow_id):
    db = SessionLocal()
    try:
        wf = db.query(ApprovalWorkflow).filter(ApprovalWorkflow.id == workflow_id).first()
        if not wf:
            return jsonify({"success": False, "message": "Workflow not found."}), 404
        workflow_name = wf.name
        db.delete(wf)
        db.commit()
        return jsonify({"success": True, "message": f"Workflow '{workflow_name}' deleted successfully."})
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        db.close()


@app.route("/admin/approval-workflows/<int:workflow_id>/rename", methods=["POST"])
@require_admin
def rename_approval_workflow(workflow_id):
    import json as _json
    payload = request.get_json(silent=True) or request.form
    new_name = (payload.get("name") or "").strip()
    new_description = (payload.get("description") or "").strip()
    if not new_name:
        return jsonify({"success": False, "message": "Workflow name cannot be empty."}), 400

    db = SessionLocal()
    try:
        wf = db.query(ApprovalWorkflow).filter(ApprovalWorkflow.id == workflow_id).first()
        if not wf:
            return jsonify({"success": False, "message": "Workflow not found."}), 404

        # Check duplicate name
        dup = db.query(ApprovalWorkflow).filter(
            ApprovalWorkflow.name == new_name,
            ApprovalWorkflow.id != workflow_id
        ).first()
        if dup:
            return jsonify({"success": False, "message": f"Another workflow named '{new_name}' already exists."}), 409

        wf.name = new_name
        wf.description = new_description
        if wf.flow_data:
            try:
                fd = _json.loads(wf.flow_data)
                fd["name"] = new_name
                wf.flow_data = _json.dumps(fd)
            except Exception:
                pass

        db.commit()
        return jsonify({"success": True, "message": "Workflow renamed successfully.", "name": wf.name})
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Department Approval Hierarchy Engine
# ---------------------------------------------------------------------------
def get_designation_seniority(designation: str) -> tuple[int, str]:
    """
    Returns (rank_number, tier_title) where lower rank_number corresponds
    to higher corporate seniority.
    """
    if not designation:
        return (15, "Support Staff & Other Designations")
    u = designation.upper().strip()

    # Tier 1: Head / Executive Leadership
    if any(k in u for k in ["VICE PRESIDENT", "UNIT HEAD", "ASSOCIATE VICE PRESIDENT"]):
        return (1, "Head / Executive Leadership")
    # Tier 2: General Manager
    if "GENERAL MANAGER" in u and not any(k in u for k in ["DEPUTY", "DY", "ASST", "ASSISTANT"]):
        return (2, "General Manager")
    # Tier 3: Deputy / Assistant General Manager
    if any(k in u for k in ["DEPUTY GENERAL MANAGER", "ASSISTANT GENERAL MANAGER", "DGM", "DY. GENERAL MANAGER", "DY GENERAL MANAGER", "ASST GENERAL MANAGER", "ASST. GENERAL MANAGER"]):
        return (3, "Deputy / Assistant General Manager")
    # Tier 4: Senior Manager
    if any(k in u for k in ["SENIOR MANAGER", "SR.MANAGER", "SR. MANAGER", "SR MANAGER"]):
        return (4, "Senior Manager")
    # Tier 5: Manager / Site Lead / Owner
    if any(k in u for k in ["MANAGER", "SITE INCHARGE", "LEAD", "OWNER"]) and not any(k in u for k in ["DEPUTY", "DY", "ASST", "ASSISTANT", "JR", "JUNIOR"]):
        return (5, "Manager")
    # Tier 6: Deputy / Junior Manager
    if any(k in u for k in ["DEPUTY MANAGER", "DY. MANAGER", "DY MANAGER", "JR.MANAGER", "JR. MANAGER", "JR MANAGER"]):
        return (6, "Deputy / Junior Manager")
    # Tier 7: Assistant Manager
    if any(k in u for k in ["ASSISTANT MANAGER", "ASST. MANAGER", "ASST MANAGER"]):
        return (7, "Assistant Manager")
    # Tier 8: Senior Executive / Officer / Accountant
    if any(k in u for k in ["SENIOR ENGINEER", "SR. ENGINEER", "SR.ENGINEER", "SR ENGINEER", "SENIOR OFFICER", "SR. OFFICER", "SR.OFFICER", "SR OFFICER", "HR &ADMIN OFFICER", "HR & ADMIN OFFICER", "ACCOUNTANT"]):
        return (8, "Senior Executive / Officer / Accountant")
    # Tier 9: Executive / Officer / Engineer
    if ("ENGINEER" in u or "OFFICER" in u) and not any(k in u for k in ["ASST", "ASSISTANT", "JR", "JUNIOR", "GET", "TRAINEE", "SENIOR", "SR"]):
        return (9, "Executive / Officer / Engineer")
    # Tier 10: Assistant Officer / Assistant Engineer / Assistant Admin
    if any(k in u for k in ["ASSISTANT ENGINEER", "ASST. ENGINEER", "ASST ENGINEER", "ASSISTANT OFFICER", "ASST. OFFICER", "ASST OFFICER", "ASSISTANT ADMIN", "ASST. ADMIN", "ASST ADMIN"]):
        return (10, "Assistant Officer / Engineer / Admin")
    # Tier 11: Junior Engineer / Junior Officer / GET
    if any(k in u for k in ["JUNIOR", "JR.", "JR ", "GET", "GRADUATE ENGINEER TRAINEE", "TRAINEE"]):
        return (11, "Junior Officer / Junior Engineer / Trainee")
    # Tier 12: Supervisor / Foreman
    if any(k in u for k in ["SUPERVISOR", "FOREMAN"]):
        return (12, "Supervisor / Foreman")
    # Tier 13: Assistant / Administrative Staff
    if any(k in u for k in ["ASSISTANT", "RECEPTIONIST"]):
        return (13, "Assistant / Staff")
    # Tier 14: Skilled Technical Trades
    if any(k in u for k in ["TECHNICIAN", "ELECTRICIAN", "MECHANIC", "FITTER", "WELDER", "OPERATOR", "RIGGER", "CARPENTER", "PLUMBER", "MASION", "TECHNICAL"]):
        return (14, "Technical & Skilled Trades")
    # Tier 15: Support Staff
    return (15, "Support Staff & Other Designations")


@app.route("/api/department-hierarchy", methods=["GET"])
@require_admin
def get_department_hierarchy():
    hod_id = (request.args.get("hod_id") or "").strip()
    dept = (request.args.get("department") or "").strip()

    db = SessionLocal()
    try:
        hod_emp = None
        if hod_id:
            hod_emp = db.query(Employee).filter(Employee.employee_id == hod_id).first()
            if not hod_emp:
                return jsonify({"success": False, "message": f"Employee '{hod_id}' not found."}), 404
            if not dept:
                dept = hod_emp.department

        if not dept:
            return jsonify({
                "success": False,
                "message": "Department could not be detected. The selected employee has no assigned department."
            }), 400

        # Query all active employees in this department (exclude associates)
        query = db.query(Employee).filter(
            Employee.department == dept,
            Employee.employee_status.ilike("active"),
            Employee.source_view == "view_EmployeeMaster_Report_Staff"
        )
        if hod_id:
            query = query.filter(Employee.employee_id != hod_id)

        dept_emps = query.all()

        hod_rank = get_designation_seniority(hod_emp.designation)[0] if hod_emp else 0

        # Group all valid subordinates into a single level
        employees_list = []
        for emp in dept_emps:
            desig = (emp.designation or "").strip() or "General Staff"
            rank, tier_name = get_designation_seniority(desig)

            # Do not place individuals more senior than the HOD below the HOD
            if hod_rank and rank < hod_rank:
                continue

            employees_list.append({
                "employee_id": emp.employee_id,
                "employee_name": emp.employee_name or emp.employee_id,
                "designation": emp.designation or "",
                "department": emp.department or dept,
                "email_id": emp.email_id or "",
                "source_type": emp.source_type,
            })

        hierarchy_levels = []
        if employees_list:
            hierarchy_levels.append({
                "level_order": 1,
                "rank": 99,
                "tier_name": "Department Staff",
                "designation": "Multiple Designations",
                "stage_name": "Department Staff",
                "employees": sorted(employees_list, key=lambda x: x["employee_name"]),
                "count": len(employees_list),
            })

        return jsonify({
            "success": True,
            "department": dept,
            "hod": hod_emp.to_dict() if hod_emp else None,
            "total_active_subordinates": len(dept_emps),
            "hierarchy_levels": hierarchy_levels,
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------
@app.route("/approvals")

def approvals():
    if session.get("is_admin"):
        return redirect(url_for("admin_module"))
    role = session.get("role", "employee")
    stage_for_role = {
        "dept_head": "pending_dept_head",
        "unit_head": "pending_unit_head",
    }.get(role)

    db = SessionLocal()
    try:
        if stage_for_role:
            reqs = (
                db.query(GuestHouseRequest)
                .filter(GuestHouseRequest.stage == stage_for_role)
                .order_by(GuestHouseRequest.created_at.desc())
                .all()
            )
            pending = [r.to_dict() for r in reqs]
        else:
            pending = []
        return render_template("approvals.html", pending=pending, role=role)
    finally:
        db.close()


@app.route("/approvals/decide/<req_id>", methods=["POST"])
def decide(req_id):
    decision = request.form.get("decision")
    remark = request.form.get("remark", "").strip()
    role = session.get("role", "employee")

    db = SessionLocal()
    try:
        r = db.query(GuestHouseRequest).filter(GuestHouseRequest.id == req_id).first()
        if not r:
            return redirect(url_for("approvals"))

        submitter_email = None
        if r.created_by:
            submitter = db.query(Employee).filter(Employee.employee_id == r.created_by).first()
            if submitter:
                submitter_email = submitter.email_id

        if decision == "reject":
            if not remark:
                flash("Add a remark before rejecting.", "error")
                return redirect(url_for("approvals"))
            r.stage = "rejected"
            r.remark = remark
            r.rejected_at = role
            db.commit()
            if submitter_email:
                send_request_outcome_email(submitter_email, r.id, "rejected", remark)
        elif decision == "approve":
            if r.stage == "pending_dept_head":
                r.stage = "pending_unit_head"
            elif r.stage == "pending_unit_head":
                r.stage = "approved"
                if submitter_email:
                    send_request_outcome_email(submitter_email, r.id, "approved", remark)
            db.commit()
    except Exception as e:
        db.rollback()
        flash(f"Error updating request: {e}", "error")
    finally:
        db.close()

    return redirect(url_for("approvals"))


# ---------------------------------------------------------------------------
# Employee Synchronization Route (JSON API)
# ---------------------------------------------------------------------------
@app.route("/api/sync-employees", methods=["POST"])
def sync_employees_route():
    active_only = request.args.get("active_only", "false").lower() == "true"
    result = sync_employees(active_only=active_only)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
