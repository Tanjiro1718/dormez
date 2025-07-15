import os

# Create templates directory
os.makedirs('templates', exist_ok=True)

templates = {
    'base.html': '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Dorm Management System{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('home') }}">Dorm System</a>
            {% if session.username %}
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">Welcome, {{ session.username }}!</span>
                <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
            </div>
            {% endif %}
        </div>
    </nav>

    <div class="container mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }} alert-dismissible fade show">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>''',

    'index.html': '''{% extends "base.html" %}

{% block content %}
<div class="jumbotron">
    <h1 class="display-4">Welcome to Dorm Management System</h1>
    <p class="lead">Manage your dormitory bookings and rooms efficiently.</p>
    <hr class="my-4">
    <div class="btn-group">
        <a class="btn btn-primary btn-lg" href="{{ url_for('login') }}">Login</a>
        <a class="btn btn-secondary btn-lg" href="{{ url_for('register_choice') }}">Register</a>
    </div>
</div>
{% endblock %}''',

    'login.html': '''{% extends "base.html" %}

{% block title %}Login - Dorm System{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h3>Login</h3>
            </div>
            <div class="card-body">
                <form method="POST">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                    <a href="{{ url_for('register_choice') }}" class="btn btn-link">Register</a>
                </form>
            </div>
        </div>
    </div>
</div>
{% endblock %}''',

    'owner_dashboard.html': '''{% extends "base.html" %}

{% block title %}Owner Dashboard - Dorm System{% endblock %}

{% block content %}
<h2>Owner Dashboard</h2>

<!-- Stats Cards -->
<div class="row mb-4">
    <div class="col-md-3">
        <div class="card bg-primary text-white">
            <div class="card-body">
                <h5>Total Users</h5>
                <h2>{{ stats.total_users }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-success text-white">
            <div class="card-body">
                <h5>Total Rooms</h5>
                <h2>{{ stats.total_rooms }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-info text-white">
            <div class="card-body">
                <h5>Active Bookings</h5>
                <h2>{{ stats.active_bookings }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-warning text-white">
            <div class="card-body">
                <h5>Pending Approvals</h5>
                <h2>{{ stats.pending_approvals }}</h2>
            </div>
        </div>
    </div>
</div>

<!-- Pending Users -->
{% if pending_users %}
<div class="card mb-4">
    <div class="card-header">
        <h4>Pending User Approvals</h4>
    </div>
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in pending_users %}
                    <tr>
                        <td>{{ user.username }}</td>
                        <td>{{ user.email }}</td>
                        <td>{{ user.role.title() }}</td>
                        <td>{{ user.created_at.strftime('%Y-%m-%d') }}</td>
                        <td>
                            <a href="{{ url_for('approve_user', user_id=user.id) }}" 
                               class="btn btn-sm btn-success">Approve</a>
                            <a href="{{ url_for('reject_user', user_id=user.id) }}" 
                               class="btn btn-sm btn-danger">Reject</a>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
{% endif %}

<div class="card">
    <div class="card-header">
        <h4>System Overview</h4>
    </div>
    <div class="card-body">
        <p>Welcome to the owner dashboard. You can manage user approvals and monitor the system from here.</p>
    </div>
</div>
{% endblock %}'''
}

# Create all template files
for filename, content in templates.items():
    with open(f'templates/{filename}', 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Created templates/{filename}")

print("All templates created successfully!")