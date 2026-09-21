def csrf_headers(client):
    cookie = client.get_cookie("csrf_access_token")
    return {"X-CSRF-TOKEN": cookie.value} if cookie else {}


def register(client, username="alice", email="alice@example.com", password="correct horse battery staple"):
    return client.post("/auth/register", json={"username": username, "email": email, "password": password})


def test_registration_hashes_password_and_sets_auth_cookies(client):
    response = register(client)
    assert response.status_code == 201
    assert "access_token_cookie" in str(response.headers)
    with client.application.app_context():
        from app.models import User
        user = User.query.filter_by(username="alice").first()
        assert user.password_hash != "correct horse battery staple"
        assert user.check_password("correct horse battery staple")


def test_user_can_only_access_owned_tasks(client):
    assert register(client).status_code == 201
    created = client.post("/api/tasks", json={"title": "private task"}, headers=csrf_headers(client))
    task_id = created.get_json()["task"]["id"]
    client.post("/auth/logout", headers=csrf_headers(client))

    assert register(client, "bob", "bob@example.com").status_code == 201
    assert client.get("/api/tasks").get_json()["tasks"] == []
    assert client.patch(f"/api/tasks/{task_id}", json={"title": "tampered"}, headers=csrf_headers(client)).status_code == 404


def test_sql_like_input_is_treated_as_data(client):
    assert register(client).status_code == 201
    response = client.post("/api/tasks", json={"title": "'; DROP TABLE user; --"}, headers=csrf_headers(client))
    assert response.status_code == 201
    assert client.get("/api/tasks").status_code == 200


def test_admin_endpoint_requires_role(client):
    assert register(client).status_code == 201
    assert client.get("/api/admin/health").status_code == 403


def test_missing_csrf_token_blocks_mutation(client):
    assert register(client).status_code == 201
    assert client.post("/api/tasks", json={"title": "blocked"}).status_code == 401
