import "./style.css";

let mode = "login";
let csrfToken = null;
const authForm = document.querySelector("#auth-form");
const authStatus = document.querySelector("#auth-status");
const taskForm = document.querySelector("#task-form");
const tasksList = document.querySelector("#tasks");
const userLabel = document.querySelector("#user-label");
const logoutButton = document.querySelector("#logout");

function setMode(nextMode) {
  mode = nextMode;
  document.querySelector("#login-tab").setAttribute("aria-selected", String(mode === "login"));
  document.querySelector("#register-tab").setAttribute("aria-selected", String(mode === "register"));
  document.querySelectorAll(".register-only").forEach((element) => element.classList.toggle("hidden", mode !== "register"));
  document.querySelectorAll(".login-only").forEach((element) => element.classList.toggle("hidden", mode !== "login"));
  authForm.password.autocomplete = mode === "register" ? "new-password" : "current-password";
  document.querySelector("#auth-submit").textContent = mode === "register" ? "Create secure account" : "Log in securely";
  authStatus.textContent = "";
}

document.querySelector("#login-tab").addEventListener("click", () => setMode("login"));
document.querySelector("#register-tab").addEventListener("click", () => setMode("register"));

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (csrfToken && !["GET", "HEAD"].includes(options.method || "GET")) headers["X-CSRF-TOKEN"] = csrfToken;
  return fetch(path, { credentials: "include", ...options, headers });
}

async function refreshCsrf() {
  const response = await api("/auth/csrf");
  if (response.ok) csrfToken = (await response.json()).csrf_token;
}

function setAuthenticated(user) {
  userLabel.textContent = `${user.username} · ${user.role}`;
  logoutButton.classList.remove("hidden");
  taskForm.querySelectorAll("input, button").forEach((element) => { element.disabled = false; });
}

function setSignedOut() {
  csrfToken = null;
  userLabel.textContent = "Sign in to load your tasks";
  logoutButton.classList.add("hidden");
  taskForm.querySelectorAll("input, button").forEach((element) => { element.disabled = true; });
  tasksList.innerHTML = '<li class="empty">Your authorized records will appear here.</li>';
}

function taskElement(task) {
  const item = document.createElement("li");
  item.className = "task";
  const check = document.createElement("button");
  check.className = `check ${task.completed ? "done" : ""}`;
  check.type = "button";
  check.setAttribute("aria-label", task.completed ? "Mark task open" : "Mark task complete");
  check.textContent = task.completed ? "✓" : "";
  check.addEventListener("click", async () => {
    const response = await api(`/api/tasks/${task.id}`, { method: "PATCH", body: JSON.stringify({ completed: !task.completed }) });
    if (response.ok) await loadTasks();
  });
  const title = document.createElement("span");
  title.className = `task-title ${task.completed ? "done" : ""}`;
  title.textContent = task.title;
  const remove = document.createElement("button");
  remove.className = "delete";
  remove.type = "button";
  remove.textContent = "Delete";
  remove.addEventListener("click", async () => {
    const response = await api(`/api/tasks/${task.id}`, { method: "DELETE" });
    if (response.ok) await loadTasks();
  });
  item.append(check, title, remove);
  return item;
}

async function loadTasks() {
  const response = await api("/api/tasks");
  if (!response.ok) return setSignedOut();
  const { tasks } = await response.json();
  tasksList.replaceChildren(...(tasks.length ? tasks.map(taskElement) : [Object.assign(document.createElement("li"), { className: "empty", textContent: "No tasks yet. Add one above." })]));
}

async function bootstrap() {
  const response = await api("/auth/me");
  if (!response.ok) return setSignedOut();
  const user = await response.json();
  setAuthenticated(user);
  await refreshCsrf();
  await loadTasks();
}

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  authStatus.className = "status";
  authStatus.textContent = mode === "register" ? "Creating account…" : "Signing in…";
  const form = new FormData(authForm);
  const payload = mode === "register"
    ? { username: form.get("username"), email: form.get("email"), password: form.get("password") }
    : { identifier: form.get("identifier"), password: form.get("password") };
  const response = await api(`/auth/${mode}`, { method: "POST", body: JSON.stringify(payload) });
  const result = await response.json();
  if (!response.ok) {
    authStatus.className = "status error";
    authStatus.textContent = result.message || "Authentication failed";
    return;
  }
  authStatus.textContent = mode === "register" ? "Account created." : "Signed in.";
  authForm.reset();
  await bootstrap();
});

taskForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const title = new FormData(taskForm).get("title");
  const response = await api("/api/tasks", { method: "POST", body: JSON.stringify({ title }) });
  if (response.ok) {
    taskForm.reset();
    await loadTasks();
  }
});

logoutButton.addEventListener("click", async () => {
  await api("/auth/logout", { method: "POST" });
  setSignedOut();
});

bootstrap();
