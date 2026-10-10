(() => {
  "use strict";

  const TOKEN_KEY = "secureapp.token";
  const USERNAME_RE = /^[A-Za-z0-9_]{3,32}$/;
  const PASSWORD_MIN = 12;
  const PASSWORD_MAX = 128;
  const TITLE_MAX = 200;
  const BODY_MAX = 10000;
  const PREVIEW_LEN = 90;

  const $ = (id) => document.getElementById(id);
  const els = {
    authView: $("auth-view"),
    appView: $("app-view"),
    session: $("session"),
    currentUser: $("current-user"),
    logoutBtn: $("logout-btn"),
    tabLogin: $("tab-login"),
    tabRegister: $("tab-register"),
    authForm: $("auth-form"),
    authUsername: $("auth-username"),
    authPassword: $("auth-password"),
    authHint: $("auth-hint"),
    authError: $("auth-error"),
    authSubmit: $("auth-submit"),
    search: $("search"),
    newBtn: $("new-btn"),
    noteList: $("note-list"),
    listEmpty: $("list-empty"),
    editorEmpty: $("editor-empty"),
    noteForm: $("note-form"),
    noteTitle: $("note-title"),
    noteBody: $("note-body"),
    noteMeta: $("note-meta"),
    charCount: $("char-count"),
    noteError: $("note-error"),
    saveBtn: $("save-btn"),
    deleteBtn: $("delete-btn"),
    status: $("status"),
  };

  const state = {
    token: null,
    user: null,
    notes: [],
    selectedId: null,
    isNew: false,
    dirty: false,
    busy: false,
    query: "",
    authMode: "login",
  };

  class ApiError extends Error {
    constructor(message, status) {
      super(message);
      this.status = status;
    }
  }

  function loadToken() {
    try {
      return sessionStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  }

  function storeToken(token) {
    try {
      sessionStorage.setItem(TOKEN_KEY, token);
    } catch {
      // Storage unavailable: the token lives in memory for this page only.
    }
  }

  function clearStoredToken() {
    try {
      sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      // Nothing stored to clear.
    }
  }

  async function api(path, { method = "GET", body } = {}) {
    const headers = {};
    const init = { method, headers, credentials: "same-origin", cache: "no-store" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    if (state.token) {
      headers["Authorization"] = `Bearer ${state.token}`;
    }

    let res;
    try {
      res = await fetch(path, init);
    } catch {
      throw new ApiError("Cannot reach the server. Check that it is running.", 0);
    }

    let data = null;
    if (res.status !== 204) {
      try {
        data = await res.json();
      } catch {
        data = null;
      }
    }

    if (!res.ok) {
      if (res.status === 401 && state.token) {
        expireSession();
      }
      const message = data && typeof data.error === "string" ? data.error : `Request failed (${res.status}).`;
      throw new ApiError(message, res.status);
    }
    return data;
  }

  function expireSession() {
    clearStoredToken();
    showAuth("Your session has expired. Please log in again.");
  }

  function showAuth(message) {
    state.token = null;
    state.user = null;
    state.notes = [];
    state.query = "";
    els.search.value = "";
    els.noteList.replaceChildren();
    els.listEmpty.hidden = true;
    els.currentUser.textContent = "";
    els.session.hidden = true;
    els.appView.hidden = true;
    resetEditor();
    els.authView.hidden = false;
    els.authPassword.value = "";
    setAuthError(message || "");
    els.authUsername.focus();
  }

  function enterApp() {
    return (async () => {
      state.user = await api("/api/me");
      els.currentUser.textContent = state.user.username;
      els.authView.hidden = true;
      els.session.hidden = false;
      els.appView.hidden = false;
      await loadNotes();
    })();
  }

  async function loadNotes() {
    state.notes = await api("/api/notes");
    state.notes.sort((a, b) => b.id - a.id);
    renderList();
  }

  function setAuthMode(mode) {
    state.authMode = mode;
    const isRegister = mode === "register";
    els.tabLogin.classList.toggle("active", !isRegister);
    els.tabLogin.setAttribute("aria-selected", String(!isRegister));
    els.tabRegister.classList.toggle("active", isRegister);
    els.tabRegister.setAttribute("aria-selected", String(isRegister));
    els.authSubmit.textContent = isRegister ? "Create account" : "Log in";
    els.authPassword.autocomplete = isRegister ? "new-password" : "current-password";
    els.authHint.hidden = !isRegister;
    setAuthError("");
  }

  function validateAuth(username, password, isRegister) {
    if (!username || !password) {
      return "Enter your username and password.";
    }
    if (!isRegister) {
      return "";
    }
    if (!USERNAME_RE.test(username)) {
      return "Username must be 3-32 letters, digits or underscores.";
    }
    if (password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
      return `Password must be ${PASSWORD_MIN}-${PASSWORD_MAX} characters.`;
    }
    return "";
  }

  async function onAuthSubmit(event) {
    event.preventDefault();
    const username = els.authUsername.value.trim();
    const password = els.authPassword.value;
    const isRegister = state.authMode === "register";

    const problem = validateAuth(username, password, isRegister);
    if (problem) {
      setAuthError(problem);
      return;
    }

    els.authSubmit.disabled = true;
    setAuthError("");
    try {
      if (isRegister) {
        await api("/api/register", { method: "POST", body: { username, password } });
      }
      const { token } = await api("/api/login", { method: "POST", body: { username, password } });
      state.token = token;
      storeToken(token);
      els.authPassword.value = "";
      await enterApp();
    } catch (err) {
      if (state.token) {
        clearStoredToken();
        showAuth(err.message);
      } else {
        setAuthError(err.message);
      }
    } finally {
      els.authSubmit.disabled = false;
    }
  }

  function onLogout() {
    if (!confirmDiscard()) {
      return;
    }
    clearStoredToken();
    showAuth("");
  }

  function setAuthError(message) {
    els.authError.textContent = message;
    els.authError.hidden = !message;
  }

  function setNoteError(message) {
    els.noteError.textContent = message;
    els.noteError.hidden = !message;
  }

  function setStatus(text) {
    els.status.textContent = text;
  }

  function setDirty(value) {
    state.dirty = value;
  }

  function setBusy(value) {
    state.busy = value;
    els.saveBtn.disabled = value;
    els.deleteBtn.disabled = value;
    els.newBtn.disabled = value;
  }

  function updateCount() {
    els.charCount.textContent = `${els.noteBody.value.length} / ${BODY_MAX}`;
  }

  function formatDate(value) {
    if (!value) {
      return "";
    }
    const date = new Date(`${String(value).replace(" ", "T")}Z`);
    return Number.isNaN(date.getTime()) ? "" : date.toLocaleString();
  }

  function confirmDiscard() {
    return !state.dirty || window.confirm("Discard your unsaved changes?");
  }

  function resetEditor() {
    state.selectedId = null;
    state.isNew = false;
    setDirty(false);
    els.noteForm.hidden = true;
    els.editorEmpty.hidden = false;
    setNoteError("");
    setStatus("");
  }

  function showEditor(note) {
    els.noteTitle.value = note ? note.title : "";
    els.noteBody.value = note ? note.body : "";
    setMeta(note);
    els.editorEmpty.hidden = true;
    els.noteForm.hidden = false;
    setNoteError("");
    setDirty(false);
    setStatus("");
    updateCount();
  }

  function setMeta(note) {
    els.noteMeta.textContent = note && note.created_at ? `Created ${formatDate(note.created_at)}` : "New note";
    els.deleteBtn.hidden = state.isNew;
  }

  function markSaved(title, body) {
    const unchanged = els.noteTitle.value.trim() === title && els.noteBody.value === body;
    setDirty(!unchanged);
    setStatus(unchanged ? "Saved" : "Unsaved changes");
  }

  function openNote(id) {
    if (!confirmDiscard()) {
      return;
    }
    const note = state.notes.find((n) => n.id === id);
    if (!note) {
      return;
    }
    state.selectedId = id;
    state.isNew = false;
    showEditor(note);
    renderList();
  }

  function startNewNote() {
    if (!confirmDiscard()) {
      return;
    }
    state.selectedId = null;
    state.isNew = true;
    showEditor(null);
    renderList();
    els.noteTitle.focus();
  }

  function onEdit() {
    setDirty(true);
    setStatus("Unsaved changes");
    updateCount();
  }

  function renderList() {
    const q = state.query.trim().toLowerCase();
    const visible = state.notes.filter(
      (n) => !q || n.title.toLowerCase().includes(q) || n.body.toLowerCase().includes(q)
    );
    els.noteList.replaceChildren(...visible.map(noteItem));
    els.listEmpty.hidden = visible.length > 0;
    els.listEmpty.textContent = state.notes.length
      ? "No notes match your search."
      : "No notes yet. Create your first one.";
  }

  function noteItem(note) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "note-item";
    if (note.id === state.selectedId) {
      btn.classList.add("selected");
      btn.setAttribute("aria-current", "true");
    }
    btn.addEventListener("click", () => openNote(note.id));

    const title = document.createElement("span");
    title.className = "note-item-title";
    title.textContent = note.title;

    const preview = document.createElement("span");
    preview.className = "note-item-preview";
    preview.textContent = note.body.replace(/\s+/g, " ").trim().slice(0, PREVIEW_LEN) || "No content";

    const date = document.createElement("span");
    date.className = "note-item-date";
    date.textContent = formatDate(note.created_at);

    btn.append(title, preview, date);
    li.append(btn);
    return li;
  }

  async function onSave(event) {
    event.preventDefault();
    if (state.busy) {
      return;
    }
    const title = els.noteTitle.value.trim();
    const body = els.noteBody.value;
    if (title.length === 0 || title.length > TITLE_MAX) {
      setNoteError(`Title must be 1-${TITLE_MAX} characters.`);
      return;
    }
    if (body.length > BODY_MAX) {
      setNoteError(`Body must be at most ${BODY_MAX} characters.`);
      return;
    }

    setNoteError("");
    setBusy(true);
    setStatus("Saving...");
    try {
      if (state.isNew) {
        const created = await api("/api/notes", { method: "POST", body: { title, body } });
        state.selectedId = created.id;
        state.isNew = false;
        await loadNotes();
        setMeta(state.notes.find((n) => n.id === created.id) || null);
      } else {
        const updated = await api(`/api/notes/${state.selectedId}`, {
          method: "PUT",
          body: { title, body },
        });
        state.notes = state.notes.map((n) => (n.id === updated.id ? updated : n));
        renderList();
      }
      markSaved(title, body);
    } catch (err) {
      setNoteError(err.message);
      setStatus("");
    } finally {
      setBusy(false);
    }
  }

  async function onDelete() {
    if (state.isNew || state.selectedId === null || state.busy) {
      return;
    }
    if (!window.confirm("Delete this note permanently?")) {
      return;
    }
    const id = state.selectedId;
    let removed = false;
    setBusy(true);
    try {
      await api(`/api/notes/${id}`, { method: "DELETE" });
      removed = true;
    } catch (err) {
      if (err.status === 404) {
        removed = true;
      } else {
        setNoteError(err.message);
      }
    }
    setBusy(false);
    if (removed) {
      state.notes = state.notes.filter((n) => n.id !== id);
      resetEditor();
      renderList();
    }
  }

  function init() {
    els.tabLogin.addEventListener("click", () => setAuthMode("login"));
    els.tabRegister.addEventListener("click", () => setAuthMode("register"));
    els.authForm.addEventListener("submit", onAuthSubmit);
    els.logoutBtn.addEventListener("click", onLogout);
    els.search.addEventListener("input", () => {
      state.query = els.search.value;
      renderList();
    });
    els.newBtn.addEventListener("click", startNewNote);
    els.noteForm.addEventListener("submit", onSave);
    els.deleteBtn.addEventListener("click", onDelete);
    els.noteTitle.addEventListener("input", onEdit);
    els.noteBody.addEventListener("input", onEdit);

    document.addEventListener("keydown", (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s" && !els.noteForm.hidden) {
        event.preventDefault();
        els.noteForm.requestSubmit();
      }
    });

    window.addEventListener("beforeunload", (event) => {
      if (state.dirty) {
        event.preventDefault();
        event.returnValue = "";
      }
    });

    const saved = loadToken();
    if (!saved) {
      showAuth("");
      return;
    }
    state.token = saved;
    enterApp().catch((err) => {
      if (state.token) {
        clearStoredToken();
        showAuth(err.message);
      }
    });
  }

  init();
})();
