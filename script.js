console.log("✅ script.js is working!");
console.log("✅ script.js loaded successfully");

// ==========================
// GLOBALS
// ==========================
let currentTrackIndex = 0;
let isPlaying = false;
let audio = new Audio();
let playlist = [];

// ==========================
// SAFE ELEMENT SELECTOR
// ==========================
function $(id) {
  return document.getElementById(id);
}

// ==========================
// PLAYER CONTROLS
// ==========================
const nowPlaying = $("nowPlaying");
const playBtn = $("playPauseBtn");
const nextBtn = $("nextBtn");
const prevBtn = $("prevBtn");
const progress = $("progress");
const volumeSlider = $("volume");

function loadTrack(index) {
  if (playlist.length === 0) return;
  currentTrackIndex = index;
  audio.src = playlist[index].src;
  if (nowPlaying) nowPlaying.textContent = "🎶 Now Playing: " + playlist[index].title;
}

function playTrack() {
  if (playlist.length === 0) return;
  audio.play();
  isPlaying = true;
  if (playBtn) playBtn.textContent = "⏸ Pause";
}

function pauseTrack() {
  audio.pause();
  isPlaying = false;
  if (playBtn) playBtn.textContent = "▶ Play";
}

// Button listeners
if (playBtn) {
  playBtn.addEventListener("click", () => {
    if (isPlaying) pauseTrack();
    else playTrack();
  });
}

if (nextBtn) {
  nextBtn.addEventListener("click", () => {
    if (playlist.length === 0) return;
    currentTrackIndex = (currentTrackIndex + 1) % playlist.length;
    loadTrack(currentTrackIndex);
    playTrack();
  });
}

if (prevBtn) {
  prevBtn.addEventListener("click", () => {
    if (playlist.length === 0) return;
    currentTrackIndex = (currentTrackIndex - 1 + playlist.length) % playlist.length;
    loadTrack(currentTrackIndex);
    playTrack();
  });
}

// Progress bar
if (progress) {
  audio.addEventListener("timeupdate", () => {
    if (audio.duration) {
      progress.value = (audio.currentTime / audio.duration) * 100;
    }
  });

  progress.addEventListener("input", () => {
    if (audio.duration) {
      audio.currentTime = (progress.value / 100) * audio.duration;
    }
  });
}

// Volume
if (volumeSlider) {
  volumeSlider.addEventListener("input", () => {
    audio.volume = volumeSlider.value;
  });
}

/*
  upload script.js — client-side for uploading songs
  --------------------------------------------------
  Features:
  - Handles music upload form with file + metadata (title, artist, album)
  - Requires user to be logged in (JWT token saved by login script)
  - Shows upload progress + status messages
  - Fetches and displays song list
  - Provides audio player links for preview

  Requirements:
  - Login script.js must already be included (provides MusicAuth API)
  - Upload page should include a form with id="uploadForm" and inputs:
      - <input type="text" name="title" />
      - <input type="text" name="artist" />
      - <input type="text" name="album" />
      - <input type="file" name="musicFile" accept="audio/*" />
      - <button type="submit">Upload</button>
    Also include:
      - <div id="uploadStatus"></div>
  - A container with id="songsList" to display uploaded songs
*/

(function(){
  'use strict';

  const API_BASE = (document.body && document.body.dataset && document.body.dataset.apiBase) || 'http://localhost:5000';

  function $(sel, root){ return (root||document).querySelector(sel); }
  function $all(sel, root){ return Array.from((root||document).querySelectorAll(sel)); }

  function setStatus(el, msg, type='info'){
    if (!el) return;
    el.textContent = msg || '';
    el.dataset.type = type;
    el.hidden = !msg;
  }

  // --- Upload form wiring ---
  function wireUploadForm(){
    const form = $('#uploadForm');
    if (!form) return;

    const statusEl = $('#uploadStatus');

    form.addEventListener('submit', async (e) => {
      e.preventDefault();

      if (!window.MusicAuth || !MusicAuth.isAuthenticated()){
        setStatus(statusEl, 'Please login first to upload.', 'error');
        return;
      }

      const formData = new FormData(form);
      const token = MusicAuth.getAuthToken();

      setStatus(statusEl, 'Uploading…', 'info');

      try {
        const res = await fetch(`${API_BASE}/upload`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
          body: formData
        });
        if (!res.ok) throw new Error(`Upload failed (${res.status})`);
        const data = await res.json();
        setStatus(statusEl, 'Upload successful!', 'success');
        form.reset();
        await loadSongs();
      } catch(err){
        setStatus(statusEl, err.message || 'Upload failed', 'error');
      }
    });
  }

  // --- Fetch songs list ---
  async function loadSongs(){
    const listEl = $('#songsList');
    if (!listEl) return;
    listEl.innerHTML = 'Loading songs…';
    try {
      const res = await fetch(`${API_BASE}/songs`);
      if (!res.ok) throw new Error('Failed to fetch songs');
      const songs = await res.json();
      if (!songs.length){
        listEl.innerHTML = '<p>No songs uploaded yet.</p>';
        return;
      }
      const html = songs.map(song => `
        <div class="song-card">
          <h3>${song.title} <small>by ${song.artist}</small></h3>
          ${song.album ? `<p><em>${song.album}</em></p>` : ''}
          <audio controls src="${API_BASE}${song.filePath}"></audio>
          <p class="uploader">Uploaded by: ${song.uploadedBy ? song.uploadedBy.name || song.uploadedBy.email : 'Unknown'}</p>
        </div>
      `).join('');
      listEl.innerHTML = html;
    } catch(err){
      listEl.innerHTML = `<p class="error">${err.message}</p>`;
    }
  }

  // --- Init ---
  document.addEventListener('DOMContentLoaded', () => {
    wireUploadForm();
    loadSongs();
  });
})();

 //---Signup 
 constform =
 document.getElementById("signupForm");

 form.addEventListener("submit", async (e) => {
  e.preventDefault();
  
  const username =
  document.getElementById("username").value;
  const email =
  document.getElementById("email").value;
  const password =
  document.getElementById("password").value;

  // Send data to backend 
  const res = await fetch("http://localhost:5000/auth/signup", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body:
    JSON.stringify({ username, email, password })
  });

  const data= await
  res.json();

  if (res.ok) {
    alert("Signup successful!");
    console.log("Response:", data)
    // Optionally redirect to login page
    window.location.href = "/login.html";
  } else {
    alert("signup failed: " +
       data.error);
     }
  console.error("Error:", err);
  alert("Something went wrong. Try again later.");
 });

// ==========================
// NAVIGATION (Single Page)
// ==========================
const navLinks = document.querySelectorAll("nav a");
const pages = document.querySelectorAll(".page");

if (navLinks.length && pages.length) {
  navLinks.forEach(link => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const target = link.getAttribute("data-page");

      pages.forEach(p => p.style.display = "none");
      const page = $(target);
      if (page) page.style.display = "block";
    });
  });

  // Show home by default
  document.addEventListener("DOMContentLoaded", () => {
    pages.forEach(p => p.style.display = "none");
    const home = $("home");
    if (home) home.style.display = "block";
  });
}
// ==========================
// PLAYLIST DATA (Example)
// ==========================
let play= [
  { title: "Blinding Lights", artist: "The Weeknd", date: "2020-01-01", src: "audio/song1.mp3" },
  { title: "Levitating", artist: "Dua Lipa", date: "2021-03-05", src: "audio/song2.mp3" },
  { title: "Peaches", artist: "Justin Bieber", date: "2021-04-10", src: "audio/song3.mp3" }
];

// ==========================
// RENDER PLAYLIST
// ==========================
const playlistContainer = document.getElementById("playlistContainer");

function renderPlaylist(list) {
  if (!playlistContainer) return;
  playlistContainer.innerHTML = "";
  list.forEach(track => {
    const li = document.createElement("li");
    li.textContent = `${track.title} - ${track.artist}`;
    playlistContainer.appendChild(li);
  });
}

// ==========================
// FILTER FUNCTIONALITY
// ==========================
const searchInput = document.getElementById("searchInput");
if (searchInput) {
  searchInput.addEventListener("input", () => {
    const query = searchInput.value.toLowerCase();
    const filtered = playlist.filter(track =>
      track.title.toLowerCase().includes(query) ||
      track.artist.toLowerCase().includes(query)
    );
    renderPlaylist(filtered);
  });
}

// ==========================
// SORT FUNCTIONALITY
// ==========================
const sortSelect = document.getElementById("sortSelect");
if (sortSelect) {
  sortSelect.addEventListener("change", () => {
    let sorted = [...playlist]; // copy array
    if (sortSelect.value === "title") {
      sorted.sort((a, b) => a.title.localeCompare(b.title));
    } else if (sortSelect.value === "artist") {
      sorted.sort((a, b) => a.artist.localeCompare(b.artist));
    } else if (sortSelect.value === "date") {
      sorted.sort((a, b) => new Date(a.date) - new Date(b.date));
    }
    renderPlaylist(sorted);
  });
}

// ==========================
// INITIAL RENDER
// ==========================
document.addEventListener("DOMContentLoaded", () => {
  renderPlaylist(playlist);
});

// Simple Newsletter Form Demo works in browser only)
const form =
document.getElementById('newsletter-form');
const emailInput =
document.getElementById('newsletter-email');
const messagebox =
document.getElementById('newsletter-message');

// save to browser local storage //
form.addEventListener('submit', function (e) {
   e.preventDefault(); // stop form reload

   const email =
   emailInput.value.trim();

   // check email format
   const valid =
   test(email);
    if (!valid) {
       messagebox.style.color = "red";
      messagebox.textContent = "Please enter a valid email.";
      return;
    }

    // store email locally
    let list =
    JSON.parse(localStorage.getItem('newsletter_emails') || '[]');
     if (!list.includes(email))
      list.push(email);

     localStorage.setItem('newsletter_emails', JSON.stringify(list));

     // feedback
     messagebox.style.color = 'green';
     messagebox.textContent ='☑'
      emailInput.value ='';
      });

      // Wait until page loads fully
      window.addEventListener("load", function() {

     const loader =
      document.getElementById("loader");
      const content =  
      this.document.getElementById("content");

      // Hide loader and show content
      loader.style.display = "none";
      content.style.display = "block";
      });
        
      const input =
      document.getElementById("searchInput" );
      const resultsList =
      document.getElementById("results");

      input.addEventListener("keyup", async () => {
        const query = input.value.trim();
        if (query === "") {
          resultsList.innerHTML = "";
          return;
        }

        const res = await
        fetch('http://localhost:5000/api/search?q=${endcodeURIComponent(query)}');
        const data = await res.json();

        resultsList.innerHTML = data.length
        ? data.map(item => `<li>$
          {item.title} - "${item.artist} ($
          {item.album})</li>`).join("")
          : "<li>No matches found</li>";
          });
          /*
  login script.js — front-end auth utilities for a music website
  -------------------------------------------------------------
  Features
  - Login form handling with client-side validation
  - "Remember me" support (localStorage vs sessionStorage)
  - Status messages + disabling UI while submitting
  - Password visibility toggle
  - Persisted user session (token + user info)
  - authFetch() wrapper that auto-attaches Authorization header
  - Logout utility and optional logout button wiring
  - Redirect back to original page via ?next=/path
  - Simple route guard to protect pages
  - Optional: CSRF header support if a <meta name="csrf-token"> is present

  How to use
  1) Add this file to your project as /assets/js/script.js (or any path) and include it on pages with a <script src="..." defer></script> tag.
  2) Your login page should contain a form with id="loginForm" and inputs with names "email" and "password".
     Optionally include:
       - a checkbox with name="remember"
       - a button or element with id="togglePassword" to show/hide password
       - a container with id="loginStatus" to display messages
       - a submit button with id="loginBtn" (not required)
  3) Backend is expected to expose POST {API_BASE}/auth/login that returns JSON like:
        { token: "<jwt>", user: { id, name, email } }
     By default API_BASE = "http://localhost:5000". Override by setting:
        <body data-api-base="https://your-api.example.com">
  4) To protect any page, add data-protected="true" on <body>.
  5) To add a logout button, include an element with id="logoutBtn".
*/

(function () {
  'use strict';

  // ---------- Config ----------
  const bodyEl = document.body;
  const API_BASE = (bodyEl && bodyEl.dataset && bodyEl.dataset.apiBase) || 'http://localhost:5000';

  // Allows pages to opt into requiring login
  const PAGE_REQUIRES_AUTH = bodyEl && bodyEl.dataset && bodyEl.dataset.protected === 'true';

  // Where to send the user after login if no ?next= is provided
  const DEFAULT_AFTER_LOGIN = bodyEl && bodyEl.dataset && bodyEl.dataset.afterLogin || '/';

  // Where to send the user after logout
  const DEFAULT_AFTER_LOGOUT = bodyEl && bodyEl.dataset && bodyEl.dataset.afterLogout || '/login.html';

  // Optional CSRF meta
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const CSRF_TOKEN = csrfMeta ? csrfMeta.getAttribute('content') : null;

  // ---------- Storage helpers ----------
  const STORAGE_KEYS = {
    token: 'musicapp.auth.token',
    user: 'musicapp.auth.user',
    expires: 'musicapp.auth.expires',
  };

  function getStorage(remember) {
    return remember ? window.localStorage : window.sessionStorage;
  }

  function setAuth({ token, user, expiresAt, remember }) {
    const store = getStorage(remember);
    store.setItem(STORAGE_KEYS.token, token);
    if (user) store.setItem(STORAGE_KEYS.user, JSON.stringify(user));
    if (expiresAt) store.setItem(STORAGE_KEYS.expires, String(expiresAt));
  }

  function clearAuth() {
    [localStorage, sessionStorage].forEach((s) => {
      s.removeItem(STORAGE_KEYS.token);
      s.removeItem(STORAGE_KEYS.user);
      s.removeItem(STORAGE_KEYS.expires);
    });
  }

  function getAuthToken() {
    // Prefer localStorage token if present, else sessionStorage
    return (
      localStorage.getItem(STORAGE_KEYS.token) ||
      sessionStorage.getItem(STORAGE_KEYS.token)
    );
  }

  function getAuthUser() {
    const raw = localStorage.getItem(STORAGE_KEYS.user) || sessionStorage.getItem(STORAGE_KEYS.user);
    try { return raw ? JSON.parse(raw) : null; } catch { return null; }
  }

  function isAuthenticated() {
    const token = getAuthToken();
    if (!token) return false;
    const exp = Number(localStorage.getItem(STORAGE_KEYS.expires) || sessionStorage.getItem(STORAGE_KEYS.expires));
    if (!exp) return true; // no expiry info means assume valid
    return Date.now() < exp;
  }

  // ---------- UI helpers ----------
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $all(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }

  function setStatus(el, msg, type = 'info') {
    if (!el) return;
    el.textContent = msg || '';
    el.dataset.type = type; // style via [data-type="error"|"success"|"info"] in CSS
    el.hidden = !msg;
  }

  function disableDuring(elList, disabled) {
    elList.forEach((el) => { if (el) el.disabled = disabled; });
  }

  function parseNextFromURL() {
    const url = new URL(window.location.href);
    const next = url.searchParams.get('next');
    if (!next) return null;
    try {
      // Prevent open redirects: allow only same-origin paths
      const u = new URL(next, window.location.origin);
      if (u.origin === window.location.origin) return u.pathname + u.search + u.hash;
    } catch { /* ignore invalid */ }
    return null;
  }

  function redirectAfterLogin() {
    const next = parseNextFromURL();
    window.location.href = next || DEFAULT_AFTER_LOGIN;
  }

  function redirectAfterLogout() {
    window.location.href = DEFAULT_AFTER_LOGOUT;
  }

  // ---------- Network helper with auth ----------
  async function authFetch(path, options = {}) {
    const token = getAuthToken();
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    if (!(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }
    if (token) headers.set('Authorization', `Bearer ${token}`);
    if (CSRF_TOKEN) headers.set('X-CSRF-Token', CSRF_TOKEN);

    const res = await fetch(`${API_BASE}${path}`, {
      method: options.method || 'GET',
      headers,
      body: options.body instanceof FormData ? options.body : options.body ? JSON.stringify(options.body) : undefined,
      credentials: options.credentials || 'omit', // change to 'include' if your API uses cookies
    });

    let data = null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      try { data = await res.json(); } catch { /* ignore */ }
    } else {
      data = await res.text().catch(() => null);
    }

    if (!res.ok) {
      const message = (data && (data.message || data.error)) || `Request failed (${res.status})`;
      const error = new Error(message);
      error.status = res.status;
      error.data = data;
      throw error;
    }

    return data;
  }

  // ---------- Auth actions ----------
  async function login({ email, password, remember }) {
    const payload = { email: String(email || '').trim(), password: String(password || '') };
    const data = await authFetch('/auth/login', { method: 'POST', body: payload });
    // Expected response: { token, user, expiresInMs? }
    const token = data.token;
    const user = data.user || null;
    const expiresAt = data.expiresInMs ? (Date.now() + Number(data.expiresInMs)) : null;
    setAuth({ token, user, expiresAt, remember });
    return { token, user };
  }

  function logout() {
    clearAuth();
    redirectAfterLogout();
  }

  // ---------- Form wiring (if present) ----------
  function wireLoginForm() {
    const form = $('#loginForm');
    if (!form) return;

    const emailEl = form.querySelector('input[name="email"]');
    const passwordEl = form.querySelector('input[name="password"]');
    const rememberEl = form.querySelector('input[name="remember"]');
    const statusEl = $('#loginStatus');
    const submitBtn = form.querySelector('[type="submit"], #loginBtn');

    // Password visibility toggle (optional)
    const toggle = $('#togglePassword');
    if (toggle && passwordEl) {
      toggle.addEventListener('click', () => {
        passwordEl.type = passwordEl.type === 'password' ? 'text' : 'password';
        toggle.setAttribute('aria-pressed', passwordEl.type === 'text');
      });
    }

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      setStatus(statusEl, '', 'info');

      const email = emailEl ? emailEl.value : '';
      const password = passwordEl ? passwordEl.value : '';
      const remember = !!(rememberEl && rememberEl.checked);

      // Basic validation
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        setStatus(statusEl, 'Please enter a valid email address.', 'error');
        emailEl && emailEl.focus();
        return;
      }
      if (!password || password.length < 6) {
        setStatus(statusEl, 'Password must be at least 6 characters.', 'error');
        passwordEl && passwordEl.focus();
        return;
      }

      disableDuring([submitBtn, emailEl, passwordEl, rememberEl], true);
      if (submitBtn) submitBtn.dataset.loading = 'true';

      try {
        await login({ email, password, remember });
        setStatus(statusEl, 'Login successful! Redirecting…', 'success');
        redirectAfterLogin();
      } catch (err) {
        const msg = err && err.message ? err.message : 'Login failed. Please try again.';
        setStatus(statusEl, msg, 'error');
      } finally {
        disableDuring([submitBtn, emailEl, passwordEl, rememberEl], false);
        if (submitBtn) submitBtn.dataset.loading = 'false';
      }
    });
  }

  function wireLogoutButton() {
    const btn = $('#logoutBtn');
    if (!btn) return;
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      logout();
    });
  }

  // ---------- Simple route guard ----------
  function guardProtectedPage() {
    if (!PAGE_REQUIRES_AUTH) return;
    if (!isAuthenticated()) {
      const next = encodeURIComponent(window.location.pathname + window.location.search + window.location.hash);
      window.location.href = `/login.html?next=${next}`;
    }
  }

  // ---------- Expose minimal API on window (optional) ----------
  window.MusicAuth = {
    API_BASE,
    isAuthenticated,
    getAuthUser,
    getAuthToken,
    login,
    logout,
    authFetch,
  };

  // ---------- Init ----------
  document.addEventListener('DOMContentLoaded', () => {
    guardProtectedPage();
    wireLoginForm();
    wireLogoutButton();
  });
})();
 