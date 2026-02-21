const state = {
  token: localStorage.getItem('nebula_token') || '',
  me: null,
  lang: localStorage.getItem('nebula_lang') || 'ru',
  authLang: localStorage.getItem('nebula_auth_lang') || 'ru',
  view: { type: null, id: null },
  events: null,
  lastDialogs: {},
  lastChannels: {},
  audioCtx: null,
  soundUnlocked: false,
  notifyEnabled: false,
};

const i18n = {
  ru: {
    login: 'Вход', register: 'Регистрация', identity: '@username', password: 'Пароль',
    send: 'Отправить', message: 'Написать сообщение...', search: 'Поиск по @username',
    dialogs: 'Диалоги', channels: 'Каналы', createAccount: 'Создать аккаунт', signIn: 'Войти',
    newMessage: 'Новое сообщение', newPost: 'Новый пост в канале', newPostShort: 'Новый пост'
  },
  en: {
    login: 'Login', register: 'Register', identity: '@username', password: 'Password',
    send: 'Send', message: 'Write a message...', search: 'Search by @username',
    dialogs: 'Dialogs', channels: 'Channels', createAccount: 'Create account', signIn: 'Sign in',
    newMessage: 'New message', newPost: 'New channel post', newPostShort: 'New post'
  }
};

const $ = (s) => document.querySelector(s);
const el = {
  authView: $('#auth-view'), appView: $('#app-view'),
  tabLogin: $('#tab-login'), tabRegister: $('#tab-register'),
  loginForm: $('#login-form'), registerForm: $('#register-form'),
  loginIdentity: $('#login-identity'), loginPassword: $('#login-password'),
  regUsername: $('#reg-username'), regNickname: $('#reg-nickname'), regPassword: $('#reg-password'),
  btnLogin: $('#btn-login'), btnRegister: $('#btn-register'), authError: $('#auth-error'),
  authLangRu: $('#auth-lang-ru'), authLangEn: $('#auth-lang-en'),
  userSearch: $('#user-search'), searchResults: $('#search-results'), dialogsList: $('#dialogs-list'), channelsList: $('#channels-list'),
  chatHeader: $('#chat-header'), chatMessages: $('#chat-messages'), composer: $('#composer'), msgInput: $('#msg-input'), btnSend: $('#btn-send'),
  openProfile: $('#open-profile'), btnAdmin: $('#btn-admin'), btnLogout: $('#btn-logout'),
  modalProfile: $('#modal-profile'), profileNickname: $('#profile-nickname'), profileAvatarFile: $('#profile-avatar-file'),
  langRu: $('#lang-ru'), langEn: $('#lang-en'), saveProfile: $('#save-profile'), closeProfile: $('#close-profile'),
  btnNewChannel: $('#btn-new-channel'), modalChannel: $('#modal-channel'), channelTitle: $('#channel-title'), channelUsername: $('#channel-username'),
  channelDescription: $('#channel-description'), channelAvatarFile: $('#channel-avatar-file'),
  createChannel: $('#create-channel'), closeChannel: $('#close-channel'),
  modalAdmin: $('#modal-admin'), adminSearch: $('#admin-search'), adminStats: $('#admin-stats'), adminUsers: $('#admin-users'),
  adminChannels: $('#admin-channels'), closeAdmin: $('#close-admin'),
  toastWrap: $('#toast-wrap'),
};

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(path, { ...opts, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `http_${res.status}`);
  return data;
}

function escapeHtml(v) {
  return (v || '').replace(/[&<>\"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function verifyBadge(flag) {
  return flag ? '<span class="verify-badge"></span>' : '';
}

function initials(name) {
  const value = (name || '').trim();
  if (!value) return 'N';
  return value.slice(0, 1).toUpperCase();
}

function avatarMarkup(url, name, cls = '') {
  if (url) {
    return `<span class="avatar ${cls}"><img src="${escapeHtml(url)}" alt="${escapeHtml(name || 'avatar')}" /></span>`;
  }
  return `<span class="avatar ${cls} placeholder">${escapeHtml(initials(name))}</span>`;
}

function fmtDate(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleString();
}

function setAuthLanguage(lang) {
  state.authLang = lang;
  localStorage.setItem('nebula_auth_lang', lang);
  const t = i18n[lang] || i18n.ru;
  el.authLangRu.classList.toggle('active', lang === 'ru');
  el.authLangEn.classList.toggle('active', lang === 'en');
  el.tabLogin.textContent = t.login;
  el.tabRegister.textContent = t.register;
  el.loginIdentity.placeholder = t.identity;
  el.loginPassword.placeholder = t.password;
  el.btnLogin.textContent = t.signIn;
  el.btnRegister.textContent = t.createAccount;
}

function setAppLanguage(lang) {
  state.lang = lang;
  localStorage.setItem('nebula_lang', lang);
  el.langRu.classList.toggle('active', lang === 'ru');
  el.langEn.classList.toggle('active', lang === 'en');
  const t = i18n[lang] || i18n.ru;
  el.userSearch.placeholder = t.search;
  el.msgInput.placeholder = t.message;
  el.btnSend.textContent = t.send;
  document.querySelectorAll('.list-title')[0].textContent = t.dialogs;
  document.querySelectorAll('.list-title')[1].textContent = t.channels;
}

function unlockSound() {
  if (!state.audioCtx) {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return;
    state.audioCtx = new Ctx();
  }
  if (state.audioCtx.state === 'suspended') state.audioCtx.resume();
  state.soundUnlocked = true;
}

function playNotify() {
  if (!state.soundUnlocked || !state.audioCtx) return;
  const ctx = state.audioCtx;
  const t = ctx.currentTime;
  const gain = ctx.createGain();
  gain.gain.setValueAtTime(0.0001, t);
  gain.gain.exponentialRampToValueAtTime(0.15, t + 0.02);
  gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.2);
  gain.connect(ctx.destination);
  const osc = ctx.createOscillator();
  osc.type = 'sine';
  osc.frequency.setValueAtTime(784, t);
  osc.frequency.setValueAtTime(659, t + 0.09);
  osc.connect(gain);
  osc.start(t);
  osc.stop(t + 0.22);
}

function showToast(title, body, onClick) {
  if (!el.toastWrap) return;
  const t = document.createElement('div');
  t.className = 'toast';
  t.innerHTML = `<div class="title">${escapeHtml(title)}</div><div class="body">${escapeHtml(body)}</div>`;
  t.onclick = () => {
    if (onClick) onClick();
    t.remove();
  };
  el.toastWrap.appendChild(t);
  setTimeout(() => t.remove(), 5000);
}

async function requestNotificationPermission() {
  if (!('Notification' in window)) return;
  if (Notification.permission === 'default') {
    try {
      const p = await Notification.requestPermission();
      state.notifyEnabled = p === 'granted';
    } catch (_) {}
  } else {
    state.notifyEnabled = Notification.permission === 'granted';
  }
}

function notifyUser(title, body, onClick) {
  playNotify();
  if (document.hidden && state.notifyEnabled && 'Notification' in window) {
    const n = new Notification(title, { body });
    if (onClick) n.onclick = () => { window.focus(); onClick(); n.close(); };
  } else {
    showToast(title, body, onClick);
  }
}

function switchTab(mode) {
  const isLogin = mode === 'login';
  el.tabLogin.classList.toggle('active', isLogin);
  el.tabRegister.classList.toggle('active', !isLogin);
  el.loginForm.classList.toggle('hidden', !isLogin);
  el.registerForm.classList.toggle('hidden', isLogin);
  el.authError.textContent = '';
}

async function fileToDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

function profileMini() {
  if (!state.me) return;
  el.openProfile.innerHTML = `
    <div class="mini-row">
      ${avatarMarkup(state.me.avatar_url, state.me.nickname || state.me.username, 'sm')}
      <span>
        <div style="font-weight:700">${escapeHtml(state.me.nickname || state.me.username)}${verifyBadge(state.me.is_verified)}</div>
        <div class="sub">@${escapeHtml(state.me.username)}</div>
      </span>
    </div>
  `;
}

async function authRegister() {
  try {
    const payload = {
      username: el.regUsername.value.trim().toLowerCase(),
      nickname: el.regNickname.value.trim(),
      password: el.regPassword.value,
      language: state.authLang,
    };
    const res = await api('/api/auth/register', { method: 'POST', body: JSON.stringify(payload) });
    state.token = res.token;
    localStorage.setItem('nebula_token', state.token);
    await bootstrapApp();
  } catch (e) { el.authError.textContent = e.message; }
}

async function authLogin() {
  try {
    const payload = { identity: el.loginIdentity.value.trim().toLowerCase(), password: el.loginPassword.value };
    const res = await api('/api/auth/login', { method: 'POST', body: JSON.stringify(payload) });
    state.token = res.token;
    localStorage.setItem('nebula_token', state.token);
    await bootstrapApp();
  } catch (e) { el.authError.textContent = e.message; }
}

async function bootstrapApp() {
  try {
    const me = await api('/api/me');
    state.me = me.user;
    state.lang = state.me.language || state.lang;
    el.authView.classList.add('hidden');
    el.appView.classList.remove('hidden');
    profileMini();
    setAppLanguage(state.lang);
    el.btnAdmin.classList.toggle('hidden', !state.me.is_admin);
    requestNotificationPermission();
    await refreshLists();
    openEvents();
  } catch (_) {
    state.token = '';
    state.me = null;
    localStorage.removeItem('nebula_token');
    el.appView.classList.add('hidden');
    el.authView.classList.remove('hidden');
  }
}

function renderList(container, items, onClick, formatter) {
  container.innerHTML = '';
  if (!items.length) {
    container.innerHTML = '<div class="item sub">Пока пусто</div>';
    return;
  }
  items.forEach((it) => {
    const d = document.createElement('div');
    d.className = 'item';
    d.innerHTML = formatter(it);
    d.onclick = () => onClick(it);
    container.appendChild(d);
  });
}

async function refreshLists() {
  const data = await api('/api/dialogs');
  const prevDialogs = state.lastDialogs || {};
  const prevChannels = state.lastChannels || {};
  const currDialogs = {};
  const currChannels = {};

  (data.dialogs || []).forEach((d) => { currDialogs[d.username] = d; });
  (data.channels || []).forEach((c) => { currChannels[c.username] = c; });

  renderList(el.dialogsList, data.dialogs || [], (it) => openDialog(it.username),
    (it) => `<div class="row-item">${avatarMarkup(it.avatar_url, it.nickname || it.username, 'sm')}<span><div>${escapeHtml(it.nickname || it.username)}${verifyBadge(it.is_verified)}</div><div class="sub">@${escapeHtml(it.username)}</div></span></div>`);

  renderList(el.channelsList, data.channels || [], (it) => openChannel(it.username),
    (it) => `<div class="row-item">${avatarMarkup(it.avatar_url, it.title, 'sm')}<span><div>${escapeHtml(it.title)}${verifyBadge(it.is_verified)}</div><div class="sub">@${escapeHtml(it.username)} · ${escapeHtml(it.role)}</div></span></div>`);

  if (state.events) {
    const t = i18n[state.lang] || i18n.ru;
    (data.dialogs || []).forEach((d) => {
      const prev = prevDialogs[d.username];
      const isNew = prev && d.last_message_id && d.last_message_id !== prev.last_message_id;
      const fromMe = d.last_message_sender_id === state.me.id;
      const active = state.view.type === 'dialog' && state.view.id === d.username;
      if (isNew && !fromMe && !active) {
        notifyUser(d.nickname || d.username, t.newMessage, () => openDialog(d.username));
      }
    });

    (data.channels || []).forEach((c) => {
      const prev = prevChannels[c.username];
      const isSub = c.role !== 'not_subscribed';
      const hasNew = prev && c.last_post_at && c.last_post_at !== prev.last_post_at;
      const fromMe = c.last_post_author_id === state.me.id;
      const active = state.view.type === 'channel' && state.view.id === c.username;
      if (isSub && hasNew && !fromMe && !active) {
        notifyUser(c.title, t.newPostShort, () => openChannel(c.username));
      }
    });
  }

  state.lastDialogs = currDialogs;
  state.lastChannels = currChannels;
}

function msgActions(msg, isMine) {
  const parts = [];
  if (!msg.is_deleted) {
    if (isMine) parts.push(`<button data-edit="${msg.id}">Edit</button>`);
    parts.push(`<button data-del="${msg.id}">Delete</button>`);
    ['👍', '❤️', '🔥'].forEach((r) => parts.push(`<button data-react="${msg.id}" data-val="${r}">${r}</button>`));
  }
  return `<div class="msg-actions">${parts.join('')}</div>`;
}

function reactionView(reactions) {
  const keys = Object.keys(reactions || {});
  if (!keys.length) return '';
  return `<div class="reactions">${keys.map((k) => `<span class="react-chip">${k} ${reactions[k]}</span>`).join('')}</div>`;
}

async function openDialog(username) {
  state.view = { type: 'dialog', id: username };
  const data = await api(`/api/messages/${encodeURIComponent(username)}`);
  const p = data.peer;
  el.chatHeader.innerHTML = `<span class="header-row">${avatarMarkup(p.avatar_url, p.nickname || p.username)}<span>${escapeHtml(p.nickname || p.username)}${verifyBadge(p.is_verified)} <span class="muted">@${escapeHtml(p.username)}</span></span></span>`;
  el.composer.classList.remove('hidden');
  el.msgInput.placeholder = i18n[state.lang].message;
  el.chatMessages.innerHTML = '';
  (data.items || []).forEach((m) => {
    const mine = m.sender_id === state.me.id;
    const b = document.createElement('div');
    b.className = `bubble ${mine ? 'mine' : ''}`;
    b.innerHTML = `
      <div>${escapeHtml(m.content)}</div>
      <div class="meta">${fmtDate(m.created_at)} ${m.edited_at ? '(edited)' : ''}</div>
      ${reactionView(m.reactions)}
      ${msgActions(m, mine)}
    `;
    el.chatMessages.appendChild(b);
  });
  bindMessageActions();
  el.chatMessages.scrollTop = el.chatMessages.scrollHeight;
}

async function openChannel(username) {
  state.view = { type: 'channel', id: username };
  const data = await api(`/api/channels/${encodeURIComponent(username)}/posts`);
  const c = data.channel;
  el.chatHeader.innerHTML = `<span class="header-row">${avatarMarkup(c.avatar_url, c.title)}<span>${escapeHtml(c.title)}${verifyBadge(c.is_verified)} <span class="muted">@${escapeHtml(c.username)}</span></span></span>`;
  el.chatMessages.innerHTML = '';
  (data.items || []).forEach((p) => {
    const b = document.createElement('div');
    b.className = 'bubble';
    b.innerHTML = `<div>${escapeHtml(p.content)}</div><div class="meta">${escapeHtml(p.author_nickname || p.author_username)} · ${fmtDate(p.created_at)}</div>`;
    el.chatMessages.appendChild(b);
  });
  const canPost = state.me && (state.me.id === c.owner_id || state.me.is_admin);
  el.composer.classList.toggle('hidden', !canPost);
  if (!canPost && c.role === 'not_subscribed') {
    const j = document.createElement('div');
    j.className = 'item sub';
    j.textContent = 'Подпишитесь, чтобы видеть обновления в списке';
    el.chatMessages.prepend(j);
    await api(`/api/channels/${encodeURIComponent(username)}/join`, { method: 'POST' }).catch(() => {});
  }
  el.chatMessages.scrollTop = el.chatMessages.scrollHeight;
}

function bindMessageActions() {
  el.chatMessages.querySelectorAll('button[data-react]').forEach((btn) => {
    btn.onclick = async () => {
      await api(`/api/messages/${btn.dataset.react}/react`, { method: 'POST', body: JSON.stringify({ reaction: btn.dataset.val }) });
      await openDialog(state.view.id);
      await refreshLists();
    };
  });
  el.chatMessages.querySelectorAll('button[data-edit]').forEach((btn) => {
    btn.onclick = async () => {
      const v = prompt('New text');
      if (!v) return;
      await api(`/api/messages/${btn.dataset.edit}`, { method: 'PUT', body: JSON.stringify({ content: v }) });
      await openDialog(state.view.id);
    };
  });
  el.chatMessages.querySelectorAll('button[data-del]').forEach((btn) => {
    btn.onclick = async () => {
      await api(`/api/messages/${btn.dataset.del}`, { method: 'DELETE' });
      await openDialog(state.view.id);
      await refreshLists();
    };
  });
}

async function sendCurrent() {
  const text = el.msgInput.value.trim();
  if (!text || !state.view.type) return;
  if (state.view.type === 'dialog') {
    await api('/api/messages', { method: 'POST', body: JSON.stringify({ to_username: state.view.id, content: text }) });
    el.msgInput.value = '';
    await openDialog(state.view.id);
    await refreshLists();
  } else if (state.view.type === 'channel') {
    await api(`/api/channels/${encodeURIComponent(state.view.id)}/posts`, { method: 'POST', body: JSON.stringify({ content: text }) });
    el.msgInput.value = '';
    await openChannel(state.view.id);
  }
}

async function doSearch() {
  const q = el.userSearch.value.trim();
  if (!q) {
    el.searchResults.innerHTML = '';
    return;
  }
  const data = await api(`/api/users/search?q=${encodeURIComponent(q)}`);
  renderList(el.searchResults, data.items || [], (it) => openDialog(it.username),
    (it) => `<div class="row-item">${avatarMarkup(it.avatar_url, it.nickname || it.username, 'sm')}<span><div>${escapeHtml(it.nickname || it.username)}${verifyBadge(it.is_verified)}</div><div class="sub">@${escapeHtml(it.username)}</div></span></div>`);
}

async function saveProfile() {
  const payload = { nickname: el.profileNickname.value.trim(), language: state.lang };
  if (el.profileAvatarFile.files[0]) payload.avatar_url = await fileToDataUrl(el.profileAvatarFile.files[0]);
  const res = await api('/api/profile', { method: 'PUT', body: JSON.stringify(payload) });
  state.me = res.user;
  profileMini();
  el.modalProfile.classList.add('hidden');
}

async function createChannel() {
  let avatar = '';
  if (el.channelAvatarFile.files[0]) avatar = await fileToDataUrl(el.channelAvatarFile.files[0]);
  await api('/api/channels', {
    method: 'POST',
    body: JSON.stringify({
      title: el.channelTitle.value.trim(),
      username: el.channelUsername.value.trim().toLowerCase(),
      description: el.channelDescription.value.trim(),
      avatar_url: avatar,
    }),
  });
  el.modalChannel.classList.add('hidden');
  el.channelTitle.value = '';
  el.channelUsername.value = '';
  el.channelDescription.value = '';
  el.channelAvatarFile.value = '';
  await refreshLists();
}

function logout() {
  if (state.events) {
    state.events.close();
    state.events = null;
  }
  state.token = '';
  state.me = null;
  state.view = { type: null, id: null };
  localStorage.removeItem('nebula_token');
  el.appView.classList.add('hidden');
  el.authView.classList.remove('hidden');
  el.chatMessages.innerHTML = '';
  el.chatHeader.textContent = 'Выберите чат';
  el.authError.textContent = '';
}

async function loadAdmin() {
  const query = el.adminSearch.value.trim();
  const data = await api(`/api/admin/overview${query ? `?query=${encodeURIComponent(query)}` : ''}`);
  el.adminStats.textContent = `users: ${data.stats.users} | channels: ${data.stats.channels} | messages: ${data.stats.messages}`;

  el.adminUsers.innerHTML = '';
  (data.users || []).forEach((u) => {
    const d = document.createElement('div');
    d.className = 'item';
    d.innerHTML = `
      <div>${escapeHtml(u.nickname || u.username)} @${escapeHtml(u.username)} ${u.is_verified ? '✔' : ''} ${u.is_admin ? '[admin]' : ''} ${u.is_banned ? '[banned]' : ''}</div>
      <div class="msg-actions">
        <button data-a="verify" data-id="${u.id}">verify</button>
        <button data-a="admin" data-id="${u.id}">admin</button>
        <button data-a="ban" data-id="${u.id}">ban</button>
        <button data-a="del" data-id="${u.id}">delete</button>
      </div>
    `;
    el.adminUsers.appendChild(d);
  });

  el.adminChannels.innerHTML = '';
  (data.channels || []).forEach((c) => {
    const d = document.createElement('div');
    d.className = 'item';
    d.innerHTML = `
      <div>${escapeHtml(c.title)} @${escapeHtml(c.username)} ${c.is_verified ? '✔' : ''}</div>
      <div class="msg-actions">
        <button data-ca="verify" data-id="${c.id}">verify</button>
        <button data-ca="del" data-id="${c.id}">delete</button>
      </div>
    `;
    el.adminChannels.appendChild(d);
  });

  el.adminUsers.querySelectorAll('button[data-a]').forEach((b) => {
    b.onclick = async () => {
      const id = b.dataset.id;
      const a = b.dataset.a;
      if (a === 'verify') await api(`/api/admin/users/${id}/verify`, { method: 'POST' });
      if (a === 'admin') await api(`/api/admin/users/${id}/admin`, { method: 'POST' });
      if (a === 'ban') await api(`/api/admin/users/${id}/ban`, { method: 'POST' });
      if (a === 'del') await api(`/api/admin/users/${id}`, { method: 'DELETE' });
      await loadAdmin();
      await refreshLists();
    };
  });

  el.adminChannels.querySelectorAll('button[data-ca]').forEach((b) => {
    b.onclick = async () => {
      const id = b.dataset.id;
      if (b.dataset.ca === 'verify') await api(`/api/admin/channels/${id}/verify`, { method: 'POST' });
      if (b.dataset.ca === 'del') await api(`/api/admin/channels/${id}`, { method: 'DELETE' });
      await loadAdmin();
      await refreshLists();
    };
  });
}

function openEvents() {
  if (state.events) state.events.close();
  state.events = new EventSource(`/api/events?token=${encodeURIComponent(state.token)}`);
  state.events.onmessage = async () => {
    try {
      await refreshLists();
      if (state.view.type === 'dialog') await openDialog(state.view.id);
      if (state.view.type === 'channel') await openChannel(state.view.id);
    } catch (_) {}
  };
}

function bind() {
  document.addEventListener('click', unlockSound, { once: true });
  el.tabLogin.onclick = () => switchTab('login');
  el.tabRegister.onclick = () => switchTab('register');
  el.btnLogin.onclick = authLogin;
  el.btnRegister.onclick = authRegister;
  el.authLangRu.onclick = () => setAuthLanguage('ru');
  el.authLangEn.onclick = () => setAuthLanguage('en');

  el.userSearch.oninput = () => doSearch().catch(() => {});
  el.btnSend.onclick = () => sendCurrent().catch(() => {});
  el.msgInput.onkeydown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendCurrent().catch(() => {});
    }
  };

  el.openProfile.onclick = () => {
    el.profileNickname.value = state.me?.nickname || '';
    el.profileAvatarFile.value = '';
    el.modalProfile.classList.remove('hidden');
  };
  el.closeProfile.onclick = () => el.modalProfile.classList.add('hidden');
  el.saveProfile.onclick = () => saveProfile().catch((e) => alert(e.message));
  el.langRu.onclick = () => setAppLanguage('ru');
  el.langEn.onclick = () => setAppLanguage('en');

  el.btnNewChannel.onclick = () => el.modalChannel.classList.remove('hidden');
  el.closeChannel.onclick = () => el.modalChannel.classList.add('hidden');
  el.createChannel.onclick = () => createChannel().catch((e) => alert(e.message));

  el.btnAdmin.onclick = async () => {
    el.modalAdmin.classList.remove('hidden');
    await loadAdmin();
  };
  el.btnLogout.onclick = logout;
  el.closeAdmin.onclick = () => el.modalAdmin.classList.add('hidden');
  el.adminSearch.oninput = () => loadAdmin().catch(() => {});
}

bind();
setAuthLanguage(state.authLang);
switchTab('login');
bootstrapApp();
