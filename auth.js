/* MealMate auth (front-end demo)
 * -------------------------------------------------------------------------
 * Accounts, the signed-in session and order history live in this browser's
 * localStorage. Passwords are salted + hashed (PBKDF2-SHA256) rather than
 * stored in plain text, but this is NOT real security: anyone with access to
 * the browser can read or edit this data. Replace the functions below with
 * calls to a real backend (e.g. FastAPI /signup, /login endpoints) before
 * handling real users.
 */
(function () {
  const USERS_KEY = 'mealmate_users_v1';
  const SESSION_KEY = 'mealmate_session_v1';
  const ORDERS_KEY = 'mealmate_orders_v1';
  const CAMPUS_KEY = 'mealmate_campus_v1';
  const CART_KEY = 'mealmate_cart_v1';

  const read = (k, fallback) => { try { const v = JSON.parse(localStorage.getItem(k)); return v ?? fallback; } catch (e) { return fallback; } };
  const write = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch (e) { return false; } };
  const norm = e => String(e || '').trim().toLowerCase();

  const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

  async function hashPassword(password, saltB64) {
    if (!(window.crypto && crypto.subtle)) throw new Error('This browser cannot hash passwords securely. Open the site over http://localhost or https.');
    const salt = saltB64 ? unb64(saltB64) : crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' }, key, 256);
    return { salt: b64(salt), hash: b64(bits) };
  }

  const users = () => read(USERS_KEY, {});
  const publicUser = u => { if (!u) return null; const { hash, salt, ...rest } = u; return rest; };

  function validEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e); }
  function passwordIssue(p) {
    if (p.length < 8) return 'Use at least 8 characters.';
    if (!/[A-Za-z]/.test(p) || !/\d/.test(p)) return 'Include at least one letter and one number.';
    return '';
  }

  const Auth = {
    validEmail, passwordIssue,

    current() { const e = read(SESSION_KEY, null); return e ? publicUser(users()[e]) : null; },

    async signup({ name, email, password, campus, studentId }) {
      email = norm(email); name = String(name || '').trim();
      if (name.length < 2) throw new Error('Please enter your full name.');
      if (!validEmail(email)) throw new Error('Please enter a valid email address.');
      const issue = passwordIssue(password); if (issue) throw new Error(issue);
      const all = users();
      if (all[email]) throw new Error('An account with this email already exists. Try logging in.');
      const { salt, hash } = await hashPassword(password);
      all[email] = {
        name, email, phone: '', studentId: String(studentId || '').trim(), campus: campus || 'USM Main Hub',
        diet: [], allergies: '', budget: '', createdAt: new Date().toISOString(), salt, hash
      };
      if (!write(USERS_KEY, all)) throw new Error('Could not save your account (browser storage is unavailable).');
      write(SESSION_KEY, email);
      try { localStorage.setItem(CAMPUS_KEY, all[email].campus); } catch (e) {}
      return publicUser(all[email]);
    },

    async login(email, password) {
      email = norm(email);
      const all = users(), u = all[email];
      const bad = new Error('Email or password is incorrect.');
      if (!u) { await hashPassword(password || 'x').catch(() => {}); throw bad; }
      const { hash } = await hashPassword(password, u.salt);
      if (hash !== u.hash) throw bad;
      write(SESSION_KEY, email);
      try { if (u.campus) localStorage.setItem(CAMPUS_KEY, u.campus); } catch (e) {}
      return publicUser(u);
    },

    logout() { try { localStorage.removeItem(SESSION_KEY); } catch (e) {} },

    updateProfile(patch) {
      const e = read(SESSION_KEY, null), all = users();
      if (!e || !all[e]) throw new Error('You are not logged in.');
      const allowed = ['name', 'phone', 'studentId', 'campus', 'diet', 'allergies', 'budget'];
      allowed.forEach(k => { if (k in patch) all[e][k] = patch[k]; });
      write(USERS_KEY, all);
      if (patch.campus) { try { localStorage.setItem(CAMPUS_KEY, patch.campus); } catch (err) {} }
      return publicUser(all[e]);
    },

    async changePassword(current, next) {
      const e = read(SESSION_KEY, null), all = users(), u = all[e];
      if (!u) throw new Error('You are not logged in.');
      const { hash } = await hashPassword(current, u.salt);
      if (hash !== u.hash) throw new Error('Your current password is incorrect.');
      const issue = passwordIssue(next); if (issue) throw new Error(issue);
      const fresh = await hashPassword(next);
      u.salt = fresh.salt; u.hash = fresh.hash; write(USERS_KEY, all);
    },

    deleteAccount() {
      const e = read(SESSION_KEY, null); if (!e) return;
      const all = users(); delete all[e]; write(USERS_KEY, all);
      const orders = read(ORDERS_KEY, {}); delete orders[e]; write(ORDERS_KEY, orders);
      this.logout();
    },

    // ---- Orders (saved per account; guests are stored under "guest") ----
    orders() { const e = read(SESSION_KEY, null); return read(ORDERS_KEY, {})[e || 'guest'] || []; },
    addOrder({ items, total, hub, slot }) {
      const e = read(SESSION_KEY, null) || 'guest', all = read(ORDERS_KEY, {});
      const order = { id: 'MM-' + String(Math.floor(1000 + Math.random() * 9000)), date: new Date().toISOString(), items, total, hub, slot };
      all[e] = [order, ...(all[e] || [])].slice(0, 50);
      write(ORDERS_KEY, all);
      return order;
    },
    reorder(order) {
      const cart = read(CART_KEY, []);
      order.items.forEach(it => {
        const ex = cart.find(c => c.name === it.name);
        if (ex) ex.qty = Math.min(10, ex.qty + it.qty); else cart.push({ name: it.name, price: it.price, qty: it.qty });
      });
      write(CART_KEY, cart);
    },

    // ---- Navbar slot: shows "Log in" or the user's avatar ----
    renderNav() {
      const slot = document.getElementById('authSlot'); if (!slot) return;
      const u = this.current();
      if (u) {
        const first = u.name.split(' ')[0];
        slot.innerHTML = `<a class="auth-chip" href="PROFILE.html" title="Your profile"><span class="auth-avatar">${esc(u.name.charAt(0).toUpperCase())}</span><span class="auth-name">${esc(first)}</span></a>`;
      } else {
        slot.innerHTML = `<a class="auth-login" href="LOGIN.html">Log in</a>`;
      }
    }
  };

  function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

  const css = document.createElement('style');
  css.textContent = `
    #authSlot { display: flex; align-items: center; }
    .auth-login { font: 700 0.88rem var(--font-body, sans-serif); color: var(--teal-primary, #006B6E); text-decoration: none; padding: 9px 16px; border-radius: 9999px; border: 2px solid var(--teal-primary, #006B6E); white-space: nowrap; transition: all .2s; }
    .auth-login:hover { background: var(--teal-primary, #006B6E); color: #fff; }
    .auth-chip { display: inline-flex; align-items: center; gap: 8px; text-decoration: none; color: var(--text-charcoal, #1E2B2C); font: 700 0.88rem var(--font-body, sans-serif); background: var(--bg-oat, #F7F2E7); border: 1px solid var(--border-sand, #E5DEC9); padding: 4px 14px 4px 4px; border-radius: 9999px; transition: all .2s; }
    .auth-chip:hover { border-color: var(--teal-primary, #006B6E); }
    .auth-avatar { width: 34px; height: 34px; border-radius: 50%; background: var(--orange-primary, #FF6B00); color: #fff; display: inline-flex; align-items: center; justify-content: center; font-family: var(--font-display, sans-serif); font-size: 1.05rem; }
    @media (max-width: 700px) { .auth-name { display: none; } .auth-chip { padding: 4px; } }
  `;
  document.head.appendChild(css);

  window.MealAuth = Auth;
  Auth.renderNav();
  // Cart badge for pages that have no cart logic of their own (login/profile)
  (function () {
    const badge = document.getElementById('cartCount');
    if (!badge || badge.dataset.managed) return;
    const raw = (function () { try { return localStorage.getItem(CART_KEY); } catch (e) { return null; } })();
    if (raw === null) return;
    try { badge.textContent = JSON.parse(raw).reduce((n, i) => n + (parseInt(i.qty, 10) || 1), 0); } catch (e) {}
  })();
})();
