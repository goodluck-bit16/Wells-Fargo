(function () {
  'use strict';
  const $ = id => document.getElementById(id);
  const fmt = cents => new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(cents / 100);
  const cap = s => s[0].toUpperCase() + s.slice(1);

  let data = null;       // latest snapshot from the server
  let tab = 'deposit';

  /* ---------- API ---------- */
  async function api(path, method, body) {
    let res;
    try {
      res = await fetch(path, {
        method: method || 'GET',
        credentials: 'same-origin',
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch {
      throw { status: 0, message: "Can't reach the bank. Check your connection and try again." };
    }
    let json = {};
    try { json = await res.json(); } catch { /* empty body */ }
    if (!res.ok) throw { status: res.status, message: json.error || 'Something went wrong. Try again.', field: json.field };
    return json;
  }

  /* ---------- toast ---------- */
  let tt;
  function toast(msg) {
    document.querySelectorAll('.toast').forEach(n => n.remove());
    const n = document.createElement('div');
    n.className = 'toast'; n.setAttribute('role', 'status'); n.textContent = msg;
    document.body.appendChild(n);
    clearTimeout(tt); tt = setTimeout(() => n.remove(), 3000);
  }

  /* ---------- top-level views ---------- */
  function showLanding() {
    data = null;
    $('dashboard').classList.add('hidden');
    $('landing').classList.remove('hidden');
    $('nav-private').classList.add('hidden');
    $('nav-public').classList.remove('hidden');
  }
  function showDash(d) {
    data = d;
    $('landing').classList.add('hidden');
    $('dashboard').classList.remove('hidden');
    $('nav-public').classList.add('hidden');
    $('nav-private').classList.remove('hidden');
    render();
  }

  /* ---------- signed-in sections ---------- */
  function setView(v) {
    document.querySelectorAll('.apptabs button').forEach(b => b.setAttribute('aria-selected', b.dataset.view === v));
    ['accounts', 'pay', 'activity'].forEach(n => $('v-' + n).classList.toggle('hidden', n !== v));
  }
  document.querySelectorAll('.apptabs button').forEach(b => b.addEventListener('click', () => setView(b.dataset.view)));
  document.querySelectorAll('[data-go]').forEach(b => b.addEventListener('click', () => setView(b.dataset.go)));

  function greeting() {
    const h = new Date().getHours();
    return h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';
  }

  function fillTx(ul, list, emptyText) {
    ul.textContent = '';
    if (!list.length) {
      const li = document.createElement('li'); li.textContent = emptyText; ul.appendChild(li); return;
    }
    for (const t of list) {
      const li = document.createElement('li');
      const left = document.createElement('div');
      const d = document.createElement('div'); d.textContent = t.description;
      const when = new Date(t.createdAt * 1000);
      const sub = document.createElement('div'); sub.className = 'd';
      sub.textContent = cap(t.account) + ', ' +
        when.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ' ' +
        when.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
      left.append(d, sub);
      const a = document.createElement('div');
      a.className = 'a ' + (t.amountCents >= 0 ? 'in' : 'out');
      a.textContent = (t.amountCents >= 0 ? '+' : '\u2212') + fmt(Math.abs(t.amountCents));
      li.append(left, a); ul.appendChild(li);
    }
  }

  function render() {
    $('welcome').textContent = greeting() + ', ' + data.user.name.split(' ')[0];
    let total = 0;
    for (const t of ['checking', 'savings']) {
      const a = data.accounts[t];
      total += a.balanceCents;
      $('b-' + t).textContent = fmt(a.balanceCents);
      $('n-' + t).textContent = 'Account ending ' + a.last4;
    }
    $('b-total').textContent = fmt(total);
    fillTx($('tx-recent'), data.transactions.slice(0, 5), 'No activity yet. Make a deposit to get started.');
    fillTx($('tx'), data.transactions, 'No activity yet. Make a deposit to get started.');
  }

  function sessionEnded() {
    showLanding();
    toast('Your session ended. Sign on again.');
    window.scrollTo(0, 0);
  }

  /* ---------- product buttons preselect the account type ---------- */
  function updateCard() {
    const type = document.querySelector('input[name=type]:checked').value;
    $('c-name').textContent = $('f-name').value.trim() || 'Your name';
    $('c-type').textContent = cap(type);
  }
  document.querySelectorAll('[data-type]').forEach(a => a.addEventListener('click', () => {
    $(a.dataset.type === 'savings' ? 't-sav' : 't-chk').checked = true;
    updateCard();
  }));
  ['f-name', 't-chk', 't-sav'].forEach(id => $(id).addEventListener('input', updateCard));

  /* ---------- open account ---------- */
  const openFields = { name: 'f-name', email: 'f-email', deposit: 'f-dep', password: 'f-pw' };
  function clearOpenErrors() {
    Object.values(openFields).forEach(id => $(id).removeAttribute('aria-invalid'));
    ['name', 'email', 'deposit', 'password'].forEach(k => { $('e-' + k).textContent = ''; });
    $('o-err').classList.add('hidden');
  }

  $('open-form').addEventListener('submit', async ev => {
    ev.preventDefault();
    clearOpenErrors();
    const btn = $('o-btn'); btn.disabled = true;
    try {
      const d = await api('/api/register', 'POST', {
        name: $('f-name').value,
        email: $('f-email').value,
        password: $('f-pw').value,
        type: document.querySelector('input[name=type]:checked').value,
        deposit: $('f-dep').value === '' ? 0 : parseFloat($('f-dep').value),
      });
      $('open-form').reset(); updateCard();
      setView('accounts'); showDash(d); window.scrollTo(0, 0);
      toast('Account opened');
    } catch (e) {
      if (e.field && openFields[e.field]) {
        $(openFields[e.field]).setAttribute('aria-invalid', 'true');
        $('e-' + e.field).textContent = e.message;
        $(openFields[e.field]).focus();
      } else {
        const box = $('o-err'); box.textContent = e.message; box.classList.remove('hidden');
      }
    } finally { btn.disabled = false; }
  });

  /* ---------- sign on / off ---------- */
  $('signin-form').addEventListener('submit', async ev => {
    ev.preventDefault();
    $('s-err').classList.add('hidden');
    const btn = $('s-btn'); btn.disabled = true;
    try {
      const d = await api('/api/login', 'POST', { email: $('s-email').value, password: $('s-pw').value });
      $('signin-form').reset();
      setView('accounts'); showDash(d); window.scrollTo(0, 0);
      toast('Signed on');
    } catch (e) {
      const box = $('s-err'); box.textContent = e.message; box.classList.remove('hidden');
    } finally { btn.disabled = false; }
  });

  $('signout').addEventListener('click', async () => {
    try { await api('/api/logout', 'POST', {}); } catch { /* cookie may already be gone */ }
    showLanding(); window.scrollTo(0, 0);
    toast('Signed off');
  });

  /* ---------- pay & transfer ---------- */
  const cfg = {
    deposit:  { btn: 'Deposit money',  toLabel: 'Into', from: false, to: true,  payee: false },
    transfer: { btn: 'Transfer money', toLabel: 'To',   from: true,  to: true,  payee: false },
    send:     { btn: 'Send money',     toLabel: '',     from: true,  to: false, payee: true  },
  };
  function setTab(t) {
    tab = t; const c = cfg[t];
    document.querySelectorAll('#v-pay .tabs button').forEach(b => b.setAttribute('aria-selected', b.dataset.tab === t));
    $('g-from').classList.toggle('hidden', !c.from);
    $('g-to').classList.toggle('hidden', !c.to);
    $('g-payee').classList.toggle('hidden', !c.payee);
    $('to-l').textContent = c.toLabel;
    $('a-btn').textContent = c.btn;
    $('a-err').textContent = '';
  }
  document.querySelectorAll('#v-pay .tabs button').forEach(b => b.addEventListener('click', () => setTab(b.dataset.tab)));

  // Deposit / Transfer shortcuts on each account row
  document.querySelectorAll('[data-quick]').forEach(b => b.addEventListener('click', () => {
    const acct = b.dataset.acct, other = acct === 'checking' ? 'savings' : 'checking';
    setTab(b.dataset.quick);
    if (b.dataset.quick === 'deposit') $('a-to').value = acct;
    else { $('a-from').value = acct; $('a-to').value = other; }
    setView('pay'); $('a-amt').focus();
  }));

  $('act-form').addEventListener('submit', async ev => {
    ev.preventDefault();
    const err = $('a-err'); err.textContent = '';
    const amount = parseFloat($('a-amt').value);
    if (isNaN(amount)) { err.textContent = 'Enter an amount greater than $0.'; return; }
    const btn = $('a-btn'); btn.disabled = true;
    try {
      let d;
      if (tab === 'deposit') d = await api('/api/deposit', 'POST', { account: $('a-to').value, amount });
      else if (tab === 'transfer') d = await api('/api/transfer', 'POST', { from: $('a-from').value, to: $('a-to').value, amount });
      else d = await api('/api/send', 'POST', { from: $('a-from').value, payee: $('a-payee').value, amount });
      $('a-amt').value = ''; if (tab === 'send') $('a-payee').value = '';
      showDash(d); setView('accounts'); toast(d.message);
    } catch (e) {
      if (e.status === 401) sessionEnded(); else err.textContent = e.message;
    } finally { btn.disabled = false; }
  });

  /* ---------- start: restore session if the cookie is still valid ---------- */
  setTab('deposit');
  api('/api/me').then(showDash).catch(() => showLanding());
})();
