/* SQLi Lab UI — toggle mode, jalankan exploit, render hasil */
(function () {
  var toastEl = document.getElementById('toast');
  var t;
  function toast(teks) {
    if (!toastEl) return;
    toastEl.textContent = teks;
    toastEl.classList.add('show');
    clearTimeout(t);
    t = setTimeout(function () { toastEl.classList.remove('show'); }, 2600);
  }

  function esc(s) { return String(s).replace(/[&<>]/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]); }); }

  function setModeBadge(sc, vuln) {
    var card = document.getElementById('sc-' + sc);
    if (!card) return;
    var btn = card.querySelector('.toggle');
    btn.classList.toggle('vuln', vuln);
    btn.classList.toggle('fixed', !vuln);
    card.classList.toggle('fixed-mode', !vuln);
    btn.innerHTML = '<i class="fa-solid ' + (vuln ? 'fa-bomb' : 'fa-shield') + '"></i> ' + (vuln ? 'RENTAN' : 'FIXED');
  }

  function renderOut(sc, data) {
    var pre = document.getElementById('out-' + sc);
    if (!data || !data.steps) return;
    var lines = data.steps.map(function (l) {
      var x = esc(l);
      if (/[A-Z0-9]+-LAB\{[^}]+\}/.test(x)) x = x.replace(/[A-Z0-9]+-LAB\{[^}]+\}/g, '<span class="flag">$&</span>');
      if (/RESULT|Berhasil/.test(x)) x = '<span class="ok">' + x + '</span>';
      if (/BLOCKED|ditolak|DITOLAK|gagal/.test(x)) x = '<span class="bad">' + x + '</span>';
      return '▸ ' + x;
    }).join('\n');
    pre.innerHTML = lines + '\n' + (data.flag ? '\n<span class="flag">🏁 FLAG: ' + esc(data.flag) + '</span>' : '');
  }

  document.addEventListener('click', function (e) {
    var tgl = e.target.closest('.toggle');
    if (tgl) {
      var sc = tgl.dataset.sc;
      fetch('/api/toggle/' + sc, { method: 'POST' })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          setModeBadge(sc, d.vulnerable);
          toast('Scenario ' + sc.toUpperCase() + ' → ' + (d.vulnerable ? 'RENTAN' : 'FIXED'));
          var pre = document.getElementById('out-' + sc);
          if (pre) pre.innerHTML = '<span class="dim">▶ mode diganti — jalankan ulang exploit.</span>';
        });
      return;
    }
    var run = e.target.closest('.btn-run');
    if (run) {
      var psc = run.dataset.poc;
      var pre = document.getElementById('out-' + psc);
      pre.innerHTML = '<span class="dim">⏳ menjalankan exploit…</span>';
      fetch('/api/poc/' + psc, { method: 'POST' })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          renderOut(psc, d);
          toast(d.ok ? 'Exploit sukses — ' + psc.toUpperCase() + ' (RENTAN)' : 'Diblokir — ' + psc.toUpperCase() + ' (FIXED)');
        })
        .catch(function () { pre.innerHTML = '<span class="bad">error jaringan.</span>'; });
    }
  });

  document.querySelectorAll('.toggle').forEach(function (b) {
    setModeBadge(b.dataset.sc, b.classList.contains('vuln'));
  });
})();