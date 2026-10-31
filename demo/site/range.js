// Test Range helper: keep every form inert. Nothing is ever sent, stored or logged — the whole point
// is that the PhishShield warning should reach you before you would have submitted anything.
(function () {
  function toast(msg) {
    var t = document.createElement('div');
    t.className = 'toast';
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(function () {
      t.remove();
    }, 3500);
  }
  document.addEventListener('submit', function (e) {
    e.preventDefault();
    toast('Demo only — nothing was sent anywhere. This is how a real phishing form would steal what you typed.');
  });
})();
