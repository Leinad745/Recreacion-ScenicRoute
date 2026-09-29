// Panel de 5ub4k3m1's inc. - bundle público
// TODO(infra): esto todavía consulta la API pública una vez por minuto. Cuando el
// control plane en 127.0.0.1:9101 exponga /v1/monitors lo leemos directo de ahí y
// quitamos este timer. -- rgarcia
(function () {
  var RELOAD_MS = 60000;
  setTimeout(function () { location.reload(); }, RELOAD_MS);

  document.querySelectorAll("footer a").forEach(function (a) {
    a.addEventListener("click", function () {
      // salto de atribución: /go?next= registra el clic y luego hace 302 al destino
      navigator.sendBeacon && navigator.sendBeacon("/static/app.js");
    });
  });
})();
