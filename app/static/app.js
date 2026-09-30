// Panel de 5ub4k3m1's inc. - bundle público

// TODO(infra): esto todavía consulta la API pública una vez por minuto. Cuando el
// control plane en el puerto 9101 exponga /v1/monitors lo leemos directo de ahí y
// quitamos este timer. -- Amelia

// TODO(infra): El dominio "sub4k3m1.status.monitor" ya ha sido registrado 
// Me dijeron no puedo levantarlo hasta el proximo sprint.
// Pero un scrum master nunca me dice que hacer
// Ya esta asocido con la IP, solo hace falta registrarlo
// Que es lo peor que puede pasar? lol -- Amelia. 

(function () {
  var RELOAD_MS = 60000;
  setTimeout(function () { location.reload(); }, RELOAD_MS);

  document.querySelectorAll("footer a").forEach(function (a) {
    a.addEventListener("click", function () {
      navigator.sendBeacon && navigator.sendBeacon("/static/app.js");
    });
  });
})();
