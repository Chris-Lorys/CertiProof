// CertiProof : petites améliorations de l'interface (l'application fonctionne aussi sans JavaScript).
(function () {
  "use strict";

  // Zones de dépôt : nom du fichier choisi et glisser-déposer
  document.querySelectorAll(".dropzone").forEach(function (zone) {
    var input = zone.querySelector("input[type=file]");
    var name = zone.querySelector(".file-name");
    if (!input) return;
    var show = function () {
      var f = input.files && input.files[0];
      zone.classList.toggle("has-file", !!f);
      if (name) name.textContent = f ? f.name + " (" + Math.max(1, Math.round(f.size / 1024)) + " Ko)" : "";
    };
    input.addEventListener("change", show);
    ["dragenter", "dragover"].forEach(function (ev) {
      zone.addEventListener(ev, function () { zone.classList.add("over"); });
    });
    ["dragleave", "drop"].forEach(function (ev) {
      zone.addEventListener(ev, function () { zone.classList.remove("over"); });
    });
    show();
  });

  // Confirmation avant une action irréversible (révocation)
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (!window.confirm(form.getAttribute("data-confirm"))) e.preventDefault();
    });
  });

  // Bouton désactivé pendant un traitement long (mesures, installation)
  document.querySelectorAll("form[data-busy]").forEach(function (form) {
    form.addEventListener("submit", function () {
      var btn = form.querySelector("button[type=submit], button:not([type])");
      if (btn) { btn.disabled = true; btn.textContent = form.getAttribute("data-busy"); }
    });
  });

  // Filtre du registre des attestations
  var filter = document.getElementById("registry-filter");
  if (filter) {
    var rows = document.querySelectorAll("#registry tbody tr");
    filter.addEventListener("input", function () {
      var q = filter.value.trim().toLowerCase();
      rows.forEach(function (r) { r.hidden = q && r.textContent.toLowerCase().indexOf(q) === -1; });
    });
  }

  // Date du jour par défaut dans le formulaire d'émission
  var date = document.querySelector("input[type=date][data-today]");
  if (date && !date.value) date.value = new Date().toISOString().slice(0, 10);
})();
