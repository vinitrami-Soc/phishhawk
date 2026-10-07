// Drag and drop onto the file field; the form works without this script.
document.querySelectorAll("[data-drop]").forEach(function (zone) {
  var input = zone.querySelector("input[type=file]");
  ["dragenter", "dragover"].forEach(function (name) {
    zone.addEventListener(name, function (event) { event.preventDefault(); zone.classList.add("over"); });
  });
  ["dragleave", "drop"].forEach(function (name) {
    zone.addEventListener(name, function () { zone.classList.remove("over"); });
  });
  zone.addEventListener("drop", function (event) {
    event.preventDefault();
    if (event.dataTransfer && event.dataTransfer.files.length) { input.files = event.dataTransfer.files; }
  });
});
