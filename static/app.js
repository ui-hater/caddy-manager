document.addEventListener("submit", function (e) {
  var msg = e.target.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) e.preventDefault();
});
document.addEventListener("change", function (e) {
  if (e.target.hasAttribute("data-autosubmit")) e.target.form.submit();
  if (e.target.name === "kind") showKind();
});

// On the edit page only show the section that belongs to the selected type.
function showKind() {
  var checked = document.querySelector('input[name="kind"]:checked');
  if (!checked) return;
  document.querySelectorAll("[data-kind]").forEach(function (el) {
    el.hidden = el.getAttribute("data-kind") !== checked.value;
  });
}
document.addEventListener("DOMContentLoaded", showKind);
