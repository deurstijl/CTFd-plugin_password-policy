document.addEventListener("DOMContentLoaded", function () {

    const heading = document.querySelector('main h1');
    if (heading) {
      const text = heading.textContent.trim();
      if (text !== 'Register' && text !== 'Settings' && text!=='Reset Password') {
        return;
      }
    }

    const passwordField = document.querySelector("#password");
    if (!passwordField) return;
  
    // Insert message div
    const messageDiv = document.createElement("div");
    messageDiv.id = "password-policy-error";
    messageDiv.style.color = "red";
    passwordField.parentNode.appendChild(messageDiv);
  
    function getPolicy() {
      return fetch("/files/password_policy.json")
        .then(res => res.json())
        .catch(() => null);
    }
  
    function validatePassword(password, policy) {
      let errors = [];
      if (policy.require_upper && !/[A-Z]/.test(password)) errors.push("uppercase letter");
      if (policy.require_lower && !/[a-z]/.test(password)) errors.push("lowercase letter");
      if (policy.require_number && !/[0-9]/.test(password)) errors.push("number");
      if (policy.require_symbol && !/[!@#$%^&*(),.?\":{}|<>]/.test(password)) errors.push("symbol");
      if (password.length < policy.min_length) errors.push(`minimum length of ${policy.min_length}`);
      return errors;
    }
  
    getPolicy().then(policy => {
      if (!policy) return;
      const form = passwordField.closest('form');
      form.addEventListener("submit", function (e) {
        const password = passwordField.value;
        const errors = validatePassword(password, policy);
        const confirm = document.getElementById('confirm');
        if (confirm && confirm.value === password){
          e.preventDefault();
          messageDiv.innerText = "Password is the same as current password!";
          passwordField.classList.add("is-invalid");
          return;
        }
        if (errors.length) {
          e.preventDefault();
          messageDiv.innerText = "Password must also contain: " + errors.join(", ");
          passwordField.classList.add("is-invalid");
        } else {
          messageDiv.innerText = "";
          passwordField.classList.remove("is-invalid");
        }
      });
    });
  });
  