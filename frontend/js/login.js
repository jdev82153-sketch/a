const loginForm = document.getElementById("loginForm");
const loginMessage = document.getElementById("loginMessage");
const loginButton = document.getElementById("loginButton");

loginForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    loginMessage.textContent = "";
    loginButton.disabled = true;
    loginButton.firstChild.textContent = "Conectando...";

    try {
        /*
         * A autenticação real será conectada ao backend.
         * Não coloque senhas administrativas neste arquivo.
         */
        loginMessage.textContent =
            "O sistema de autenticação ainda será conectado ao servidor.";
    } finally {
        loginButton.disabled = false;
        loginButton.firstChild.textContent = "Entrar na plataforma ";
    }
});
