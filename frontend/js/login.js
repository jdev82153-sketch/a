const API_URL = "https://agencia-marks.onrender.com";

const loginForm = document.getElementById("loginForm");
const loginMessage = document.getElementById("loginMessage");
const loginButton = document.getElementById("loginButton");

if (loginForm && loginMessage && loginButton) {
loginForm.addEventListener("submit", async function (event) {
event.preventDefault();

    loginMessage.textContent = "";
    loginButton.disabled = true;

    const originalText = loginButton.textContent;
    loginButton.textContent = "Conectando...";

    try {
        const usernameInput = loginForm.querySelector(
            '[name="username"], #username'
        );

        const passwordInput = loginForm.querySelector(
            '[name="password"], #password'
        );

        const keyInput = loginForm.querySelector(
            '[name="key"], #key'
        );

        if (!usernameInput) {
            throw new Error(
                "Não encontrei o campo de usuário no formulário."
            );
        }

        const username = usernameInput.value.trim();

        if (!username) {
            throw new Error("Digite seu usuário.");
        }

        let endpoint;
        let payload;

        if (keyInput && keyInput.value.trim()) {
            endpoint = "/api/auth/company-login";
            payload = {
                username: username,
                key: keyInput.value.trim()
            };
        } else {
            if (!passwordInput || !passwordInput.value) {
                throw new Error(
                    "Digite sua senha ou a KEY da empresa."
                );
            }

            endpoint = "/api/auth/admin-login";
            payload = {
                username: username,
                password: passwordInput.value
            };
        }

        const response = await fetch(API_URL + endpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            throw new Error(
                data.message ||
                data.error ||
                "Não foi possível entrar. Confira seus dados."
            );
        }

        if (!data.token) {
            throw new Error(
                "O servidor não retornou o token de acesso."
            );
        }

        sessionStorage.setItem("marksToken", data.token);

        if (data.account && data.account.role === "admin") {
            window.location.href = "admin.html";
        } else {
            window.location.href = "dashboard.html";
        }

    } catch (error) {
        loginMessage.textContent =
            error.message ||
            "Não foi possível conectar ao servidor.";
    } finally {
        loginButton.disabled = false;
        loginButton.textContent = originalText;
    }
});

}
