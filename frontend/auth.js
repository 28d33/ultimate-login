document.addEventListener('DOMContentLoaded', async () => {
    // 1. Fetch CSRF
    try {
        const res = await fetch('/csrf-token');
        const data = await res.json();
        document.getElementById('csrfToken').value = data.csrfToken;
        sessionStorage.setItem('csrf', data.csrfToken);
    } catch(e) { console.error("CSRF Error"); }

    // 2. Handle Login
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const csrf = document.getElementById('csrfToken').value;
        const msg = document.getElementById('message');

        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrf },
            body: JSON.stringify({ username, password, _csrf: csrf })
        });

        const result = await response.json();
        
        if (response.ok) {
            // Redirect based on role
            if (result.role === 'admin') window.location.href = 'admin.html';
            else window.location.href = 'dashboard.html';
        } else {
            msg.style.color = 'var(--danger)';
            msg.innerText = result.error || "Login Failed";
        }
    });
});
