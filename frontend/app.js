document.addEventListener('DOMContentLoaded', async () => {
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');
    const message = document.getElementById('message');

    // 1. Fetch CSRF Token on Load
    try {
        const res = await fetch('/csrf-token');
        const data = await res.json();
        document.getElementById('csrfToken').value = data.csrfToken;
        sessionStorage.setItem('csrf', data.csrfToken); // Store for use
    } catch (e) {
        console.error("Could not fetch CSRF token");
    }

    // 2. Handle Login
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        message.innerText = "Processing...";
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const csrf = document.getElementById('csrfToken').value;

        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'CSRF-Token': csrf 
                },
                body: JSON.stringify({ username, password, _csrf: csrf })
            });

            const result = await response.json();
            
            if (response.ok) {
                message.style.color = 'green';
                message.innerText = "Success! Secure Cookie Set.";
            } else {
                message.style.color = 'red';
                message.innerText = result.error || "Login Failed";
            }
        } catch (err) {
            message.innerText = "Network Error";
        }
    });

    // 3. Handle Register (Simpler implementation for testing)
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('regUser').value;
        const password = document.getElementById('regPass').value;
        
        await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        alert("Registration request sent (Check console/network)");
    });
});
