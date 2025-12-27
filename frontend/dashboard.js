document.addEventListener('DOMContentLoaded', async () => {
    // 1. Fetch CSRF Token (Required for Logout)
    let csrfToken = '';
    try {
        const res = await fetch('/csrf-token');
        const data = await res.json();
        csrfToken = data.csrfToken;
    } catch (e) {
        console.error("Could not fetch CSRF token");
    }

    // 2. Fetch User Info (To show "Welcome, [Username]")
    try {
        const userRes = await fetch('/me');
        if (userRes.ok) {
            const userData = await userRes.json();
            document.getElementById('displayUser').innerText = userData.username;
        } else {
            // If /me fails (token expired), force logout
            window.location.href = 'login.html';
        }
    } catch (e) {
        window.location.href = 'login.html';
    }

    // 3. Handle Logout Click
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            await fetch('/logout', { 
                method: 'POST', 
                headers: { 
                    'Content-Type': 'application/json',
                    'CSRF-Token': csrfToken 
                },
                body: JSON.stringify({ _csrf: csrfToken })
            });
            window.location.href = '/';
        });
    }
});
