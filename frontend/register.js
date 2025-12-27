document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const msg = document.getElementById('message');

    const response = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });

    if (response.ok) {
        msg.style.color = 'green';
        msg.innerText = "Success! Redirecting...";
        setTimeout(() => window.location.href = 'login.html', 1500);
    } else {
        const data = await response.json();
        msg.style.color = 'red';
        msg.innerText = data.error || "Failed";
    }
});
