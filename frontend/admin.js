document.addEventListener('DOMContentLoaded', async () => {
    const tableBody = document.querySelector('#userTable tbody');
    
    // 1. Init: Fetch CSRF
    let csrf = '';
    try {
        const csrfRes = await fetch('/csrf-token');
        const csrfData = await csrfRes.json();
        csrf = csrfData.csrfToken;
    } catch (e) { console.error("CSRF Error"); }

    // 2. Fetch Users
    async function loadUsers() {
        const res = await fetch('/admin/users');
        if (res.status === 403 || res.status === 401) {
            window.location.href = '/'; // Kick out if not admin
            return;
        }
        
        const users = await res.json();
        tableBody.innerHTML = '';
        
        users.forEach(user => {
            const tr = document.createElement('tr');
            const isMe = user.username === 'admin'; 
            
            // Note: We removed 'onclick' and added class 'delete-btn' + 'data-username'
            tr.innerHTML = `
                <td>${user.username}</td>
                <td><span class="tag ${user.role === 'admin' ? 'tag-admin' : ''}">${user.role}</span></td>
                <td>${user.failed_login_attempts || 0}</td>
                <td>
                    ${!isMe ? `<button class="btn btn-danger delete-btn" data-username="${user.username}">Remove</button>` : ''}
                </td>
            `;
            tableBody.appendChild(tr);
        });
    }

    // 3. Delete User Function (Internal)
    async function deleteUser(username) {
        if(!confirm(`Are you sure you want to remove ${username}?`)) return;
        
        try {
            const res = await fetch(`/admin/users/${username}`, {
                method: 'DELETE',
                headers: { 
                    'CSRF-Token': csrf, 
                    'Content-Type': 'application/json' 
                },
                body: JSON.stringify({ _csrf: csrf })
            });
            
            if (res.ok) {
                loadUsers(); // Refresh list
            } else {
                alert("Failed to delete user");
            }
        } catch (err) {
            console.error(err);
        }
    }

    // 4. EVENT DELEGATION (The Fix for CSP)
    // Instead of onclick, we listen for clicks on the entire table
    document.getElementById('userTable').addEventListener('click', (e) => {
        // Check if the clicked element has the class 'delete-btn'
        if (e.target.classList.contains('delete-btn')) {
            const username = e.target.getAttribute('data-username');
            deleteUser(username);
        }
    });

    // 5. Logout Logic
    document.getElementById('logoutBtn').addEventListener('click', async () => {
        await fetch('/logout', { 
            method: 'POST', 
            headers: {'CSRF-Token': csrf, 'Content-Type': 'application/json'}, 
            body: JSON.stringify({_csrf: csrf}) 
        });
        window.location.href = '/';
    });

    // Initial Load
    loadUsers();
});
