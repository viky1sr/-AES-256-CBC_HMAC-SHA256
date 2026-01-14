<?php

namespace Kelompok1\CryptoGraphy;

final class RegisterPage
{
    public static function render(string $title, string $content, string $message = ''): string
    {
        $msgHtml = $message ? "<div style='color: red; margin-bottom: 10px;'>$message</div>" : "";
        return <<<HTML
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>$title - Kelompok 1</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; }
        .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 400px; }
        input { width: 100%; padding: 0.5rem; margin: 0.5rem 0; box-sizing: border-box; }
        button { width: 100%; padding: 0.5rem; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .links { margin-top: 1rem; text-align: center; font-size: 0.9rem; }
    </style>
</head>
<body>
    <div class="card">
        <h2>$title</h2>
        $msgHtml
        $content
    </div>
</body>
</html>
HTML;
    }

    public static function loginForm(string $message = ''): string
    {
        $content = <<<HTML
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <div class="links">
            Belum punya akun? <a href="/register">Daftar</a>
        </div>
HTML;
        return self::render('Login', $content, $message);
    }

    public static function registerForm(string $message = ''): string
    {
        $content = <<<HTML
        <form method="POST" action="/register">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Daftar</button>
        </form>
        <div class="links">
            Sudah punya akun? <a href="/login">Login</a>
        </div>
HTML;
        return self::render('Register', $content, $message);
    }

    public static function welcome(string $username, string $chatHtml = '', string $message = ''): string
    {
        $msgHtml = $message ? "<div style='color: red; margin-bottom: 10px;'>$message</div>" : "";
        $content = <<<HTML
        <p>Selamat datang, <strong>$username</strong>!</p>
        
        $msgHtml

        <div id="chat-box" style="border: 1px solid #ccc; padding: 10px; height: 300px; overflow-y: scroll; margin-bottom: 10px; background: #fff; text-align: left;">
            $chatHtml
        </div>

        <form id="chat-form" method="POST" action="/chat">
            <input type="text" name="message" id="chat-input" placeholder="Tulis pesan..." required>
            <input type="password" name="chat_password" id="chat-password" placeholder="Password untuk enkripsi chat" required>
            <button type="submit">Kirim (Enkripsi)</button>
        </form>

        <hr>
        <form id="view-form" method="GET" action="/dashboard">
            <input type="password" name="view_password" id="view-password" placeholder="Password untuk dekripsi chat">
            <button type="submit" style="background: #28a745;">Lihat/Refresh Chat (Dekripsi)</button>
        </form>

        <div class="links">
            <a href="/logout">Logout</a>
        </div>

        <script>
            const chatBox = document.getElementById('chat-box');
            const chatForm = document.getElementById('chat-form');
            const viewForm = document.getElementById('view-form');
            const viewPasswordInput = document.getElementById('view-password');

            // Simpan password dekripsi di session storage agar tetap ada saat polling
            if (new URLSearchParams(window.location.search).has('view_password')) {
                sessionStorage.setItem('view_password', viewPasswordInput.value);
            } else if (sessionStorage.getItem('view_password')) {
                viewPasswordInput.value = sessionStorage.getItem('view_password');
            }

            async function fetchChat() {
                const viewPassword = viewPasswordInput.value;
                try {
                    const response = await fetch('/api/chat?view_password=' + encodeURIComponent(viewPassword));
                    if (response.ok) {
                        const html = await response.text();
                        if (html.trim() !== "") {
                            chatBox.innerHTML = html;
                        }
                    }
                } catch (e) {
                    console.error("Gagal mengambil chat:", e);
                }
            }

            // Polling setiap 3 detik
            setInterval(fetchChat, 3000);

            // Scroll ke bawah saat pertama kali
            chatBox.scrollTop = chatBox.scrollHeight;

            chatForm.onsubmit = async (e) => {
                e.preventDefault();
                const formData = new FormData(chatForm);
                try {
                    const response = await fetch('/chat', {
                        method: 'POST',
                        body: formData
                    });
                    if (response.ok) {
                        document.getElementById('chat-input').value = '';
                        fetchChat();
                        setTimeout(() => chatBox.scrollTop = chatBox.scrollHeight, 100);
                    }
                } catch (e) {
                    alert("Gagal mengirim pesan");
                }
            };
            
            viewForm.onsubmit = (e) => {
                sessionStorage.setItem('view_password', viewPasswordInput.value);
            };
        </script>
HTML;
        return self::render('Dashboard & Chat', $content);
    }
}
