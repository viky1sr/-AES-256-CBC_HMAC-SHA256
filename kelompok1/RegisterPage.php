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
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: #f0f2f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .card { background: white; padding: 2.5rem; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.1); width: 100%; max-width: 900px; min-height: 600px; display: flex; flex-direction: column; position: relative; }
        h2 { color: #1c1e21; margin-top: 0; }
        input { width: 100%; padding: 0.75rem; margin: 0.5rem 0; box-sizing: border-box; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem; }
        button { width: 100%; padding: 0.75rem; background: #007bff; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 1rem; font-weight: 600; transition: background 0.2s; }
        button:hover { background: #0056b3; }
        .links { margin-top: 1.5rem; text-align: center; font-size: 0.95rem; }
        .links a { color: #007bff; text-decoration: none; }
        
        #chat-container { display: flex; gap: 20px; flex: 1; min-height: 400px; }
        #chat-main { flex: 3; display: flex; flex-direction: column; }
        #chat-box { border: 1px solid #e4e6eb; padding: 15px; flex: 1; overflow-y: auto; margin-bottom: 15px; background: #f9f9f9; border-radius: 8px; font-size: 1.05rem; }
        #chat-form { display: flex; gap: 10px; }
        #chat-input { flex: 1; margin: 0; }
        #chat-password { width: 200px; margin: 0; }
        #chat-btn { width: auto; white-space: nowrap; }
        
        #sidebar { flex: 1; border-left: 1px solid #e4e6eb; padding-left: 15px; }
        #user-list ul { list-style: none; padding: 0; }
        #user-list li { padding: 8px 0; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 8px; }

        /* Modal Styles */
        .modal { display: none; position: fixed; z-index: 10000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); align-items: center; justify-content: center; backdrop-filter: blur(4px); }
        .modal-content { background: white; padding: 25px; border-radius: 12px; width: 90%; max-width: 400px; box-shadow: 0 20px 50px rgba(0,0,0,0.5); position: relative; z-index: 10001; }
        .modal-header { margin-bottom: 15px; font-weight: bold; font-size: 1.2rem; color: #1c1e21; }

        .encrypted-msg { color: #555; font-family: 'Courier New', Courier, monospace; font-weight: bold; cursor: pointer; padding: 6px 10px; border-radius: 6px; transition: all 0.2s; display: inline-block; position: relative; z-index: 1; background: #eee; border: 1px solid #ccc; font-size: 0.9rem; }
        .encrypted-msg:hover { background: #e0e0e0; border-color: #007bff; color: #007bff; }
        .msg-entry { margin-bottom: 10px; line-height: 1.4; padding: 4px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="card">
        <h2>$title</h2>
        $msgHtml
        $content
    </div>

    <!-- Password Modal -->
    <div id="passwordModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">Buka Pesan Terenkripsi</div>
            <p style="font-size: 0.9rem; color: #666;">Masukkan password yang digunakan saat mengenkripsi pesan ini.</p>
            <input type="password" id="modal-password" placeholder="Password dekripsi...">
            <div style="display: flex; gap: 10px; margin-top: 10px;">
                <button id="modal-submit-btn" style="flex: 1;">Buka</button>
                <button id="modal-cancel-btn" style="flex: 1; background: #6c757d;">Batal</button>
            </div>
        </div>
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
        <p style="margin-bottom: 20px;">Halo, <strong>$username</strong>! Selamat datang di forum Kelompok 1.</p>
        
        $msgHtml

        <div id="chat-container">
            <div id="chat-main">
                <div id="chat-box">
                    $chatHtml
                </div>

                <form id="chat-form" method="POST" action="/chat">
                    <div style="display: flex; flex-direction: column; gap: 8px; width: 100%;">
                        <div style="display: flex; gap: 10px;">
                            <select name="target_uuid" id="target-user" style="padding: 0.75rem; border-radius: 6px; border: 1px solid #ddd;">
                                <option value="all">Kirim ke: Semua Orang</option>
                            </select>
                            <input type="text" name="message" id="chat-input" placeholder="Tulis pesan rahasia..." required style="flex: 1; margin: 0;">
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <input type="password" name="chat_password" id="chat-password" placeholder="Password Enkripsi" required style="flex: 1; margin: 0;">
                            <button type="submit" id="chat-btn" style="width: auto;">Kirim Terenkripsi</button>
                        </div>
                    </div>
                </form>
                
                <p style="font-size: 0.85rem; color: #666; margin-top: 10px;">
                    💡 Tips: Klik pesan bertanda <i>[Terenkripsi]</i> untuk membukanya dengan password.
                </p>
            </div>
            
            <div id="sidebar">
                <h4 style="margin-top: 0;">Online</h4>
                <div id="user-list">
                    <i>Memuat...</i>
                </div>
                <div class="links" style="text-align: left; margin-top: 40px;">
                    <a href="/database" style="color: #007bff; font-weight: bold; display: block; margin-bottom: 10px;">📊 Database Explorer</a>
                    <a href="/logout" style="color: #dc3545; font-weight: bold;">🚪 Logout</a>
                </div>
            </div>
        </div>

        <script>
            // Pastikan fungsi tersedia secara global SEGERA sebelum DOM dimuat lengkap jika perlu
            window.openDecryptModal = function(token) {
                const modal = document.getElementById('passwordModal');
                const modalInput = document.getElementById('modal-password');
                if (modal && modalInput) {
                    window.currentTokenToDecrypt = token;
                    modalInput.value = '';
                    modal.style.display = 'flex';
                    modalInput.focus();
                }
            };

            // Global store for decrypted messages in RAM
            window.decryptedMessages = window.decryptedMessages || {};

            document.addEventListener('DOMContentLoaded', () => {
                const chatBox = document.getElementById('chat-box');
                const userList = document.getElementById('user-list');
                const chatForm = document.getElementById('chat-form');
                const modal = document.getElementById('passwordModal');
                const modalInput = document.getElementById('modal-password');
                const modalSubmit = document.getElementById('modal-submit-btn');
                const modalCancel = document.getElementById('modal-cancel-btn');

                if (chatBox && chatForm && modal && modalSubmit && modalCancel) {
                    // Polling State
                    let globalViewPassword = '';
                    let globalViewToken = '';
                    let lastChatHtml = '';

                    async function fetchChat() {
                        try {
                            const url = '/api/chat?view_password=' + encodeURIComponent(globalViewPassword) + 
                                        '&view_token=' + encodeURIComponent(globalViewToken);
                            const response = await fetch(url);
                            if (response.ok) {
                                const html = await response.text();
                                
                                // RAM-based temporary storage for decrypted entries
                                const tempDiv = document.createElement('div');
                                tempDiv.innerHTML = html;
                                const entries = tempDiv.querySelectorAll('.msg-entry');
                                
                                entries.forEach(entry => {
                                    const decryptedLabel = entry.querySelector('span[style*="font-weight: bold;"]');
                                    if (decryptedLabel) {
                                        // If this entry matches our current decrypt target, store it
                                        if (globalViewToken) {
                                            window.decryptedMessages[globalViewToken] = entry.innerHTML;
                                        }
                                    }
                                });

                                // Build final HTML merging new entries with RAM cache
                                let finalHtml = '';
                                entries.forEach(entry => {
                                    const encryptedSpan = entry.querySelector('.encrypted-msg');
                                    if (encryptedSpan) {
                                        const token = encryptedSpan.getAttribute('data-token');
                                        if (window.decryptedMessages[token]) {
                                            finalHtml += '<div class="msg-entry">' + window.decryptedMessages[token] + '</div>';
                                        } else {
                                            finalHtml += entry.outerHTML;
                                        }
                                    } else {
                                        finalHtml += entry.outerHTML;
                                    }
                                });

                                const trimmedHtml = finalHtml.trim();
                                if (trimmedHtml !== "" && lastChatHtml !== trimmedHtml) {
                                    const shouldScroll = chatBox.scrollTop + chatBox.clientHeight >= chatBox.scrollHeight - 50;
                                    chatBox.innerHTML = finalHtml;
                                    lastChatHtml = trimmedHtml;
                                    if (shouldScroll) {
                                        chatBox.scrollTop = chatBox.scrollHeight;
                                    }
                                }
                            }
                        } catch (e) {
                            console.error("Gagal mengambil chat:", e);
                        }
                    }

                    async function fetchUsers() {
                        try {
                            const response = await fetch('/api/users?format=json');
                            if (response.ok) {
                                const onlineUsers = await response.json();
                                const targetSelect = document.getElementById('target-user');
                                const currentTarget = targetSelect.value;
                                
                                // Update Select Dropdown
                                targetSelect.innerHTML = '<option value="all">Kirim ke: Semua Orang</option>';
                                for (const [uuid, name] of Object.entries(onlineUsers)) {
                                    const option = document.createElement('option');
                                    option.value = uuid;
                                    option.textContent = 'Kirim ke: ' + name;
                                    if (uuid === currentTarget) option.selected = true;
                                    targetSelect.appendChild(option);
                                }

                                // Update Visual List Sidebar
                                if (userList) {
                                    let listHtml = "<ul>";
                                    const entries = Object.entries(onlineUsers);
                                    if (entries.length === 0) {
                                        listHtml = "<i>Tidak ada user online</i>";
                                    } else {
                                        for (const [uuid, name] of entries) {
                                            listHtml += "<li><span style='color: green;'>●</span> " + name + "</li>";
                                        }
                                        listHtml += "</ul>";
                                    }
                                    userList.innerHTML = listHtml;
                                }
                            }
                        } catch (e) {
                            console.error("Gagal mengambil user list:", e);
                        }
                    }

                    modalCancel.onclick = () => {
                        modal.style.display = 'none';
                        window.currentTokenToDecrypt = null;
                    };

                    modalSubmit.onclick = async () => {
                        const pass = modalInput.value;
                        if (!pass) return;

                        const token = window.currentTokenToDecrypt;
                        globalViewPassword = pass;
                        globalViewToken = token || '';
                        
                        modal.style.display = 'none';
                        lastChatHtml = '';
                        await fetchChat();
                    };

                    modalInput.onkeypress = (e) => {
                        if (e.key === 'Enter') modalSubmit.click();
                    };

                    window.onclick = (event) => {
                        if (event.target == modal) modalCancel.onclick();
                    };

                    // Delegate click for encrypted messages
                    document.addEventListener('click', (e) => {
                        const target = e.target.closest('.encrypted-msg');
                        if (target) {
                            e.preventDefault();
                            e.stopPropagation();
                            window.openDecryptModal(target.dataset.token);
                        }
                    }, true);

                    // Polling
                    setInterval(fetchChat, 3000);
                    setInterval(fetchUsers, 4000);
                    
                    fetchUsers();
                    fetchChat();

                    setTimeout(() => { chatBox.scrollTop = chatBox.scrollHeight; }, 500);

                    chatForm.onsubmit = async (e) => {
                        e.preventDefault();
                        const formData = new FormData(chatForm);
                        formData.append('_ajax', '1');
                        const btn = document.getElementById('chat-btn');
                        btn.disabled = true;
                        btn.innerText = 'Mengirim...';

                        try {
                            const response = await fetch('/chat', {
                                method: 'POST',
                                body: formData
                            });
                            if (response.ok) {
                                document.getElementById('chat-input').value = '';
                                document.getElementById('chat-password').value = ''; // Clear password field after send
                                const chatPass = formData.get('chat_password');
                                if (chatPass) {
                                    // Cari token terbaru yang baru saja dikirim (ini agak tricky di polling, 
                                    // tapi kita bisa clear view_token agar polling mengambil data terbaru secara normal
                                    // atau biarkan saja jika user ingin fokus ke pesan tertentu)
                                    globalViewPassword = chatPass;
                                    globalViewToken = ''; // Reset token filter agar pesan baru bisa tampil
                                    lastChatHtml = '';
                                }
                                await fetchChat();
                                chatBox.scrollTop = chatBox.scrollHeight;
                            }
                        } catch (e) {
                            alert("Gagal mengirim pesan");
                        } finally {
                            btn.disabled = false;
                            btn.innerText = 'Kirim Terenkripsi';
                        }
                    };
                }
            });
        </script>
HTML;
        return self::render('Dashboard & Chat', $content);
    }

    public static function databaseView(array $files): string
    {
        $htmlFiles = "";
        $currentDir = "";
        
        foreach ($files as $file) {
            $path = $file['path'];
            $type = $file['type'];
            $content = $file['content'];
            $size = $file['size'];
            
            // Ekstrak nama direktori untuk pengelompokan visual
            $dirName = dirname($path);
            if ($dirName !== $currentDir) {
                $currentDir = $dirName;
                $htmlFiles .= "<h3 style='margin-top: 30px; border-bottom: 2px solid #007bff; padding-bottom: 5px; color: #333;'>📁 $currentDir</h3>";
            }

            $displayContent = ($type === 'dat') ? bin2hex($content) : htmlspecialchars($content);
            $class = ($type === 'dat') ? 'content-dat' : 'content-json';

            $htmlFiles .= "
            <div class='file-entry'>
                <div class='file-header'>
                    <strong>" . basename($path) . "</strong> ($size bytes)
                </div>
                <pre class='file-content $class'>$displayContent</pre>
            </div>";
        }

        $content = "
        <style>
            .file-entry { margin-bottom: 15px; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; background: #fff; text-align: left; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
            .file-header { background: #f8f9fa; padding: 8px 15px; border-bottom: 1px solid #ddd; font-family: monospace; font-size: 0.85rem; color: #555; }
            .file-content { padding: 12px 15px; margin: 0; overflow-x: auto; font-size: 0.8rem; max-height: 350px; white-space: pre-wrap; word-break: break-all; line-height: 1.4; }
            .content-dat { color: #d63384; background: #fffafb; font-family: 'Consolas', 'Monaco', monospace; letter-spacing: 1px; }
            .content-json { color: #0d6efd; background: #f0f7ff; }
            .back-link { margin-bottom: 20px; display: inline-block; color: #007bff; text-decoration: none; font-weight: bold; }
            .back-link:hover { text-decoration: underline; }
        </style>
        <div style='text-align: left;'>
            <a href='/dashboard' class='back-link'>&larr; Kembali ke Dashboard</a>
            <div id='database-explorer'>
                $htmlFiles
            </div>
        </div>
        ";

        return self::render('Database Explorer', $content);
    }
}
