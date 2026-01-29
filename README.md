# moreweb PHP Messenger

![Version](https://img.shields.io/badge/version-0.0.1-blue.svg)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-purple.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**moreweb Messenger** is a self-contained chat application built in a single PHP file. It bridges the gap between privacy and persistence by using the server purely as an ephemeral courier while storing chat history permanently in the user's browser.

## 🚀 Features

*   **Zero-Knowledge Server:** Messages are deleted from the server database immediately upon delivery. The server has no knowledge of your chat history.
*   **Browser Persistence:** Chat history is stored locally in your browser's `localStorage`, ensuring you keep your data without leaving a footprint on the server.
*   **End-to-End Encryption (E2EE):** Optional "Secret Mode" using the Web Crypto API (ECDH + AES-GCM) ensures the server cannot read your messages even while they are in transit.
*   **Single File Deployment:** The entire application runs from a single `index.php` file. No Composer, Node.js, or complex installation required.
*   **Modern UI:** A sleek, dark-themed interface with a vertical navigation rail, mobile responsiveness, and smooth interactions (no heavy animations).
*   **Rich Messaging:**
    *   Emoji Reactions.
    *   Reply/Quote functionality.
    *   Image Sharing (Base64 encoded).
*   **Group Chats:**
    *   **Public Groups:** Join via a generated 6-digit code.
    *   **Private Groups:** Invite-only (database level).
*   **Notifications:** Built-in notification center for missed messages.

## 📋 Requirements

*   **PHP 7.4** or higher.
*   **PDO SQLite** extension enabled (Standard on most hosts).
*   **Write Permissions:** The script must be able to create and write to `chat_mw.db` in its directory.
*   **HTTPS (SSL):** Required for End-to-End Encryption features (Browsers block the Web Crypto API on insecure HTTP connections, except `localhost`).

## 🛠️ Installation

1.  **Download:** Download the `index.php` file from this repository.
2.  **Upload:** Upload the file to your web server (e.g., `public_html/messenger/index.php`).
3.  **Permissions:** Ensure the folder containing the file is writable by the web server.
    *   *Linux/Unix:* `chmod 755` or `chmod 777` on the folder.
4.  **Run:** Navigate to the URL (e.g., `https://yourdomain.com/messenger/`).
5.  **First Run:** The database (`chat_mw.db`) will be created automatically.

## 🔒 Security Architecture

### Ephemeral Storage Logic
Unlike traditional messengers, **moreweb Messenger** does not keep a history on the server.
1.  **Sender** posts a message to the database.
2.  **Recipient** polls the server.
3.  Once the recipient fetches the message, the server executes a **DELETE** command in the same transaction cycle.
4.  The message now exists **only** in the recipient's and sender's browser `localStorage`.

### End-to-End Encryption (E2EE)
When enabled in a Direct Message (DM):
1.  Users exchange public keys via an initial handshake.
2.  A shared secret is derived using **ECDH** (Elliptic Curve Diffie-Hellman).
3.  Messages are encrypted with **AES-GCM** before leaving the browser.
4.  The server only sees and stores encrypted ciphertext strings until delivery.

## 📖 Usage Guide

### Registration
Simply toggle the login box to "Register" and create a username and password.

### Adding Contacts
1.  Click the **+** button next to "Chats".
2.  Type the exact username of the person you want to message.
3.  Once the chat opens, say "Hi".

### Group Chats
*   **Create:** Go to the Groups tab, click **+**, name your group, and choose "Public" or "Private".
*   **Join:** If a group is Public, ask the creator for the **6-digit Join Code**. Click "Join via Code" in the Groups tab.

### Enabling Encryption
1.  Open a Direct Message.
2.  Click the **Lock Icon** (🔒) in the top header.
3.  Wait for the recipient to come online and acknowledge the handshake.
4.  Once the alert confirms "Secure channel ready," your chats are encrypted.

## ⚙️ Configuration

You can adjust upload limits at the top of `index.php`:

```php
ini_set('upload_max_filesize', '10M');
ini_set('post_max_size', '10M');
```
