# SSH Multi-Port Forwarder (Tkinter GUI)

Aplikasi GUI Port Forwarding berbasis Python Tkinter dengan dukungan **Multi-Port (-L)**, quick command parser & generator, session profile management, serta backend **Paramiko** dan **OpenSSH**.

Cocok untuk menggantikan `ssh-port-forwarder` bawaan yang hanya mendukung satu port.

---

## 🚀 Fitur Utama

1. **Multi-Port Forwarding (-L)**:
   - Mampu membuka banyak tunnel port sekaligus dalam 1 sesi SSH.
   - Contoh perintah SSH:
     ```bash
     ssh -N -L 8002:localhost:8002 -L 5173:localhost:5173 -L 19000:localhost:19000 user@your-server-ip
     ```
   - Input port fleksibel: Single Port Add, Batch Add (contoh: `8002, 5173, 19000`), dan Import langsung dari teks perintah SSH.

2. **Dua Mode Mesin Forwarding (Engine)**:
   - **Paramiko (Built-in)**: Pure Python port forwarding via `direct-tcpip`, menangani autentikasi Password, Private Key (`.pem`, `.key`, `id_rsa`), atau SSH Agent langsung di dalam GUI tanpa perlu terminal eksternal.
   - **OpenSSH (CLI `ssh`)**: Menjalankan subprocess perintah `ssh -N -L ...` standar sistem dan menampilkan output log secara langsung.

3. **Smart SSH Command Parser & Generator**:
   - **Live Command Preview**: Preview perintah SSH otomatis diperbarui setiap kali port ditambah/diubah.
   - **Tombol Copy Command**: Salin perintah langsung ke clipboard.
   - **Import / Parse Command**: Paste perintah SSH lengkap (seperti contoh di atas) dan GUI akan otomatis mengisi Server, User, Port, serta seluruh port forwarding.

4. **Tabel Pengaturan Port Modern (Treeview)**:
   - Status per-port: Idle, Listening, Active connections, Error.
   - Double-click untuk toggle aktif/nonaktif suatu port.
   - Label/Deskripsi per service (contoh: *API / Backend*, *Frontend Vite*, *Expo*).

5. **Profile & Konfigurasi Otomatis**:
   - Otomatis menyimpan pengaturan ke `~/.ssh_multi_port_forwarder.json` (diabaikan oleh git untuk keamanan data).
   - Mendukung multi-profile untuk menyimpan konfigurasi server yang berbeda-beda.

6. **Activity Log Real-Time**:
   - Konsol log berwarna (Info, Success, Warning, Error) dengan timestamp dan auto-scroll.

---

## 📦 Kebutuhan & Instalasi

Pastikan virtual environment telah aktif atau modul telah terinstal:

```bash
# Masuk ke direktori
cd ~/src/python/pf

# Aktifkan virtual environment
source venv/bin/activate

# Install dependensi jika belum ada
pip install paramiko
```

---

## 🏃‍♂️ Cara Menjalankan

Jalankan perintah berikut:

```bash
python pf.py
```
atau langsung:
```bash
./pf.py
```
