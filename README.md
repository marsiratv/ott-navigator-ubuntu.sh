# Download script
wget [https://raw.githubusercontent.com/your-repo/ott-navigator/main/scripts/ott-navigator-ubuntu.sh](https://raw.githubusercontent.com/marsiratv/ott-navigator-ubuntu.sh/refs/heads/main/ott-navigator-ubuntu.sh)



# Beri permission
chmod +x ott-navigator-ubuntu.sh



# Jalankan installation
sudo ./ott-navigator-ubuntu.sh install



# Check status panel
sudo ./ott-navigator-ubuntu.sh status


# Buat backup
sudo ./ott-navigator-ubuntu.sh backup


# Monitor system
sudo ./ott-navigator-ubuntu.sh monitor


# Update panel
sudo ./ott-navigator-ubuntu.sh update


FITUR KHUSUS UBUNTU 22.04:

✅ Optimized for Ubuntu 22.04 LTS
✅ Systemd service configuration
✅ PostgreSQL 14+ support
✅ Redis 6+ integration
✅ Nginx optimization
✅ UFW firewall setup
✅ Automatic SSL with Let's Encrypt
✅ Log rotation configuration
✅ Resource limits optimization
✅ Security hardening

STRUKTUR DIREKTORI SETELAH INSTALL:

```
/opt/ott-navigator/
├── src/                    # React source code
├── public/                 # Static files
├── data/                   # Application data
│   ├── users/              # User data
│   ├── playlists/          # Playlist files
│   └── channels/           # Channel data
├── backups/                # Auto-backups
└── .env                    # Environment config

/var/log/ott-navigator/     # Log files
/var/backups/ott-navigator/ # System backups
```

SERVICES YANG DIINSTALL:

1. ott-navigator - Panel utama
2. nginx - Web server & reverse proxy
3. postgresql - Database
4. redis-server - Cache & sessions
5. fail2ban - Security protection

SECURITY FEATURES:

· 🔒 Firewall dengan UFW
· 🛡️ Fail2ban untuk protection
· 🔐 SSL/TLS encryption
· 🚫 Directory protection
· 📝 Log monitoring
· 🔄 Auto-update & backup

Script ini siap untuk production di Ubuntu 22.04
