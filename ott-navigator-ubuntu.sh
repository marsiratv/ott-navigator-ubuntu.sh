#!/bin/bash

# OTT Navigator Panel Installation Script for Ubuntu 22.04 LTS
# Author: OTT Navigator Team
# Version: 2.0.0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration for Ubuntu 22.04
PANEL_NAME="OTT Navigator Panel"
PANEL_VERSION="2.0.0"
INSTALL_DIR="/opt/ott-navigator"
BACKUP_DIR="/var/backups/ott-navigator"
LOG_DIR="/var/log/ott-navigator"
PORT="3000"
DOMAIN=""
EMAIL=""
DB_PASSWORD=""
ADMIN_PASSWORD="admin123"

# Function to log messages
log_message() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_DIR/install.log"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: Script must be run as root${NC}"
        echo -e "Use: ${GREEN}sudo ./ott-navigator-ubuntu.sh${NC}"
        exit 1
    fi
}

# Function to check Ubuntu version
check_ubuntu_version() {
    echo -e "${CYAN}Checking Ubuntu version...${NC}"
    
    if [ ! -f /etc/os-release ]; then
        echo -e "${RED}Error: Not running on Ubuntu${NC}"
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$VERSION_ID" != "22.04" ]]; then
        echo -e "${YELLOW}Warning: This script is optimized for Ubuntu 22.04${NC}"
        echo -e "You are running Ubuntu ${VERSION_ID}"
        read -p "Continue anyway? (y/N): " continue_anyway
        if [[ ! $continue_anyway =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    log_message "Ubuntu $VERSION_ID detected"
    echo -e "${GREEN}✓ Ubuntu version OK${NC}"
}

# Function to update system
update_system() {
    echo -e "${CYAN}Updating system packages...${NC}"
    
    export DEBIAN_FRONTEND=noninteractive
    
    # Update package list
    apt-get update -y
    
    # Upgrade existing packages
    apt-get upgrade -y
    
    # Install essential packages
    apt-get install -y \
        curl \
        wget \
        git \
        unzip \
        tar \
        gzip \
        build-essential \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        ufw \
        fail2ban
    
    log_message "System updated and essential packages installed"
    echo -e "${GREEN}✓ System updated${NC}"
}

# Function to install Node.js 18.x (LTS)
install_nodejs() {
    echo -e "${CYAN}Installing Node.js 18.x...${NC}"
    
    # Remove existing Node.js
    apt-get remove -y nodejs npm
    
    # Add NodeSource repository
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    
    # Install Node.js and npm
    apt-get install -y nodejs
    
    # Verify installation
    node_version=$(node --version)
    npm_version=$(npm --version)
    
    log_message "Node.js $node_version installed"
    log_message "npm $npm_version installed"
    
    echo -e "${GREEN}✓ Node.js $node_version installed${NC}"
    echo -e "${GREEN}✓ npm $npm_version installed${NC}"
}

# Function to install Nginx
install_nginx() {
    echo -e "${CYAN}Installing Nginx...${NC}"
    
    # Install Nginx
    apt-get install -y nginx
    
    # Start and enable Nginx
    systemctl start nginx
    systemctl enable nginx
    
    # Configure firewall for Nginx
    ufw allow 'Nginx Full'
    ufw allow 'Nginx HTTP'
    ufw allow 'Nginx HTTPS'
    
    log_message "Nginx installed and configured"
    echo -e "${GREEN}✓ Nginx installed${NC}"
}

# Function to install PostgreSQL
install_postgresql() {
    echo -e "${CYAN}Installing PostgreSQL...${NC}"
    
    # Install PostgreSQL
    apt-get install -y postgresql postgresql-contrib
    
    # Start and enable PostgreSQL
    systemctl start postgresql
    systemctl enable postgresql
    
    # Create database and user
    sudo -u postgres psql <<EOF
CREATE DATABASE ott_navigator;
CREATE USER ott_admin WITH PASSWORD '$DB_PASSWORD';
ALTER ROLE ott_admin SET client_encoding TO 'utf8';
ALTER ROLE ott_admin SET default_transaction_isolation TO 'read committed';
ALTER ROLE ott_admin SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE ott_navigator TO ott_admin;
\c ott_navigator
GRANT ALL ON SCHEMA public TO ott_admin;
EOF
    
    log_message "PostgreSQL installed and database created"
    echo -e "${GREEN}✓ PostgreSQL installed${NC}"
}

# Function to install Redis
install_redis() {
    echo -e "${CYAN}Installing Redis...${NC}"
    
    # Install Redis
    apt-get install -y redis-server
    
    # Configure Redis
    sed -i 's/supervised no/supervised systemd/g' /etc/redis/redis.conf
    sed -i 's/bind 127.0.0.1 ::1/bind 0.0.0.0/g' /etc/redis/redis.conf
    
    # Start and enable Redis
    systemctl restart redis-server
    systemctl enable redis-server
    
    log_message "Redis installed and configured"
    echo -e "${GREEN}✓ Redis installed${NC}"
}

# Function to install PM2
install_pm2() {
    echo -e "${CYAN}Installing PM2...${NC}"
    
    # Install PM2 globally
    npm install -g pm2
    
    # Setup PM2 startup
    pm2 startup ubuntu -u www-data
    
    log_message "PM2 installed"
    echo -e "${GREEN}✓ PM2 installed${NC}"
}

# Function to create directories
create_directories() {
    echo -e "${CYAN}Creating directories...${NC}"
    
    # Create main directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$INSTALL_DIR/data"
    mkdir -p "$INSTALL_DIR/public/uploads"
    mkdir -p "$INSTALL_DIR/backups"
    mkdir -p "$INSTALL_DIR/ssl"
    
    # Set permissions
    chown -R www-data:www-data "$INSTALL_DIR"
    chmod -R 755 "$INSTALL_DIR"
    chown -R www-data:www-data "$BACKUP_DIR"
    chown -R www-data:www-data "$LOG_DIR"
    
    log_message "Directories created"
    echo -e "${GREEN}✓ Directories created${NC}"
}

# Function to download panel code
download_panel() {
    echo -e "${CYAN}Downloading OTT Navigator Panel...${NC}"
    
    # Create basic React app structure
    cat > "$INSTALL_DIR/package.json" << 'EOF'
{
  "name": "ott-navigator-panel",
  "version": "2.0.0",
  "private": true,
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "lucide-react": "^0.263.1",
    "axios": "^1.4.0",
    "socket.io-client": "^4.6.1"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test",
    "eject": "react-scripts eject"
  },
  "devDependencies": {
    "react-scripts": "5.0.1"
  },
  "browserslist": {
    "production": [
      ">0.2%",
      "not dead",
      "not op_mini all"
    ],
    "development": [
      "last 1 chrome version",
      "last 1 firefox version",
      "last 1 safari version"
    ]
  }
}
EOF

    # Create React app structure
    mkdir -p "$INSTALL_DIR/src"
    mkdir -p "$INSTALL_DIR/public"
    
    # Create index.html
    cat > "$INSTALL_DIR/public/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <link rel="icon" href="%PUBLIC_URL%/favicon.ico" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="theme-color" content="#000000" />
    <meta name="description" content="OTT Navigator Admin Panel" />
    <title>OTT Navigator Panel</title>
</head>
<body>
    <noscript>You need to enable JavaScript to run this app.</noscript>
    <div id="root"></div>
</body>
</html>
EOF

    # Create main React component
    cat > "$INSTALL_DIR/src/App.js" << 'EOF'
import React from 'react';
import OTTNavigatorPanel from './components/OTTNavigatorPanel';

function App() {
  return <OTTNavigatorPanel />;
}

export default App;
EOF

    # Create index.js
    cat > "$INSTALL_DIR/src/index.js" << 'EOF'
import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
EOF

    # Create CSS file
    cat > "$INSTALL_DIR/src/index.css" << 'EOF'
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
    'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',
    sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

code {
  font-family: source-code-pro, Menlo, Monaco, Consolas, 'Courier New',
    monospace;
}
EOF

    # Create components directory
    mkdir -p "$INSTALL_DIR/src/components"
    
    # Copy your React component code here
    # You'll need to copy your main component code to:
    # $INSTALL_DIR/src/components/OTTNavigatorPanel.js
    
    log_message "Panel structure created"
    echo -e "${GREEN}✓ Panel structure created${NC}"
}

# Function to install npm dependencies
install_dependencies() {
    echo -e "${CYAN}Installing npm dependencies...${NC}"
    
    cd "$INSTALL_DIR"
    
    # Install dependencies
    npm install
    
    # Install additional packages
    npm install react-router-dom express cors body-parser jsonwebtoken bcryptjs
    
    log_message "npm dependencies installed"
    echo -e "${GREEN}✓ npm dependencies installed${NC}"
}

# Function to create environment file
create_env_file() {
    echo -e "${CYAN}Creating environment configuration...${NC}"
    
    # Generate secure secrets
    JWT_SECRET=$(openssl rand -hex 32)
    SESSION_SECRET=$(openssl rand -hex 32)
    API_KEY=$(openssl rand -hex 32)
    ENCRYPTION_KEY=$(openssl rand -hex 32)
    
    # Create .env file
    cat > "$INSTALL_DIR/.env" << EOF
# OTT Navigator Panel Configuration
NODE_ENV=production
PORT=$PORT
HOST=0.0.0.0

# Security
JWT_SECRET=$JWT_SECRET
SESSION_SECRET=$SESSION_SECRET
API_KEY=$API_KEY
ENCRYPTION_KEY=$ENCRYPTION_KEY

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=ott_navigator
DB_USER=ott_admin
DB_PASSWORD=$DB_PASSWORD

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# Application
PANEL_NAME="$PANEL_NAME"
SUPPORT_EMAIL=$EMAIL
CURRENCY=RM
MAX_CONNECTIONS=3
AUTO_RENEW=true

# Paths
DATA_PATH=$INSTALL_DIR/data
LOG_PATH=$LOG_DIR
BACKUP_PATH=$BACKUP_DIR
UPLOAD_PATH=$INSTALL_DIR/public/uploads

# SSL
ENABLE_SSL=false
SSL_CERT_PATH=/etc/letsencrypt/live/$DOMAIN/fullchain.pem
SSL_KEY_PATH=/etc/letsencrypt/live/$DOMAIN/privkey.pem

# API
API_BASE_URL=http://$DOMAIN/api
CORS_ORIGIN=*
EOF
    
    # Protect .env file
    chmod 600 "$INSTALL_DIR/.env"
    chown www-data:www-data "$INSTALL_DIR/.env"
    
    log_message "Environment file created"
    echo -e "${GREEN}✓ Environment configuration created${NC}"
}

# Function to create systemd service
create_systemd_service() {
    echo -e "${CYAN}Creating systemd service...${NC}"
    
    cat > /etc/systemd/system/ott-navigator.service << EOF
[Unit]
Description=OTT Navigator Panel
After=network.target postgresql.service redis-server.service
Wants=postgresql.service redis-server.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=$INSTALL_DIR
Environment=NODE_ENV=production
Environment=PATH=/usr/bin:/usr/local/bin
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=/usr/bin/npm start
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=ott-navigator

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR/data $LOG_DIR $BACKUP_DIR
PrivateDevices=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Resource limits
LimitNOFILE=65536
LimitNPROC=512
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    log_message "Systemd service created"
    echo -e "${GREEN}✓ Systemd service created${NC}"
}

# Function to configure Nginx
configure_nginx() {
    echo -e "${CYAN}Configuring Nginx...${NC}"
    
    # Remove default site
    rm -f /etc/nginx/sites-enabled/default
    
    # Create Nginx configuration
    cat > /etc/nginx/sites-available/ott-navigator << EOF
# OTT Navigator Panel Nginx Configuration
# Optimized for Ubuntu 22.04

upstream ott_backend {
    server 127.0.0.1:$PORT;
    keepalive 32;
}

server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    
    # Root directory for static files
    root $INSTALL_DIR/build;
    index index.html;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;
    
    # Client settings
    client_max_body_size 50M;
    client_body_timeout 30s;
    client_header_timeout 30s;
    
    # Proxy settings
    location / {
        try_files \$uri \$uri/ @proxy;
    }
    
    location @proxy {
        proxy_pass http://ott_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        proxy_busy_buffers_size 8k;
    }
    
    # API endpoints
    location /api/ {
        proxy_pass http://ott_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Static files
    location /static/ {
        alias $INSTALL_DIR/build/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
    
    # Uploads
    location /uploads/ {
        alias $INSTALL_DIR/public/uploads/;
        expires 30d;
        add_header Cache-Control "public";
        access_log off;
    }
    
    # Health check
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
    
    # Deny access to sensitive files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    location ~ /(\.env|\.git|\.ht) {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF
    
    # Enable site
    ln -sf /etc/nginx/sites-available/ott-navigator /etc/nginx/sites-enabled/
    
    # Test Nginx configuration
    nginx -t
    
    # Restart Nginx
    systemctl restart nginx
    
    log_message "Nginx configured"
    echo -e "${GREEN}✓ Nginx configured${NC}"
}

# Function to setup SSL with Let's Encrypt
setup_ssl() {
    echo -e "${CYAN}Setting up SSL certificate...${NC}"
    
    # Install certbot
    apt-get install -y certbot python3-certbot-nginx
    
    # Get SSL certificate
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --email "$EMAIL"
    
    # Auto-renewal setup
    echo "0 12 * * * /usr/bin/certbot renew --quiet" | crontab -
    
    # Update Nginx config for SSL
    sed -i "s/listen 80;/listen 80;\n    listen 443 ssl http2;/g" /etc/nginx/sites-available/ott-navigator
    sed -i "s/server_name $DOMAIN;/server_name $DOMAIN;\n\n    # SSL\n    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;\n    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;\n    ssl_trusted_certificate /etc/letsencrypt/live/$DOMAIN/chain.pem;\n\n    # SSL optimization\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;\n    ssl_prefer_server_ciphers off;\n    ssl_session_cache shared:SSL:10m;\n    ssl_session_timeout 10m;/g" /etc/nginx/sites-available/ott-navigator
    
    # Update .env for SSL
    sed -i "s/ENABLE_SSL=false/ENABLE_SSL=true/g" "$INSTALL_DIR/.env"
    sed -i "s|API_BASE_URL=http://|API_BASE_URL=https://|g" "$INSTALL_DIR/.env"
    
    # Restart Nginx
    systemctl restart nginx
    
    log_message "SSL certificate installed"
    echo -e "${GREEN}✓ SSL certificate installed${NC}"
}

# Function to configure firewall
configure_firewall() {
    echo -e "${CYAN}Configuring firewall...${NC}"
    
    # Enable UFW if not enabled
    ufw --force enable
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow ssh
    
    # Allow HTTP and HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Allow panel port
    ufw allow $PORT/tcp
    
    # Allow PostgreSQL
    ufw allow 5432/tcp
    
    # Allow Redis
    ufw allow 6379/tcp
    
    # Show firewall status
    ufw status verbose
    
    log_message "Firewall configured"
    echo -e "${GREEN}✓ Firewall configured${NC}"
}

# Function to create backup script
create_backup_script() {
    echo -e "${CYAN}Creating backup script...${NC}"
    
    cat > /usr/local/bin/backup-ott.sh << 'EOF'
#!/bin/bash

# Backup script for OTT Navigator Panel

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
BACKUP_DIR="/var/backups/ott-navigator"
INSTALL_DIR="/opt/ott-navigator"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/backup_$DATE.tar.gz"
LOG_FILE="/var/log/ott-navigator/backup.log"

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

echo "Starting backup process..."

# Stop services
log "Stopping services..."
systemctl stop ott-navigator
sleep 5

# Create backup
log "Creating backup archive..."
tar -czf "$BACKUP_FILE" \
    "$INSTALL_DIR/data" \
    "$INSTALL_DIR/public/uploads" \
    "$INSTALL_DIR/.env" \
    "/etc/nginx/sites-available/ott-navigator" \
    "/etc/systemd/system/ott-navigator.service" \
    2>/dev/null

BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)

# Start services
log "Starting services..."
systemctl start ott-navigator

# Verify backup
if [ -f "$BACKUP_FILE" ]; then
    log "Backup created: $BACKUP_FILE ($BACKUP_SIZE)"
    echo -e "${GREEN}✓ Backup created: $BACKUP_FILE ($BACKUP_SIZE)${NC}"
    
    # Remove old backups (keep last 30)
    find "$BACKUP_DIR" -name "backup_*.tar.gz" -mtime +30 -delete
    
    # Count remaining backups
    BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/backup_*.tar.gz 2>/dev/null | wc -l)
    log "Backup rotation complete. $BACKUP_COUNT backups retained."
    
else
    log "Backup failed!"
    echo -e "${RED}✗ Backup failed${NC}"
    exit 1
fi
EOF
    
    chmod +x /usr/local/bin/backup-ott.sh
    
    # Add to crontab (daily at 2 AM)
    (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/backup-ott.sh >> /var/log/ott-navigator/backup.log 2>&1") | crontab -
    
    log_message "Backup script created"
    echo -e "${GREEN}✓ Backup script created${NC}"
}

# Function to create monitoring script
create_monitoring_script() {
    echo -e "${CYAN}Creating monitoring script...${NC}"
    
    cat > /usr/local/bin/monitor-ott.sh << 'EOF'
#!/bin/bash

# Monitoring script for OTT Navigator Panel

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
INSTALL_DIR="/opt/ott-navigator"
PORT="3000"
LOG_FILE="/var/log/ott-navigator/monitor.log"

# Log function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Send alert function
send_alert() {
    local message="$1"
    local severity="$2"
    
    log "ALERT [$severity]: $message"
    
    # You can add email or Telegram notification here
    # Example for Telegram:
    # curl -s -X POST "https://api.telegram.org/botYOUR_BOT_TOKEN/sendMessage" \
    #     -d chat_id=YOUR_CHAT_ID \
    #     -d text="[OTT Navigator] $severity: $message"
}

# Check system resources
check_resources() {
    echo -e "${BLUE}=== System Resources ===${NC}"
    
    # CPU Load
    LOAD=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
    CORES=$(nproc)
    LOAD_PER_CORE=$(echo "scale=2; $LOAD / $CORES" | bc)
    
    if (( $(echo "$LOAD_PER_CORE > 2.0" | bc -l) )); then
        echo -e "${RED}✗ High CPU load: $LOAD (Per core: $LOAD_PER_CORE)${NC}"
        send_alert "High CPU load: $LOAD" "CRITICAL"
    else
        echo -e "${GREEN}✓ CPU load: $LOAD (Per core: $LOAD_PER_CORE)${NC}"
    fi
    
    # Memory
    MEMORY=$(free -m | awk 'NR==2{printf "%.2f", $3*100/$2}')
    if (( $(echo "$MEMORY > 90" | bc -l) )); then
        echo -e "${RED}✗ High memory usage: ${MEMORY}%${NC}"
        send_alert "High memory usage: ${MEMORY}%" "WARNING"
    else
        echo -e "${GREEN}✓ Memory usage: ${MEMORY}%${NC}"
    fi
    
    # Disk space
    DISK=$(df -h / | awk 'NR==2{print $5}' | tr -d '%')
    if [ "$DISK" -gt 90 ]; then
        echo -e "${RED}✗ Low disk space: ${DISK}% used${NC}"
        send_alert "Low disk space: ${DISK}%" "CRITICAL"
    else
        echo -e "${GREEN}✓ Disk space: ${DISK}% used${NC}"
    fi
}

# Check services
check_services() {
    echo -e "\n${BLUE}=== Services Status ===${NC}"
    
    SERVICES=("ott-navigator" "nginx" "postgresql" "redis-server")
    
    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo -e "${GREEN}✓ $service is running${NC}"
        else
            echo -e "${RED}✗ $service is NOT running${NC}"
            send_alert "Service $service is down" "CRITICAL"
            
            # Try to restart
            systemctl restart "$service"
            sleep 2
            
            if systemctl is-active --quiet "$service"; then
                echo -e "${YELLOW}  ↳ Restarted successfully${NC}"
                send_alert "Service $service restarted successfully" "INFO"
            else
                echo -e "${RED}  ↳ Restart failed${NC}"
            fi
        fi
    done
}

# Check application health
check_application() {
    echo -e "\n${BLUE}=== Application Health ===${NC}"
    
    # Check if port is listening
    if netstat -tulpn | grep -q ":$PORT"; then
        echo -e "${GREEN}✓ Port $PORT is listening${NC}"
    else
        echo -e "${RED}✗ Port $PORT is NOT listening${NC}"
        send_alert "Application not listening on port $PORT" "CRITICAL"
        return 1
    fi
    
    # Check HTTP response
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$PORT/health || echo "000")
    
    if [ "$RESPONSE" = "200" ]; then
        echo -e "${GREEN}✓ Application health check: OK${NC}"
    else
        echo -e "${RED}✗ Application health check: FAILED (HTTP $RESPONSE)${NC}"
        send_alert "Health check failed: HTTP $RESPONSE" "WARNING"
    fi
    
    # Check database connection
    if sudo -u postgres psql -d ott_navigator -c "SELECT 1" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Database connection: OK${NC}"
    else
        echo -e "${RED}✗ Database connection: FAILED${NC}"
        send_alert "Database connection failed" "CRITICAL"
    fi
    
    # Check Redis connection
    if redis-cli ping | grep -q "PONG"; then
        echo -e "${GREEN}✓ Redis connection: OK${NC}"
    else
        echo -e "${RED}✗ Redis connection: FAILED${NC}"
        send_alert "Redis connection failed" "WARNING"
    fi
}

# Check backups
check_backups() {
    echo -e "\n${BLUE}=== Backup Status ===${NC}"
    
    BACKUP_DIR="/var/backups/ott-navigator"
    BACKUP_COUNT=$(find "$BACKUP_DIR" -name "backup_*.tar.gz" -mtime -1 | wc -l)
    
    if [ "$BACKUP_COUNT" -gt 0 ]; then
        LATEST_BACKUP=$(ls -t "$BACKUP_DIR"/backup_*.tar.gz | head -1)
        BACKUP_SIZE=$(du -h "$LATEST_BACKUP" | cut -f1)
        BACKUP_TIME=$(stat -c %y "$LATEST_BACKUP" | cut -d' ' -f1)
        
        echo -e "${GREEN}✓ Recent backup found${NC}"
        echo -e "  ↳ Latest: $BACKUP_TIME ($BACKUP_SIZE)"
        echo -e "  ↳ Count last 24h: $BACKUP_COUNT"
    else
        echo -e "${RED}✗ No recent backups found${NC}"
        send_alert "No backups in last 24 hours" "WARNING"
    fi
}

# Main monitoring function
main() {
    log "Starting monitoring check"
    
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}    OTT Navigator Panel Monitoring     ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    check_resources
    check_services
    check_application
    check_backups
    
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}✓ Monitoring check completed $(date)${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Run monitoring
main
EOF
    
    chmod +x /usr/local/bin/monitor-ott.sh
    
    # Add to crontab (every 5 minutes)
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/monitor-ott.sh >> /var/log/ott-navigator/monitor.log 2>&1") | crontab -
    
    log_message "Monitoring script created"
    echo -e "${GREEN}✓ Monitoring script created${NC}"
}

# Function to create update script
create_update_script() {
    echo -e "${CYAN}Creating update script...${NC}"
    
    cat > /usr/local/bin/update-ott.sh << 'EOF'
#!/bin/bash

# Update script for OTT Navigator Panel

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="/opt/ott-navigator"

echo -e "${BLUE}=== OTT Navigator Panel Update ===${NC}"
echo ""

# Check for updates
echo "1. Checking for updates..."
cd "$INSTALL_DIR"

# Backup before update
echo "2. Creating backup..."
/usr/local/bin/backup-ott.sh

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Backup failed. Update aborted.${NC}"
    exit 1
fi

# Stop service
echo "3. Stopping service..."
systemctl stop ott-navigator

# Update dependencies
echo "4. Updating system packages..."
apt-get update -y
apt-get upgrade -y

# Update Node.js packages
echo "5. Updating npm packages..."
cd "$INSTALL_DIR"
npm update

# Run migrations if needed
echo "6. Running migrations..."
# Add migration commands here

# Start service
echo "7. Starting service..."
systemctl start ott-navigator

# Wait and verify
sleep 10

if systemctl is-active --quiet ott-navigator; then
    echo -e "${GREEN}✓ Update completed successfully${NC}"
    
    # Show version
    if [ -f "$INSTALL_DIR/package.json" ]; then
        VERSION=$(node -e "console.log(require('$INSTALL_DIR/package.json').version || 'unknown')")
        echo -e "${BLUE}Current version: ${VERSION}${NC}"
    fi
    
    # Restart Nginx
    systemctl restart nginx
    
else
    echo -e "${RED}✗ Service failed to start after update${NC}"
    
    # Rollback from latest backup
    echo "Attempting rollback..."
    LATEST_BACKUP=$(ls -t /var/backups/ott-navigator/backup_*.tar.gz | head -1)
    if [ -f "$LATEST_BACKUP" ]; then
        tar -xzf "$LATEST_BACKUP" -C /
        systemctl start ott-navigator
        echo -e "${YELLOW}Rolled back to previous version${NC}"
    fi
fi
EOF
    
    chmod +x /usr/local/bin/update-ott.sh
    
    log_message "Update script created"
    echo -e "${GREEN}✓ Update script created${NC}"
}

# Function to show installation banner
show_banner() {
    clear
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                                                          ║"
    echo "║     OTT Navigator Panel Installer for Ubuntu 22.04      ║"
    echo "║                                                          ║"
    echo "║                  Version: $PANEL_VERSION                     ║"
    echo "║                                                          ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

# Function to collect user input
collect_input() {
    echo -e "${CYAN}Please provide installation details:${NC}"
    echo ""
    
    # Get domain name
    while true; do
        read -p "Enter your domain name (e.g., ott.yourdomain.com): " DOMAIN
        if [[ -n "$DOMAIN" ]]; then
            break
        fi
        echo -e "${YELLOW}Domain name is required${NC}"
    done
    
    # Get email for SSL
    while true; do
        read -p "Enter your email address (for SSL certificates): " EMAIL
        if [[ "$EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
            break
        fi
        echo -e "${YELLOW}Please enter a valid email address${NC}"
    done
    
    # Generate database password
    DB_PASSWORD=$(openssl rand -base64 16)
    
    # Ask for admin password
    read -p "Enter admin password [default: admin123]: " input_pass
    if [[ -n "$input_pass" ]]; then
        ADMIN_PASSWORD="$input_pass"
    fi
    
    # Summary
    echo ""
    echo -e "${GREEN}Installation Summary:${NC}"
    echo "────────────────────────────"
    echo -e "Domain:          ${BLUE}$DOMAIN${NC}"
    echo -e "Email:           ${BLUE}$EMAIL${NC}"
    echo -e "Install Dir:     ${BLUE}$INSTALL_DIR${NC}"
    echo -e "Port:            ${BLUE}$PORT${NC}"
    echo -e "Admin Password:  ${BLUE}$ADMIN_PASSWORD${NC}"
    echo ""
    
    read -p "Continue with installation? (y/N): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        echo "Installation cancelled"
        exit 0
    fi
}

# Main installation function
install_panel() {
    show_banner
    check_root
    check_ubuntu_version
    collect_input
    
    echo -e "${CYAN}Starting installation...${NC}"
    echo ""
    
    # Create log directory
    mkdir -p "$LOG_DIR"
    
    # Start installation steps
    update_system
    install_nodejs
    install_nginx
    install_postgresql
    install_redis
    install_pm2
    create_directories
    download_panel
    install_dependencies
    create_env_file
    create_systemd_service
    configure_nginx
    configure_firewall
    create_backup_script
    create_monitoring_script
    create_update_script
    
    # Ask about SSL
    read -p "Do you want to setup SSL certificate now? (Y/n): " ssl_choice
    if [[ ! $ssl_choice =~ ^[Nn]$ ]]; then
        setup_ssl
    fi
    
    # Start the service
    systemctl start ott-navigator
    systemctl enable ott-navigator
    
    # Wait for service to start
    sleep 5
    
    # Show completion message
    show_completion_message
}

# Function to show completion message
show_completion_message() {
    local_ip=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}           INSTALLATION COMPLETED SUCCESSFULLY           ${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BLUE}📊 Panel Information:${NC}"
    echo -e "  URL:              ${GREEN}http://$DOMAIN${NC}"
    echo -e "  Local Access:     ${GREEN}http://$local_ip:$PORT${NC}"
    echo -e "  Admin Username:   ${GREEN}admin${NC}"
    echo -e "  Admin Password:   ${GREEN}$ADMIN_PASSWORD${NC}"
    echo ""
    echo -e "${BLUE}🔧 Services Installed:${NC}"
    echo -e "  ✅ Node.js 18.x"
    echo -e "  ✅ Nginx (Reverse Proxy)"
    echo -e "  ✅ PostgreSQL Database"
    echo -e "  ✅ Redis Cache"
    echo -e "  ✅ PM2 Process Manager"
    echo ""
    echo -e "${BLUE}🛠️  Available Commands:${NC}"
    echo -e "  sudo systemctl start ott-navigator"
    echo -e "  sudo systemctl stop ott-navigator"
    echo -e "  sudo systemctl status ott-navigator"
    echo -e "  sudo /usr/local/bin/backup-ott.sh"
    echo -e "  sudo /usr/local/bin/monitor-ott.sh"
    echo -e "  sudo /usr/local/bin/update-ott.sh"
    echo ""
    echo -e "${YELLOW}⚠️  Important Notes:${NC}"
    echo "  1. Change the default admin password immediately"
    echo "  2. Configure your DNS to point to this server"
    echo "  3. Check firewall settings if unable to access"
    echo "  4. Monitor logs at: /var/log/ott-navigator/"
    echo ""
    echo -e "${BLUE}📁 Installation Directory:${NC}"
    echo "  $INSTALL_DIR"
    echo ""
    echo -e "${GREEN}🚀 Panel is now running!${NC}"
    echo ""
}

# Function to uninstall panel
uninstall_panel() {
    echo -e "${RED}══════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}               UNINSTALL OTT NAVIGATOR PANEL             ${NC}"
    echo -e "${RED}══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  WARNING: This will remove all panel data!${NC}"
    echo ""
    
    read -p "Are you sure? Type 'YES' to confirm: " confirm
    if [[ "$confirm" != "YES" ]]; then
        echo "Uninstall cancelled"
        exit 0
    fi
    
    echo "Stopping services..."
    systemctl stop ott-navigator
    systemctl disable ott-navigator
    
    echo "Removing services..."
    rm -f /etc/systemd/system/ott-navigator.service
    rm -f /etc/nginx/sites-available/ott-navigator
    rm -f /etc/nginx/sites-enabled/ott-navigator
    
    echo "Removing data..."
    rm -rf "$INSTALL_DIR"
    rm -rf "$BACKUP_DIR"
    rm -rf "$LOG_DIR"
    
    echo "Removing scripts..."
    rm -f /usr/local/bin/backup-ott.sh
    rm -f /usr/local/bin/monitor-ott.sh
    rm -f /usr/local/bin/update-ott.sh
    
    echo "Removing crontab entries..."
    crontab -l | grep -v "ott-navigator" | crontab -
    
    echo "Restarting Nginx..."
    systemctl restart nginx
    
    echo ""
    echo -e "${GREEN}✓ Uninstallation completed${NC}"
}

# Function to show panel status
show_status() {
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}               OTT NAVIGATOR PANEL STATUS                ${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Service status
    if systemctl is-active --quiet ott-navigator; then
        echo -e "Service Status:    ${GREEN}● RUNNING${NC}"
    else
        echo -e "Service Status:    ${RED}● STOPPED${NC}"
    fi
    
    # Uptime
    if systemctl is-active --quiet ott-navigator; then
        UPTIME=$(systemctl show ott-navigator --property=ActiveEnterTimestamp | awk -F= '{print $2}')
        echo -e "Started:           ${BLUE}$UPTIME${NC}"
    fi
    
    # Memory usage
    if pgrep -f "node.*ott-navigator" > /dev/null; then
        PID=$(pgrep -f "node.*ott-navigator")
        MEM=$(pmap $PID | tail -n 1 | awk '{print $2}')
        echo -e "Memory Usage:      ${BLUE}$MEM${NC}"
    fi
    
    # Database status
    if systemctl is-active --quiet postgresql; then
        echo -e "Database:          ${GREEN}● RUNNING${NC}"
    else
        echo -e "Database:          ${RED}● STOPPED${NC}"
    fi
    
    # Redis status
    if systemctl is-active --quiet redis-server; then
        echo -e "Redis:             ${GREEN}● RUNNING${NC}"
    else
        echo -e "Redis:             ${RED}● STOPPED${NC}"
    fi
    
    # Nginx status
    if systemctl is-active --quiet nginx; then
        echo -e "Nginx:             ${GREEN}● RUNNING${NC}"
    else
        echo -e "Nginx:             ${RED}● STOPPED${NC}"
    fi
    
    # Disk usage
    if [ -d "$INSTALL_DIR/data" ]; then
        DATA_SIZE=$(du -sh "$INSTALL_DIR/data" | cut -f1)
        echo -e "Data Size:         ${BLUE}$DATA_SIZE${NC}"
    fi
    
    # Last backup
    LAST_BACKUP=$(ls -t "$BACKUP_DIR"/backup_*.tar.gz 2>/dev/null | head -1)
    if [ -n "$LAST_BACKUP" ]; then
        BACKUP_TIME=$(stat -c %y "$LAST_BACKUP" | cut -d' ' -f1)
        BACKUP_SIZE=$(du -h "$LAST_BACKUP" | cut -f1)
        echo -e "Last Backup:       ${BLUE}$BACKUP_TIME ($BACKUP_SIZE)${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}Access URLs:${NC}"
    echo -e "  Panel:            http://$(hostname -I | awk '{print $1}'):$PORT"
    echo -e "  Local:            http://localhost:$PORT"
    if [ -n "$DOMAIN" ]; then
        echo -e "  Domain:           http://$DOMAIN"
    fi
    echo ""
}

# Main script logic
case "$1" in
    "install")
        install_panel
        ;;
    "uninstall")
        uninstall_panel
        ;;
    "status")
        show_status
        ;;
    "backup")
        /usr/local/bin/backup-ott.sh
        ;;
    "monitor")
        /usr/local/bin/monitor-ott.sh
        ;;
    "update")
        /usr/local/bin/update-ott.sh
        ;;
    "help"|"")
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  install     - Install OTT Navigator Panel"
        echo "  uninstall   - Remove OTT Navigator Panel"
        echo "  status      - Show panel status"
        echo "  backup      - Create backup"
        echo "  monitor     - Check system health"
        echo "  update      - Update panel"
        echo "  help        - Show this help"
        echo ""
        echo "Example:"
        echo "  sudo ./ott-navigator-ubuntu.sh install"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use: $0 help"
        exit 1
        ;;
esac
