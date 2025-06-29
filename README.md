# RTT-Secure - Enterprise Grade Stealth Tunnel


ابزار پیشرفته و فوق امن تونل معکوس TLS که کاملاً توسط **RmnJL** طراحی، توسعه و بهینه‌سازی شده است. هیچ داده یا کد خارجی در این پروژه وجود ندارد و امنیت، سرعت و مصرف پایین منابع در اولویت است.

## 🛡️ ویژگی‌های امنیتی پیشرفته

- 🔒 **رمزنگاری AES-256-GCM** - بالاترین سطح امنیت
- 🚫 **Zero-Log Policy** - هیچ ردی از فعالیت کاربران
- 🎭 **Advanced Traffic Obfuscation** - مخفی‌سازی کامل ترافیک
- 🛡️ **Anti-DPI Technology** - محافظت در برابر تشخیص عمیق
- 🔐 **Perfect Forward Secrecy** - امنیت کلیدهای جلسه
- 📡 **Stealth Mode** - کاملاً نامرئی در مقابل فیلترینگ
- ⚡ **Ultra-Low Resource Usage** - مصرف بهینه CPU و RAM
- 🎯 **Anti-Fingerprinting** - جلوگیری از fingerprinting

## 📊 بهینه‌سازی‌های عملکردی

- ⚡ **High-Performance Multiplexing** - کارایی بالا
- 🔄 **Intelligent Load Balancing** - توزیع بار هوشمند  
- 🌐 **Multi-Protocol Support** - پشتیبانی TCP/UDP
- 📈 **Connection Pooling** - مدیریت بهینه اتصالات
- 🎯 **Adaptive Bandwidth** - تطبیق خودکار پهنای باند

---

📚 **مستندات کامل:**
- [🎬 آموزش های ویدویی](./docs/Tutorials.md)
- [🔧 راهنمای مالتی پورت](./docs/MultiPort.md)
- [⚙️ تنظیم سرویس سیستم](./docs/Service.md)
- [🌍 پیکربندی Load Balancer](./docs/Loadbalancer.md)
- [🔗 Connection Multiplexer](./docs/Mux.md)
- [📤 آپلود فیک](./docs/FUpload.md)
- [🌐 پشتیبانی IPv6](./docs/Ipv6.md)
- [📡 فوروارد UDP](./docs/Udp.md)

## 🔍 تکنولوژی RTT-Secure

**RTT-Secure** یک تونل معکوس پیشرفته است که بر اساس تکنولوژی‌های مدرن امنیتی ساخته شده است. برخلاف تونل‌های عادی که اتصال از سرور داخلی شروع می‌شود، در این روش سرور خارجی مانند یک بازدیدکننده عادی اتصال را آغاز می‌کند و پس از برقراری ارتباط امن، داده‌ها به صورت دوطرفه رد و بدل می‌شوند.

### 🎯 مزایای کلیدی:

- **🔒 امنیت بالا**: استفاده از رمزنگاری AES-256-GCM با کلیدهای تصادفی
- **👻 حالت شبح**: کاملاً نامرئی در برابر سیستم‌های فیلترینگ مدرن
- **⚡ کارایی بالا**: مصرف بهینه منابع سیستم با تکنولوژی multiplexing
- **🛡️ ضد تشخیص**: محافظت کامل در برابر DPI و traffic analysis
- **🔄 خودکار**: مدیریت خودکار کلیدها و اتصالات

### 🧬 معماری پیشرفته:

این پیاده‌سازی از تکنولوژی‌های زیر استفاده می‌کند:
- **Connection Multiplexing** برای کاهش تعداد اتصالات
- **Dynamic Key Exchange** برای امنیت بیشتر
- **Adaptive Traffic Shaping** برای مخفی‌سازی الگوهای ترافیک
- **Intelligent Retry Logic** برای پایداری اتصال

این طراحی باعث می‌شود حتی با IP های "کثیف" یا فیلتر شده نیز بتوان ارتباط برقرار کرد.

## 🚀 نصب و راه‌اندازی سریع

### روش اول - نصب خودکار (پیشنهادی)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/RmnJL/RTT-Secure/master/scripts/RttSecure.sh)
```

### روش دوم - نصب دستی

```bash
wget "https://raw.githubusercontent.com/RmnJL/RTT-Secure/master/scripts/install-secure.sh" -O install.sh && chmod +x install.sh && bash install.sh
```

## 🏠 سرور داخلی (ایران)

```bash
./RTT-Secure --iran --lport:443 --sni:aparat.com --password:"MyUltraSecureKey2024!" --stealth-mode
```

### 🔧 پارامترهای پیشرفته

| پارامتر | توضیح | نمونه |
|---------|-------|--------|
| `--lport` | پورت گوش دادن | `443` (TLS) یا `80` (HTTP) |
| `--sni` | دامنه امن برای handshake | `aparat.com`, `digikala.com` |
| `--password` | رمز عبور قوی (12+ کاراکتر) | `SecureP@ss2024!` |
| `--stealth-mode` | فعال‌سازی حالت مخفی | - |
| `--anti-detection` | ضد تشخیص پیشرفته | `--level:5` |

## 🌍 سرور خارجی (خارج)

```bash
./RTT-Secure --kharej --iran-ip:YOUR_IRAN_IP --iran-port:443 --toip:127.0.0.1 --toport:2083 --password:"MyUltraSecureKey2024!" --sni:aparat.com --stealth-mode
```

### 🔧 پارامترهای خارجی

| پارامتر | توضیح | نمونه |
|---------|-------|--------|
| `--iran-ip` | آدرس IP سرور داخلی | `1.2.3.4` |
| `--iran-port` | پورت سرور داخلی | `443` |
| `--toip` | آدرس هدف | `127.0.0.1` |
| `--toport` | پورت سرویس محلی | `2083`, `multiport` |

## 🛡️ تنظیمات امنیتی پیشرفته

### 🔐 حداکثر امنیت

```bash
# فعال‌سازی کامل حالت امن
./RTT-Secure --iran --lport:443 --sni:aparat.com \
  --password:"UltraSecure2024#@!" \
  --encrypt-level:maximum \
  --stealth-mode \
  --anti-fingerprint \
  --zero-logs \
  --perfect-forward-secrecy

# تنظیمات مخفی‌سازی ترافیک
--traffic-obfuscation:aggressive \
--connection-age:180 \
--trust-time:3 \
--noise-ratio:25
```

### ⚡ بهینه‌سازی عملکرد

```bash
# بهینه‌سازی برای کارایی بالا
--high-performance \
--connection-pool:50 \
--multiplexing:enabled \
--adaptive-bandwidth \
--low-latency-mode

# تنظیمات پیشرفته
--parallel-connections:16 \
--buffer-size:8192 \
--compression:enabled
```

## 🚀 امکانات پیشرفته

### ✅ ویژگی‌های کلیدی

| ویژگی | وضعیت | توضیح |
|--------|--------|--------|
| **Multi-Port Support** | ✅ | پشتیبانی همزمان چندین پورت |
| **Smart Load Balancing** | ✅ | توزیع بار هوشمند و خودکار |
| **UDP Forwarding** | ✅ | پروکسی کامل UDP |
| **Connection Multiplexing** | ✅ | بهینه‌سازی اتصالات |
| **Anti-Detection Shield** | ✅ | محافظت کامل از تشخیص |
| **Zero-Log Architecture** | ✅ | هیچ ردی از فعالیت کاربران |
| **Perfect Forward Secrecy** | ✅ | امنیت کلیدهای جلسه |
| **Traffic Obfuscation** | ✅ | مخفی‌سازی کامل ترافیک |

### 🌐 پشتیبانی پروتکل‌ها

- **TCP/UDP** - پشتیبانی کامل
- **HTTP/HTTPS** - پروکسی وب
- **WebSocket** - اتصالات real-time
- **SOCKS5** - پروکسی سریع

## 🎯 مثال‌های کاربردی

### 🔄 تنظیم Multi-Port

```bash
# سرور داخلی - پورت‌های متعدد
./RTT-Secure --iran --lport:443-8443 --sni:aparat.com \
  --password:"MultiPortSecure2024!" \
  --multi-port-mode

# سرور خارجی - Multi-Port
./RTT-Secure --kharej --iran-ip:1.2.3.4 --iran-port:443 \
  --toip:127.0.0.1 --toport:multiport \
  --password:"MultiPortSecure2024!" --sni:aparat.com
```

### 📡 پشتیبانی UDP

```bash
# فعال‌سازی UDP Forwarding
./RTT-Secure --iran --lport:443 --sni:digikala.com \
  --password:"UDPSecure2024!" \
  --accept-udp --udp-optimization
```

### 🔄 Load Balancing

```bash
# تنظیم Load Balancer
./RTT-Secure --iran --lport:443 --sni:cafebazaar.ir \
  --password:"LoadBalanceSecure!" \
  --load-balance-mode \
  --servers:3 --auto-failover
```

## ⚙️ راه‌اندازی سرویس سیستم

### 🔧 ایجاد سرویس خودکار

```bash
# ایجاد فایل سرویس
sudo nano /etc/systemd/system/rtt-secure.service
```

```ini
[Unit]
Description=RTT-Secure Advanced Stealth Tunnel by RmnJL
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/rtt-secure
ExecStart=/opt/rtt-secure/RTT-Secure --iran --lport:443 --sni:aparat.com --password:"YourUltraSecurePassword2024!" --stealth-mode --zero-logs
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=3
KillMode=mixed
TimeoutStopSec=5

# امنیت بیشتر
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/rtt-secure

[Install]
WantedBy=multi-user.target
```

### 🚀 فعال‌سازی و اجرا

```bash
# بارگذاری مجدد تنظیمات
sudo systemctl daemon-reload

# فعال‌سازی خودکار در بوت
sudo systemctl enable rtt-secure

# شروع سرویس
sudo systemctl start rtt-secure

# بررسی وضعیت
sudo systemctl status rtt-secure
```

## 🔒 تنظیمات امنیتی حیاتی

### 1️⃣ انتخاب SNI بهینه

```bash
# تست اعتبار SNI
curl -I https://aparat.com --max-time 5
curl -I https://digikala.com --max-time 5
curl -I https://cafebazaar.ir --max-time 5

# SNI های پیشنهادی (تست شده)
- aparat.com ✅
- digikala.com ✅  
- cafebazaar.ir ✅
- snapp.ir ✅
- tgju.org ✅
```

### 2️⃣ تولید رمز عبور فوق امن

```bash
# تولید رمز 32 کاراکتری
openssl rand -base64 32

# نمونه رمز قوی
SecureP@ssw0rd2024!#$%^&*()_+
```

### 3️⃣ پیکربندی فایروال

```bash
# تنظیم UFW
sudo ufw reset
sudo ufw default deny incoming
sudo ufw default allow outgoing

# اجازه پورت‌های ضروری
sudo ufw allow 443/tcp comment 'RTT-Secure'
sudo ufw allow 22/tcp comment 'SSH'

# فعال‌سازی
sudo ufw --force enable

# نمایش وضعیت
sudo ufw status numbered
```

### 4️⃣ تنظیمات سیستم بهینه

```bash
# بهینه‌سازی شبکه
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_window_scaling = 1' >> /etc/sysctl.conf

# اعمال تغییرات
sysctl -p
```

## 🔧 نظارت و عیب‌یابی

### 📊 مانیتورینگ سیستم

```bash
# بررسی وضعیت سرویس
sudo systemctl status rtt-secure

# مشاهده لاگ‌های زنده
sudo journalctl -u rtt-secure -f --no-pager

# بررسی عملکرد
sudo netstat -tulnp | grep RTT-Secure
sudo ss -tulnp | grep 443

# مانیتور مصرف منابع
htop -p $(pgrep RTT-Secure)
```

### 🐛 حل مشکلات رایج

#### ❌ خطای Resource temporarily unavailable
```bash
# تغییر DNS به سرور‌های سریع
echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" > /etc/resolv.conf

# یا استفاده از Cloudflare
echo -e "nameserver 1.1.1.1\nnameserver 1.0.0.1" > /etc/resolv.conf
```

#### ❌ خطای Permission denied
```bash
# اجرا با دسترسی کامل
sudo -i
cd /opt/rtt-secure
./RTT-Secure --keep-os-limit --debug-mode

# یا تغییر مالکیت فایل‌ها
sudo chown -R root:root /opt/rtt-secure
sudo chmod +x /opt/rtt-secure/RTT-Secure
```

#### ❌ خطای Connection failed
```bash
# بررسی اتصال شبکه
ping -c 4 8.8.8.8

# تست اتصال به SNI
curl -I https://aparat.com --connect-timeout 5

# بررسی پورت‌ها
sudo netstat -tlnp | grep :443
sudo lsof -i :443
```

#### ❌ خطای TLS Handshake Failed
```bash
# تست مستقیم TLS
openssl s_client -connect aparat.com:443 -servername aparat.com

# بررسی تاریخ سیستم
timedatectl status
sudo ntpdate -s time.nist.gov
```

### 🔍 ابزارهای تشخیص

```bash
# اسکریپت تست کامل
cat > /tmp/rtt-test.sh << 'EOF'
#!/bin/bash
echo "=== RTT-Secure Diagnostic Tool ==="
echo "1. System Info:"
uname -a
echo -e "\n2. Network Status:"
ip route get 8.8.8.8
echo -e "\n3. DNS Resolution:"
nslookup aparat.com
echo -e "\n4. Port Status:"
ss -tulnp | grep 443
echo -e "\n5. Service Status:"
systemctl is-active rtt-secure
echo -e "\n6. Memory Usage:"
free -h
echo "=== End Diagnostic ==="
EOF

chmod +x /tmp/rtt-test.sh && /tmp/rtt-test.sh
```

## 🛡️ امنیت پیشرفته

### 🔐 تقویت امنیت سیستم

```bash
# غیرفعال‌سازی سرویس‌های غیرضروری
sudo systemctl disable apache2 nginx
sudo systemctl stop apache2 nginx

# تنظیم SSH امن
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# فعال‌سازی fail2ban
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
```



### 🕵️ مخفی‌سازی سرویس و بهینه‌سازی مصرف منابع

برای بیشترین امنیت و کمترین مصرف منابع:

- همیشه از `--stealth-mode` و `--anti-detection` استفاده کنید تا سرویس در پس‌زمینه و بدون ردپا اجرا شود.
- باینری را به نامی بی‌معنی و مسیر مخفی منتقل کنید (مثلاً `/opt/.sysd/updaterd`).
- پارامتر `--zero-logs` را فعال کنید تا هیچ لاگی تولید نشود و مصرف دیسک و RAM به حداقل برسد.
- از `--high-performance` و `--low-latency-mode` برای بهینه‌سازی مصرف CPU و RAM استفاده کنید.
- مقداردهی صحیح به `--connection-pool` و `--buffer-size` (مثلاً 16 یا 32) باعث کاهش مصرف منابع و افزایش سرعت می‌شود.
- اگر نیاز به مصرف بسیار پایین دارید، مقدار `--multiplexing:enabled` و `--adaptive-bandwidth` را فعال کنید تا اتصالات و پهنای باند بهینه شوند.
- همیشه سرویس را با کاربر محدود (غیر root) اجرا کنید و فقط دسترسی لازم را بدهید.
- با ابزارهایی مانند `htop`, `ps`, `lsof` و `ss` مصرف منابع را مانیتور کنید و در صورت نیاز پارامترها را کاهش دهید.


نمونه اجرای فوق بهینه:
```bash
sudo mv /opt/rtt-secure/RTT-Secure /opt/.sysd/updaterd
sudo ln -sf /opt/.sysd/updaterd /usr/local/bin/updaterd
/usr/local/bin/updaterd --iran --stealth-mode --anti-detection --zero-logs --high-performance --low-latency-mode --connection-pool:16 --buffer-size:4096 --multiplexing:enabled --adaptive-bandwidth

# حمایت از توسعه‌دهنده (Tron TRX Wallet):
echo "Support RmnJL: Tron Wallet TU4WSdCA51Kh1T67ryAUuP2uoYt7HevzkG"
```

> **نکته امنیتی و بهینه‌سازی:**
> همیشه پارامترها را متناسب با منابع سرور تنظیم کنید. برای سرورهای کم‌قدرت، connection-pool و buffer-size را پایین نگه دارید و لاگ را غیرفعال کنید.

## 📞 پشتیبانی فنی

### 🆘 دریافت کمک

برای دریافت پشتیبانی فنی:


1. **GitHub Issues**: گزارش مشکلات فنی (در صورت نیاز)
2. **Security Issues**: گزارش مشکلات امنیتی فقط به صورت رمزنگاری‌شده به تیم RmnJL

### 📧 تماس با توسعه‌دهنده



**RmnJL** - طراح، توسعه‌دهنده و تنها مالک رسمی این پروژه
هیچ شخص یا تیم دیگری در توسعه یا پشتیبانی این پروژه دخیل نبوده است.

---

## ⚠️ اخطارات قانونی

> **هشدار مهم**: این ابزار صرفاً برای اهداف آموزشی و تست امنیت شبکه طراحی شده است. استفاده از این نرم‌افزار باید مطابق با قوانین محلی کشور شما باشد. توسعه‌دهنده هیچ مسئولیتی در قبال سوء‌استفاده، نقض قوانین، یا هرگونه ضرر ناشی از استفاده نادرست این ابزار ندارد.

## 📜 مجوز


© 2025 RmnJL. تمامی حقوق محفوظ است. هرگونه کپی‌برداری یا استفاده بدون اجازه ممنوع است.

این پروژه تحت مجوز MIT منتشر شده است - جزئیات در فایل [LICENSE](LICENSE) موجود است.

---

<div align="center">

**⭐ اگر از این پروژه استفاده کردید و مایل به حمایت مالی هستید، لطفاً به آدرس ولت ترون زیر کمک کنید:**

<b>TRON Wallet (TRC20):</b>
<br>
<code>TU4WSdCA51Kh1T67ryAUuP2uoYt7HevzkG</code>

**⭐ اگر از این پروژه استفاده کردید، لطفاً ستاره بدهید! ⭐**

</div>

