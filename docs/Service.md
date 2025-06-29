

# راه‌اندازی سرویس فوق امن RmnJL (RTT-Secure)

در این راهنما نحوه اجرای برنامه به صورت سرویس امن، با قابلیت ری‌استارت خودکار و لاگ‌گیری مخفی توضیح داده می‌شود. این روش توسط RmnJL توسعه یافته و هیچ داده‌ای از توسعه‌دهندگان قبلی یا منابع خارجی ندارد.

اول اینکه دستور سرور داخل و خارج اتون رو اجرا کنید و تست کنید تا مطمعن شین دستور ها درست هستن و کار میکنه بعد باید سرویس رو ایجاد کنیم

مرحله اول اینکه وارد این مسیر بشین
```sh
cd /etc/systemd/system
```
بعد باید سرویس رو ایجاد کنیم ؛ من اسم سرویس ام رو به اختیار میزارم tunnel
```sh
nano tunnel.service
```
خوب حالا این محتویات رو قرار میدیم 
```sh

[Unit]
Description=RTT-Secure Stealth Tunnel by RmnJL



[Service]
Type=simple
User=root
WorkingDirectory=/opt/rtt-secure
ExecStart=/opt/rtt-secure/RTT-Secure <your arguments> --terminate:24 --stealth-mode --zero-logs
Restart=always

[Install]
WantedBy=multi-user.target
```


نمونه فایل سرویس پیشنهادی:
```ini
[Unit]
Description=RTT-Secure Stealth Tunnel by RmnJL

[Service]
Type=simple
User=root
WorkingDirectory=/opt/rtt-secure
ExecStart=/opt/rtt-secure/RTT-Secure --kharej --iran-ip:1.2.3.4 --iran-port:443 --toip:127.0.0.1 --toport:443 --password:UltraSecureKey2025! --sni:domain.com --terminate:24 --stealth-mode --zero-logs
Restart=always

[Install]
WantedBy=multi-user.target
```



خوب حالا دقت کنین که برنامه رو توی پوشه /root نصب کرده باشین فکر نکنم این نیاز به توضیح داشته باشه ؛ وارد پوشه روت بشین و یه بار دستور برنامه رو اجرا کنین تا فایل RTT اونجا باشه

دوم اینکه توی این فایلی که الان نوشتیم بخش ExecStart  باید جای \<your argemunts\>  پارامتر های برنامه رو بنویسید اما بعدش ما یک اپشن اضافه به اسم --terminate اضافه کردیم

این اپشن یه عدد میگیره و به ساعت هست که یعنی تو این مثال بعد از ۲۴ ساعت برنامه کامل بسته میشه

ولی چون ما سرویس ایجاد کردیم ؛ برنامه به محض اینکه بسته بشه به هر دلیلی ؛ دوباره توسط سیستم مجددا اجرا میشه
و اینطوری کاربر کمترین آسیپ رو میبینه اما خوب بازم خیلی بهتر هست که این ری استارت در زمانی انجام بشه مثلا ۴ تا ۸ صبح چون هربار 
ری استارت کانکشن ها قبلی رو لحظه ای قطع میکنه و اگه کاربر توی اون زمان مشفول دیدن ریلز اینستا یا یه سری برنامه های دیگه که به بسته نشدن کانکشن حساس هستن باشه ... ناراحت میشه :)
دیگه خودتون این زمان رو تنظیم کنین


خوب الان این دستورات رو به ترتیب اجرا میکنیم تا سرویس امون تکمیل بشه و در هنگام بوت شدن سیستم هم اجرا بشه

اول چک کنین برنامه در حال اجرا نباشه اگه اجرا بوده باید ببندینش با دستور 
> pkill RTT

بعد این مراحل رو اجرا کنید


> sudo systemctl daemon-reload

> sudo systemctl start tunnel.service

> sudo systemctl enable tunnel.service


اگه بعدا خواستین تونل رو استوپ کنین این دستور
> service tunnel stop

و یا

> sudo systemctl stop tunnel.service



***

هروقت خواستید لاگ تونل رو ببینید از این دستور استفاده کنید:

> journalctl -u tunnel.service -e -f


برای امنیت بیشتر، لاگ‌گیری را روی صفر یا یک قرار دهید و از --zero-logs استفاده کنید.

---

تمام حقوق متعلق به RmnJL. هرگونه کپی‌برداری یا استفاده بدون اجازه ممنوع است.



