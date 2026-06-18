ssh admin@10.0.0.15
scp report_q4.xlsx backup@192.168.1.50:/backups/
mysql -h 10.0.0.15 -u corpnet_app -p
cat /etc/secrets.txt
ls -la /var/www/html
sudo systemctl status nginx
tail -f /var/log/nginx/access.log
python3 backup_script.py
git pull origin main
