source env/bin/activate

python manage.py runserver 0.0.0.0:8000




sudo systemctl daemon-reload
sudo systemctl enable fortigate_to_clickhouse.service
sudo systemctl start fortigate_to_clickhouse.service
sudo systemctl status fortigate_to_clickhouse.service