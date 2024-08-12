from pymongo import MongoClient

MONGO_DB_URI = 'mongodb+srv://histennn:PM1gR78yI4Y5WYrU@cluster0.mrtj4.mongodb.net/'
client = MongoClient(MONGO_DB_URI)
db = client['aidjango']

try:
    # Попробуйте выполнить простое действие, чтобы проверить подключение
    db.command("ping")
    print("Подключение успешно!")
except Exception as e:
    print(f"Ошибка подключения: {e}")
