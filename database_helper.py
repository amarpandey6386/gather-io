import mysql.connector
import os
from dotenv import load_dotenv

# .env file se data load karne ke liye
load_dotenv()

def get_db_connection():
    connection = mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        port=os.getenv('DB_PORT'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME')
    )
    return connection