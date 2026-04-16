from cryptography.fernet import Fernet
from sqlalchemy.orm import validates
from flask_sqlalchemy import SQLAlchemy
import os

# Initialize the database
db = SQLAlchemy()

# Generate or load encryption key
if not os.environ.get("FERNET_KEY"):
    os.environ["FERNET_KEY"] = Fernet.generate_key().decode()

key = os.environ.get("FERNET_KEY")
if not key:
    raise ValueError("FERNET_KEY is not set in environment variables")

cipher = Fernet(key.encode())

# Encryption and Decryption Helper Functions
def encrypt(data):
    return cipher.encrypt(data.encode('utf-8')).decode('utf-8')

def decrypt(data):
    return cipher.decrypt(data.encode('utf-8')).decode('utf-8')

# Signup Model
class Signup(db.Model):
    __tablename__ = "signups"
    id = db.Column(db.Integer, primary_key=True)
    gmail = db.Column(db.String(255), unique=True, nullable=False)
    otp = db.Column(db.String(255), nullable=False)  # Increased size of OTP column to 255 characters

    @validates('otp')
    def encrypt_otp(self, key, value):
        return encrypt(value)

    @property
    def otp_decrypted(self):
        return decrypt(self.otp)

# System Scan Model
class SystemScan(db.Model):
    __tablename__ = "system_scan"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    hostname = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(255), nullable=False)
    os = db.Column(db.String(255))
    os_version = db.Column(db.String(255))
    processor = db.Column(db.String(255))
    machine = db.Column(db.String(255))
    running_processes = db.Column(db.Integer)
    memory_usage = db.Column(db.String(255))
    cpu_usage = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, server_default=db.func.current_timestamp())

    @validates( 'ip_address', 'os', 'os_version',  'machine')
    def encrypt_fields(self, key, value):
        return encrypt(value)

    @property
    def decrypted_fields(self):
        return {
            # "hostname": decrypt(self.hostname),
            "ip_address": decrypt(self.ip_address),
            "os": decrypt(self.os),
            "os_version": decrypt(self.os_version),
            # "processor": decrypt(self.processor),
            "machine": decrypt(self.machine),
            # "memory_usage": decrypt(self.memory_usage),
            # "cpu_usage": decrypt(self.cpu_usage),
            # "timestamp": decrypt(self.timestamp),
        }

# Network Scan Model
class NetworkScan(db.Model):
    __tablename__ = "network_scan"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(255), nullable=False)
    open_ports = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, server_default=db.func.current_timestamp())

    @validates('ip_address', 'open_ports')
    def encrypt_fields(self, key, value):
        return encrypt(value)

    @property
    def decrypted_fields(self):
        return {
            "ip_address": decrypt(self.ip_address),
            "open_ports": decrypt(self.open_ports),
        }

# Web Scan Model
class WebScan(db.Model):
    __tablename__ = "web_scan"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    website = db.Column(db.String(255), nullable=False)
    title = db.Column(db.String(255))
    missing_headers = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, server_default=db.func.current_timestamp())

    @validates( 'missing_headers')
    def encrypt_fields(self, key, value):
        return encrypt(value)

    @property
    def decrypted_fields(self):
        return {
            "website": decrypt(self.website),
            "title": decrypt(self.title),
            "missing_headers": decrypt(self.missing_headers),
            # "timestamp": decrypt(self.timestamp),
        }

# Initialize Database
def init_db(app):
    db.init_app(app)
    with app.app_context():
        # db.drop_all()
        db.create_all()  
