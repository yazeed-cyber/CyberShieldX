import uuid
import socket
import platform
import hashlib


def get_device_uid():
    raw = f"{socket.gethostname()}-{uuid.getnode()}-{platform.system()}-{platform.machine()}"
    return "DEV-" + hashlib.sha256(raw.encode()).hexdigest()[:16].upper()


def get_device_info():
    return {
        "device_uid": get_device_uid(),
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "machine": platform.machine(),
    }
