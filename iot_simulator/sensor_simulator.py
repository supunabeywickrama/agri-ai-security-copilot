import requests
import time
import random

# URL for testing locally: http://localhost:5000/sensor-data
# URL for n8n: http://localhost:5678/webhook/sensor-input
URL = "http://localhost:5000/sensor-data"

def simulate_sensors():
    while True:
        try:
            data = {
                "device_id": "sensor_01",
                "soil_moisture": round(random.uniform(30.0, 70.0), 2),
                "temperature": round(random.uniform(20.0, 35.0), 2),
                "timestamp": time.time()
            }

            print(f"Sending Sensor Data: {data}")
            response = requests.post(URL, json=data)
            
            if response.status_code == 200:
                print(f"Successfully sent data: {response.json()}")
            else:
                print(f"Failed to send data: {response.status_code} - {response.text}")

        except Exception as e:
            print(f"Error: {e}")

        time.sleep(5)

if __name__ == "__main__":
    simulate_sensors()
