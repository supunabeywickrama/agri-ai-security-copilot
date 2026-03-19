from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/sensor-data", methods=["POST"])
def receive_data():
    data = request.json
    print("Received Sensor Data:", data)

    return jsonify({
        "status": "received",
        "data": data
    })

if __name__ == "__main__":
    app.run(port=5000, debug=True)