# Cybersecurity Dashboard
![Dashboard UI](Screenshot%201.png)
The Cybersecurity Dashboard is a web-based application for real-time network traffic monitoring and analysis. It integrates with Snort for intrusion detection, uses a Res-CNN model with Reptile++ meta-learning for anomaly detection, and provides a user-friendly interface to visualize traffic, block/unblock IPs, and view packet details. Built with FastAPI, Scapy, and Tailwind CSS, it is designed for Windows environments.

## Features
- **Real-Time Traffic Monitoring**: Capture and analyze network packets using Scapy.
- **Anomaly Detection**: Leverage a Res-CNN model with Reptile++ meta-learning to identify suspicious network activity.
- **Snort Integration**: Manage Snort rules to block/unblock IPs dynamically.
- **Interactive Dashboard**: View live traffic logs, system status, and blocked IPs with a responsive UI.
- **IP Management**: Block or unblock IPs manually or based on anomaly detection.
- **Packet Details**: Inspect detailed packet information and model features in a modal view.
- **IP Filtering**: Filter traffic logs by specific IPs.
- **Clear Traffic**: Reset the traffic log display for a fresh view.

## Project Structure
```
cybersecurity_dashboard/
├── static/
│   └── index.html           # Dashboard UI
├── logs/
│   └── (log files)         # Application and traffic logs
├── log/
│   └── snort/             # Snort logs
├── app.py                 # FastAPI application and WebSocket handling
├── dashboard.py           # Folder initialization and dashboard setup
├── interfaces.py          # Network interface detection
├── packet_processing.py   # Packet capture and ML model processing
├── snort.py               # Snort management (start/stop, rules)
├── utils.py               # Logging and utility functions
├── main.py                # Application entry point
├── requirements.txt       # Python dependencies
└── rescnn_reptile_plus_plus_best_model.keras  # Res-CNN model file
```

## Res-CNN with Reptile++ Model
The application uses a **Residual Convolutional Neural Network (Res-CNN)** enhanced with the **Reptile++** meta-learning algorithm for anomaly detection in network traffic. This model is stored as `rescnn_reptile_plus_plus_best_model.keras` in the project root.

### Res-CNN Architecture
The Res-CNN is a convolutional neural network with residual connections, designed to capture complex patterns in network traffic data. Key characteristics:
- **Input**: 54 network features (e.g., destination port, protocol, packet sizes, flow durations) reshaped to `(1, 54, 1)` for 1D convolution.
- **Layers**: Multiple 1D convolutional layers with residual connections to prevent vanishing gradients and improve training stability.
- **Output**: A binary classification (Normal vs. Anomaly) with a confidence score, used to flag suspicious packets.
- **Advantages**: Effective for sequential data like network packets, robust to noise, and capable of learning hierarchical features.

### Reptile++ Meta-Learning
Reptile++ is an advanced meta-learning algorithm that enhances the model's ability to adapt to new network environments with limited data. It builds on the Reptile algorithm, optimizing for few-shot learning. Key aspects:
- **Purpose**: Enables the model to generalize across diverse network traffic patterns, adapting quickly to new domains (e.g., different networks or attack types).
- **Mechanism**: Iteratively updates model weights by performing gradient descent on tasks (subsets of data) and moving the initial weights toward the average of task-specific weights, with enhancements for stability and convergence.
- **Benefits**: Improves performance in scenarios with limited labeled data, making it ideal for detecting novel network anomalies.
- **Implementation**: The model is pre-trained using Reptile++ to optimize its initialization weights, stored in `rescnn_reptile_plus_plus_best_model.keras`.

### Model Placement
- Place the trained `rescnn_reptile_plus_plus_best_model.keras` file in the project root (`cybersecurity_dashboard/`).
- If the model is missing, the application creates a basic, untrained Res-CNN model (see `create_basic_model` in `packet_processing.py`). For accurate detection, use a trained model.
- To use a different path, update `MODEL_PATH` in `packet_processing.py`:
  ```python
  MODEL_PATH = "model/rescnn_reptile_plus_plus_best_model.keras"
  ```

### Training Notes
- The model expects 54 input features (listed in `REQUIRED_FEATURES` in `packet_processing.py`). Train on network traffic data with these features for best results.
- Update `FEATURE_MEANS` and `FEATURE_STDS` in `packet_processing.py` with your training data's statistics for proper feature standardization.
- Reptile++ requires task-based training (e.g., different network environments or attack scenarios). Ensure your training pipeline supports meta-learning.

## Prerequisites
- **Operating System**: Windows (due to Snort paths and interface detection logic).
- **Python**: Version 3.8 or higher.
- **Snort**: Installed at `C:/Snort` with configuration file (`snort.conf`) and rules directory.
- **Npcap**: For packet capturing with Scapy (WinPcap-compatible mode).
- **Administrative Privileges**: Required for packet capture and Snort operations.

## Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd cybersecurity_dashboard
```

### 2. Set Up a Virtual Environment
```bash
python -m venv venv
.\venv\Scripts\activate
```

### 3. Install Dependencies
Create a `requirements.txt` file with the following content:
```
fastapi==0.115.2
uvicorn==0.32.0
scapy==2.6.0
tensorflow==2.17.0
pandas==2.2.3
numpy==1.26.4
psutil==6.1.0
```
Install the dependencies:
```bash
pip install -r requirements.txt
```

### 4. Install Snort
- Download and install Snort from [snort.org](https://www.snort.org/downloads).
- Ensure Snort is installed at `C:/Snort` (or update paths in `snort.py` if different).
- Create `C:/Snort/rules/local.rules` if it doesn't exist:
  ```bash
  mkdir C:\Snort\rules
  echo # Snort local rules > C:\Snort\rules\local.rules
  ```
- Verify Snort installation:
  ```bash
  C:\Snort\bin\snort.exe -V
  ```

### 5. Install Npcap
- Download Npcap from [nmap.org/npcap](https://nmap.org/npcap/).
- Install in WinPcap-compatible mode.

### 6. Prepare the Res-CNN Model
- Place the trained `rescnn_reptile_plus_plus_best_model.keras` file in the project root.
- If no trained model is available, the application will create an untrained Res-CNN model. Train a model using Reptile++ on your network data for accurate anomaly detection.
- To use a different model path (e.g., `models/`), create the directory and update `MODEL_PATH` in `packet_processing.py`:
  ```bash
  mkdir models
  mv rescnn_reptile_plus_plus_best_model.keras models/
  ```
  ```python
  MODEL_PATH = "models/rescnn_reptile_plus_plus_best_model.keras"
  ```

## Running the Application

1. **Open a Command Prompt with Administrative Privileges**:
   - Right-click Command Prompt or PowerShell and select "Run as administrator".

2. **Navigate to the Project Directory**:
   ```bash
   cd path\to\cybersecurity_dashboard
   ```

3. **Activate the Virtual Environment** (if used):
   ```bash
   .\venv\Scripts\activate
   ```

4. **Run the Application**:
   ```bash
   python main.py
   ```
   The server will start at `http://localhost:8000`. You should see logs like:
   ```
   INFO:utils:Starting Cybersecurity Dashboard server...
   INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
   ```

5. **Access the Dashboard**:
   - Open a browser and navigate to `http://localhost:8000`.
   - Select a network interface, start analysis, and monitor traffic.

## Usage
- **Interface Selection**: Choose a network interface from the dropdown to start capturing packets.
- **Start/Stop Analysis**: Use the "Start Analysis" and "Stop Analysis" buttons to control packet capture.
- **IP Management**: Enter an IP address to block or unblock it. Blocked IPs are listed with unblock options.
- **Traffic Logs**: View real-time packet information, including source/destination IPs, protocol, ports, size, action, and Res-CNN prediction (Normal/Anomaly).
- **Packet Details**: Click a traffic log row to view detailed packet information and Res-CNN features.
- **Blocked IP Details**: Click a blocked IP to see its block trigger and analysis features.
- **IP Filtering**: Use the filter input to show only traffic for specific IPs.
- **Clear Traffic**: Reset the traffic log display.

## Logs
- Application logs: `logs/cybersecurity_dashboard.log` (rotated at 10MB, 5 backups).
- Traffic analysis logs: `logs/traffic_analysis.json`.
- Snort logs: `log/snort`.

## Troubleshooting
- **Dashboard not loading**:
  - Verify `static/index.html` exists.
  - Check browser console errors at `http://localhost:8000`.
- **No interfaces listed**:
  - Ensure Npcap is installed and running.
  - Run with administrative privileges.
  - Check `logs/cybersecurity_dashboard.log` for errors.
- **Snort not starting**:
  - Confirm Snort installation and paths in `snort.py`.
  - Test Snort manually: `C:\Snort\bin\snort.exe -i <interface> -c C:\Snort\etc\snort.conf -l log\snort`.
  - Check Snort logs in `log/snort`.
- **Model errors**:
  - Ensure `rescnn_reptile_plus_plus_best_model.keras` exists and is compatible with TensorFlow 2.17.0.
  - Verify feature preprocessing in `packet_processing.py` matches the model's expectations.
  - If predictions are unreliable, train the model with your data.
- **Packet capture issues**:
  - Ensure the selected interface is active and has traffic.
  - Add debug prints in `packet_processing.py` (`packet_callback`) to verify capture.

## Stopping the Application
- Press `Ctrl+C` in the terminal to stop the server.
- The application will stop packet capture and Snort automatically.

## Notes
- **Security**: Running with administrative privileges and capturing traffic can pose risks. Use in a controlled environment.
- **Model Training**: Train the Res-CNN model with Reptile++ for your network to ensure accurate anomaly detection.
- **Port Conflicts**: If port 8000 is in use, update `main.py`:
  ```python
  uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False, workers=1)
  ```
- **Customization**: Update Snort paths, model paths, or UI styles as needed.

## Contributing
Contributions are welcome! Please submit issues or pull requests to the repository.

## License
This project is licensed under the MIT License.
