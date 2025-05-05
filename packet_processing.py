import time
import json
import threading
import numpy as np
import pandas as pd
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, conf, IPv6
import tensorflow as tf
from utils import logger

# Global variables
RUNNING = False
INTERFACE = None
PACKETS_QUEUE = []
QUEUE_LOCK = threading.Lock()
BLOCKED_IPS = set()
MODEL_PATH = "rescnn_reptile_plus_plus_best_model.keras"
CAPTURE_THREAD = None
PROCESSING_THREAD = None
MODEL = None
BLOCKED_IPS_FILE = "logs/blocked_ips.json"

# Feature names required by the model
REQUIRED_FEATURES = [
    'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 
    'TotLen Fwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 
    'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 
    'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean', 'Flow IAT Std', 
    'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 
    'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 
    'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 
    'Bwd URG Flags', 'Fwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s', 'Pkt Len Min', 
    'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt', 
    'RST Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 
    'Down/Up Ratio', 'Fwd Seg Size Min', 'Active Mean', 'Idle Mean', 'Active Std', 'Active Max'
]

# Store feature means and standard deviations for standardization
FEATURE_MEANS = {feature: 0.0 for feature in REQUIRED_FEATURES}
FEATURE_STDS = {feature: 1.0 for feature in REQUIRED_FEATURES}

# Flow tracking dictionary for feature calculation
flow_tracker = {}

class FlowKey:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))
    
    def __eq__(self, other):
        if not isinstance(other, FlowKey):
            return False
        return (self.src_ip == other.src_ip and 
                self.dst_ip == other.dst_ip and 
                self.src_port == other.src_port and 
                self.dst_port == other.dst_port and 
                self.protocol == other.protocol)
    
    def get_reverse(self):
        return FlowKey(
            self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol
        )

class FlowStats:
    def __init__(self):
        self.start_time = time.time()
        self.last_time = self.start_time
        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.fwd_pkt_lens = []
        self.bwd_pkt_lens = []
        self.fwd_iat = []
        self.bwd_iat = []
        self.fwd_pkt_times = []
        self.bwd_pkt_times = []
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0
        self.fwd_header_len = 0
        self.fin_flags = 0
        self.syn_flags = 0
        self.rst_flags = 0
        self.ack_flags = 0
        self.urg_flags = 0
        self.cwe_flags = 0
        self.ece_flags = 0
        self.active_times = []
        self.idle_times = []
        self.last_active_time = self.start_time
        self.active = False
        self.fwd_seg_size_min = float('inf')

def extract_packet_features(packet):
    """Extract features from a packet"""
    try:
        if IP not in packet:
            logger.debug("Packet does not contain IP layer")
            return None, None
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # Extract basic features
        features = {}
        try:
            # Protocol features
            features['Protocol'] = float(protocol)
            
            # Port features
            if TCP in packet:
                features['Dst Port'] = float(packet[TCP].dport)
                features['src_port'] = float(packet[TCP].sport)
                
                # Check for TCP flags
                features['FIN Flag Cnt'] = float(1 if packet[TCP].flags & 0x01 else 0)
                features['SYN Flag Cnt'] = float(1 if packet[TCP].flags & 0x02 else 0)
                features['RST Flag Cnt'] = float(1 if packet[TCP].flags & 0x04 else 0)
                features['PSH Flag Cnt'] = float(1 if packet[TCP].flags & 0x08 else 0)
                features['ACK Flag Cnt'] = float(1 if packet[TCP].flags & 0x10 else 0)
                features['URG Flag Cnt'] = float(1 if packet[TCP].flags & 0x20 else 0)
                
            elif UDP in packet:
                features['Dst Port'] = float(packet[UDP].dport)
                features['src_port'] = float(packet[UDP].sport)
            else:
                features['Dst Port'] = 0.0
                features['src_port'] = 0.0
            
            # Packet size features
            packet_size = len(packet)
            features['TotLen Fwd Pkts'] = float(packet_size)
            features['Pkt Len Min'] = float(packet_size)
            features['Pkt Len Max'] = float(packet_size)
            features['Pkt Len Mean'] = float(packet_size)
            
            # Flow features
            features['Flow Duration'] = 0.0  # Will be updated by flow tracking
            features['Flow Pkts/s'] = 1.0
            features['Flow Byts/s'] = float(packet_size)
            
            logger.debug(f"Extracted features for {src_ip}: {features}")
            return src_ip, features
            
        except Exception as e:
            logger.error(f"Error extracting packet features: {e}")
            return src_ip, None
            
    except Exception as e:
        logger.error(f"Error in extract_packet_features: {e}")
        return None, None

def cleanup_flows():
    current_time = time.time()
    keys_to_remove = []
    
    for key, flow in flow_tracker.items():
        if current_time - flow.last_time > 300:
            keys_to_remove.append(key)
    
    for key in keys_to_remove:
        del flow_tracker[key]

def preprocess_features(features):
    df = pd.DataFrame([features])
    
    for feature in REQUIRED_FEATURES:
        if feature not in df.columns:
            df[feature] = 0
    
    for feature in REQUIRED_FEATURES:
        df[feature] = (df[feature] - FEATURE_MEANS[feature]) / FEATURE_STDS[feature]
    
    df = df[REQUIRED_FEATURES]
    X = df.values.reshape((1, 54, 1))
    return X

def load_model():
    """Load the TensorFlow model with proper error handling"""
    try:
        model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), MODEL_PATH)
        logger.info(f"Attempting to load model from: {model_path}")
        
        if not os.path.exists(model_path):
            logger.error(f"Model file not found at: {model_path}")
            # Create a simple model for testing
            logger.info("Creating a basic model for testing purposes")
            model = create_basic_model()
            # Save the model for future use
            model.save(model_path)
            logger.info(f"Basic model saved to: {model_path}")
            return model
            
        model = tf.keras.models.load_model(model_path)
        logger.info("Model loaded successfully")
        return model
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        logger.info("Creating a basic model as fallback")
        try:
            model = create_basic_model()
            model.save(model_path)
            logger.info(f"Basic model saved to: {model_path}")
            return model
        except Exception as e:
            logger.error(f"Error creating basic model: {e}")
            return None

def create_basic_model():
    """Create a basic model for testing purposes"""
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(54, 1)),
        tf.keras.layers.Conv1D(32, 3, activation='relu'),
        tf.keras.layers.Flatten(),
        tf.keras.layers.Dense(64, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])
    
    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    
    logger.info("Created basic model architecture")
    return model

def predict_traffic(model, preprocessed_data):
    try:
        predictions = model.predict(preprocessed_data)
        raw_prediction = float(predictions[0][0])
        confidence = abs(0.5 - raw_prediction) * 2  # Convert to 0-1 confidence scale
        confidence = max(0.0, min(1.0, float(confidence)))  # Ensure value is between 0 and 1
        prediction = 1 if raw_prediction >= 0.5 else 0
        logger.debug(f"Model prediction: {prediction}, raw value: {raw_prediction}, confidence: {confidence}")
        return prediction, confidence
    except Exception as e:
        logger.error(f"Error during prediction: {e}")
        return 1, 0.0

def packet_callback(packet):
    """Callback function for packet capture"""
    global RUNNING, PACKETS_QUEUE
    
    if not RUNNING:
        return
    
    try:
        current_time = time.time()
        logger.debug(f"[{datetime.fromtimestamp(current_time).strftime('%H:%M:%S.%f')}] Processing new packet")
        
        # Check for IP or IPv6 packet
        ip_layer = None
        if IP in packet:
            ip_layer = packet[IP]
        elif IPv6 in packet:
            ip_layer = packet[IPv6]
        
        if not ip_layer:
            logger.debug("Packet does not contain IP/IPv6 layer")
            return
        
        # Extract basic packet info
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.nh if IPv6 in packet else ip_layer.proto
        
        # Get port information if available
        src_port = dst_port = 0
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            proto_name = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            proto_name = "UDP"
        else:
            proto_name = "Other"
        
        # Create packet info dictionary with current timestamp
        packet_info = {
            "timestamp": current_time,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": proto_name,
            "src_port": src_port,
            "dst_port": dst_port,
            "size": len(packet),
            "summary": packet.summary()
        }
        
        # Extract features for ML model
        src_ip, features = extract_packet_features(packet)
        
        if src_ip in BLOCKED_IPS:
            logger.debug(f"Skipping already blocked IP: {src_ip}")
            packet_info["action"] = "blocked"
        else:
            packet_info["action"] = "allowed"
            
        # Add features to packet info if available
        if features:
            packet_info["features"] = {
                name: float(value) for name, value in features.items()
            }
            
        with QUEUE_LOCK:
            if RUNNING:  # Double check we're still running
                PACKETS_QUEUE.append((src_ip, features, packet_info))
                queue_size = len(PACKETS_QUEUE)
                logger.debug(f"Added packet to queue. Queue size: {queue_size}")
                
                # Limit queue size to prevent memory issues
                if queue_size > 1000:
                    PACKETS_QUEUE = PACKETS_QUEUE[-1000:]
                    logger.debug("Queue size limited to last 1000 packets")
            
    except Exception as e:
        logger.error(f"Error in packet callback: {e}")

def start_capture(interface):
    """Start packet capture on specified interface"""
    global RUNNING
    try:
        logger.info(f"Starting packet capture on interface {interface}")
        # Set promiscuous mode
        conf.iface = interface
        conf.sniff_promisc = True
        
        # Only start sniffing if RUNNING is True
        while