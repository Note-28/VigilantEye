import os
import json
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from interfaces import get_windows_interfaces
from packet_processing import (
    INTERFACE, RUNNING, CAPTURE_THREAD, PROCESSING_THREAD, MODEL,
    stop_analysis, start_snort, stop_snort, update_snort_rules, BLOCKED_IPS,
    INTERFACE_MAP, get_system_status
)
from utils import logger

# Set TensorFlow environment variables
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

app = FastAPI()

# Mount static files directory
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    with open("static/index.html", "r") as file:
        return file.read()

@app.get("/interfaces")
async def get_interfaces():
    """Get list of network interfaces"""
    try:
        interfaces = get_windows_interfaces()
        if not interfaces:
            logger.warning("No interfaces found!")
            return {"interfaces": [], "error": "No network interfaces found"}
        logger.info(f"Returning {len(interfaces)} interfaces")
        return {"interfaces": interfaces}
    except Exception as e:
        logger.error(f"Error getting interfaces: {e}")
        return {"interfaces": [], "error": str(e)}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    
    try:
        last_update_time = 0
        last_status_time = 0
        last_log_check = 0
        while True:
            try:
                # Use a shorter timeout for receive to allow for more frequent status checks
                data = await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
                command = json.loads(data)
                current_time = time.time()
                
                if command["action"] == "get_status":
                    status = get_system_status()
                    await websocket.send_json({
                        "update": "status",
                        "system_status": status
                    })
                    continue
                
                if command["action"] == "start_analysis":
                    friendly_name = command["interface"]
                    
                    if friendly_name not in INTERFACE_MAP:
                        await websocket.send_json({
                            "status": f"Invalid interface: {friendly_name}",
                            "error": True
                        })
                        continue
                    
                    # Stop any existing analysis
                    stop_analysis()
                    
                    global INTERFACE, RUNNING, CAPTURE_THREAD, PROCESSING_THREAD, MODEL
                    INTERFACE = INTERFACE_MAP[friendly_name]
                    logger.info(f"Starting capture on interface: {INTERFACE}")
                    
                    # Start Snort (but continue even if it fails)
                    start_snort(INTERFACE)
                    
                    # Load the model if not already loaded
                    if MODEL is None:
                        MODEL = load_model()
                        if not MODEL:
                            await websocket.send_json({
                                "status": "Failed to load model. Please check logs for details.",
                                "error": True
                            })
                            continue
                    
                    # Start packet capture and processing
                    RUNNING = True
                    CAPTURE_THREAD = threading.Thread(target=lambda: start_capture(INTERFACE), daemon=True)
                    CAPTURE_THREAD.start()
                    
                    PROCESSING_THREAD = threading.Thread(target=lambda: process_packets(MODEL), daemon=True)
                    PROCESSING_THREAD.start()
                    
                    logger.info("Started packet capture and processing threads")
                    status = get_system_status()
                    await websocket.send_json({
                        "status": "Analysis started",
                        "interface": friendly_name,
                        "message": "Capturing traffic... You should see packets shortly.",
                        "update": "status",
                        "system_status": status
                    })
                    
                    # Reset update times when starting analysis
                    last_update_time = 0
                    last_status_time = 0
                
                elif command["action"] == "stop_analysis":
                    stop_analysis()
                    stop_snort()
                    status = get_system_status()
                    await websocket.send_json({
                        "status": "Analysis stopped",
                        "update": "status",
                        "system_status": status
                    })
                
                elif command["action"] == "block_ip":
                    ip = command["ip"]
                    if ip not in BLOCKED_IPS:
                        if update_snort_rules(ip, block=True):
                            BLOCKED_IPS.add(ip)
                            reload_snort_rules()
                            logger.info(f"Blocked IP: {ip}")
                            status = get_system_status()
                            await websocket.send_json({
                                "status": f"IP {ip} blocked",
                                "ip": ip,
                                "blocked_ips": list(BLOCKED_IPS),
                                "update": "status",
                                "system_status": status
                            })
                        else:
                            await websocket.send_json({
                                "status": f"Failed to block IP {ip}",
                                "ip": ip,
                                "error": True
                            })
                    else:
                        await websocket.send_json({
                            "status": f"IP {ip} already blocked",
                            "ip": ip
                        })
                
                elif command["action"] == "unblock_ip":
                    ip = command["ip"]
                    if ip in BLOCKED_IPS:
                        if update_snort_rules(ip, block=False):
                            BLOCKED_IPS.remove(ip)
                            reload_snort_rules()
                            logger.info(f"Unblocked IP: {ip}")
                            status = get_system_status()
                            await websocket.send_json({
                                "status": f"IP {ip} unblocked",
                                "ip": ip,
                                "blocked_ips": list(BLOCKED_IPS),
                                "update": "status",
                                "system_status": status
                            })
                        else:
                            await websocket.send_json({
                                "status": f"Failed to unblock IP {ip}",
                                "ip": ip,
                                "error": True
                            })
                    else:
                        await websocket.send_json({
                            "status": f"IP {ip} not in block list",
                            "ip": ip
                        })
                
            except asyncio.TimeoutError:
                # No new messages, check for updates
                current_time = time.time()
                
                # Send status updates if needed
                if current_time - last_status_time >= 2.0:  # Status updates every 2 seconds
                    try:
                        status = get_system_status()
                        await websocket.send_json({
                            "update": "status",
                            "system_status": status
                        })
                        last_status_time = current_time
                    except WebSocketDisconnect:
                        logger.info("WebSocket disconnected during status update")
                        break
                    except Exception as e:
                        logger.error(f"Error sending status update: {e}")
                        continue
                
                # Check for new logs if analysis is running
                if RUNNING and (current_time - last_log_check >= 0.1):  # Check logs every 100ms
                    try:
                        recent_logs = []
                        if os.path.exists("logs/traffic_analysis.json"):
                            with open("logs/traffic_analysis.json", "r") as log_file:
                                log_file.seek(0, 2)
                                file_size = log_file.tell()
                                seek_pos = max(0, file_size - 8192)
                                log_file.seek(seek_pos)
                                
                                lines = log_file.readlines()
                                if seek_pos > 0:
                                    lines = lines[1:]
                                
                                for line in lines[-100:]:
                                    try:
                                        log_entry = json.loads(line)
                                        if log_entry["timestamp"] > last_update_time:
                                            log_entry["time"] = datetime.fromtimestamp(
                                                log_entry["timestamp"]
                                            ).strftime("%H:%M:%S.%f")[:-3]
                                            recent_logs.append(log_entry)
                                    except json.JSONDecodeError:
                                        continue
                        
                        if recent_logs:
                            last_update_time = current_time
                            await websocket.send_json({
                                "update": "logs",
                                "logs": recent_logs
                            })
                            logger.debug(f"Sent {len(recent_logs)} new log entries to client")
                        
                        last_log_check = current_time
                        
                    except WebSocketDisconnect:
                        logger.info("WebSocket disconnected during log update")
                        break
                    except Exception as e:
                        logger.error(f"Error reading logs: {e}")
                        continue
                
                continue
                
            except WebSocketDisconnect:
                logger.info("WebSocket disconnected")
                break
            except Exception as e:
                logger.error(f"Error processing message: {e}")
                continue
    
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        # Clean up when the connection is closed
        stop_analysis()
        stop_snort()