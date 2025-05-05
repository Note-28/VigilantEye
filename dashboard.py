import os
from pathlib import Path
from utils import logger

def initialize_folders():
    """Initialize all necessary folders for the application"""
    folders = [
        "logs",
        "static",
        "log",
        "log/snort"
    ]
    
    for folder in folders:
        try:
            os.makedirs(folder, exist_ok=True)
            logger.info(f"Created directory: {folder}")
        except Exception as e:
            logger.error(f"Error creating directory {folder}: {e}")
    
    # Create an empty HTML file if it doesn't exist
    html_path = Path("static/index.html")
    if not html_path.exists():
        html_path.write_text("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Loading...</title>
        </head>
        <body>
            <h1>Loading Dashboard...</h1>
        </body>
        </html>
        """)