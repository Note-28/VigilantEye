import uvicorn
from dashboard import initialize_folders
from utils import logger
import sys
import os

def main():
    """Main entry point for the Cybersecurity Dashboard application"""
    try:
        # Initialize necessary folders
        initialize_folders()
        
        # Ensure static/index.html exists
        if not os.path.exists("static/index.html"):
            logger.error("Dashboard HTML file not found. Please ensure static/index.html exists.")
            sys.exit(1)
        
        # Start the FastAPI server
        logger.info("Starting Cybersecurity Dashboard server...")
        uvicorn.run(
            "app:app",
            host="0.0.0.0",
            port=8000,
            reload=False,
            workers=1
        )
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()