"""
SwARM IDS Dashboard Launcher
Swarm Agent Response Monitoring
Launch the web dashboard to view real-time statistics
"""

import sys
import logging
from pathlib import Path

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from src.dashboard.dashboard import SwarmDashboard
from src.database.database import SwarmDatabase
from src.utils.config import Config
from src.utils.logger import setup_logging

def main():
    """Launch the SwARM IDS Dashboard"""
    # Setup logging
    config = Config("config/default.yaml")
    setup_logging(config.config_data)
    
    logger = logging.getLogger(__name__)
    
    print("🚀 SwARM IDS - Swarm Agent Response Monitoring")
    print("🚀 Dashboard Starting...")
    print("=" * 60)
    
    try:
        # Initialize database connection
        print("📊 Initializing database connection...")
        database = SwarmDatabase("data/swarm_ids.db")
        print("✅ Database connected successfully")
        
        # Create and start dashboard
        print("🌐 Creating dashboard server...")
        dashboard = SwarmDashboard(database, host="127.0.0.1", port=5000)
        
        print("\n✅ Dashboard ready!")
        print("🔗 Access URL: http://127.0.0.1:5000")
        print("📈 Features available:")
        print("   - Real-time alerts and statistics")
        print("   - System performance metrics") 
        print("   - ML model performance tracking")
        print("   - Smart workflow monitoring")
        print("\n🔄 Starting server... (Press Ctrl+C to stop)")
        print("=" * 60)
        
        # Start the dashboard server
        dashboard.run()
        
    except KeyboardInterrupt:
        print("\n🛑 Dashboard shutdown requested")
        print("✅ Stopped successfully")
    except Exception as e:
        print(f"❌ Dashboard failed to start: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
