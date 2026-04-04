import sys
import time
import logging
import datetime
import signal
import os
import pathlib
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
from sqlmodel import Session, select
from .poller import poll_once
from .cleaner import clean_old
from .config import POLL_INTERVAL, reload_config
from .db import init_db, engine, Miner, Reading
from .notifier import send_startup_notification, send_ip_change_alert
from .settings_manager import load_settings
from .discovery import get_arp_table, ping_sweep, get_local_subnet, verify_bitaxe

logger = logging.getLogger(__name__)

# Global scheduler for access in signal handler
scheduler = None
DATA_DIR = pathlib.Path(os.getenv("DB_DATA_DIR", "/app/data"))
PID_FILE = DATA_DIR / "sentry.pid"
DB_PATH = pathlib.Path(os.getenv("DB_PATH", DATA_DIR / "bitaxe_sentry.db"))# Track current poll interval to detect changes
current_poll_interval = POLL_INTERVAL

def cleanup():
    """Remove PID file on exit"""
    try:
        if PID_FILE.exists():
            PID_FILE.unlink()
            logger.info(f"Removed PID file {PID_FILE}")
    except Exception as e:
        logger.warning(f"Could not remove PID file: {e}")

def handle_sighup(signum, frame):
    """Handle SIGHUP signal to reload configuration"""
    logger.info("Received SIGHUP signal, reloading configuration...")
    
    # Reload config from file
    global scheduler, current_poll_interval
    reload_config()
    
    # Update the scheduler if poll interval changed
    update_scheduler_if_needed()

def update_scheduler_if_needed():
    """Update the scheduler if poll interval has changed"""
    global scheduler, current_poll_interval
    
    # Get the current poll interval from config
    from .config import POLL_INTERVAL
    
    # Check if poll interval has changed
    if current_poll_interval != POLL_INTERVAL:
        logger.info(f"Poll interval changed from {current_poll_interval} to {POLL_INTERVAL} minutes")
        
        if scheduler:
            try:
                # Reschedule the polling job with the new interval
                scheduler.reschedule_job('poller', trigger='interval', minutes=POLL_INTERVAL)
                logger.info(f"Scheduler updated with new poll interval: {POLL_INTERVAL} minutes")
                
                # Update the current poll interval
                current_poll_interval = POLL_INTERVAL
            except Exception as e:
                logger.exception(f"Error updating scheduler: {e}")
        else:
            logger.warning("Scheduler not initialized, cannot update")
            current_poll_interval = POLL_INTERVAL

def auto_heal():
    """
    Check for offline miners with stored MAC addresses and try to find them at new IPs.
    If found, update their endpoint and send a notification.
    """
    logger.info("Starting auto-heal scan for offline miners")
    
    try:
        ping_sweep(get_local_subnet()[0])
        arp_table = get_arp_table()
        
        if not arp_table:
            logger.warning("ARP table empty, skipping auto-heal")
            return
        
        mac_to_ip = {mac: ip for mac, ip in arp_table.items()}
        
        with Session(engine) as session:
            miners = session.exec(select(Miner)).all()
            stale_threshold = datetime.datetime.utcnow() - datetime.timedelta(minutes=POLL_INTERVAL * 2)
            
            healed = 0
            for miner in miners:
                if not miner.mac_address:
                    continue
                
                last_reading = session.exec(
                    select(Reading)
                    .where(Reading.miner_id == miner.id)
                    .order_by(Reading.timestamp.desc())
                    .limit(1)
                ).first()
                
                if last_reading and last_reading.timestamp > stale_threshold:
                    continue
                
                target_mac = miner.mac_address.lower().strip()
                new_ip = mac_to_ip.get(target_mac)
                
                if not new_ip:
                    logger.debug(f"Miner {miner.name} (MAC: {target_mac}) not found in ARP table")
                    continue
                
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(miner.endpoint)
                    current_ip = parsed.hostname
                except Exception:
                    current_ip = miner.endpoint
                
                if new_ip == current_ip:
                    logger.debug(f"Miner {miner.name} already at correct IP {new_ip}")
                    continue
                
                info = verify_bitaxe(new_ip)
                if not info:
                    logger.warning(f"Device at {new_ip} with MAC {target_mac} is not a Bitaxe")
                    continue
                
                old_endpoint = miner.endpoint
                new_endpoint = f"{parsed.scheme}://{new_ip}"
                miner.endpoint = new_endpoint
                session.add(miner)
                session.commit()
                
                logger.info(f"Auto-healed {miner.name}: {old_endpoint} -> {new_endpoint}")
                
                try:
                    send_ip_change_alert(miner, old_endpoint, new_endpoint)
                except Exception as e:
                    logger.warning(f"Failed to send IP change alert for {miner.name}: {e}")
                
                healed += 1
            
            if healed > 0:
                logger.info(f"Auto-heal complete: {healed} miner(s) recovered")
            else:
                logger.info("Auto-heal complete: no miners needed recovery")
                
    except Exception as e:
        logger.exception(f"Error during auto-heal: {e}")

def main():
    """Main entry point for the Bitaxe Sentry application."""
    logger.info("Starting Bitaxe Sentry")
    
    # Save PID to file for inter-service communication
    pid = os.getpid()
    try:
        PID_FILE.write_text(str(pid))
        logger.info(f"Saved PID {pid} to {PID_FILE}")
        # Register cleanup function
        atexit.register(cleanup)
    except Exception as e:
        logger.warning(f"Could not save PID to file: {e}")
    
    # Initialize database
    init_db()
    
    # Register signal handler for SIGHUP
    signal.signal(signal.SIGHUP, handle_sighup)
    logger.info("Registered SIGHUP handler for configuration reload")
    
    # Create scheduler
    global scheduler, current_poll_interval
    scheduler = BackgroundScheduler()
    
    # Add jobs
    scheduler.add_job(
        poll_once, 
        'interval', 
        minutes=POLL_INTERVAL, 
        id='poller'
    )
    scheduler.add_job(clean_old, 'cron', hour=0, id='cleaner')
    scheduler.add_job(auto_heal, 'interval', minutes=10, id='auto_heal', misfire_grace_time=600)
    
    # Start the scheduler
    scheduler.start()
    logger.info(f"Scheduler started. Polling every {POLL_INTERVAL} minutes")
    
    # Send startup notification to Discord
    notification_status = send_startup_notification()
    if notification_status:
        logger.info("Discord webhook verified")
    else:
        logger.warning("Discord notifications may not be working correctly")
    
    try:
        # Run initial poll immediately
        logger.info("Running initial poll now")
        poll_once()
        logger.info("Initial poll completed")
        
        # Keep the main thread running
        while True:
            time.sleep(60)  # Check every minute
            
            # Check if config has changed
            try:
                if reload_config():
                    # Config has changed, update scheduler if needed
                    update_scheduler_if_needed()
            except Exception as e:
                logger.exception(f"Error checking config: {e}")
                
    except KeyboardInterrupt:
        logger.info("Shutting down Bitaxe Sentry")
        scheduler.shutdown()
        cleanup()  # Explicit cleanup
        sys.exit(0)
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        scheduler.shutdown()
        cleanup()  # Explicit cleanup
        sys.exit(1)


if __name__ == "__main__":
    main() 