"""
Real-time Log Monitoring Module
Provides continuous monitoring capabilities for log streams
"""

import asyncio
import aiofiles
import time
from datetime import datetime
from typing import AsyncGenerator, Callable, List, Dict, Any
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pandas as pd
from queue import Queue
import threading
import json
import logging

class LogFileWatcher(FileSystemEventHandler):
    """Watch log files for changes and trigger analysis"""
    
    def __init__(self, callback: Callable, file_extensions: List[str] = None):
        self.callback = callback
        self.file_extensions = file_extensions or ['.log', '.txt', '.csv']
        self.logger = logging.getLogger(__name__)
    
    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            if any(file_path.endswith(ext) for ext in self.file_extensions):
                self.logger.info(f"Log file modified: {file_path}")
                self.callback(file_path)

class RealTimeMonitor:
    """Real-time log monitoring and anomaly detection"""
    
    def __init__(self, detector, config: Dict[str, Any] = None):
        self.detector = detector
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.is_monitoring = False
        self.log_queue = Queue()
        self.anomaly_callbacks = []
        
        # Monitoring settings
        self.batch_size = self.config.get('batch_size', 10)
        self.batch_timeout = self.config.get('batch_timeout', 30)  # seconds
        self.watch_directories = self.config.get('watch_directories', [])
        
    def add_anomaly_callback(self, callback: Callable):
        """Add callback function to be called when anomalies are detected"""
        self.anomaly_callbacks.append(callback)
    
    def _notify_anomalies(self, anomalies: pd.DataFrame):
        """Notify all registered callbacks about detected anomalies"""
        for callback in self.anomaly_callbacks:
            try:
                callback(anomalies)
            except Exception as e:
                self.logger.error(f"Error in anomaly callback: {e}")
    
    async def _process_log_batch(self):
        """Process accumulated log entries in batches"""
        batch = []
        
        while self.is_monitoring:
            try:
                # Collect logs for batch processing
                start_time = time.time()
                while (len(batch) < self.batch_size and 
                       time.time() - start_time < self.batch_timeout):
                    
                    if not self.log_queue.empty():
                        log_entry = self.log_queue.get()
                        batch.append(log_entry)
                    else:
                        await asyncio.sleep(0.1)
                
                if batch:
                    self.logger.info(f"Processing batch of {len(batch)} log entries")
                    
                    # Convert to DataFrame
                    df = pd.DataFrame(batch)
                    
                    # Detect anomalies
                    anomalies = self.detector.analyze_chunk(df)
                    
                    if not anomalies.empty:
                        self.logger.warning(f"Real-time anomalies detected: {len(anomalies)}")
                        self._notify_anomalies(anomalies)
                    
                    batch.clear()
                    
            except Exception as e:
                self.logger.error(f"Error processing batch: {e}")
                batch.clear()
            
            await asyncio.sleep(1)
    
    def add_log_entry(self, log_entry: Dict[str, Any]):
        """Add a log entry to the processing queue"""
        log_entry['ingestion_time'] = datetime.now().isoformat()
        self.log_queue.put(log_entry)
    
    async def monitor_log_stream(self, log_stream: AsyncGenerator[Dict[str, Any], None]):
        """Monitor an async log stream"""
        self.logger.info("Starting log stream monitoring")
        
        async for log_entry in log_stream:
            if not self.is_monitoring:
                break
            self.add_log_entry(log_entry)
    
    def start_file_monitoring(self):
        """Start monitoring log files in specified directories"""
        if not self.watch_directories:
            self.logger.warning("No directories specified for file monitoring")
            return
        
        self.observer = Observer()
        
        def file_changed_callback(file_path):
            """Callback for when log files change"""
            try:
                # Read new lines from the file
                # This is a simplified implementation
                # In production, you'd track file positions to read only new content
                with open(file_path, 'r') as f:
                    lines = f.readlines()
                    
                for line in lines[-10:]:  # Process last 10 lines
                    if line.strip():
                        log_entry = self._parse_log_line(line.strip(), file_path)
                        if log_entry:
                            self.add_log_entry(log_entry)
                            
            except Exception as e:
                self.logger.error(f"Error reading file {file_path}: {e}")
        
        watcher = LogFileWatcher(file_changed_callback)
        
        for directory in self.watch_directories:
            self.observer.schedule(watcher, directory, recursive=True)
        
        self.observer.start()
        self.logger.info(f"Started monitoring directories: {self.watch_directories}")
    
    def _parse_log_line(self, line: str, source_file: str) -> Dict[str, Any]:
        """Parse a log line into structured data"""
        # This is a basic parser - you'd customize this based on your log format
        try:
            # Assuming a common log format like: timestamp level message
            parts = line.split(' ', 2)
            if len(parts) >= 3:
                return {
                    'timestamp': parts[0] + ' ' + parts[1] if len(parts) > 1 else datetime.now().isoformat(),
                    'level': parts[1] if len(parts) > 2 else 'INFO',
                    'message': parts[2] if len(parts) > 2 else line,
                    'source_file': source_file,
                    'raw_line': line
                }
        except Exception as e:
            self.logger.error(f"Error parsing log line: {e}")
        
        # Fallback parsing
        return {
            'timestamp': datetime.now().isoformat(),
            'level': 'UNKNOWN',
            'message': line,
            'source_file': source_file,
            'raw_line': line
        }
    
    async def start_monitoring(self):
        """Start real-time monitoring"""
        self.is_monitoring = True
        self.logger.info("Starting real-time anomaly monitoring")
        
        # Start file monitoring if configured
        if self.watch_directories:
            self.start_file_monitoring()
        
        # Start batch processing
        await self._process_log_batch()
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.is_monitoring = False
        
        if hasattr(self, 'observer'):
            self.observer.stop()
            self.observer.join()
        
        self.logger.info("Stopped real-time monitoring")

class AlertManager:
    """Manage alerts and notifications for detected anomalies"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Email settings
        self.email_enabled = self.config.get('email', {}).get('enabled', False)
        self.webhook_enabled = self.config.get('webhook', {}).get('enabled', False)
    
    async def send_email_alert(self, anomalies: pd.DataFrame):
        """Send email alert for detected anomalies"""
        if not self.email_enabled:
            return
        
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            email_config = self.config.get('email', {})
            
            msg = MIMEMultipart()
            msg['From'] = email_config.get('sender')
            msg['To'] = ', '.join(email_config.get('recipients', []))
            msg['Subject'] = f"Anomaly Alert: {len(anomalies)} anomalies detected"
            
            body = f"""
            Security Alert: Log Anomalies Detected
            
            Time: {datetime.now().isoformat()}
            Number of anomalies: {len(anomalies)}
            
            Top anomalies:
            """
            
            for idx, (_, row) in enumerate(anomalies.head(5).iterrows()):
                body += f"""
            {idx + 1}. {row.get('anomaly_reason', 'Unknown reason')}
               Recommended action: {row.get('remediation_steps', 'No recommendation')}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(email_config.get('smtp_server'), email_config.get('smtp_port', 587))
            server.starttls()
            server.login(email_config.get('username'), email_config.get('password'))
            
            text = msg.as_string()
            server.sendmail(email_config.get('sender'), email_config.get('recipients'), text)
            server.quit()
            
            self.logger.info("Email alert sent successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
    
    async def send_webhook_alert(self, anomalies: pd.DataFrame):
        """Send webhook alert for detected anomalies"""
        if not self.webhook_enabled:
            return
        
        try:
            import aiohttp
            
            webhook_config = self.config.get('webhook', {})
            url = webhook_config.get('url')
            
            payload = {
                'timestamp': datetime.now().isoformat(),
                'anomaly_count': len(anomalies),
                'anomalies': anomalies.to_dict('records')[:10],  # Send top 10
                'alert_type': 'anomaly_detection'
            }
            
            headers = {
                'Content-Type': 'application/json'
            }
            
            if webhook_config.get('auth_token'):
                headers['Authorization'] = f"Bearer {webhook_config.get('auth_token')}"
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, headers=headers) as response:
                    if response.status == 200:
                        self.logger.info("Webhook alert sent successfully")
                    else:
                        self.logger.error(f"Webhook alert failed: {response.status}")
            
        except Exception as e:
            self.logger.error(f"Failed to send webhook alert: {e}")
    
    async def process_anomaly_alert(self, anomalies: pd.DataFrame):
        """Process anomaly alerts through all configured channels"""
        if anomalies.empty:
            return
        
        self.logger.warning(f"Processing alert for {len(anomalies)} anomalies")
        
        # Send alerts concurrently
        tasks = []
        
        if self.email_enabled:
            tasks.append(self.send_email_alert(anomalies))
        
        if self.webhook_enabled:
            tasks.append(self.send_webhook_alert(anomalies))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

# Example usage for real-time monitoring
async def example_real_time_usage():
    """Example of how to use real-time monitoring"""
    from main import SystemLogAnomalyDetector
    
    # Initialize detector
    detector = SystemLogAnomalyDetector()
    
    # Configure real-time monitoring
    monitor_config = {
        'batch_size': 5,
        'batch_timeout': 10,
        'watch_directories': ['/var/log', '/tmp/logs']
    }
    
    # Set up monitoring
    monitor = RealTimeMonitor(detector, monitor_config)
    
    # Set up alerts
    alert_config = {
        'email': {
            'enabled': True,
            'recipients': ['admin@example.com'],
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'username': 'your_email@gmail.com',
            'password': 'your_password'
        },
        'webhook': {
            'enabled': True,
            'url': 'https://hooks.slack.com/your-webhook',
            'auth_token': 'your_token'
        }
    }
    
    alert_manager = AlertManager(alert_config)
    
    # Register alert callback
    monitor.add_anomaly_callback(alert_manager.process_anomaly_alert)
    
    # Start monitoring
    try:
        await monitor.start_monitoring()
    except KeyboardInterrupt:
        monitor.stop_monitoring()
        print("Monitoring stopped")

if __name__ == "__main__":
    asyncio.run(example_real_time_usage())