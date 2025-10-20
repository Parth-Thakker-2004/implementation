# Advanced System Log Anomaly Detection System

## Overview

This is a comprehensive system for detecting anomalies in system logs using Large Language Models (LLMs), specifically Google's Gemini model. The system provides both batch processing and real-time monitoring capabilities with advanced analytics and alerting features.

## Features

### Core Features
- **LLM-powered anomaly detection** using Google Gemini
- **Batch processing** of large log files with intelligent chunking
- **Real-time monitoring** of log files and streams
- **Advanced analytics** with ML-based detection and statistical analysis
- **Comprehensive reporting** with HTML, JSON, and CSV outputs
- **Visualization** capabilities with charts and interactive dashboards
- **Alert system** with email and webhook notifications

### Enhanced Capabilities
- **Retry mechanism** with exponential backoff for API failures
- **Rate limiting** to respect API quotas
- **Comprehensive logging** with configurable levels
- **Performance metrics** tracking and reporting
- **Deduplication** of anomalies
- **Configurable thresholds** and detection rules
- **Memory-efficient processing** for large datasets

## Installation

### Prerequisites
- Python 3.8 or higher
- Google Gemini API key

### Basic Installation
```bash
pip install -r pyproject.toml
```

### Enhanced Installation (with all features)
```bash
pip install -r requirements_enhanced.txt
```

### Environment Setup
Create a `.env` file in the project root:
```
GOOGLE_API_KEY=your_gemini_api_key_here
```

## Configuration

The system uses `config.json` for configuration. Key settings include:

```json
{
    "input_csv_path": "log_structured.csv",
    "output_csv_path": "anomalies_detected.csv",
    "chunk_size": 50,
    "max_retries": 3,
    "rate_limit_delay": 1,
    "log_level": "INFO"
}
```

## Usage

### Basic Usage
```python
from main import SystemLogAnomalyDetector

# Initialize detector
detector = SystemLogAnomalyDetector(chunk_size=50)

# Process CSV file
anomalies = detector.process_csv_file("your_logs.csv", "anomalies.csv")
```

### Command Line Usage
```bash
python main.py
```

### Advanced Usage with Configuration
```python
from main import main

config = {
    'input_csv_path': 'custom_logs.csv',
    'chunk_size': 100,
    'log_level': 'DEBUG'
}

main(config)
```

### Real-time Monitoring
```python
from real_time_monitor import RealTimeMonitor, AlertManager
import asyncio

# Set up monitoring
monitor = RealTimeMonitor(detector, {
    'batch_size': 10,
    'watch_directories': ['/var/log']
})

# Set up alerts
alert_manager = AlertManager({
    'email': {'enabled': True, 'recipients': ['admin@company.com']},
    'webhook': {'enabled': True, 'url': 'https://hooks.slack.com/...'}
})

# Register callbacks
monitor.add_anomaly_callback(alert_manager.process_anomaly_alert)

# Start monitoring
asyncio.run(monitor.start_monitoring())
```

## Input Data Format

The system expects CSV files with the following columns (minimum):

| Column | Description | Required |
|--------|-------------|----------|
| timestamp | Log timestamp | Recommended |
| level | Log level (INFO, ERROR, etc.) | Recommended |
| message | Log message content | Required |
| source | Source file/component | Optional |

Example CSV format:
```csv
timestamp,level,message,source
2024-01-01 10:00:00,INFO,User login successful,auth.py
2024-01-01 10:01:00,ERROR,Failed login attempt,auth.py
2024-01-01 10:02:00,WARNING,High CPU usage detected,monitor.py
```

## Output Format

### Anomalies CSV
The system outputs detected anomalies with additional fields:

| Column | Description |
|--------|-------------|
| *original columns* | All original log data |
| anomaly_reason | Explanation of why it's anomalous |
| remediation_steps | Suggested actions to take |
| detection_timestamp | When the anomaly was detected |
| confidence_score | Confidence level (0-1) |

### Analysis Report (JSON)
```json
{
    "summary": "Detected 5 anomalies across 3 categories",
    "total_anomalies": 5,
    "anomaly_categories": {
        "Security": 3,
        "Performance": 2
    },
    "severity_distribution": {
        "High": 1,
        "Medium": 3,
        "Low": 1
    },
    "processing_metrics": {
        "total_chunks_processed": 10,
        "processing_time": 45.2,
        "api_calls_made": 10,
        "failed_chunks": 0
    },
    "recommendations": [
        "Immediate attention required: High-severity anomalies detected",
        "Consider implementing additional security monitoring"
    ]
}
```

## Architecture

### Core Components

1. **SystemLogAnomalyDetector** - Main detection engine
   - Handles LLM interactions
   - Manages chunking and processing
   - Implements retry logic and rate limiting

2. **AdvancedLogAnalytics** - Enhanced analytics
   - ML-based anomaly detection using Isolation Forest
   - Statistical analysis and feature extraction
   - Visualization generation

3. **RealTimeMonitor** - Real-time processing
   - File system monitoring
   - Stream processing
   - Batch accumulation and processing

4. **AlertManager** - Notification system
   - Email alerts via SMTP
   - Webhook notifications
   - Configurable alert rules

### Data Flow
```
Log Files → CSV Parser → Chunker → LLM Analysis → Anomaly Detection → 
Aggregation → Deduplication → Reporting → Alerts
```

## Performance Optimization

### Chunking Strategy
- Default chunk size: 50 rows
- Automatically adjusts for token limits
- Memory-efficient processing

### Rate Limiting
- Configurable delays between API calls
- Respects API quotas
- Implements exponential backoff on failures

### Memory Management
- Processes data in chunks
- Releases memory after each chunk
- Monitors memory usage in performance tests

## Error Handling

The system implements comprehensive error handling:

1. **API Failures**: Retry with exponential backoff
2. **JSON Parsing Errors**: Graceful fallback with logging
3. **File I/O Errors**: Detailed error messages and recovery
4. **Memory Issues**: Chunk size auto-adjustment
5. **Network Issues**: Configurable timeouts and retries

## Testing

### Running Tests
```bash
# Run all tests
python test_suite.py

# Run specific test category
python -m unittest test_suite.TestSystemLogAnomalyDetector

# Run with verbose output
python -m unittest test_suite -v
```

### Test Categories
1. **Unit Tests** - Individual component testing
2. **Integration Tests** - End-to-end workflow testing
3. **Performance Tests** - Large dataset processing
4. **Error Handling Tests** - Failure scenario testing

## Advanced Features

### Machine Learning Integration
The system includes ML-based anomaly detection as a complement to LLM analysis:

```python
from advanced_analytics import AdvancedLogAnalytics

analytics = AdvancedLogAnalytics()
ml_results = analytics.ml_based_detection(log_data)
```

### Custom Visualization
Generate interactive dashboards and charts:

```python
viz_files = analytics.generate_visualizations(original_data, anomalies)
html_report = create_html_report(analysis_results, anomalies)
```

### Real-time Stream Processing
Process log streams in real-time:

```python
async def log_stream():
    # Your log stream implementation
    yield log_entry

await monitor.monitor_log_stream(log_stream())
```

## Configuration Options

### Detection Settings
- `chunk_size`: Number of rows per processing chunk
- `max_retries`: Maximum retry attempts for failed API calls
- `rate_limit_delay`: Delay between API calls (seconds)
- `confidence_threshold`: Minimum confidence for anomaly reporting

### LLM Settings
- `model`: Gemini model version
- `temperature`: Creativity level (0.0-1.0)
- `max_tokens`: Maximum response tokens

### Monitoring Settings
- `batch_size`: Logs per batch in real-time mode
- `batch_timeout`: Maximum wait time for batch completion
- `watch_directories`: Directories to monitor for log files

### Alert Settings
- `email`: SMTP configuration for email alerts
- `webhook`: Webhook URLs and authentication
- `severity_thresholds`: Custom severity classification rules

## Best Practices

### For Large Datasets
1. Use appropriate chunk sizes (50-100 rows)
2. Enable rate limiting to avoid API quotas
3. Monitor memory usage
4. Use batch processing for historical analysis

### For Real-time Monitoring
1. Set reasonable batch sizes (5-20 logs)
2. Configure appropriate timeouts
3. Use webhooks for immediate notifications
4. Monitor system resources

### For Production Deployment
1. Use environment variables for sensitive data
2. Implement proper logging and monitoring
3. Set up health checks
4. Configure backup and recovery procedures

## Troubleshooting

### Common Issues

1. **API Key Errors**
   - Ensure `GOOGLE_API_KEY` is set correctly
   - Verify API key has proper permissions

2. **Memory Issues**
   - Reduce chunk size
   - Enable streaming mode for large files
   - Monitor system resources

3. **Rate Limiting**
   - Increase `rate_limit_delay`
   - Reduce `chunk_size` to make fewer API calls
   - Implement exponential backoff

4. **JSON Parsing Errors**
   - Check LLM responses in debug logs
   - Verify system prompt format
   - Update JSON cleaning logic

### Debug Mode
Enable detailed debugging:
```python
config = {'log_level': 'DEBUG'}
main(config)
```

### Performance Monitoring
Track processing metrics:
```python
detector = SystemLogAnomalyDetector()
# ... process logs ...
print(detector.metrics)
```

## Contributing

1. Follow PEP 8 style guidelines
2. Add comprehensive tests for new features
3. Update documentation for changes
4. Use meaningful commit messages

### Development Setup
```bash
# Install development dependencies
pip install -r requirements_enhanced.txt

# Run tests
python test_suite.py

# Format code
black *.py

# Lint code
flake8 *.py
```

## License

MIT License - see LICENSE file for details

## Support

For issues and support:
1. Check the troubleshooting section
2. Review debug logs
3. Open an issue with detailed information
4. Include configuration and error logs