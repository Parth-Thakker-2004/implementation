# System Log Anomaly Detector

An intelligent system log analysis tool that uses Google's Gemini LLM via Langchain to detect security anomalies and system threats in CSV log files.

## Features

- **Intelligent Anomaly Detection**: Uses Google Gemini Pro to analyze system logs for security threats and anomalies
- **Chunked Processing**: Processes large CSV files in configurable chunks (default: 50 rows)
- **Detailed Analysis**: Provides human-friendly explanations and remediation steps for each anomaly
- **CSV Output**: Saves detected anomalies with additional analysis columns
- **Progress Tracking**: Real-time progress updates during processing

## Requirements

- Python >= 3.8
- Google Gemini API key
- UV package manager

## Installation

1. **Clone or setup the project directory**

2. **Install dependencies using UV:**
   ```bash
   uv sync
   ```

3. **Set up your Google Gemini API key:**
   
   Get your API key from [Google AI Studio](https://makersuite.google.com/app/apikey)
   
   Create a `.env` file in the project root:
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and add your API key:
   ```
   GOOGLE_API_KEY=your_actual_api_key_here
   ```

## Usage

### Basic Usage

Run the application:
```bash
uv run main.py
```

The application will prompt you for:
1. **Input CSV file path**: Path to your system log CSV file
2. **Output file path**: Where to save detected anomalies (optional, defaults to `anomalies_detected.csv`)

### Expected CSV Format

Your system log CSV should contain columns like:
- `timestamp`: When the log entry occurred
- `user`: User associated with the action
- `action`: Type of action performed
- `ip_address`: Source IP address
- `status`: Result status (success, failed, blocked, etc.)
- `resource`: Resource accessed
- `user_agent`: Client user agent
- `bytes_transferred`: Amount of data transferred

**Note**: The tool is flexible and can work with different column structures. The LLM will analyze whatever columns are present.

### Sample Data

A sample CSV file (`sample_system_logs.csv`) is included with various types of log entries including:
- Normal user activities
- Security threats (SQL injection, brute force, etc.)
- System events
- Suspicious activities
- Malicious attempts

### Output Format

The tool generates a CSV file with detected anomalies plus two additional columns:
- `anomaly_reason`: Explanation of why the log entry is considered anomalous
- `remediation_steps`: Specific steps to address the security issue

## Configuration

### Chunk Size
You can modify the chunk size by editing the `SystemLogAnomalyDetector` initialization in `main.py`:

```python
detector = SystemLogAnomalyDetector(chunk_size=100)  # Process 100 rows at a time
```

### LLM Parameters
Adjust the Gemini model parameters in the `SystemLogAnomalyDetector` class:

```python
self.llm = ChatGoogleGenerativeAI(
    model="gemini-pro",
    google_api_key=api_key,
    temperature=0.1  # Lower temperature for more consistent results
)
```

## Example Output

When anomalies are detected, you'll see output like:

```
Sample anomalies detected:
------------------------------

Anomaly 1:
Reason: Multiple failed login attempts from external IP indicating brute force attack
Remediation: Implement IP blocking, enable account lockout policies, and monitor for continued attempts

Anomaly 2:
Reason: SQL injection attempt detected in login parameters
Remediation: Implement input validation, use parameterized queries, and enable WAF protection
------------------------------
```

## Architecture

The application consists of:

1. **SystemLogAnomalyDetector**: Main class that handles:
   - CSV file loading and chunking
   - LLM integration with Gemini
   - Anomaly analysis and detection
   - Results aggregation and output

2. **LLM Integration**: Uses Langchain with Google Gemini for:
   - System security expert persona
   - Structured JSON responses
   - Detailed anomaly analysis

3. **Data Processing**: Pandas-based CSV processing with:
   - Configurable chunk sizes
   - Progress tracking
   - Error handling

## Error Handling

The application includes comprehensive error handling for:
- Invalid CSV files
- API key issues
- LLM response parsing errors
- Network connectivity problems
- File I/O errors

## Security Considerations

- Store your API key securely in the `.env` file
- Don't commit the `.env` file to version control
- The tool processes logs locally and only sends data to Google's Gemini API for analysis
- Consider data privacy requirements when processing sensitive logs

## Troubleshooting

### Common Issues

1. **"Google API key is required" error**
   - Ensure your `.env` file exists and contains a valid `GOOGLE_API_KEY`

2. **"Error loading CSV file" error**
   - Check the file path and ensure the CSV file is properly formatted
   - Ensure the file is not locked by another application

3. **JSON parsing errors**
   - The LLM occasionally returns malformed JSON; the tool will skip these chunks and continue
   - Try reducing the chunk size if this happens frequently

4. **Rate limiting**
   - If you hit API rate limits, the tool will show errors; wait and retry
   - Consider reducing chunk size or adding delays between requests

## Contributing

Feel free to submit issues and enhancement requests!