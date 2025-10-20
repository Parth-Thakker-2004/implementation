import pandas as pd
import os
import logging
from typing import List, Dict, Any, Optional
from tqdm import tqdm
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.schema import HumanMessage, SystemMessage
import json
import csv
from io import StringIO
from datetime import datetime
import time

# Try to import advanced analytics, but make it optional
try:
    from advanced_analytics import AdvancedLogAnalytics, create_html_report
    ADVANCED_ANALYTICS_AVAILABLE = True
except ImportError as e:
    print(f"Advanced analytics not available: {e}")
    ADVANCED_ANALYTICS_AVAILABLE = False
    AdvancedLogAnalytics = None
    create_html_report = None

# Load environment variables
load_dotenv()

# Configure logging
def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('anomaly_detection.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

class SystemLogAnomalyDetector:
    def __init__(self, api_key: str = None, chunk_size: int = 50, log_level: str = "INFO"):
        """
        Initialize the System Log Anomaly Detector
        
        Args:
            api_key: Google Gemini API key (if not provided, will look for GOOGLE_API_KEY env var)
            chunk_size: Number of rows to process in each chunk
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        """
        self.chunk_size = chunk_size
        self.logger = setup_logging(log_level)
        self.metrics = {
            'total_chunks_processed': 0,
            'total_anomalies_found': 0,
            'processing_time': 0,
            'api_calls_made': 0,
            'failed_chunks': 0
        }
        
        # Initialize Gemini LLM
        api_key = api_key or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("Google API key is required. Set GOOGLE_API_KEY environment variable or pass api_key parameter.")
        
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-1.5-flash",
            google_api_key=api_key,
            temperature=0.1
        )
        
        # Rate limiting and retry configuration
        self.max_retries = 3
        self.retry_delay = 2  # seconds
        self.rate_limit_delay = 1  # seconds between API calls
        
        # System prompt for the security expert
        self.system_prompt = """You are a System Security Expert with extensive experience in analyzing system logs for anomalies and security threats. 

Your task is to analyze system log entries and identify potential anomalies that could indicate:
- Security breaches or intrusion attempts (failed logins, suspicious IPs, privilege escalation)
- System misconfigurations (incorrect permissions, exposed services)
- Performance issues (high CPU/memory usage, slow responses, timeouts)
- Unauthorized access attempts (brute force attacks, unusual user behavior)
- Malicious activities (malware execution, data exfiltration attempts)
- System failures or errors (crashes, service failures, database errors)

IMPORTANT CRITERIA FOR ANOMALIES:
- Multiple failed login attempts from same IP
- Access attempts outside business hours
- Unusual error patterns or frequencies
- Privilege escalation attempts
- Suspicious file access patterns
- Network anomalies (port scanning, unusual traffic)
- System resource exhaustion

For each log entry that you identify as anomalous, you must:
1. Include ALL original fields from the log entry
2. Add "anomaly_reason": A clear, specific explanation of why this entry is anomalous
3. Add "remediation_steps": Concrete, actionable steps to address the issue

OUTPUT FORMAT: Return ONLY a valid JSON array. Each anomaly object must contain:
- All original log fields (timestamp, level, message, source, etc.)
- "anomaly_reason": String explaining the anomaly
- "remediation_steps": String with specific actions to take

If no anomalies are found, return exactly: []

Focus on HIGH-CONFIDENCE anomalies only. Avoid flagging normal operational logs as anomalies."""

    def chunk_dataframe(self, df: pd.DataFrame) -> List[pd.DataFrame]:
        """Split dataframe into chunks of specified size"""
        chunks = []
        for i in range(0, len(df), self.chunk_size):
            chunk = df.iloc[i:i + self.chunk_size]
            chunks.append(chunk)
        return chunks

    def analyze_chunk_with_retry(self, chunk: pd.DataFrame, chunk_id: int) -> pd.DataFrame:
        """
        Analyze a chunk with retry logic and rate limiting
        """
        for attempt in range(self.max_retries):
            try:
                self.logger.debug(f"Analyzing chunk {chunk_id}, attempt {attempt + 1}")
                
                # Rate limiting
                if self.rate_limit_delay > 0:
                    time.sleep(self.rate_limit_delay)
                
                result = self.analyze_chunk(chunk)
                self.metrics['api_calls_made'] += 1
                return result
                
            except Exception as e:
                self.logger.warning(f"Attempt {attempt + 1} failed for chunk {chunk_id}: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (2 ** attempt))  # Exponential backoff
                else:
                    self.logger.error(f"All retry attempts failed for chunk {chunk_id}")
                    self.metrics['failed_chunks'] += 1
                    return pd.DataFrame(columns=list(chunk.columns) + ['anomaly_reason', 'remediation_steps'])

    def _split_and_analyze_large_chunk(self, chunk: pd.DataFrame) -> pd.DataFrame:
        """Split large chunks and analyze them separately"""
        half_size = len(chunk) // 2
        if half_size == 0:  # Single row that's too large
            self.logger.error("Single log entry too large for processing")
            return pd.DataFrame(columns=list(chunk.columns) + ['anomaly_reason', 'remediation_steps'])
        
        first_half = chunk.iloc[:half_size]
        second_half = chunk.iloc[half_size:]
        
        # Analyze both halves
        anomalies_1 = self.analyze_chunk(first_half)
        anomalies_2 = self.analyze_chunk(second_half)
        
        # Combine results
        if not anomalies_1.empty and not anomalies_2.empty:
            return pd.concat([anomalies_1, anomalies_2], ignore_index=True)
        elif not anomalies_1.empty:
            return anomalies_1
        elif not anomalies_2.empty:
            return anomalies_2
        else:
            return pd.DataFrame(columns=list(chunk.columns) + ['anomaly_reason', 'remediation_steps'])

    def analyze_chunk(self, chunk: pd.DataFrame) -> pd.DataFrame:
        """
        Analyze a chunk of log data for anomalies using Gemini LLM
        
        Args:
            chunk: DataFrame containing log entries
            
        Returns:
            DataFrame containing only anomalous entries with additional columns
        """
        start_time = time.time()
        
        try:
            # Convert chunk to CSV string for LLM processing
            csv_string = chunk.to_csv(index=False)
            
            # Validate chunk size to avoid token limits
            if len(csv_string) > 50000:  # Rough estimate for token limit
                self.logger.warning(f"Chunk size too large ({len(csv_string)} chars), splitting into smaller chunks")
                # Split chunk into smaller pieces
                return self._split_and_analyze_large_chunk(chunk)
            
            # Create the user message
            user_message = f"""Analyze the following system log entries for anomalies:

{csv_string}

Identify any log entries that represent security threats, system anomalies, or suspicious activities. Return the results as specified in the system prompt."""

            # Create messages
            messages = [
                SystemMessage(content=self.system_prompt),
                HumanMessage(content=user_message)
            ]
            
            # Get LLM response
            response = self.llm.invoke(messages)
            response_content = response.content.strip()
            
            # Parse JSON response
            try:
                # Clean up response if needed
                if response_content.startswith("```json"):
                    response_content = response_content.replace("```json", "").replace("```", "").strip()
                elif response_content.startswith("```"):
                    # Handle other code block formats
                    lines = response_content.split('\n')
                    response_content = '\n'.join(lines[1:-1]) if len(lines) > 2 else response_content
                
                anomalies_data = json.loads(response_content)
                
                if not anomalies_data:
                    empty_df = pd.DataFrame(columns=list(chunk.columns) + ['anomaly_reason', 'remediation_steps'])
                    return empty_df
                
                # Validate that the response has expected fields
                if isinstance(anomalies_data, list) and len(anomalies_data) > 0:
                    required_fields = ['anomaly_reason', 'remediation_steps']
                    
                    # Check if all entries have required fields
                    valid_anomalies = []
                    for entry in anomalies_data:
                        if isinstance(entry, dict) and all(field in entry for field in required_fields):
                            valid_anomalies.append(entry)
                        else:
                            self.logger.warning(f"Skipping invalid anomaly entry: {entry}")
                    
                    if not valid_anomalies:
                        self.logger.warning("No valid anomaly entries found in LLM response")
                        return pd.DataFrame(columns=list(chunk.columns) + ['anomaly_reason', 'remediation_steps'])
                    
                    anomalies_data = valid_anomalies
                
                anomalies_df = pd.DataFrame(anomalies_data)
                
                # Add metadata
                anomalies_df['detection_timestamp'] = datetime.now().isoformat()
                anomalies_df['confidence_score'] = 1.0  # Could be enhanced with actual confidence
                
                processing_time = time.time() - start_time
                self.logger.info(f"Chunk processed in {processing_time:.2f}s, found {len(anomalies_df)} anomalies")
                
                return anomalies_df
                
            except json.JSONDecodeError as e:
                self.logger.error(f"Error parsing JSON response: {e}")
                self.logger.debug(f"Response content: {response_content}")
                empty_df = pd.DataFrame(columns=list(chunk.columns) + ['anomaly_reason', 'remediation_steps'])
                return empty_df
                
        except Exception as e:
            self.logger.error(f"Error analyzing chunk: {e}")
            empty_df = pd.DataFrame(columns=list(chunk.columns) + ['anomaly_reason', 'remediation_steps'])
            return empty_df

    def process_csv_file(self, input_file_path: str, output_file_path: str = None) -> pd.DataFrame:
        """
        Process entire CSV file for anomaly detection
        
        Args:
            input_file_path: Path to input CSV file
            output_file_path: Path to save anomalous entries (optional)
            
        Returns:
            DataFrame containing all anomalous entries
        """
        print(f"Loading CSV file: {input_file_path}")
        
        # Load the CSV file
        try:
            df = pd.read_csv(input_file_path)
        except Exception as e:
            raise Exception(f"Error loading CSV file: {e}")
        
        # Validate input data
        if df.empty:
            self.logger.warning("Input CSV file is empty")
            return pd.DataFrame(columns=['anomaly_reason', 'remediation_steps', 'detection_timestamp', 'confidence_score'])
        
        # Check for required columns (at minimum, should have some content)
        if df.shape[1] == 0:
            raise Exception("CSV file has no columns")
        
        # Log data structure info
        self.logger.info(f"Input data shape: {df.shape}")
        self.logger.info(f"Columns: {list(df.columns)}")
        
        # Check for common log fields and warn if missing
        recommended_fields = ['timestamp', 'level', 'message']
        missing_fields = [field for field in recommended_fields if field not in df.columns]
        if missing_fields:
            self.logger.warning(f"Recommended fields missing: {missing_fields}")
            self.logger.info("Detection may be less accurate without standard log fields")
        
        print(f"Loaded {len(df)} log entries with {len(df.columns)} columns")
        
        # Split into chunks
        chunks = self.chunk_dataframe(df)
        print(f"Processing {len(chunks)} chunks of {self.chunk_size} rows each...")
        
        # Process each chunk
        all_anomalies = []
        start_time = time.time()
        
        for i, chunk in enumerate(tqdm(chunks, desc="Processing chunks")):
            self.logger.info(f"Processing chunk {i+1}/{len(chunks)}...")
            
            chunk_anomalies = self.analyze_chunk_with_retry(chunk, i+1)
            self.metrics['total_chunks_processed'] += 1
            
            if not chunk_anomalies.empty:
                all_anomalies.append(chunk_anomalies)
                self.metrics['total_anomalies_found'] += len(chunk_anomalies)
                self.logger.info(f"Found {len(chunk_anomalies)} anomalies in chunk {i+1}")
            else:
                self.logger.debug(f"No anomalies found in chunk {i+1}")
        
        # Combine all anomalies
        if all_anomalies:
            final_anomalies = pd.concat(all_anomalies, ignore_index=True)
            # Remove duplicates based on original log content
            original_columns = [col for col in final_anomalies.columns if col not in ['anomaly_reason', 'remediation_steps', 'detection_timestamp', 'confidence_score']]
            final_anomalies = final_anomalies.drop_duplicates(subset=original_columns)
        else:
            final_anomalies = pd.DataFrame(columns=list(df.columns) + ['anomaly_reason', 'remediation_steps', 'detection_timestamp', 'confidence_score'])
        
        self.metrics['processing_time'] = time.time() - start_time
        self.logger.info(f"Total anomalies detected: {len(final_anomalies)}")
        self.logger.info(f"Processing completed in {self.metrics['processing_time']:.2f} seconds")
        
        # Save to output file if specified
        if output_file_path:
            final_anomalies.to_csv(output_file_path, index=False)
            print(f"Anomalies saved to: {output_file_path}")
        
        return final_anomalies
    
    def generate_analysis_report(self, anomalies: pd.DataFrame) -> Dict[str, Any]:
        """Generate comprehensive analysis report"""
        if anomalies.empty:
            return {
                'summary': 'No anomalies detected',
                'total_anomalies': 0,
                'processing_metrics': self.metrics
            }
        
        # Analyze anomaly patterns
        anomaly_categories = {}
        severity_distribution = {}
        
        for _, row in anomalies.iterrows():
            reason = row.get('anomaly_reason', 'Unknown')
            
            # Simple categorization based on keywords
            if any(keyword in reason.lower() for keyword in ['security', 'breach', 'intrusion', 'attack']):
                category = 'Security'
            elif any(keyword in reason.lower() for keyword in ['performance', 'slow', 'timeout']):
                category = 'Performance'
            elif any(keyword in reason.lower() for keyword in ['error', 'failure', 'exception']):
                category = 'System Error'
            elif any(keyword in reason.lower() for keyword in ['access', 'unauthorized', 'permission']):
                category = 'Access Control'
            else:
                category = 'Other'
            
            anomaly_categories[category] = anomaly_categories.get(category, 0) + 1
            
            # Simple severity assessment
            if any(keyword in reason.lower() for keyword in ['critical', 'severe', 'emergency']):
                severity = 'High'
            elif any(keyword in reason.lower() for keyword in ['warning', 'suspicious', 'unusual']):
                severity = 'Medium'
            else:
                severity = 'Low'
            
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
        
        return {
            'summary': f"Detected {len(anomalies)} anomalies across {len(anomaly_categories)} categories",
            'total_anomalies': len(anomalies),
            'anomaly_categories': anomaly_categories,
            'severity_distribution': severity_distribution,
            'processing_metrics': self.metrics,
            'recommendations': self._generate_recommendations(anomaly_categories, severity_distribution)
        }
    
    def _generate_recommendations(self, categories: Dict[str, int], severities: Dict[str, int]) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        if severities.get('High', 0) > 0:
            recommendations.append("Immediate attention required: High-severity anomalies detected")
        
        if categories.get('Security', 0) > 5:
            recommendations.append("Consider implementing additional security monitoring")
        
        if categories.get('Performance', 0) > 10:
            recommendations.append("Review system performance and resource allocation")
        
        if self.metrics['failed_chunks'] > 0:
            recommendations.append(f"Review {self.metrics['failed_chunks']} failed chunks for processing issues")
        
        return recommendations
    
    def save_detailed_report(self, anomalies: pd.DataFrame, report_path: str = "anomaly_report.json"):
        """Save detailed analysis report as JSON"""
        report = self.generate_analysis_report(anomalies)
        report['generated_at'] = datetime.now().isoformat()
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Detailed report saved to {report_path}")
        return report

def main(config: Optional[Dict[str, Any]] = None):
    """
    Main function to run the system log anomaly detector
    
    Args:
        config: Optional configuration dictionary
    """
    # Default configuration
    default_config = {
        'input_csv_path': "log_structured.csv",
        'output_csv_path': "anomalies_detected.csv",
        'report_path': "anomaly_report.json",
        'chunk_size': 50,
        'log_level': "INFO",
        'max_retries': 3,
        'rate_limit_delay': 1
    }
    
    # Update with provided config
    if config:
        default_config.update(config)
    
    logger = setup_logging(default_config['log_level'])
    
    print("System Log Anomaly Detector v2.0")
    print("=" * 40)
    
    # Check if input file exists
    if not os.path.exists(default_config['input_csv_path']):
        logger.error(f"Input file '{default_config['input_csv_path']}' not found!")
        return 1  # Return error code
    
    try:
        # Initialize detector with enhanced configuration
        detector = SystemLogAnomalyDetector(
            chunk_size=default_config['chunk_size'],
            log_level=default_config['log_level']
        )
        detector.max_retries = default_config['max_retries']
        detector.rate_limit_delay = default_config['rate_limit_delay']
        
        # Process the CSV file
        logger.info("Starting anomaly detection process...")
        anomalies = detector.process_csv_file(
            default_config['input_csv_path'], 
            default_config['output_csv_path']
        )
        
        # Generate and save detailed report
        report = detector.save_detailed_report(anomalies, default_config['report_path'])
        
        # Advanced analytics (only if available and anomalies found)
        if ADVANCED_ANALYTICS_AVAILABLE and not anomalies.empty:
            try:
                logger.info("Running advanced analytics...")
                analytics = AdvancedLogAnalytics()
                
                # Load original data for comprehensive analysis
                original_df = pd.read_csv(default_config['input_csv_path'])
                
                # Perform comprehensive analysis
                comprehensive_results = analytics.comprehensive_analysis(original_df)
                
                # Generate visualizations
                viz_files = analytics.generate_visualizations(original_df, anomalies)
                
                # Create HTML report
                html_report_path = create_html_report(comprehensive_results, anomalies)
                logger.info(f"HTML report generated: {html_report_path}")
                
                # Update report with advanced analytics
                report['advanced_analytics'] = comprehensive_results
                report['visualizations'] = viz_files
                report['html_report'] = html_report_path
            except Exception as e:
                logger.warning(f"Advanced analytics failed: {e}")
                logger.info("Continuing without advanced analytics...")
        elif not ADVANCED_ANALYTICS_AVAILABLE:
            logger.info("Advanced analytics not available - install required dependencies to enable")
        
        # Display results
        print("\n" + "=" * 50)
        print("ANALYSIS COMPLETE")
        print("=" * 50)
        
        if not anomalies.empty:
            print(f"Found {len(anomalies)} anomalous log entries")
            print(f"Results saved to: {default_config['output_csv_path']}")
            print(f"Detailed report saved to: {default_config['report_path']}")
            
            # Display summary statistics
            print(f"\nProcessing Metrics:")
            print(f"- Total chunks processed: {detector.metrics['total_chunks_processed']}")
            print(f"- API calls made: {detector.metrics['api_calls_made']}")
            print(f"- Failed chunks: {detector.metrics['failed_chunks']}")
            print(f"- Processing time: {detector.metrics['processing_time']:.2f} seconds")
            
            # Display category breakdown
            if 'anomaly_categories' in report:
                print(f"\nAnomaly Categories:")
                for category, count in report['anomaly_categories'].items():
                    print(f"- {category}: {count}")
            
            # Display recommendations
            if report.get('recommendations'):
                print(f"\nRecommendations:")
                for rec in report['recommendations']:
                    print(f"- {rec}")
            
            # Display sample anomalies
            print("\nSample anomalies detected:")
            print("-" * 30)
            for idx, row in anomalies.head(3).iterrows():
                print(f"\nAnomaly {idx + 1}:")
                print(f"Reason: {row.get('anomaly_reason', 'N/A')}")
                print(f"Remediation: {row.get('remediation_steps', 'N/A')}")
                if 'confidence_score' in row:
                    print(f"Confidence: {row.get('confidence_score', 'N/A')}")
                print("-" * 30)
        else:
            print("No anomalies detected in the system logs.")
            logger.info("Analysis completed successfully - no anomalies found")
            
    except KeyboardInterrupt:
        logger.info("Process interrupted by user")
        print("\nProcess interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    main()
