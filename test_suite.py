"""
Comprehensive Testing Module for Log Anomaly Detection
Provides unit tests, integration tests, and performance tests
"""

import unittest
import pandas as pd
import numpy as np
import json
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
import time
from datetime import datetime, timedelta
import sys
import asyncio

# Add project root to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import SystemLogAnomalyDetector

class TestSystemLogAnomalyDetector(unittest.TestCase):
    """Test cases for the main anomaly detector"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_data = pd.DataFrame({
            'timestamp': pd.date_range('2024-01-01', periods=100, freq='1H'),
            'level': ['INFO'] * 50 + ['ERROR'] * 30 + ['WARNING'] * 20,
            'message': [f'Normal log message {i}' for i in range(50)] + 
                      [f'Error occurred {i}' for i in range(30)] + 
                      [f'Warning message {i}' for i in range(20)],
            'source': ['app.py'] * 100
        })
        
        # Create mock LLM responses
        self.mock_normal_response = json.dumps([])
        self.mock_anomaly_response = json.dumps([{
            'timestamp': '2024-01-01 12:00:00',
            'level': 'ERROR',
            'message': 'Suspicious login attempt',
            'source': 'auth.py',
            'anomaly_reason': 'Multiple failed login attempts from unknown IP',
            'remediation_steps': 'Block IP address and review security logs'
        }])
    
    def test_initialization(self):
        """Test detector initialization"""
        with patch.dict(os.environ, {'GOOGLE_API_KEY': 'test_key'}):
            detector = SystemLogAnomalyDetector(chunk_size=10)
            self.assertEqual(detector.chunk_size, 10)
            self.assertIsNotNone(detector.llm)
    
    def test_chunk_dataframe(self):
        """Test dataframe chunking functionality"""
        with patch.dict(os.environ, {'GOOGLE_API_KEY': 'test_key'}):
            detector = SystemLogAnomalyDetector(chunk_size=25)
            chunks = detector.chunk_dataframe(self.test_data)
            
            self.assertEqual(len(chunks), 4)  # 100 rows / 25 = 4 chunks
            self.assertEqual(len(chunks[0]), 25)
            self.assertEqual(len(chunks[-1]), 25)
    
    @patch('main.ChatGoogleGenerativeAI')
    def test_analyze_chunk_no_anomalies(self, mock_llm_class):
        """Test chunk analysis with no anomalies"""
        # Mock LLM response
        mock_llm = Mock()
        mock_response = Mock()
        mock_response.content = self.mock_normal_response
        mock_llm.invoke.return_value = mock_response
        mock_llm_class.return_value = mock_llm
        
        with patch.dict(os.environ, {'GOOGLE_API_KEY': 'test_key'}):
            detector = SystemLogAnomalyDetector()
            
            result = detector.analyze_chunk(self.test_data.head(10))
            
            self.assertTrue(result.empty)
            self.assertIn('anomaly_reason', result.columns)
            self.assertIn('remediation_steps', result.columns)
    
    @patch('main.ChatGoogleGenerativeAI')
    def test_analyze_chunk_with_anomalies(self, mock_llm_class):
        """Test chunk analysis with anomalies detected"""
        # Mock LLM response
        mock_llm = Mock()
        mock_response = Mock()
        mock_response.content = self.mock_anomaly_response
        mock_llm.invoke.return_value = mock_response
        mock_llm_class.return_value = mock_llm
        
        with patch.dict(os.environ, {'GOOGLE_API_KEY': 'test_key'}):
            detector = SystemLogAnomalyDetector()
            
            result = detector.analyze_chunk(self.test_data.head(10))
            
            self.assertFalse(result.empty)
            self.assertEqual(len(result), 1)
            self.assertIn('anomaly_reason', result.columns)
            self.assertIn('remediation_steps', result.columns)
    
    @patch('main.ChatGoogleGenerativeAI')
    def test_malformed_json_response(self, mock_llm_class):
        """Test handling of malformed JSON responses"""
        # Mock LLM with malformed JSON
        mock_llm = Mock()
        mock_response = Mock()
        mock_response.content = "This is not valid JSON"
        mock_llm.invoke.return_value = mock_response
        mock_llm_class.return_value = mock_llm
        
        with patch.dict(os.environ, {'GOOGLE_API_KEY': 'test_key'}):
            detector = SystemLogAnomalyDetector()
            
            result = detector.analyze_chunk(self.test_data.head(10))
            
            self.assertTrue(result.empty)
    
    def test_process_csv_file(self):
        """Test full CSV file processing"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            self.test_data.to_csv(f.name, index=False)
            
            with patch.dict(os.environ, {'GOOGLE_API_KEY': 'test_key'}):
                with patch('main.ChatGoogleGenerativeAI') as mock_llm_class:
                    # Mock LLM response
                    mock_llm = Mock()
                    mock_response = Mock()
                    mock_response.content = self.mock_normal_response
                    mock_llm.invoke.return_value = mock_response
                    mock_llm_class.return_value = mock_llm
                    
                    detector = SystemLogAnomalyDetector(chunk_size=25)
                    
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as output_f:
                        result = detector.process_csv_file(f.name, output_f.name)
                        
                        self.assertIsInstance(result, pd.DataFrame)
                        self.assertTrue(os.path.exists(output_f.name))
                        
                        # Cleanup
                        os.unlink(output_f.name)
            
            # Cleanup
            os.unlink(f.name)
    
    def test_retry_mechanism(self):
        """Test retry mechanism for failed API calls"""
        with patch.dict(os.environ, {'GOOGLE_API_KEY': 'test_key'}):
            with patch('main.ChatGoogleGenerativeAI') as mock_llm_class:
                # Mock LLM to fail first two attempts, succeed on third
                mock_llm = Mock()
                mock_llm.invoke.side_effect = [
                    Exception("API Error"),
                    Exception("API Error"),
                    Mock(content=self.mock_normal_response)
                ]
                mock_llm_class.return_value = mock_llm
                
                detector = SystemLogAnomalyDetector()
                detector.max_retries = 3
                detector.retry_delay = 0.1  # Fast retry for testing
                
                result = detector.analyze_chunk_with_retry(self.test_data.head(10), 1)
                
                self.assertIsInstance(result, pd.DataFrame)
                # Should have made 3 calls (2 failures + 1 success)
                self.assertEqual(mock_llm.invoke.call_count, 3)

class TestAdvancedAnalytics(unittest.TestCase):
    """Test cases for advanced analytics module"""
    
    def setUp(self):
        """Set up test data for advanced analytics"""
        self.test_data = pd.DataFrame({
            'timestamp': pd.date_range('2024-01-01', periods=1000, freq='1min'),
            'level': np.random.choice(['INFO', 'WARNING', 'ERROR', 'DEBUG'], 1000),
            'message': [f'Log message {i}' for i in range(1000)],
            'source_ip': ['192.168.1.' + str(i % 255) for i in range(1000)]
        })
    
    def test_feature_extraction(self):
        """Test numerical feature extraction"""
        try:
            from advanced_analytics import AdvancedLogAnalytics
            
            analytics = AdvancedLogAnalytics()
            features = analytics.extract_numerical_features(self.test_data)
            
            self.assertFalse(features.empty)
            self.assertIn('hour', features.columns)
            self.assertIn('message_length', features.columns)
            self.assertIn('level_numeric', features.columns)
        except ImportError:
            self.skipTest("Advanced analytics module not available")
    
    def test_ml_based_detection(self):
        """Test machine learning based anomaly detection"""
        try:
            from advanced_analytics import AdvancedLogAnalytics
            
            analytics = AdvancedLogAnalytics()
            result = analytics.ml_based_detection(self.test_data.copy())
            
            self.assertIn('ml_anomaly_score', result.columns)
            self.assertIn('ml_is_anomaly', result.columns)
            self.assertEqual(len(result), len(self.test_data))
        except ImportError:
            self.skipTest("Advanced analytics module not available")

class PerformanceTest(unittest.TestCase):
    """Performance tests for the anomaly detection system"""
    
    def setUp(self):
        """Set up large dataset for performance testing"""
        # Create larger dataset for performance testing
        self.large_dataset = pd.DataFrame({
            'timestamp': pd.date_range('2024-01-01', periods=10000, freq='1min'),
            'level': np.random.choice(['INFO', 'WARNING', 'ERROR', 'DEBUG'], 10000),
            'message': [f'Performance test log message {i}' for i in range(10000)],
            'source': ['perf_test.py'] * 10000
        })
    
    def test_large_dataset_processing_time(self):
        """Test processing time for large datasets"""
        with patch.dict(os.environ, {'GOOGLE_API_KEY': 'test_key'}):
            with patch('main.ChatGoogleGenerativeAI') as mock_llm_class:
                # Mock fast LLM response
                mock_llm = Mock()
                mock_response = Mock()
                mock_response.content = json.dumps([])  # No anomalies for speed
                mock_llm.invoke.return_value = mock_response
                mock_llm_class.return_value = mock_llm
                
                detector = SystemLogAnomalyDetector(chunk_size=100)
                detector.rate_limit_delay = 0  # Remove delays for performance test
                
                start_time = time.time()
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                    self.large_dataset.to_csv(f.name, index=False)
                    
                    result = detector.process_csv_file(f.name)
                    
                    processing_time = time.time() - start_time
                    
                    # Should process 10000 logs in reasonable time (adjust threshold as needed)
                    self.assertLess(processing_time, 60)  # 60 seconds threshold
                    self.assertIsInstance(result, pd.DataFrame)
                    
                    # Cleanup
                    os.unlink(f.name)
    
    def test_memory_usage(self):
        """Test memory usage with large datasets"""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        with patch.dict(os.environ, {'GOOGLE_API_KEY': 'test_key'}):
            with patch('main.ChatGoogleGenerativeAI') as mock_llm_class:
                mock_llm = Mock()
                mock_response = Mock()
                mock_response.content = json.dumps([])
                mock_llm.invoke.return_value = mock_response
                mock_llm_class.return_value = mock_llm
                
                detector = SystemLogAnomalyDetector(chunk_size=100)
                
                # Process multiple chunks
                for i in range(10):
                    detector.analyze_chunk(self.large_dataset.iloc[i*100:(i+1)*100])
                
                final_memory = process.memory_info().rss / 1024 / 1024  # MB
                memory_increase = final_memory - initial_memory
                
                # Memory increase should be reasonable (adjust threshold as needed)
                self.assertLess(memory_increase, 100)  # 100 MB threshold

class IntegrationTest(unittest.TestCase):
    """Integration tests for end-to-end functionality"""
    
    def test_complete_workflow(self):
        """Test complete anomaly detection workflow"""
        # Create test log file
        test_logs = pd.DataFrame({
            'timestamp': pd.date_range('2024-01-01', periods=50, freq='1H'),
            'level': ['INFO'] * 40 + ['ERROR'] * 10,
            'message': [f'Normal operation {i}' for i in range(40)] + 
                      ['Suspicious activity detected'] * 10,
            'source': ['app.py'] * 50
        })
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as input_file:
            test_logs.to_csv(input_file.name, index=False)
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as output_file:
                
                # Mock environment and LLM
                with patch.dict(os.environ, {'GOOGLE_API_KEY': 'test_key'}):
                    with patch('main.ChatGoogleGenerativeAI') as mock_llm_class:
                        # Mock LLM to return anomalies for ERROR logs
                        mock_llm = Mock()
                        
                        def mock_invoke(messages):
                            # Check if chunk contains ERROR logs
                            csv_content = messages[1].content
                            if 'ERROR' in csv_content:
                                return Mock(content=json.dumps([{
                                    'timestamp': '2024-01-01 12:00:00',
                                    'level': 'ERROR',
                                    'message': 'Suspicious activity detected',
                                    'source': 'app.py',
                                    'anomaly_reason': 'Repeated suspicious activity',
                                    'remediation_steps': 'Investigate source'
                                }]))
                            else:
                                return Mock(content=json.dumps([]))
                        
                        mock_llm.invoke.side_effect = mock_invoke
                        mock_llm_class.return_value = mock_llm
                        
                        # Test main function
                        config = {
                            'input_csv_path': input_file.name,
                            'output_csv_path': output_file.name,
                            'chunk_size': 10,
                            'log_level': 'INFO'
                        }
                        
                        from main import main
                        result = main(config)
                        
                        self.assertEqual(result, 0)  # Success
                        self.assertTrue(os.path.exists(output_file.name))
                        
                        # Check output file has anomalies
                        output_data = pd.read_csv(output_file.name)
                        self.assertFalse(output_data.empty)
                        
                # Cleanup
                os.unlink(output_file.name)
            
            # Cleanup
            os.unlink(input_file.name)

def create_test_suite():
    """Create a comprehensive test suite"""
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTest(unittest.makeSuite(TestSystemLogAnomalyDetector))
    suite.addTest(unittest.makeSuite(TestAdvancedAnalytics))
    suite.addTest(unittest.makeSuite(PerformanceTest))
    suite.addTest(unittest.makeSuite(IntegrationTest))
    
    return suite

def run_tests():
    """Run all tests and generate report"""
    print("Running Comprehensive Test Suite")
    print("=" * 50)
    
    # Create and run test suite
    suite = create_test_suite()
    runner = unittest.TextTestRunner(verbosity=2)
    
    start_time = time.time()
    result = runner.run(suite)
    end_time = time.time()
    
    # Generate test report
    print("\n" + "=" * 50)
    print("TEST RESULTS SUMMARY")
    print("=" * 50)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    print(f"Total time: {end_time - start_time:.2f} seconds")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)