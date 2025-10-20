"""
Advanced Analytics Module for Log Anomaly Detection
Provides statistical analysis, ML-based detection, and visualization capabilities
"""

import pandas as pd
import numpy as np
from typing import List, Dict, Any, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import warnings
warnings.filterwarnings('ignore')

class AdvancedLogAnalytics:
    """Advanced analytics for log anomaly detection"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        
    def extract_numerical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract numerical features from log data"""
        features = pd.DataFrame()
        
        # Basic features
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            features['hour'] = df['timestamp'].dt.hour
            features['day_of_week'] = df['timestamp'].dt.dayofweek
            features['is_weekend'] = (df['timestamp'].dt.dayofweek >= 5).astype(int)
        
        # Log message length features
        if 'message' in df.columns:
            features['message_length'] = df['message'].str.len()
            features['word_count'] = df['message'].str.split().str.len()
            features['special_char_count'] = df['message'].str.count(r'[^a-zA-Z0-9\s]')
        
        # Log level encoding
        if 'level' in df.columns:
            level_mapping = {'DEBUG': 1, 'INFO': 2, 'WARNING': 3, 'ERROR': 4, 'CRITICAL': 5}
            features['level_numeric'] = df['level'].map(level_mapping).fillna(2)
        
        # IP address features (if present)
        ip_columns = [col for col in df.columns if 'ip' in col.lower()]
        for ip_col in ip_columns:
            features[f'{ip_col}_is_private'] = df[ip_col].str.match(
                r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'
            ).astype(int)
        
        return features.fillna(0)
    
    def ml_based_detection(self, df: pd.DataFrame) -> pd.DataFrame:
        """Use machine learning for anomaly detection"""
        # Extract features
        features = self.extract_numerical_features(df)
        
        if features.empty:
            df['ml_anomaly_score'] = 0
            df['ml_is_anomaly'] = False
            return df
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # Detect anomalies
        anomaly_scores = self.isolation_forest.fit_predict(features_scaled)
        decision_scores = self.isolation_forest.decision_function(features_scaled)
        
        # Add results to dataframe
        df['ml_anomaly_score'] = -decision_scores  # Higher score = more anomalous
        df['ml_is_anomaly'] = anomaly_scores == -1
        
        return df
    
    def text_based_analysis(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze log messages using NLP techniques"""
        if 'message' not in df.columns:
            return {}
        
        messages = df['message'].dropna()
        
        # TF-IDF analysis
        try:
            tfidf_matrix = self.tfidf_vectorizer.fit_transform(messages)
            feature_names = self.tfidf_vectorizer.get_feature_names_out()
            
            # Get top terms
            mean_scores = np.mean(tfidf_matrix.toarray(), axis=0)
            top_terms_indices = np.argsort(mean_scores)[-20:][::-1]
            top_terms = [(feature_names[i], mean_scores[i]) for i in top_terms_indices]
            
            return {
                'top_terms': top_terms,
                'vocabulary_size': len(feature_names),
                'average_message_length': messages.str.len().mean(),
                'unique_messages': len(messages.unique()),
                'total_messages': len(messages)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def temporal_analysis(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze temporal patterns in logs"""
        if 'timestamp' not in df.columns:
            return {}
        
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df_clean = df.dropna(subset=['timestamp'])
        
        if df_clean.empty:
            return {}
        
        # Hourly distribution
        hourly_counts = df_clean.groupby(df_clean['timestamp'].dt.hour).size()
        
        # Daily distribution
        daily_counts = df_clean.groupby(df_clean['timestamp'].dt.date).size()
        
        # Detect time-based anomalies
        hourly_mean = hourly_counts.mean()
        hourly_std = hourly_counts.std()
        anomalous_hours = hourly_counts[
            (hourly_counts < hourly_mean - 2*hourly_std) | 
            (hourly_counts > hourly_mean + 2*hourly_std)
        ]
        
        return {
            'hourly_distribution': hourly_counts.to_dict(),
            'daily_distribution': daily_counts.to_dict(),
            'peak_hour': hourly_counts.idxmax(),
            'quiet_hour': hourly_counts.idxmin(),
            'anomalous_hours': anomalous_hours.to_dict(),
            'total_time_span': str(df_clean['timestamp'].max() - df_clean['timestamp'].min())
        }
    
    def generate_visualizations(self, df: pd.DataFrame, anomalies: pd.DataFrame, 
                              output_dir: str = "visualizations") -> List[str]:
        """Generate various visualizations"""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        generated_files = []
        
        # 1. Anomaly distribution by category
        if not anomalies.empty and 'anomaly_reason' in anomalies.columns:
            plt.figure(figsize=(12, 6))
            
            # Extract categories from anomaly reasons
            categories = []
            for reason in anomalies['anomaly_reason']:
                if 'security' in reason.lower() or 'breach' in reason.lower():
                    categories.append('Security')
                elif 'performance' in reason.lower():
                    categories.append('Performance')
                elif 'error' in reason.lower() or 'failure' in reason.lower():
                    categories.append('System Error')
                elif 'access' in reason.lower():
                    categories.append('Access Control')
                else:
                    categories.append('Other')
            
            category_counts = pd.Series(categories).value_counts()
            
            plt.pie(category_counts.values, labels=category_counts.index, autopct='%1.1f%%')
            plt.title('Distribution of Anomaly Categories')
            plt.tight_layout()
            
            pie_chart_path = os.path.join(output_dir, 'anomaly_categories.png')
            plt.savefig(pie_chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            generated_files.append(pie_chart_path)
        
        # 2. Temporal analysis visualization
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df_clean = df.dropna(subset=['timestamp'])
            
            if not df_clean.empty:
                plt.figure(figsize=(15, 8))
                
                # Hourly distribution
                plt.subplot(2, 2, 1)
                hourly_counts = df_clean.groupby(df_clean['timestamp'].dt.hour).size()
                hourly_counts.plot(kind='bar')
                plt.title('Log Distribution by Hour')
                plt.xlabel('Hour of Day')
                plt.ylabel('Log Count')
                
                # Daily distribution
                plt.subplot(2, 2, 2)
                daily_counts = df_clean.groupby(df_clean['timestamp'].dt.date).size()
                daily_counts.plot()
                plt.title('Log Distribution by Date')
                plt.xlabel('Date')
                plt.ylabel('Log Count')
                plt.xticks(rotation=45)
                
                # Log level distribution
                if 'level' in df.columns:
                    plt.subplot(2, 2, 3)
                    level_counts = df['level'].value_counts()
                    level_counts.plot(kind='bar')
                    plt.title('Log Level Distribution')
                    plt.xlabel('Log Level')
                    plt.ylabel('Count')
                
                # Anomaly timeline
                if not anomalies.empty and 'timestamp' in anomalies.columns:
                    plt.subplot(2, 2, 4)
                    anomalies['timestamp'] = pd.to_datetime(anomalies['timestamp'], errors='coerce')
                    anomaly_hourly = anomalies.groupby(anomalies['timestamp'].dt.hour).size()
                    anomaly_hourly.plot(kind='bar', color='red')
                    plt.title('Anomaly Distribution by Hour')
                    plt.xlabel('Hour of Day')
                    plt.ylabel('Anomaly Count')
                
                plt.tight_layout()
                
                temporal_chart_path = os.path.join(output_dir, 'temporal_analysis.png')
                plt.savefig(temporal_chart_path, dpi=300, bbox_inches='tight')
                plt.close()
                generated_files.append(temporal_chart_path)
        
        # 3. Interactive dashboard (HTML)
        if not anomalies.empty:
            # Create interactive plot with Plotly
            fig = go.Figure()
            
            # Add anomaly timeline if timestamp exists
            if 'timestamp' in anomalies.columns:
                anomalies['timestamp'] = pd.to_datetime(anomalies['timestamp'], errors='coerce')
                anomaly_timeline = anomalies.dropna(subset=['timestamp'])
                
                if not anomaly_timeline.empty:
                    fig.add_trace(go.Scatter(
                        x=anomaly_timeline['timestamp'],
                        y=anomaly_timeline.index,
                        mode='markers',
                        marker=dict(size=8, color='red'),
                        text=anomaly_timeline['anomaly_reason'],
                        hovertemplate='<b>Time:</b> %{x}<br><b>Reason:</b> %{text}<extra></extra>',
                        name='Anomalies'
                    ))
            
            fig.update_layout(
                title='Anomaly Detection Dashboard',
                xaxis_title='Time',
                yaxis_title='Anomaly Index',
                hovermode='closest'
            )
            
            dashboard_path = os.path.join(output_dir, 'interactive_dashboard.html')
            fig.write_html(dashboard_path)
            generated_files.append(dashboard_path)
        
        return generated_files
    
    def comprehensive_analysis(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Perform comprehensive analysis on log data"""
        results = {}
        
        # ML-based analysis
        try:
            ml_results = self.ml_based_detection(df.copy())
            ml_anomalies = ml_results[ml_results['ml_is_anomaly'] == True]
            results['ml_analysis'] = {
                'total_anomalies': len(ml_anomalies),
                'anomaly_percentage': len(ml_anomalies) / len(df) * 100,
                'avg_anomaly_score': ml_anomalies['ml_anomaly_score'].mean() if not ml_anomalies.empty else 0
            }
        except Exception as e:
            results['ml_analysis'] = {'error': str(e)}
        
        # Text analysis
        results['text_analysis'] = self.text_based_analysis(df)
        
        # Temporal analysis
        results['temporal_analysis'] = self.temporal_analysis(df)
        
        # Statistical summary
        results['statistical_summary'] = {
            'total_logs': len(df),
            'unique_sources': df.get('source', pd.Series([])).nunique(),
            'date_range': {
                'start': str(df['timestamp'].min()) if 'timestamp' in df.columns else None,
                'end': str(df['timestamp'].max()) if 'timestamp' in df.columns else None
            },
            'log_levels': df.get('level', pd.Series([])).value_counts().to_dict()
        }
        
        return results

def create_html_report(analysis_results: Dict[str, Any], anomalies: pd.DataFrame, 
                      output_file: str = "comprehensive_report.html"):
    """Create an HTML report with all analysis results"""
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Log Anomaly Detection Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
            .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
            .anomaly {{ background-color: #ffe6e6; margin: 10px 0; padding: 10px; border-radius: 3px; }}
            .metric {{ display: inline-block; margin: 10px; padding: 10px; background-color: #e6f3ff; border-radius: 3px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>System Log Anomaly Detection Report</h1>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="metric">Total Logs: {analysis_results.get('statistical_summary', {}).get('total_logs', 'N/A')}</div>
            <div class="metric">Anomalies Found: {len(anomalies)}</div>
            <div class="metric">Anomaly Rate: {len(anomalies) / analysis_results.get('statistical_summary', {}).get('total_logs', 1) * 100:.2f}%</div>
        </div>
        
        <div class="section">
            <h2>Machine Learning Analysis</h2>
            <p>ML-detected anomalies: {analysis_results.get('ml_analysis', {}).get('total_anomalies', 'N/A')}</p>
            <p>Average anomaly score: {analysis_results.get('ml_analysis', {}).get('avg_anomaly_score', 'N/A')}</p>
        </div>
        
        <div class="section">
            <h2>Top Anomalies</h2>
    """
    
    # Add top anomalies
    for idx, (_, row) in enumerate(anomalies.head(10).iterrows()):
        html_content += f"""
            <div class="anomaly">
                <strong>Anomaly {idx + 1}:</strong><br>
                <strong>Reason:</strong> {row.get('anomaly_reason', 'N/A')}<br>
                <strong>Remediation:</strong> {row.get('remediation_steps', 'N/A')}<br>
                <strong>Timestamp:</strong> {row.get('timestamp', 'N/A')}
            </div>
        """
    
    html_content += """
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <ul>
    """
    
    # Add recommendations based on analysis
    if len(anomalies) > 20:
        html_content += "<li>High number of anomalies detected - consider reviewing system security policies</li>"
    
    if 'security' in str(anomalies.get('anomaly_reason', '')).lower():
        html_content += "<li>Security-related anomalies found - implement additional monitoring</li>"
    
    html_content += """
            </ul>
        </div>
    </body>
    </html>
    """
    
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    return output_file