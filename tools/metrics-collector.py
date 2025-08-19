#!/usr/bin/env python3
"""
Real-time VPN Metrics Collector
Collects actual strongSwan VPN metrics and system performance data
"""

import os
import sys
import time
import json
import argparse
import subprocess
import re
import psutil
import threading
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('metrics-collector')

@dataclass
class ConnectionMetrics:
    """Real VPN connection metrics"""
    connection_id: str
    state: str
    local_host: str
    remote_host: str
    remote_id: str
    established_time: datetime
    bytes_in: int
    bytes_out: int
    packets_in: int
    packets_out: int
    ike_version: str
    encr_alg: str
    integ_alg: str
    prf_alg: str
    dh_group: str
    esp_encr: str
    esp_integ: str
    rekey_time: Optional[datetime]
    lifetime: int
    is_pqc: bool

@dataclass
class SystemMetrics:
    """System performance metrics"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_used: int
    memory_total: int
    disk_usage_percent: float
    network_bytes_sent: int
    network_bytes_recv: int
    network_packets_sent: int
    network_packets_recv: int
    active_connections: int
    strongswan_status: str
    uptime_seconds: int

class StrongSwanParser:
    """Parser for strongSwan status and statistics"""
    
    def __init__(self):
        self.pqc_algorithms = {
            'kyber512', 'kyber768', 'kyber1024',
            'bike1l1', 'bike1l3', 'bike1l5',
            'hqc128', 'hqc192', 'hqc256'
        }
        self.pqc_signatures = {
            'dilithium2', 'dilithium3', 'dilithium5',
            'falcon512', 'falcon1024',
            'sphincsshake256s', 'sphincssha256s'
        }
    
    def parse_status_all(self) -> List[ConnectionMetrics]:
        """Parse ipsec statusall output for detailed connection info"""
        try:
            result = subprocess.run(['ipsec', 'statusall'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                logger.error(f"ipsec statusall failed: {result.stderr}")
                return []
            
            return self._parse_statusall_output(result.stdout)
        except subprocess.TimeoutExpired:
            logger.error("ipsec statusall timed out")
            return []
        except Exception as e:
            logger.error(f"Error parsing statusall: {e}")
            return []
    
    def _parse_statusall_output(self, output: str) -> List[ConnectionMetrics]:
        """Parse the actual statusall output"""
        connections = []
        current_conn = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Connection header (e.g., "pqc-pki[1]: ESTABLISHED")
            conn_match = re.match(r'(\w+)\[(\d+)\]:\s+ESTABLISHED\s+(.*)', line)
            if conn_match:
                conn_name = conn_match.group(1)
                conn_id = conn_match.group(2)
                details = conn_match.group(3)
                
                current_conn = {
                    'connection_id': f"{conn_name}[{conn_id}]",
                    'state': 'ESTABLISHED',
                    'established_time': self._parse_timestamp(details),
                    'local_host': '',
                    'remote_host': '',
                    'remote_id': '',
                    'bytes_in': 0,
                    'bytes_out': 0,
                    'packets_in': 0,
                    'packets_out': 0,
                    'ike_version': 'IKEv2',
                    'encr_alg': '',
                    'integ_alg': '',
                    'prf_alg': '',
                    'dh_group': '',
                    'esp_encr': '',
                    'esp_integ': '',
                    'rekey_time': None,
                    'lifetime': 3600,
                    'is_pqc': False
                }
                continue
            
            if current_conn is None:
                continue
            
            # Local/Remote hosts
            host_match = re.match(r'(\d+\.\d+\.\d+\.\d+)\[.*\]\.\.\.(\d+\.\d+\.\d+\.\d+)\[.*\]', line)
            if host_match:
                current_conn['local_host'] = host_match.group(1)
                current_conn['remote_host'] = host_match.group(2)
                continue
            
            # IKE algorithms
            ike_match = re.search(r'IKE.*?:\s+(.*)', line)
            if ike_match:
                algs = ike_match.group(1)
                current_conn.update(self._parse_ike_algorithms(algs))
                continue
            
            # ESP algorithms
            esp_match = re.search(r'ESP.*?:\s+(.*)', line)
            if esp_match:
                algs = esp_match.group(1)
                current_conn.update(self._parse_esp_algorithms(algs))
                continue
            
            # CHILD_SA with traffic stats
            child_match = re.search(r'CHILD_SA.*?(\d+)\s+bytes_i\s+\((\d+)\s+pkts.*?(\d+)\s+bytes_o\s+\((\d+)\s+pkts', line)
            if child_match:
                current_conn['bytes_in'] = int(child_match.group(1))
                current_conn['packets_in'] = int(child_match.group(2))
                current_conn['bytes_out'] = int(child_match.group(3))
                current_conn['packets_out'] = int(child_match.group(4))
                
                # Complete the connection and add to list
                conn_metrics = ConnectionMetrics(**current_conn)
                connections.append(conn_metrics)
                current_conn = None
        
        return connections
    
    def _parse_ike_algorithms(self, alg_string: str) -> Dict[str, Any]:
        """Parse IKE algorithm string"""
        result = {'is_pqc': False}
        
        # Example: "AES_GCM_16-256/PRF_HMAC_SHA2_512/MODP_3072"
        parts = alg_string.split('/')
        
        if len(parts) >= 1:
            result['encr_alg'] = parts[0].strip()
        if len(parts) >= 2:
            result['prf_alg'] = parts[1].strip()
        if len(parts) >= 3:
            dh_group = parts[2].strip()
            result['dh_group'] = dh_group
            # Check for PQC algorithms
            if any(pqc in dh_group.lower() for pqc in self.pqc_algorithms):
                result['is_pqc'] = True
        
        return result
    
    def _parse_esp_algorithms(self, alg_string: str) -> Dict[str, str]:
        """Parse ESP algorithm string"""
        result = {}
        
        # Example: "AES_GCM_16-256/MODP_3072"
        parts = alg_string.split('/')
        
        if len(parts) >= 1:
            result['esp_encr'] = parts[0].strip()
        if len(parts) >= 2:
            result['esp_integ'] = parts[1].strip()
        
        return result
    
    def _parse_timestamp(self, details: str) -> datetime:
        """Parse established timestamp from details"""
        # Try to extract time from details, fallback to now
        now = datetime.now()
        
        # Look for time patterns in the details
        time_match = re.search(r'(\d+)\s*seconds?\s*ago', details)
        if time_match:
            seconds_ago = int(time_match.group(1))
            return now - timedelta(seconds=seconds_ago)
        
        return now
    
    def get_strongswan_status(self) -> str:
        """Get overall strongSwan daemon status"""
        try:
            result = subprocess.run(['ipsec', 'status'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                if 'no connections' in result.stdout.lower():
                    return 'running_no_connections'
                elif 'ESTABLISHED' in result.stdout:
                    return 'running_with_connections'
                else:
                    return 'running'
            else:
                return 'error'
        except:
            return 'not_running'

class MetricsCollector:
    """Main metrics collection class"""
    
    def __init__(self, hub_ip: str, interval: int = 30):
        self.hub_ip = hub_ip
        self.interval = interval
        self.parser = StrongSwanParser()
        self.start_time = datetime.now()
        self.metrics_file = '/tmp/pqc-vpn-metrics.json'
        self.running = False
        
    def collect_system_metrics(self) -> SystemMetrics:
        """Collect real system performance metrics"""
        # Get network stats
        net_io = psutil.net_io_counters()
        
        # Count active network connections
        connections = psutil.net_connections()
        active_conns = sum(1 for conn in connections if conn.status == 'ESTABLISHED')
        
        # Get strongSwan status
        strongswan_status = self.parser.get_strongswan_status()
        
        # Calculate uptime
        uptime = (datetime.now() - self.start_time).total_seconds()
        
        return SystemMetrics(
            timestamp=datetime.now(),
            cpu_percent=psutil.cpu_percent(interval=1),
            memory_percent=psutil.virtual_memory().percent,
            memory_used=psutil.virtual_memory().used,
            memory_total=psutil.virtual_memory().total,
            disk_usage_percent=psutil.disk_usage('/').percent,
            network_bytes_sent=net_io.bytes_sent,
            network_bytes_recv=net_io.bytes_recv,
            network_packets_sent=net_io.packets_sent,
            network_packets_recv=net_io.packets_recv,
            active_connections=active_conns,
            strongswan_status=strongswan_status,
            uptime_seconds=int(uptime)
        )
    
    def collect_vpn_metrics(self) -> List[ConnectionMetrics]:
        """Collect real VPN connection metrics"""
        return self.parser.parse_status_all()
    
    def save_metrics(self, system_metrics: SystemMetrics, vpn_metrics: List[ConnectionMetrics]):
        """Save metrics to file for API consumption"""
        data = {
            'timestamp': system_metrics.timestamp.isoformat(),
            'system': asdict(system_metrics),
            'vpn_connections': [asdict(conn) for conn in vpn_metrics],
            'summary': {
                'total_connections': len(vpn_metrics),
                'pqc_connections': sum(1 for conn in vpn_metrics if conn.is_pqc),
                'total_bytes_in': sum(conn.bytes_in for conn in vpn_metrics),
                'total_bytes_out': sum(conn.bytes_out for conn in vpn_metrics),
                'hub_ip': self.hub_ip
            }
        }
        
        try:
            with open(self.metrics_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving metrics: {e}")
    
    def run_collection_loop(self):
        """Main collection loop"""
        logger.info(f"Starting metrics collection (interval: {self.interval}s)")
        self.running = True
        
        while self.running:
            try:
                # Collect metrics
                system_metrics = self.collect_system_metrics()
                vpn_metrics = self.collect_vpn_metrics()
                
                # Log summary
                logger.info(f"Collected metrics: {len(vpn_metrics)} VPN connections, "
                          f"{system_metrics.cpu_percent:.1f}% CPU, "
                          f"{system_metrics.memory_percent:.1f}% Memory")
                
                # Save to file
                self.save_metrics(system_metrics, vpn_metrics)
                
                # Wait for next collection
                time.sleep(self.interval)
                
            except KeyboardInterrupt:
                logger.info("Collection stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in collection loop: {e}")
                time.sleep(self.interval)
        
        self.running = False
    
    def update_once(self):
        """Single metrics update"""
        try:
            system_metrics = self.collect_system_metrics()
            vpn_metrics = self.collect_vpn_metrics()
            self.save_metrics(system_metrics, vpn_metrics)
            logger.info(f"Metrics updated: {len(vpn_metrics)} connections")
        except Exception as e:
            logger.error(f"Error updating metrics: {e}")

def main():
    parser = argparse.ArgumentParser(description='PQC-VPN Real Metrics Collector')
    parser.add_argument('--hub-ip', required=True, help='Hub IP address')
    parser.add_argument('--interval', type=int, default=30, help='Collection interval in seconds')
    parser.add_argument('--update', action='store_true', help='Single update instead of continuous')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    collector = MetricsCollector(args.hub_ip, args.interval)
    
    if args.update:
        collector.update_once()
    else:
        try:
            collector.run_collection_loop()
        except KeyboardInterrupt:
            logger.info("Shutting down metrics collector")

if __name__ == '__main__':
    main()
