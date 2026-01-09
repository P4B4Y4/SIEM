"""
JFS SIEM - Configuration Manager
Centralized configuration management for all components
Fixes Issue #1 (Empty passwords) and Issue #18 (Hardcoded config)
"""

import configparser
import os
import sys

class ConfigManager:
    """Manages all configuration files for JFS SIEM"""
    
    def __init__(self):
        # Get the base directory (JFS-SIEM-FIXED)
        self.base_dir = self._get_base_dir()
        self.config_dir = os.path.join(self.base_dir, 'config')
        
        # Ensure config directory exists
        if not os.path.exists(self.config_dir):
            raise Exception(f"Config directory not found: {self.config_dir}")
        
        self._configs = {}
    
    def _get_base_dir(self):
        """Get the base installation directory"""
        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # Go up to base directory: common -> python -> base
        base_dir = os.path.dirname(os.path.dirname(script_dir))
        return base_dir
    
    def get_config(self, config_name):
        """
        Load and return a configuration file
        
        Args:
            config_name: Name of config file without .ini extension
                        (e.g., 'database', 'eset', 'fortigate')
        
        Returns:
            configparser.ConfigParser object
        """
        if config_name in self._configs:
            return self._configs[config_name]
        
        config_file = os.path.join(self.config_dir, f'{config_name}.ini')
        
        if not os.path.exists(config_file):
            raise Exception(f"Configuration file not found: {config_file}")
        
        config = configparser.ConfigParser()
        config.read(config_file)
        
        self._configs[config_name] = config
        return config
    
    def get_database_config(self):
        """Get database configuration"""
        config = self.get_config('database')
        return {
            'host': config.get('database', 'host'),
            'port': config.getint('database', 'port'),
            'user': config.get('database', 'user'),
            'password': config.get('database', 'password'),
            'database': config.get('database', 'database'),
            'charset': config.get('database', 'charset'),
            'pool_name': config.get('connection_pool', 'pool_name'),
            'pool_size': config.getint('connection_pool', 'pool_size'),
            'pool_reset_session': config.getboolean('connection_pool', 'pool_reset_session')
        }
    
    def get_eset_config(self):
        """Get ESET configuration"""
        config = self.get_config('eset')
        return {
            'enabled': config.getboolean('eset', 'enabled'),
            'server_host': config.get('eset', 'server_host'),
            'server_port': config.getint('eset', 'server_port'),
            'username': config.get('eset', 'username'),
            'password': config.get('eset', 'password'),
            'use_ssl': config.getboolean('eset', 'use_ssl'),
            'verify_ssl': config.getboolean('eset', 'verify_ssl'),
            'max_events': config.getint('collection', 'max_events'),
            'time_window_hours': config.getint('collection', 'time_window_hours'),
            'simulation_mode': config.getboolean('simulation', 'simulation_mode')
        }
    
    def get_fortigate_config(self):
        """Get FortiGate configuration"""
        config = self.get_config('fortigate')
        return {
            'enabled': config.getboolean('fortigate', 'enabled'),
            'firewall_host': config.get('fortigate', 'firewall_host'),
            'firewall_port': config.getint('fortigate', 'firewall_port'),
            'api_token': config.get('fortigate', 'api_token'),
            'use_ssl': config.getboolean('fortigate', 'use_ssl'),
            'verify_ssl': config.getboolean('fortigate', 'verify_ssl'),
            'max_events': config.getint('collection', 'max_events'),
            'time_window_minutes': config.getint('collection', 'time_window_minutes'),
            'simulation_mode': config.getboolean('simulation', 'simulation_mode')
        }
    
    def get_soar_config(self):
        """Get SOAR configuration"""
        config = self.get_config('soar')
        return {
            'enabled': config.getboolean('soar', 'enabled'),
            'simulation_mode': config.getboolean('soar', 'simulation_mode'),
            'enable_block_ip': config.getboolean('actions', 'enable_block_ip'),
            'enable_isolate_host': config.getboolean('actions', 'enable_isolate_host'),
            'enable_kill_process': config.getboolean('actions', 'enable_kill_process'),
            'enable_reset_password': config.getboolean('actions', 'enable_reset_password'),
            'enable_email_alert': config.getboolean('actions', 'enable_email_alert'),
            'enable_create_ticket': config.getboolean('actions', 'enable_create_ticket'),
            'smtp_server': config.get('email', 'smtp_server'),
            'smtp_port': config.getint('email', 'smtp_port'),
            'smtp_use_tls': config.getboolean('email', 'smtp_use_tls'),
            'smtp_username': config.get('email', 'smtp_username'),
            'smtp_password': config.get('email', 'smtp_password'),
            'from_email': config.get('email', 'from_email'),
            'to_emails': [email.strip() for email in config.get('email', 'to_emails').split(',')],
            'firewall_type': config.get('firewall', 'firewall_type'),
            'allowed_processes': [proc.strip() for proc in config.get('process_control', 'allowed_processes').split(',')],
            'failed_login_threshold': config.getint('thresholds', 'failed_login_threshold'),
            'high_severity_threshold': config.getint('thresholds', 'high_severity_threshold')
        }
    
    def get_remote_pcs_config(self):
        """Get remote PCs configuration"""
        config = self.get_config('remote_pcs')
        pc_list_str = config.get('remote_pcs', 'pc_list')
        
        # Parse PC list
        pcs = []
        for pc in pc_list_str.split(','):
            pc = pc.strip()
            if ':' in pc:
                parts = pc.split(':')
                pcs.append({
                    'name': parts[0],
                    'username': parts[1] if len(parts) > 1 else '',
                    'password': parts[2] if len(parts) > 2 else ''
                })
            else:
                pcs.append({
                    'name': pc,
                    'username': '',
                    'password': ''
                })
        
        return {
            'pcs': pcs,
            'max_events_per_log': config.getint('collection', 'max_events_per_log'),
            'collect_security': config.getboolean('collection', 'collect_security'),
            'collect_system': config.getboolean('collection', 'collect_system'),
            'collect_application': config.getboolean('collection', 'collect_application'),
            'connection_timeout': config.getint('collection', 'connection_timeout')
        }

# Global instance
_config_manager = None

def get_config_manager():
    """Get global configuration manager instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager
