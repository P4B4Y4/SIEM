"""
JFS SIEM - Path Manager
Fixes: Issue #7 (ML models wrong directory), Issue #4 (Service import paths)
"""

import os
import sys

class PathManager:
    """Manages all file paths for JFS SIEM"""
    
    def __init__(self):
        self._base_dir = None
        self._init_paths()
    
    def _init_paths(self):
        """Initialize base directory"""
        # Get the directory where this file is located
        current_file = os.path.abspath(__file__)
        # common -> python -> base
        self._base_dir = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
    
    def get_base_dir(self):
        """Get base installation directory"""
        return self._base_dir
    
    def get_config_dir(self):
        """Get configuration directory"""
        return os.path.join(self._base_dir, 'config')
    
    def get_logs_dir(self):
        """Get logs directory"""
        return os.path.join(self._base_dir, 'logs')
    
    def get_models_dir(self):
        """Get ML models directory"""
        return os.path.join(self._base_dir, 'models')
    
    def get_python_dir(self):
        """Get python directory"""
        return os.path.join(self._base_dir, 'python')
    
    def get_scripts_dir(self):
        """Get scripts directory"""
        return os.path.join(self._base_dir, 'scripts')
    
    def get_web_dir(self):
        """Get web directory"""
        return os.path.join(self._base_dir, 'web')
    
    def get_database_dir(self):
        """Get database directory"""
        return os.path.join(self._base_dir, 'database')
    
    def ensure_directory(self, path):
        """
        Ensure directory exists, create if it doesn't
        
        Args:
            path: Directory path
        
        Returns:
            bool: True if directory exists or was created
        """
        if not os.path.exists(path):
            try:
                os.makedirs(path)
                return True
            except Exception as e:
                print(f"Failed to create directory {path}: {e}")
                return False
        return True
    
    def setup_python_path(self):
        """
        Setup Python import paths for the SIEM
        Fixes import issues in Windows Service
        """
        python_dir = self.get_python_dir()
        if python_dir not in sys.path:
            sys.path.insert(0, python_dir)

# Global instance
_path_manager = None

def get_path_manager():
    """Get global path manager instance"""
    global _path_manager
    if _path_manager is None:
        _path_manager = PathManager()
    return _path_manager
