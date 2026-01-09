"""
JFS SIEM - Database Manager with Connection Pooling
Fixes: Issue #1 (Empty passwords), Issue #22 (Connection pooling), Issue #6 (Hardcoded localhost)
"""

import mysql.connector
from mysql.connector import pooling, Error
from .config_manager import get_config_manager
from .logger import get_logger
import sys

class DatabaseManager:
    """Manages database connections with pooling and security"""
    
    _instance = None
    _pool = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._pool is None:
            self._initialize_pool()
        self.logger = get_logger('database')
    
    def _initialize_pool(self):
        """Initialize connection pool"""
        try:
            config_mgr = get_config_manager()
            db_config = config_mgr.get_database_config()
            
            self._pool = pooling.MySQLConnectionPool(
                pool_name=db_config['pool_name'],
                pool_size=db_config['pool_size'],
                pool_reset_session=db_config['pool_reset_session'],
                host=db_config['host'],
                port=db_config['port'],
                user=db_config['user'],
                password=db_config['password'],
                database=db_config['database'],
                charset=db_config['charset'],
                autocommit=False
            )
            
        except Error as e:
            print(f"FATAL: Failed to initialize database connection pool: {e}")
            sys.exit(1)
    
    def get_connection(self):
        """
        Get a connection from the pool
        
        Returns:
            mysql.connector.connection.MySQLConnection
        
        Raises:
            Error: If connection cannot be obtained
        """
        try:
            connection = self._pool.get_connection()
            return connection
        except Error as e:
            self.logger.error(f"Failed to get database connection: {e}")
            raise
    
    def execute_query(self, query, params=None, fetch=False):
        """
        Execute a query with automatic connection management
        
        Args:
            query: SQL query string
            params: Query parameters (tuple or dict)
            fetch: Whether to fetch results
        
        Returns:
            For fetch=True: List of rows
            For fetch=False: Number of affected rows
        """
        connection = None
        cursor = None
        
        try:
            connection = self.get_connection()
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute(query, params or ())
            
            if fetch:
                results = cursor.fetchall()
                return results
            else:
                connection.commit()
                return cursor.rowcount
                
        except Error as e:
            if connection:
                connection.rollback()
            self.logger.error(f"Query execution failed: {e}")
            self.logger.error(f"Query: {query}")
            raise
            
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
    
    def execute_many(self, query, data_list):
        """
        Execute same query with multiple parameter sets
        
        Args:
            query: SQL query string
            data_list: List of parameter tuples
        
        Returns:
            Number of affected rows
        """
        connection = None
        cursor = None
        
        try:
            connection = self.get_connection()
            cursor = connection.cursor()
            
            cursor.executemany(query, data_list)
            connection.commit()
            
            return cursor.rowcount
            
        except Error as e:
            if connection:
                connection.rollback()
            self.logger.error(f"Batch execution failed: {e}")
            raise
            
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()
    
    def test_connection(self):
        """
        Test database connectivity
        
        Returns:
            bool: True if connection successful
        """
        try:
            connection = self.get_connection()
            cursor = connection.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            connection.close()
            return True
        except Error as e:
            self.logger.error(f"Database connection test failed: {e}")
            return False

# Global instance
_db_manager = None

def get_db_manager():
    """Get global database manager instance"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager
