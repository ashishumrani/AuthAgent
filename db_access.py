import os
from dotenv import load_dotenv
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row  # results as dictionaries

class PostgresDB:
    def __init__(self, conn_str=None, min_size=1, max_size=10):
        """
        Initialize connection pool.
        :param conn_str: PostgreSQL connection string. Example:
                         "postgresql://user:password@localhost:5432/mydb"
        :param min_size: Minimum connections in pool
        :param max_size: Maximum connections in pool
        """
        load_dotenv(override=True)
        self.conn_str = conn_str or os.getenv("POSTGRES_CONN_STR")
        if not self.conn_str:
            raise ValueError("Connection string must be provided or set in POSTGRES_CONN_STR env variable")

        self.pool = ConnectionPool(
            conninfo=self.conn_str,
            min_size=min_size,
            max_size=max_size,
            open=True
        )

    def execute(self, sql, params=None, commit=False):
        """
        Execute a SQL command (INSERT/UPDATE/DELETE).
        :param sql: SQL string
        :param params: tuple or dict of parameters
        :param commit: whether to commit transaction
        :return: rowcount
        """
        with self.pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params or ())
                if commit:
                    conn.commit()
                return cur.rowcount

    def fetch_one(self, sql, params=None):
        """
        Fetch a single row.
        """
        with self.pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params or ())
                return cur.fetchone()

    def fetch_all(self, sql, params=None):
        """
        Fetch multiple rows.
        """
        with self.pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params or ())
                return cur.fetchall()

    def close(self):
        """
        Close the pool.
        """
        self.pool.close()
