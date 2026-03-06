"""
GUARDIAN Memory Vault
Saves successful relay outputs, retrieves best prior solutions.
The compound interest of the hive.
Adapted from Swarm vault.py.
"""

import sqlite3
import datetime
import hashlib
from typing import Optional, List, Dict, Any

from . import config

DB_PATH = config.VAULT_DB


def init_vault():
    """Initialize the vault database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS solutions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            problem_hash TEXT NOT NULL,
            problem_text TEXT NOT NULL,
            solution TEXT NOT NULL,
            score INTEGER DEFAULT 0,
            model_chain TEXT,
            elapsed_seconds REAL,
            retrieval_count INTEGER DEFAULT 0,
            last_retrieved TEXT
        )
    ''')

    cursor.execute('''
        CREATE VIRTUAL TABLE IF NOT EXISTS solutions_fts USING fts5(
            problem_text, solution,
            content='solutions',
            content_rowid='id'
        )
    ''')

    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_problem_hash ON solutions(problem_hash)
    ''')

    conn.commit()
    conn.close()


def hash_problem(problem: str) -> str:
    return hashlib.sha256(problem.strip().lower().encode()).hexdigest()[:16]


def save_solution(problem: str, solution: str, score: int = 0,
                  model_chain: str = "", elapsed: float = 0.0) -> int:
    """Save a solution to the vault. Returns the solution ID."""
    init_vault()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    problem_hash = hash_problem(problem)

    cursor.execute('''
        SELECT id, score FROM solutions
        WHERE problem_hash = ?
        ORDER BY score DESC LIMIT 1
    ''', (problem_hash,))

    existing = cursor.fetchone()
    if existing and existing[1] >= score:
        conn.close()
        return existing[0]

    cursor.execute('''
        INSERT INTO solutions
        (timestamp, problem_hash, problem_text, solution, score, model_chain, elapsed_seconds)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.datetime.now().isoformat(),
        problem_hash, problem, solution, score, model_chain, elapsed
    ))

    solution_id = cursor.lastrowid

    cursor.execute('''
        INSERT INTO solutions_fts(rowid, problem_text, solution)
        VALUES (?, ?, ?)
    ''', (solution_id, problem, solution))

    conn.commit()
    conn.close()
    return solution_id


def get_best_prior(problem: str) -> Optional[Dict[str, Any]]:
    """Get the best prior solution for exact or similar problems."""
    init_vault()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    problem_hash = hash_problem(problem)

    cursor.execute('''
        SELECT id, problem_text, solution, score, model_chain, elapsed_seconds
        FROM solutions WHERE problem_hash = ?
        ORDER BY score DESC LIMIT 1
    ''', (problem_hash,))

    result = cursor.fetchone()
    if result:
        cursor.execute('''
            UPDATE solutions SET retrieval_count = retrieval_count + 1,
                last_retrieved = ? WHERE id = ?
        ''', (datetime.datetime.now().isoformat(), result[0]))
        conn.commit()
        conn.close()
        return {
            'id': result[0], 'problem': result[1], 'solution': result[2],
            'score': result[3], 'model_chain': result[4], 'elapsed': result[5],
            'match_type': 'exact'
        }

    # FTS search for similar
    try:
        terms = ' OR '.join(problem.split()[:10])
        cursor.execute('''
            SELECT s.id, s.problem_text, s.solution, s.score, s.model_chain, s.elapsed_seconds
            FROM solutions s JOIN solutions_fts fts ON s.id = fts.rowid
            WHERE solutions_fts MATCH ? ORDER BY s.score DESC LIMIT 1
        ''', (terms,))
        result = cursor.fetchone()
        if result and result[3] >= 7:
            cursor.execute('''
                UPDATE solutions SET retrieval_count = retrieval_count + 1,
                    last_retrieved = ? WHERE id = ?
            ''', (datetime.datetime.now().isoformat(), result[0]))
            conn.commit()
            conn.close()
            return {
                'id': result[0], 'problem': result[1], 'solution': result[2],
                'score': result[3], 'model_chain': result[4], 'elapsed': result[5],
                'match_type': 'similar'
            }
    except Exception:
        pass

    conn.close()
    return None


def search_vault(query: str, limit: int = 5) -> List[Dict[str, Any]]:
    """Search the vault for relevant solutions."""
    init_vault()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    results = []
    try:
        cursor.execute('''
            SELECT s.id, s.problem_text, s.solution, s.score, s.timestamp
            FROM solutions s JOIN solutions_fts fts ON s.id = fts.rowid
            WHERE solutions_fts MATCH ? ORDER BY s.score DESC LIMIT ?
        ''', (query, limit))
        for row in cursor.fetchall():
            results.append({
                'id': row[0], 'problem': row[1][:200],
                'solution': row[2][:500], 'score': row[3], 'timestamp': row[4]
            })
    except Exception:
        pass
    conn.close()
    return results


def get_vault_stats() -> Dict[str, Any]:
    """Get vault statistics."""
    init_vault()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM solutions')
    total = cursor.fetchone()[0]
    cursor.execute('SELECT AVG(score) FROM solutions')
    avg_score = cursor.fetchone()[0] or 0
    cursor.execute('SELECT SUM(retrieval_count) FROM solutions')
    total_retrievals = cursor.fetchone()[0] or 0

    conn.close()
    return {
        'total_solutions': total,
        'avg_score': round(avg_score, 1),
        'total_retrievals': total_retrievals,
    }
