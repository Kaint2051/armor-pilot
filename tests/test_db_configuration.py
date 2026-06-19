# Copyright 2026 ArmorPilot Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app.db as db


class DatabaseConfigurationTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.original_db_path = db.DB_PATH
        db.DB_PATH = str(Path(self.temp_dir.name) / "users.db")
        self.addCleanup(self._restore_db_path)

    def _restore_db_path(self):
        db.DB_PATH = self.original_db_path

    def test_fresh_database_requires_admin_credentials(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ADMIN_USER", None)
            os.environ.pop("ADMIN_PASS", None)
            with self.assertRaisesRegex(RuntimeError, "ADMIN_USER must be configured"):
                db.init_db()

    def test_fresh_database_rejects_short_admin_password(self):
        with patch.dict(os.environ, {
            "ADMIN_USER": "admin",
            "ADMIN_PASS": "too-short",
        }):
            with self.assertRaisesRegex(RuntimeError, "at least 12 characters"):
                db.init_db()

    def test_fresh_database_seeds_configured_admin(self):
        with patch.dict(os.environ, {
            "ADMIN_USER": "security-admin",
            "ADMIN_PASS": "correct-horse-battery-staple",
        }):
            db.init_db()

        user = db.get_user("security-admin")
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "admin")
        self.assertTrue(db.verify_password("correct-horse-battery-staple", user["password_hash"]))


if __name__ == "__main__":
    unittest.main()
