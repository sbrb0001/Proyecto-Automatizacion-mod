

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SWITCHES_FILE = os.path.join(BASE_DIR, 'devices', 'switches.json')

BACKUP_DIR = os.path.join(BASE_DIR, 'static', 'backups')

SECRET_KEY = '1234'


