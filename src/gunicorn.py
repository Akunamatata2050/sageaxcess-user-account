import os

if os.environ.get('MODE') == 'dev':
    reload = True
    
bind = '0.0.0.0:5000'
workers = 4
threads = 4