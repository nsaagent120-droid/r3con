"""Web domain PRO v7.2 - Dashboard + Real-time + Analyzer."""
try:
    from .dashboard import create_app as create_app_v1
except ImportError:
    create_app_v1 = None

try:
    from .dashboard_v2 import create_app_v2, create_app, add_realtime_log, update_realtime_stats, SOCKETIO_AVAILABLE
except ImportError:
    create_app_v2 = None
    create_app = create_app_v1
    add_realtime_log = lambda *a, **k: None
    update_realtime_stats = lambda *a, **k: None
    SOCKETIO_AVAILABLE = False

__all__ = ["create_app_v1", "create_app_v2", "create_app", "add_realtime_log", "update_realtime_stats", "SOCKETIO_AVAILABLE"]
