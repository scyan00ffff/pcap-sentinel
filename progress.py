import threading

_lock = threading.Lock()

current_detector = None
completed = 0
total = 0
status = "idle"

def update_progress(detector_name, comp, tot):
    global current_detector, completed, total, status
    with _lock:
        current_detector = detector_name
        completed = comp
        total = tot
        status = "running"

def set_complete():
    global status
    with _lock:
        status = "complete"

def reset():
    global current_detector, completed, total, status
    with _lock:
        current_detector = None
        completed = 0
        total = 0
        status = "idle"

def get_progress():
    with _lock:
        return {
            "current_detector": current_detector,
            "completed": completed,
            "total": total,
            "status": status
        }