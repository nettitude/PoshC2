import requests
import time

# Configuration
BASE_URL = "http://localhost:5000"
USERNAME = "poshc2"
PASSWORD = "change_on_install"
FILTER_USERNAME = "bt"  # The username to filter tasks by
TASKS_ENDPOINT = f"{BASE_URL}/tasks"
TASK_ENDPOINT = f"{BASE_URL}/task"
POLL_INTERVAL = 5  # Poll every 5 seconds when no task is found


def get_latest_task_id():
    """Get the latest task ID from the tasks API."""
    response = requests.get(f"{TASKS_ENDPOINT}/1", auth=(USERNAME, PASSWORD))
    if response.status_code == 200:
        tasks = response.json()
        if isinstance(tasks, list) and tasks:
            latest_task = tasks[0]
            task_id = latest_task.get("id")
            if task_id is not None:
                return int(task_id)
    return 0


def get_task_by_id(task_id):
    """Get task details by task ID from the task API."""
    response = requests.get(f"{TASK_ENDPOINT}/{task_id}", auth=(USERNAME, PASSWORD))
    if response.status_code == 200:
        try:
            task = response.json()
            if task and task.get("completed_time") is not None:
                return task
        except ValueError:
            return None
    return None


def format_task(task, status):
    """Format the task details for printing."""
    task_id = f"Task {int(task.get('id', 0)):05d}"  # Format task ID as 5-digit
    operator = task.get("user", "Unknown")
    implant = task.get("implant_numeric_id", "Unknown")
    output = task.get("output")
    context = task.get("output", "Unknown").splitlines()[0] if task.get("output") else "Unknown Context"
    timestamp = task.get("sent_time") if status == "sent" else task.get("completed_time", "Unknown Time")
    command = task.get("command", "Unknown Command")
    if status == "sent":
        return f"{task_id} sent | Operator: {operator} | Implant: {implant} | Context: {context} | {timestamp}\n{command}\n"
    elif status == "returned":
        return f"{task_id} returned | Operator: {operator} | Implant: {implant} | Context: {context} | {timestamp}\n\n{output}\n"
    return ""


def poll_new_tasks(latest_task_id):
    """Continuously poll for new tasks."""
    while True:
        latest_task_id += 1
        task = get_task_by_id(latest_task_id)
        if task:
            # Check if the task belongs to the specified username
            task_user = task.get("user")
            if task_user == FILTER_USERNAME:
                print(format_task(task, "sent"))
                if task.get("output"):  # If task is completed and has output
                    print(format_task(task, "returned"))
        else:
            # No task found, start the timer before retrying
            latest_task_id -= 1  # Reset ID if no task found
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    print(f"Fetching latest task ID for user '{FILTER_USERNAME}'...")
    latest_task_id = get_latest_task_id()
    print(f"Starting polling from task ID: {latest_task_id + 1}")
    poll_new_tasks(latest_task_id)
