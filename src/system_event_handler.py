from common.log_writer import *

logger = get_logger("system-event-handler")

def process_system_events(body):
	debug(logger, "user-account/process_system_events ...")
	debug(logger, body)