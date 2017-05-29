from common.log_writer import *
import common.sql_db_adapter
from common.dbadapter import get_list_by_query,get_list,save
from common.helper import get_consul_server
import common.services_helper
import requests
from common.config_manager import get_system_admin_email
import arrow
import user_base
consul_server = get_consul_server()
logger = get_logger("user-service-preflight")


def run(login_url,user_id=None):
	info(logger,"Running preflight step...")
	
	create_aegis_admin_user(login_url)

	info(logger,"Completed preflight step.")

def create_aegis_admin_user(login_url):
	system_admin_email = get_system_admin_email(consul_server)
	if system_admin_email != None:
		data = {"Email": system_admin_email, "IsAegisAdministrator": True, "PermissionLevel": 0}	
		response = user_base.create_user(data,login_url)
	else:
		warn(logger, "Check if system_admin_email is defined in environment file. Aborting preflight step.")