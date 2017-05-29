from flask import Flask, request, jsonify
from common.config_manager import get_config, get_logging_handler, is_local_or_dev_environment
from common.dbadapter import save, get_list_by_query, get_by_id, delete
from common.helper import get_consul_server
from common.log_writer import *
from bson.json_util import dumps
import user_base
import preflight

app = Flask(__name__)
logger = get_logger("user-service")
consul_server = get_consul_server()
config_arr = get_config(consul_server, ["frontend_url"])
login_url = config_arr[0]["frontend_url"] + "/#/pages/signin"
preflight.run(login_url)
##TODO: Protect service urls based on user PermissionLevel
@app.route("/create", methods = ["POST"])
@app.route("/", methods = ["POST", "GET"])
@app.route("/<id>/", methods = ["PUT", "GET", "DELETE"])
def root(id=None):

	try:

		data = request.get_json(force=False, silent=True)
		
		if request.method == "POST":
			if not data:
				return jsonify({"error": True, "msg": "Request was not understood"}), 500
			else:
				response = user_base.create_user(data,login_url)
				if("error" in response and response["error"] == True):
					return jsonify(response), 403
				else:
					return jsonify(response), 201

		if request.method == "PUT":
			response = user_base.update_user(data)		

			if "error" in response:
				return dumps(response), 400
			else:
				return dumps(response), 200

		if request.method == "GET":
			if id==None:
				return dumps(user_base.load_all_users()), 200	
			else:
				response = user_base.load_user(user_id=id)						
				return dumps(response), 200

		if request.method == "DELETE":
			return jsonify(user_base.delete_user(id)),200

	except Exception as e:
		error(logger, e)

@app.route("/login", methods = ["POST"])
def login():	

	try:

		data = request.get_json(force=False, silent=True)
		if not data:
			return jsonify({"error": True, "msg": "Request was not understood"}), 500
		else:	
			return_value, status_code = user_base.login(data)

			return jsonify(return_value), status_code 

	except Exception as e:
		error(logger, e)


@app.route("/changepassword", methods = ["POST"])
def change_password():	
	#TODO: Move this to a decorator
	try:

		if "User-ID" not in request.headers:
			return jsonify({"error": True, "msg": "Can not authenticate user"})

		data = request.get_json(force=False, silent=True)
		if not data:
			return jsonify({"error": True, "msg": "Request was not understood"}), 500
		
		return_value, status_code = user_base.change_password(data)

		return jsonify(return_value), status_code

	except Exception as e:
		error(logger, e)

@app.route("/cancelpasswordchange", methods = ["POST"])
def cancel_password_change():	
	#TODO: Move this to a decorator
	try:

		if "User-ID" not in request.headers:
			return jsonify({"error": True, "msg": "Can not authenticate user"})

		data = request.get_json(force=False, silent=True)
		if not data:
			return jsonify({"error": True, "msg": "Request was not understood"}), 500
		
		return_value, status_code = user_base.cancel_password_change(data)

		return jsonify(return_value), status_code

	except Exception as e:
		error(logger, e)

@app.route("/resetpassword", methods = ["POST"])
def resetpassword():	
	try:

		data = request.get_json(force=False, silent=True)
		if not data:
			return jsonify({"error": True, "msg": "Request was not understood"}), 500
			
		return_value, status_code = user_base.reset_password(data)

		return jsonify(return_value), status_code

	except Exception as e:
		error(logger, e)

@app.route("/profile", methods = ["GET", "PUT"])
def profile():
	#TODO: Move this to a decorator

	try:

		if "User-ID" not in request.headers:
			return jsonify({"error": True, "msg": "Can not authenticate user"})

		user_id = request.headers["User-ID"]
		if request.method == "GET":		
				
			return_value, status_code = user_base.get_profile(user_id)

			return jsonify(return_value), status_code
		elif request.method == "PUT":			
			data = request.get_json(force=False, silent=True)
			return_value, status_code = user_base.update_profile(data, user_id)

			return jsonify(return_value), status_code
		else:
			return jsonify({"error": True, "msg": "Unsupported HTTP Method {0} requested".format(request.method)})

	except Exception as e:
		error(logger, e)

if __name__ == "__main__":
	app.logger.addHandler(get_logging_handler(consul_server))
	if is_local_or_dev_environment(consul_server):
		app.run(debug=True,host='0.0.0.0')
	else:
		app.run(debug=False,host='0.0.0.0')