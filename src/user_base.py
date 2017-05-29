from flask import request, render_template

from common.db_collections import *
from common.queue import publish_command_to_service
from common.dbadapter import save, get_list_by_query, get_by_id, get_logged_in_user_id, get_logged_in_user_client, delete, make_response_obj, make_response_list
from common.helper import get_encrypted_str, generate_random_pwd, get_void_uuid, base64_encode, get_consul_server
import arrow
import json
import common.services_helper
import requests

from common.email_templates import *
from common.error_codes import *
from common.decorators import *
from common.log_writer import *
from common.config_manager import get_config, get_system_email_account, get_client_ip
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

import jinja2

consul_server = get_consul_server()
logger = get_logger("user-base")

INVALID_CURRENT_PASSWORD_ERROR_CODE=601
INVALID_PWD_RESET_TOKEN_ERROR_CODE=602

CLIENT_OFFICE_COLLECTION = "client_office"
CLIENT_DEPARTMENT_COLLECTION = "client_department"

def create_user(data, login_url): 

    check = get_user_by_email(data["Email"])
    if check.count() > 0:
        return {"error": True, "msg": "An user with this email already exists", "errorCode": DUPLICATE_USER_ERROR_CODE} 

    client_id = ""
    is_aegis_administrator=True

    if "IsAegisAdministrator" not in data or data["IsAegisAdministrator"] == False:
        client_id = determine_client_id(data)
        is_aegis_administrator=False

    pwd = generate_random_pwd()
    hashed_pwd = get_encrypted_str(pwd)
    changed_by = get_void_uuid()
    changed_on = arrow.utcnow() 
    item = {
    "Email": data["Email"],
    "HashedPassword": hashed_pwd,
    "EmailHash": get_encrypted_str(data["Email"]),
    "EntityID": "",
    "Version": get_void_uuid(),
    "ClientID": client_id,
    "PermissionLevel": data["PermissionLevel"],
    "ChangePasswordOnLogin": True,
    "IsAegisAdministrator": is_aegis_administrator
    }   

    if "FirstName" in data:
        item["FirstName"] = data["FirstName"]

    if "LastName" in data:
        item["LastName"] = data["LastName"]

    if "FirstName" in data and "LastName" in data:
        item["DisplayName"]  = data["FirstName"] + " "+ data["LastName"]
                
    if "Phone" in data:
        item["Phone"] = data["Phone"]

    if "DisplayName" not in item or item["DisplayName"] == " ":
        item["DisplayName"] = data["Email"]

    ret = save(item, changed_by, changed_on, USER_COLLECTION)

    send_registration_email(item["Email"], pwd, login_url)

    return make_response_obj(ret)

def determine_client_id(data):
    client_id = ""
    if "OrganizationName" in data:
        client = create_user_client({"Name": data["OrganizationName"]}) 

        if "EntityID" not in client:
            return {"error": True, "msg": "Error occured while creating user organization.", "errorCode": UNEXPECTED_ERROR_CODE}
        else:
            client_id = client["EntityID"]
    else:
            client_id = get_logged_in_user_client()["EntityID"]

    return client_id

def send_registration_email(email, password, login_url):
    email_command = {
        "to": email,
        "from": get_system_email_account(consul_server),
        "flag": "to-email",
        "action": "send-email",
        "template_id": 1148341,
        "template_model": {
        	"email":email,
        	"password":password,
        	"action_url":login_url.replace("io//","io/")
        	}
        }       

    publish_command_to_service(logger, "mail", json.dumps(email_command))

def create_user_client(client):
    client_service = common.services_helper.lookup_client_service() 
    response = requests.post(client_service, data=json.dumps(client), headers=get_service_header())

    return response.json()

def get_service_header():
    request_headers = {}
    for k, v in request.headers.items():
        request_headers[k] = v

    final_header = {"User-Agent": request_headers["User-Agent"]}

    if "Content-Type" in request_headers:
        final_header["Content-Type"] = request_headers["Content-Type"]
    else:
        final_header["Content-Type"] = "application/json"

    # final_header["User-Id"] = get_logged_in_user_id()

    return final_header

def login(data):
    if not data:
            return {"error": True, "msg": "Request was not understood"}, 500
    if not "username" in data or len(data["username"]) <= 0:
        return {"error": True, "msg": "Username/Password is wrong"}, 401
    if not "password" in data:
        return {"error": True, "msg": "Username/Password is wrong"}, 401
        
    check = get_list_by_query({"Email": {"$regex": escape_email_for_plus_sign(data["username"]), "$options": "i"}, "HashedPassword": get_encrypted_str(data["password"]),
                                   "Active": True, "Latest": True},USER_COLLECTION)
    array = list(check)     
    if check.count() > 0:
        user = array[0]   
        debug(logger, "User found.")
        
        if "ClientID" in user and user["ClientID"]:
            client = get_by_id(user["ClientID"], CLIENT_COLLECTION)
            if not client["Active"]:
                debug(logger, "User associated with invalid client. Cant login.")               
                return {}, 404

        if "IsResetLink" in data:
            if is_valid_token(data["password"]):                
                return make_response_obj(update_login_data(array[0])), 200
            else:
                error(logger, "Invalid token")
                return {"error": True, "msg": "Invalid token.", "errorCode": INVALID_PWD_RESET_TOKEN_ERROR_CODE}, 200
        else:            
            return make_response_obj(update_login_data(array[0])), 200
    else:
        debug(logger, "User not found.")               
        return {}, 404

def update_login_data(user):
    user["LastLoginTime"]=str(arrow.utcnow())
    if user["Email"][-10:].lower() == "@gmail.com":
        user["gmail"] = True
    else:
        user["gmail"] = False
    request_headers = {}
    for k, v in request.headers.items():
        request_headers[k] = v

    debug(logger, request_headers)
    
    if "X-Forwarded-For" in request_headers:    
        user["LastLoginIpAdress"]=request_headers['X-Forwarded-For'].split(',')[0]
    else:
        user["LastLoginIpAdress"]='n/a'
      
    user.pop("_id")
    return save(user, user["EntityID"], arrow.utcnow(), USER_COLLECTION)

def is_valid_token(token):
    is_valid = True
    s = Serializer(get_secret_key())
    try:
        data = s.loads(token)
    except SignatureExpired:
        is_valid = False
    except BadSignature:
        is_valid = False

    return is_valid

def change_password(data):
    if "UserAccountID" not in data:
        return {"error": True, "msg": "Cannot perform action. No user data"}, 400
    if "NewPassword" not in data:
        return {"error": True, "msg": "Cannot perform action. Please supply the new password"}, 400
    if "CurrentPassword" not in data:
        return {"error": True, "msg": "Cannot perform action. Please supply current password"}, 400
    
    check = get_by_id(data["UserAccountID"], USER_COLLECTION)
    if not check :
        return {"error": True, "msg": "User does not exist"}, 403
    
    item = dict(check)

    if item["HashedPassword"] != get_encrypted_str(data["CurrentPassword"]):
        return {"error": True, "msg": "Invalid current password.", "errorCode": INVALID_CURRENT_PASSWORD_ERROR_CODE}, 400
    else:
        changed_on = arrow.utcnow()
        item["HashedPassword"] = get_encrypted_str(data["NewPassword"])
        item["ChangePasswordOnLogin"] = False
        ret = save(item, data["UserAccountID"], changed_on, USER_COLLECTION)
        if ret  == None:
            return {"error": True, "msg": "Saving error"}, 404
        token = base64_encode(ret["Email"].lower() + ":" + item["HashedPassword"])
    
        return {"Status": 0, "AuthToken": token}, 200

def cancel_password_change(data):
    if "UserAccountID" not in data:
        return {"error": True, "msg": "Cannot perform action. No user data"}, 400    
    
    check = get_by_id(data["UserAccountID"], USER_COLLECTION)
    if not check :
        return {"error": True, "msg": "User does not exist"}, 403
    
    item = dict(check)

    changed_on = arrow.utcnow()
    item["ChangePasswordOnLogin"] = False
    ret = save(item, data["UserAccountID"], changed_on, USER_COLLECTION)
    if ret  == None:
        return {"error": True, "msg": "Saving error"}, 404    
    
    return {"Status": 0}, 200

def escape_email_for_plus_sign(email):
    return email.replace("+","\\+")

def get_user_by_email(email):
    return get_list_by_query({"Email": {"$regex": escape_email_for_plus_sign(email), "$options": "i"},"Active": True, "Latest": True}, USER_COLLECTION)

def reset_password(data):
    debug(logger, "reset_password")
    if "Email" not in data:
        return {"error": True, "msg": "Cannot perform action. No Email"}, 401
    
    check = get_user_by_email(data["Email"])
    if check.count() == 0:
        info(logger, "User not found for reset password.Ignoring request.")
        return {"Status": 0}, 200 #We're going to return an OK status since we don't want to allow users to "search" for accounts
    else:           
        array = list(check)
        item = array[0]
        item.pop("_id")
        reset_token = generate_password_reset_token(item)
        # pwd = get_encrypted_str(rand_pass)            
        encrypted_reset_token = get_encrypted_str(reset_token)
        item["HashedPassword"] = encrypted_reset_token
        item["ChangePasswordOnLogin"] = True
        changed_on = arrow.utcnow()
        changed_by =  item["EntityID"]          
        ret = save(item, changed_by, changed_on, USER_COLLECTION)                       
        if ret == None:
            return {"error": True, "msg": "Error happened while saving"}, 500
        
        debug(logger, reset_token)

        send_password_reset_email(item, reset_token)        
    
        return {"Status": 0}, 200

def generate_password_reset_token(user=None):  
   
   #Default is 1 hour   
   expires_in = 3600

   if "ClientID" in user and user["ClientID"]:    
    client = get_by_id(user["ClientID"], CLIENT_COLLECTION)

    if "ResetLinkTimeoutInMinutes" in client:
        expires_in = int(client["ResetLinkTimeoutInMinutes"])*60

   s = Serializer(get_secret_key(), expires_in = expires_in)
   return s.dumps({ 'id': user["EntityID"]})

def get_secret_key():
    config_arr = get_config(consul_server, ["secret_key"])
    
    return config_arr[0]["secret_key"]

def send_password_reset_email(item, reset_token):
    debug(logger, "send_password_reset_email...")

    login_url=build_login_url(item, reset_token)

    email_command = {
        "to": item["Email"],
        "from": get_system_email_account(consul_server),
        "flag": "to-email",
        "action": "send-email",
        "template_id": 1153183,
        "template_model": {
            "action_url":login_url.replace("io//","io/")
            }
        }   

    publish_command_to_service(logger, "mail", json.dumps(email_command))

def build_login_url(item, reset_token):
    config_arr = get_config(consul_server, ["frontend_url"])
    login_url = config_arr[0]["frontend_url"]+"/#/pages/signin/?un="+item["Email"].encode('base64','strict')+"&token="+reset_token
    return login_url                

def get_profile(user_id):
    user = get_by_id(user_id, USER_COLLECTION)
    
    if not user:
        return {"error": True, "msg": "user does not exist"}, 404
    
    return_json = {
        "UserAccountID": user["EntityID"],
        "Email": user["Email"],
        "ClientID": user["ClientID"],
        "PermissionLevel": user["PermissionLevel"],
        "ChangePasswordOnLogin": user["ChangePasswordOnLogin"],
        "IsAegisAdministrator": user["IsAegisAdministrator"] if "IsAegisAdministrator" in user else False,
        "IsAcceptedLicense": user["IsAcceptedLicense"] if "IsAcceptedLicense" in user else False        
    }

    return_json = populate_display_name(user, return_json)  
    return_json = populate_first_name(user, return_json)
    return_json = populate_last_name(user, return_json)
    return_json = populate_email_hash(user, return_json)

    if "OfficeID" in user:
        return_json["OfficeID"] = user["OfficeID"]

    if "DepartmentID" in user:
        return_json["DepartmentID"] = user["DepartmentID"]

    if "LastViewedClientID" in user:
        return_json["LastViewedClientID"] = user["LastViewedClientID"]

    return make_response_obj(return_json), 200

def populate_display_name(user, return_json):
    if "DisplayName" in user:
        return_json["DisplayName"] = user["DisplayName"]
    else:
        return_json["DisplayName"] = user["Email"]

    return return_json

@admin_required
def load_all_users():
    response = get_list_by_query({
        "ClientID": get_logged_in_user_client()["EntityID"],        
        "Active": True, 
        "Latest": True}, USER_COLLECTION)
    return make_response_list(list(response))

def load_user(user_id): 
    user = get_by_id(user_id, USER_COLLECTION)

    if "OfficeID" in user and user["OfficeID"]:
        office = get_by_id(user["OfficeID"], CLIENT_OFFICE_COLLECTION)
        if office:
            user["OfficeName"]=office["Name"]

    if "DepartmentID" in user and user["DepartmentID"]:
        department = get_by_id(user["DepartmentID"], CLIENT_DEPARTMENT_COLLECTION)
        if department:
            user["DepartmentName"]=department["Name"]

    return make_response_obj(user)

def update_user(data):  
    check = get_user_by_email(data["Email"])

    user = get_by_id(data["EntityID"], USER_COLLECTION)     

    if check.count()>0:
        ''' If an user exists with input email and is not the same person. Alert as duplicate user'''
        existing_user = list(check)[0]
        debug(logger, existing_user["EntityID"])
        debug(logger, user["EntityID"])
        debug(logger, existing_user["Email"])
        debug(logger, user["Email"])

        if existing_user["EntityID"] != user["EntityID"] and existing_user["Email"] == data["Email"] :
            return {"error": True, "msg": "An user with this email already exists", "errorCode": DUPLICATE_USER_ERROR_CODE} 

    if "FirstName" in data:
        user["FirstName"] = data["FirstName"]

    if "LastName" in data:
        user["LastName"] = data["LastName"]

    if "Phone" in data:
        user["Phone"] = data["Phone"]

    if "Email" in data:
        user["Email"] = data["Email"]
    
    if "FirstName" in data and "LastName" in data:
        user["DisplayName"]  = data["FirstName"] + " "+ data["LastName"]

    if "PermissionLevel" in data:
        user["PermissionLevel"] = data["PermissionLevel"]

    if "IsAcceptedLicense" in data:
        user["IsAcceptedLicense"] = data["IsAcceptedLicense"]

    ret = save(user, get_logged_in_user_id(), arrow.utcnow(), USER_COLLECTION)

    if ret == None:
        return {"error": True, "msg": "Error when saving user"}
    else:
        return make_response_obj(ret)

def is_user_email_changed(data, user):
    return data["Email"] != user["Email"]

def populate_first_name(user, return_json):
    if "FirstName" in user:
        return_json["FirstName"] = user["FirstName"]
    else:
        return_json["FirstName"] = ""

    return return_json

def populate_last_name(user, return_json):
    if "LastName" in user:
        return_json["LastName"] = user["LastName"]
    else:
        return_json["LastName"] = ""

    return return_json

def populate_email_hash(user, return_json):
    if "EmailHash" in user:
        return_json["EmailHash"] = user["EmailHash"]
    else:
        return_json["EmailHash"] = ""

    return return_json

def update_profile(data, user_id):

    user = get_by_id(user_id, USER_COLLECTION)
        
    if not user:
        return {"error": True, "msg": "Can not find user"}, 400

    previous_email = user["Email"]
    email_changed = False
    if is_user_email_changed(data, user):
        if "Password" not in data:
            return {"error": True, "msg": "Password required to change email"}, 400

        if user["HashedPassword"] != get_encrypted_str(data["Password"]):
            return {"error": True, "msg": "Invalid user password.", "errorCode": INVALID_CURRENT_PASSWORD_ERROR_CODE}, 400

        email_changed = True
        check = get_user_by_email(data["Email"])

        if check.count()>0:
            return {"error": True, "msg": "An user with this email already exists", "errorCode": DUPLICATE_USER_ERROR_CODE}, 404
    
    ret = update_profile_attributes(user, data)

    profile_data = get_profile(ret["EntityID"])[0] 

    if email_changed == True:
        send_email_changed_notification_to_user(user, previous_email)
        send_email_changed_notification_to_admins(user, previous_email)

        token = base64_encode(data["Email"].lower() + ":" + get_encrypted_str(data["Password"]))
        profile_data["AuthToken"] = token

    return profile_data, 200

def send_email_changed_notification_to_user(user, email):
    debug(logger, "send_email_changed_notification_to_user...")
    email_command = {
    "to": email,
    "from": get_system_email_account(consul_server),
    "subject": "Email changed",
    "flag": "to-email",
    "action": "send-email",
    "body":  render_template(USER_EMAIL_CHANGED_TEMPLATE, 
                               email=user["Email"], previous_email=email, ip_address=get_client_ip(request))
    }   

    publish_command_to_service(logger, "mail", json.dumps(email_command))

def send_email_changed_notification_to_admins(user, previous_email):
    debug(logger, "send_email_changed_notification_to_admins...")
    for admin in get_client_admins():
        email_command = {
        "to": admin["Email"],
        "from": get_system_email_account(consul_server),
        "subject": "User email changed",
        "flag": "to-email",
        "action": "send-email",
        "body":  render_template(USER_EMAIL_CHANGED_ADMIN_TEMPLATE, 
                               admin_email=admin["Email"], email=user["Email"], previous_email=previous_email, ip_address=get_client_ip(request))
        }   

        publish_command_to_service(logger, "mail", json.dumps(email_command))

def get_client_admins():
    return get_list_by_query({"ClientID": get_logged_in_user_client()["EntityID"], "PermissionLevel": 0, "Latest":True, "Active":True}, USER_COLLECTION)

def update_profile_attributes(user, data):
    item = user
    debug(logger, "update_profile_attributes")
    if "FirstName" in data:
        item["FirstName"] = data["FirstName"]
        
    if "LastName" in data:
        item["LastName"] = data["LastName"]
        
    if "FirstName" in data and "LastName" in data:
        item["DisplayName"]  = data["FirstName"] + " "+ data["LastName"]

    if "DisplayName" not in item or item["DisplayName"] == " ":
        item["DisplayName"] = data["Email"]

    if "Email" in data:
        item["Email"] = data["Email"]
        
    if "Password" in data:
        item["HashedPassword"] = get_encrypted_str(data["Password"])

    if "OfficeID" in data:
        item["OfficeID"] = data["OfficeID"]

    if "DepartmentID" in data:
        item["DepartmentID"] = data["DepartmentID"]

    if "IsAcceptedLicense" in data:
        item["IsAcceptedLicense"] = data["IsAcceptedLicense"]

    if "LastViewedClientID" in data:
        item["LastViewedClientID"] = data["LastViewedClientID"]

    ret = save(item, data["UserAccountID"], arrow.utcnow(), USER_COLLECTION)
    if ret == None:
        return {"error": True, "msg": "Error when saving user"}, 500

    return make_response_obj(ret)

def delete_user(user_id):
    delete(user_id, get_logged_in_user_id(), arrow.utcnow(), USER_COLLECTION)

    return {}
