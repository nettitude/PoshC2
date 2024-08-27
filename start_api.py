#!/usr/bin/env python3

# Install
# ========
# cd /opt/PoshC2/
# pipenv install flask
# pipenv install flask-httpauth
# pipenv install flask-restx
# pipenv install waitress

# Run
# ===
# cd /opt/PoshC2/
# pipenv run python3 start_api.py

import re
import sys
import os

from flask import Flask, request, jsonify, make_response, send_from_directory, render_template, redirect, url_for
from flask_httpauth import HTTPBasicAuth
from flask_restx import Api, Resource, fields

# import do_generate_reports from the ImplantHandler.py file
from poshc2.client.command_handlers.ImplantHandler import do_generate_reports

from poshc2.client.command_handlers.PSHandler import commands as powershellsc,commands_help as commands_help_powershell, examples as examples_powershell, common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help, ImplantType
from poshc2.client.command_handlers.SharpHandler import commands as sharpsc,commands_help as commands_help_sharp, examples as examples_sharp, common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help, ImplantType
from poshc2.client.command_handlers.PyHandler import commands as pythonsc,commands_help as commands_help_python, examples as examples_python, common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help, ImplantType
from poshc2.client.command_handlers.FCommHandler import commands as fcomsc,commands_help as commands_help_fcom, examples as examples_fcom, common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help, ImplantType
from poshc2.client.command_handlers.JxaHandler import commands as jxasc,commands_help as commands_help_jxa, examples as examples_jxa, common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help, ImplantType
from poshc2.client.command_handlers.LinuxHandler import commands as linuxsc,commands_help as commands_help_linux, examples as examples_linux, common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help, ImplantType
from poshc2.client.command_handlers.PBindHandler import commands as pbindsc,commands_help as commands_help_pbind, examples as examples_pbind, common_implant_commands, common_implant_commands_help, common_implant_examples, common_block_help, ImplantType

from poshc2.server.Core import decrypt
from poshc2.server.Config import PoshInstallDirectory, DownloadsDirectory, PayloadsDirectory, ReportsDirectory
from poshc2.server.database.Helpers import delete_object, get_alive_implants, get_c2_messages, get_implant, get_new_tasks_for_implant, get_tasks_for_implant, insert_object, select_first, select_all, select_subset
from poshc2.server.database.Model import URL, Implant, Task, NewTask, AutoRun, C2Server, Cred, OpsecEntry, C2Message, PowerStatus, HostedFile, MitreTTP

app = Flask(__name__, template_folder=f"{PoshInstallDirectory}/resources/html-templates/", static_folder=f"{PoshInstallDirectory}/resources/html-templates/include/")
auth = HTTPBasicAuth()

# ! This must be defined *before* the API is created, otherwise the API will hijack the default route '/'
@app.route('/')
@app.route('/home')
@auth.login_required
def home_view():
    return render_template('home.html', username=auth.username())

api = Api(app, version='1.0', title='PoshC2 API', description='A simple API for PoshC2', doc='/swagger')

API_USERS = {
    "poshc2": "change_on_install",
}

@auth.verify_password
def verify_password(username, password):
    if username in API_USERS and API_USERS[username] == password:
        return username

@auth.error_handler
def unauthorized():
    return make_response(jsonify({'error': 'Unauthorized access'}), 401)

def subset_data_to_json(object_type, number_of_rows):
    all_data = select_subset(object_type, number_of_rows)
    return_data = [attributes_to_dict(object_type, single_data) for single_data in all_data]
    return return_data

def data_to_json(object_type):
    all_data = select_all(object_type)
    return_data = [attributes_to_dict(object_type, single_data) for single_data in all_data]
    return return_data

def attributes_to_dict(model, single_object):
    attributes = {}
    column_names = [col.name for col in model.__table__.columns]
    for col_name in column_names:
        col_value = getattr(single_object, col_name)
        attributes[col_name] = col_value
    return attributes

def model_to_api_fields(model):
    field_dict = {}
    for column in model.__table__.columns:
        field_dict[column.name] = fields.String
    return field_dict

# Iterate over all Models:
# URL, Implant, Task, NewTask, AutoRun, C2Server
# Cred, OpsecEntry, C2Message, PowerStatus, HostedFile, MitreTTP
DOWNLOADS_DIR = os.path.dirname(DownloadsDirectory)
PAYLOADS_DIR = os.path.dirname(PayloadsDirectory)
REPORTS_DIR = os.path.dirname(ReportsDirectory)

@api.route('/urls')
class URLS(Resource):
    @api.doc("urls")
    @auth.login_required
    @api.marshal_list_with(api.model('URL', model_to_api_fields(URL)))
    def get(self):
        """
        Returns a list of defined urls
        """
        return data_to_json(URL)


@api.route('/implants')
class Implants(Resource):
    @api.doc("implants")
    @auth.login_required
    @api.marshal_list_with(api.model('Implant', model_to_api_fields(Implant)))
    def get(self):
        """
        Returns a list of defined implants
        """
        return data_to_json(Implant)


@api.route('/liveimplants')
class LiveImplants(Resource):
    @api.doc("liveimplants")
    @auth.login_required
    @api.marshal_list_with(api.model('Implant', model_to_api_fields(Implant)))
    def get(self):
        """
        Returns a list of defined implants
        """
        all_data = get_alive_implants()
        return [attributes_to_dict(Implant, single_data) for single_data in all_data]


@api.route('/tasks')
@api.route('/tasks/<number_of_rows>')
@api.route('/tasks/implant/<implant_id>')
class Tasks(Resource):
    @api.doc("tasks")
    @auth.login_required
    @api.marshal_list_with(api.model('Task', model_to_api_fields(Task)))
    def get(self, number_of_rows=None, implant_id=None):
        """
        Returns a list of tasks
        """
        if number_of_rows:
            return subset_data_to_json(Task, number_of_rows)
        elif implant_id:
            all_data =  get_tasks_for_implant(implant_id)
            return [attributes_to_dict(Task, single_data) for single_data in all_data]
        else:
            return data_to_json(Task)


newtask_model = api.model('NewTask', {
    'implant_id': fields.String(required=True, description='The unique implant_id for which the task is to be executed'),
    'command': fields.String(required=True, description='The task to be executed'),
    'user': fields.String(required=True, description='The user that exuted the command'),
})

@api.route('/newtasks')
class NewTasks(Resource):
    @api.doc("newtasks")
    @auth.login_required
    @api.marshal_list_with(api.model('NewTask', model_to_api_fields(NewTask)))
    def get(self):
        """
        Returns a list of defined newtasks
        """
        return data_to_json(NewTask)

    @api.response(201, 'Task successfully created.')
    @api.expect(newtask_model, validate=True)
    def post(self):
        """
        Adds a newtask
        """
        implant_id = request.json['implant_id']
        command = request.json['command']
        user = request.json['user']
        new_task = NewTask(
                implant_id=implant_id,
                command=command,
                user=user,
                child_implant_id=None
            )
        insert_object(new_task)
        return "Success", 201


@api.route('/autoruns')
class AutoRuns(Resource):
    @api.doc("autoruns")
    @auth.login_required
    @api.marshal_list_with(api.model('AutoRun', model_to_api_fields(AutoRun)))
    def get(self):
        """
        Returns a list of defined autoruns
        """
        return data_to_json(AutoRun)


@api.route('/c2server')
class GetC2Server(Resource):
    @api.doc("c2server")
    @auth.login_required
    @api.marshal_list_with(api.model('C2Server', model_to_api_fields(C2Server)))
    def get(self):
        """
        Returns the c2server configuration
        """
        return data_to_json(C2Server)


@api.route('/creds')
class Creds(Resource):
    @api.doc("creds")
    @auth.login_required
    @api.marshal_list_with(api.model('Cred', model_to_api_fields(Cred)))
    def get(self):
        """
        Returns the creds
        """
        return data_to_json(Cred)


@api.route('/opsecentrys')
class OpsecEntrys(Resource):
    @api.doc("opsecentrys")
    @auth.login_required
    @api.marshal_list_with(api.model('OpsecEntry', model_to_api_fields(OpsecEntry)))
    def get(self):
        """
        Returns the opsec entries
        """
        return data_to_json(OpsecEntry)


@api.route('/c2messagesview')
class C2Messages(Resource):
    @api.doc("c2messages")
    @auth.login_required
    @api.marshal_list_with(api.model('C2Message', model_to_api_fields(C2Message)))
    def get(self):
        """
        Returns the c2messages
        """
        return data_to_json(C2Message)


@api.route('/powerstatus')
class GetPowerStatus(Resource):
    @api.doc("powerstatus")
    @auth.login_required
    @api.marshal_list_with(api.model('PowerStatus', model_to_api_fields(PowerStatus)))
    def get(self):
        """
        Returns the powerstatus entries
        """
        return data_to_json(PowerStatus)


@api.route('/hostedfiles')
class HostedFiles(Resource):
    @api.doc("hostedfiles")
    @auth.login_required
    @api.marshal_list_with(api.model('HostedFile', model_to_api_fields(HostedFile)))
    def get(self):
        """
        Returns the hostedfiles entries
        """
        return data_to_json(HostedFile)


@api.route('/mitrettps')
class MitreTTPs(Resource):
    @api.doc("mitrettps")
    @auth.login_required
    @api.marshal_list_with(api.model('MitreTTP', model_to_api_fields(MitreTTP)))
    def get(self):
        """
        Returns the mitrettps entries
        """
        return data_to_json(MitreTTP)


@app.route('/files', methods=['GET'])
@app.route('/files/<int:number_of_files>', methods=['GET'])
@auth.login_required
def list_files(number_of_files=None):
    files = os.listdir(DOWNLOADS_DIR)
    sorted_files = sorted(files, key=lambda x: os.path.getctime(os.path.join(DOWNLOADS_DIR, x)), reverse=True)
    if number_of_files:
        images = [f for f in sorted_files[0:number_of_files]]
    else:
        images = [f for f in sorted_files]
    return render_template('files.html', images=images)


@app.route('/files-list', methods=['GET'])
@app.route('/files-list/<int:number_of_files>', methods=['GET'])
@auth.login_required
def list_files_json(number_of_files=None):
    files = os.listdir(DOWNLOADS_DIR)
    sorted_files = sorted(files, key=lambda x: os.path.getctime(os.path.join(DOWNLOADS_DIR, x)), reverse=True)
    if number_of_files:
        images = [f for f in sorted_files[0:number_of_files]]
    else:
        images = [f for f in sorted_files]
    response = {
        'files': sorted_files,
        'base_url': url_for('serve_file', filename='', _external=True)
    }
    return jsonify(response)


@app.route('/file/<path:filename>', methods=['GET'])
@auth.login_required
def serve_file(filename):
    return send_from_directory(DOWNLOADS_DIR, filename)


@app.route('/file/upload', methods=['POST'])
@auth.login_required
def upload_file():
    file = request.files['file']
    if file:
        file.save(os.path.join(PAYLOADS_DIR, file.filename))
    return redirect(url_for('list_payloads'))


@app.route('/taskviewwithnew')
@app.route('/taskviewwithnew/<number_of_rows>')
@app.route('/taskviewwithnew/implant/<implant_id>')
@auth.login_required
def display_tasks_with_new(number_of_rows=None, implant_id=None):
    if number_of_rows:
        new_tasks = subset_data_to_json(NewTask, number_of_rows)
        tasks = subset_data_to_json(Task, number_of_rows)
    elif implant_id:
        all_data = get_tasks_for_implant(implant_id)
        tasks = [attributes_to_dict(Task, single_data) for single_data in all_data]

        all_new_data = get_new_tasks_for_implant(implant_id)
        new_tasks = [attributes_to_dict(NewTask, single_data) for single_data in all_new_data]
    else:
        tasks = data_to_json(Task)
        new_tasks = data_to_json(NewTask)

    return render_template('components/implant_tasks.html', tasks=tasks, new_tasks=new_tasks, implant_id=implant_id, username=auth.username())

@app.route('/newtasksview')
@app.route('/newtasksview/<number_of_rows>')
@app.route('/newtasksview/del/<task_id>')
@auth.login_required
def display_newtasks(number_of_rows=None, task_id=None):
    if task_id:
        delete_object(NewTask, {NewTask.id: task_id})

    if number_of_rows:
        new_tasks = subset_data_to_json(NewTask, number_of_rows)
    else:
        new_tasks = data_to_json(NewTask)

    return render_template('tasksview.html', new_tasks=new_tasks)


@app.route('/implantview')
@app.route('/implantview/<number_of_rows>')
@auth.login_required
def display_implants(number_of_rows=None):
    if number_of_rows:
        implants = subset_data_to_json(Implant, number_of_rows)
    else:
        implants = data_to_json(Implant)

    return render_template('implants.html', implants=implants)


@app.route('/liveimplantview')
@app.route('/implants/kill/<implant_id>')
@auth.login_required
def display_live_implants(implant_id=None):
    if implant_id:
        delete_object(Implant, {Implant.numeric_id: implant_id})

    all_data = get_alive_implants()
    implants = [attributes_to_dict(Implant, single_data) for single_data in all_data]
    return render_template('components/implants_table.html', implants=implants)


@app.route('/c2messages')
@auth.login_required
def display_c2_messages():
    all_data = get_c2_messages()
    c2messages = [attributes_to_dict(C2Message, single_data) for single_data in all_data]
    return render_template('components/c2_message_logs.html', c2messages=c2messages)


@app.route('/commands')
@auth.login_required
def display_command_handler():
    all_data = get_alive_implants()
    implants = [attributes_to_dict(Implant, single_data) for single_data in all_data]
    return render_template('components/commands_form.html', implants=implants,username=auth.username())


@app.route('/c2view')
@app.route('/c2view/<number_of_rows>')
@auth.login_required
def c2_view(number_of_rows=None):
    if number_of_rows:
        tasks = subset_data_to_json(Task, number_of_rows)
    else:
        tasks = data_to_json(Task)

    all_data = get_alive_implants()
    implants = [attributes_to_dict(Implant, single_data) for single_data in all_data]

    return render_template('c2view.html', tasks=tasks, implants=implants, username=auth.username())


@app.route('/autorunsview',methods=['GET','POST'])
@app.route('/autorunsview/del/<autorun_id>')
@auth.login_required
def autoruns_view(autorun_id=None):
    if autorun_id:
        delete_object(AutoRun, {AutoRun.id: autorun_id})
    elif request.form.get("task"):
        task = request.form.get('task')
        new_autorun = AutoRun(
                task=task,
            )
        insert_object(new_autorun)
    autoruns = data_to_json(AutoRun)

    return render_template('autoruns.html', autoruns=autoruns)


@app.route('/payloads', methods=['GET'])
@auth.login_required
def list_payloads():
    files = os.listdir(PAYLOADS_DIR)
    sorted_files = sorted(files, key=lambda x: os.path.getctime(os.path.join(PAYLOADS_DIR, x)))
    images = [f for f in sorted_files]
    return render_template('payloads.html', images=images)


@app.route('/payload/<path:filename>', methods=['GET'])
@auth.login_required
def serve_payload(filename):
    return send_from_directory(PAYLOADS_DIR, filename)


@app.route('/reports', methods=['GET'])
@auth.login_required
def list_reports():
    files = os.listdir(REPORTS_DIR)
    return render_template('reports.html', reports=files)


@app.route('/reports/<path:filename>', methods=['GET'])
@auth.login_required
def serve_report(filename):
    return send_from_directory(REPORTS_DIR, filename)

@app.route('/generate_reports')
@auth.login_required
def generate_reports():
    try:
        do_generate_reports()
    except Exception as e:
        app.logger.error(f"Error generating reports: {e}")
        pass
    return redirect(url_for('list_reports'))


@app.route('/autocompletecmd/<implant_id>', methods=['GET'])
@app.route('/autocompletecmd/<implant_id>/<commandRemote>', methods=['GET'])
@auth.login_required
def autocompletecmd(implant_id=None,commandRemote=None):
    implant = get_implant(implant_id)
    implant_type = ImplantType.get(implant.type)
    if implant_type is ImplantType.PowerShellHttp:
        commands = powershellsc
        commands_help = commands_help_powershell
        examples = examples_powershell
    elif implant_type is ImplantType.SharpHttp:
        commands = sharpsc
        commands_help = commands_help_sharp
        examples = examples_sharp
    elif implant_type is ImplantType.PythonHttp:
        commands = pythonsc
        commands_help = commands_help_python
        examples = examples_python
    elif implant_type is ImplantType.SharpFComm:
        commands = fcommsc
        commands_help = commands_help_fcomm
        examples = examples_fcomm
    elif implant_type is ImplantType.JXAHttp:
        commands = jxasc
        commands_help = commands_help_jxa
        examples = examples_jxa
    elif implant_type is ImplantType.SharpPBind:
        commands = pbindsc
        commands_help = commands_help_pbind
        examples = examples_pbind
    elif implant_type is ImplantType.LinuxHttp:
        commands = linuxsc
        commands_help = commands_help_linux
        examples = examples_linux

    commands_help = commands_help_powershell
    block_help = {}
    block_help.update(common_block_help)
    mergedList = list(commands.keys())
    mergedList = mergedList + examples
    mergedList.append('beacon')
    mergedList.append('beacon 10m')
    mergedList.append('beacon 2h')
    mergedList.append('beacon 60s')
    mergedList.append('dir')
    finalList =[]
    if commandRemote:
        for i in mergedList:
            if  i.startswith(commandRemote):
                finalList.append(i)
    else:
        finalList = mergedList
    x=[]
    for i in finalList:
        if i not in x:
            x.append(i)
    cmd_with_removed_common=x
    for i in common_implant_commands:
        if i in cmd_with_removed_common:
            cmd_with_removed_common.remove(i)
    cmd_with_removed_common.sort()

    return render_template('components/autocomplete.html', commands=cmd_with_removed_common)


if __name__ == '__main__':
    # For debugging
    app.run(debug=True)

    # For production
    # from waitress import serve
    # serve(app, host="127.0.0.1", port=5000)
