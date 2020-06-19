#!/usr/bin/env/python
#
# remote_diag.py
#
# - Puts the specified Edge in live mode
# - Causes it to initiate a remote diagnostic action
# - Polls for action output, dumps result to stdout
# - Exits live mode
#
# Disclaimer:
# - Python script, provided 'as-is', as an example of how to execute one remote diagnostics action at a time via API.
# - The current incarnation of the Live Mode API is intended primary to satisfy a narrow set of UI-driven workflows limited to one-off troubleshooting tasks and ad-hoc monitoring of individual Edges. 
#   We don't advise using the Live Mode API for any type of large (or medium)-scale automation (e.g. running it on cron or keeping multiple Edges in live mode persistently).
# - Each edge's results will be saved under the 'results' directory with format 'remote_diags_edgeName_action_curentTime.html'
# - The Live Mode API is on track to be deprecated in a future release and replaced with an API that is better suited for use cases involving more extensive client-side automation.
#
# Usage : remote_diag.py <test> <params> <edge_list> --host <host> --enterprise <enterprise> [--operator] [--insecure]
#
# Example: python3 remote_diag.py FLOW_DUMP "{\"segment\":\"all\",\"count\":\"100\",\"src_ip\":\"\",\"src_port\":\"\",\"dst_ip\":\"\",\"dst_port\":\"\"}" 2 55 23 75 --host vco.hostname.xyz -c 1 --operator --insecure
#
# Options:
#   test              the diagnostic test to perform, one of:
#                       - PATHS_DUMP
#                       - TRACEROUTE
#                       - CLIENTS_DUMP
#                       - BASIC_PING
#                       - FLUSH_NAT
#                       - RESTART_DNSMASQ
#                       - ROUTE_DUMP
#                       - NAT_DUMP
#                       - VPN_TEST
#                       - ARP_DUMP
#                       - RESET_USB_MODEM
#                       - DNS_TEST
#                       - ROUTE_SELECT
#                       - BW_TEST
#                       - AP_SCAN_DUMP
#                       - FLOW_DUMP
#                       - INTERFACE_STATUS
#                       - FLUSH_FLOWS
#                       - CLEAR_ARP
#                       - HEALTH_REPORT
#                       - NTP_DUMP
#   params            JSON-encoded, test specific-params
#   edge_list         A list of edge ids to run the action separated by a space. (i.e 1 2 3 4). Set to 0 to run for every edge in the enterprise
#   host              the VCO hostname (e.g. vcoXX-usca1.velocloud.net or 12.34.56.7)
#   -c enterprise     id of the enterprise with ownership of the edge
#   --operator        authenticate as an operator user (defaults to True)
#   --insecure        when passed, tells the client to ignore SSL certificate verifcation errors (e.g. in a
#                     sandbox environment)
#
# Dependencies:
#   - The only library required to use this tool is the Python requests library, which can be installed with pip

POLL_SLEEP_INTERVAL = 10 # seconds to sleep between calls to readLiveData
OUTPUT_FILE = 'results/remote_diags_' # file to which HTML-formatted output is written
FILE_EXTENSION = '.html'
HTMLBEGIN = """
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <meta http-equiv='X-UA-Compatible' content='IE=edge'>
    <title>Remote diagnostics results</title>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <link rel="stylesheet" href="../remotediag.css">
</head>
<body>
"""
HTMLEND = """
</body>
</html>
"""
client = None
token = None
username = os.environ['VC_USERNAME']
password = os.environ['VC_PASSWORD']
# we DO NOT encourage you to save credentials in a script. Use environment variables as much as possible.
# if you need to use your credentials, add a # (like the lines below) to the front of username = get_env_or_abort("VC_USERNAME") and password = get_env_or_abort("VC_PASSWORD")
# then remove the # from the lines below
# username = 'yourUsername'
# password = 'YourPassword'
successful_run = []

import argparse
import requests
import json
import re
import sys
import time
import os
from datetime import datetime

class ApiException(Exception):
    pass

class VcoClient(object):

    def __init__(self, hostname, verify_ssl=True):
        self._session = requests.Session()
        self._verify_ssl = verify_ssl
        self._root_url = self._get_root_url(hostname)
        self._portal_url = self._root_url + "/portal/"
        self._livepull_url = self._root_url + "/livepull/liveData/"
        self._seqno = 0

    def _get_root_url(self, hostname):
        """
        Translate VCO hostname to a root url for API calls 
        """
        if hostname.startswith("http"):
            re.sub("http(s)?://", "", hostname)
        proto = "https://"
        return proto + hostname

    def authenticate(self, username, password, is_operator=False):
        """
        Authenticate to API - on success, a cookie is stored in the session
        """
        path = "/login/operatorLogin" if is_operator else "/login/enterpriseLogin"
        url = self._root_url + path
        data = { "username": username, "password": password }
        headers = { "Content-Type": "application/json" }
        r = self._session.post(url, headers=headers, data=json.dumps(data),
                               allow_redirects=False, verify=self._verify_ssl)

    def request(self, method, params, ignore_null_properties=False):
        """
        Build and submit a request
        Returns method result as a Python dictionary
        """
        self._seqno += 1
        headers = { "Content-Type": "application/json" }
        method = self._clean_method_name(method)
        payload = { "jsonrpc": "2.0",
                    "id": self._seqno,
                    "method": method,
                    "params": params }
        if method == "liveMode/readLiveData" or method == "liveMode/requestLiveActions":
            url = self._livepull_url
        else:
            url = self._portal_url

        r = self._session.post(url, headers=headers,
                               data=json.dumps(payload), verify=self._verify_ssl)

        kwargs = {}
        if ignore_null_properties:
            kwargs["object_hook"] = self._remove_null_properties
        response_dict = r.json(**kwargs)
        if "error" in response_dict:
            raise ApiException(response_dict["error"]["message"])
        return response_dict["result"]

    def _remove_null_properties(self, data):
        return {k: v for k, v in data.items() if v is not None}

    def _clean_method_name(self, raw_name):
        """
        Ensure method name is properly formatted prior to initiating request
        """
        return raw_name.strip("/")

def make_test(name, params):
    return { "name": name,
             "parameters": [params] }

def get_edges(enterpriseId):
    global client
    edges = client.request('enterprise/getEnterpriseEdgeList', {"with":["links"],"enterpriseId": enterpriseId})
    edgeList = []
    for edge in edges:
        edgeList.append(edge)
    return edgeList

def run_diagnostics(method, params, test, edge, enterprise_id):
    global client
    global token
    try:
        action_result = client.request(method, params)
    except ApiException as e:
        print("Encountered API error in call to %s: %s" % (method, e))
        sys.exit(-1)

    action_key = action_result["actionsRequested"][0]["actionId"] 
    print("Enqueued %s remote diagnostic action" % test)

    # 3 : Read live data
    method = "liveMode/readLiveData"
    params = { "token": token }
    live_data = None
    action = None
    dump_complete = False
    retries = 0
    while not dump_complete:

        time.sleep(POLL_SLEEP_INTERVAL)
        print("Polling readLiveData...")

        # We're looking for a status value greater than 1 as a cue that the remote precedure has 
        # completed.
        #
        # Status enum is:
        #   0: PENDING
        #   1: NOTIFIED (i.e. Edge has ack'ed its receipt of the action)
        #   2: COMPLETE
        #   3: ERROR
        #   4: TIMEDOUT

        try:
            live_data = client.request(method, params, ignore_null_properties=True)
        except ApiException as e:
            print("Encountered API error in call to %s: %s" % (method, e))
            sys.exit(-1)

        all_action_data = live_data.get("data", {}).get("liveAction", {}).get("data", [])
        actions_matching_key = [a for a in all_action_data if a["data"]["actionId"] == action_key]
        if len(actions_matching_key) > 0:
            action = actions_matching_key[0]
            status = action["data"]["status"]
        else:
            status = 0
        dump_complete = status > 1 or status < 0

        # give up if we've tried to get the result more than 25 times
        retries += 1
        if retries > 25:
            print('Retried action more than 25 times, giving up')
            dump_complete = -1

    if status == 2:
        diag_results = action["data"].get("results", [])
        output = [r for r in diag_results if r["name"] == test][0]["results"]["output"]
        EDGE_FILE = OUTPUT_FILE + edge['name'].replace(' ', '_')  + "_" + test + "_" + datetime.now().strftime("%Y-%m-%dT%H%M%S") + FILE_EXTENSION
        print('Writing diagnostics result to ' + EDGE_FILE)
        with open(EDGE_FILE, "w+") as f:
            f.write(HTMLBEGIN)
            f.write(output)
            f.write(HTMLEND)
            print("Diagnostic result written to " + EDGE_FILE)
        successful_run.append(edge['name'])
    else:
        print("Diagnostic failed, see dump below for details...")
        print(json.dumps(action, sort_keys=True, indent=2))

    # 4 : Exit live mode
    method = "liveMode/exitLiveMode"
    params = { "edgeId": edge['id'], "enterpriseId": enterprise_id }

    try:
        exit_result = client.request(method, params)    
    except ApiException as e:
        print("Encountered API error in call to %s: %s" % (method, e))
        sys.exit(-1)
    print("==========\nEdge %s exited live mode...\n==========" % edge['name'])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("test", help="diagnostic test to perform")
    parser.add_argument("test_params", help="the parameters needed to run your test, optional")
    parser.add_argument("edge_list", nargs='+', help="A list of edge ids to run the action separated by a space. (i.e 1 2 3 4). If set to 0, run for every edge in the enterprise.")
    parser.add_argument("--host", default=os.environ.get("VC_HOSTNAME"), help="vco hostname")
    parser.add_argument("-c", "--enterprise", type=int, help="id of the enterprise with ownership of the specified edge")
    parser.add_argument("--operator", action="store_true", default=False, help="login as operator")
    parser.add_argument("--insecure", action="store_true", help="ignore ssl cert warnings/errors")
    args = parser.parse_args()

    if args.insecure:
        from requests.packages.urllib3.exceptions import (
            InsecureRequestWarning,
            InsecurePlatformWarning,
            SNIMissingWarning
        )
        for warning in ( InsecureRequestWarning, InsecurePlatformWarning, SNIMissingWarning ):
            requests.packages.urllib3.disable_warnings(warning)

    # Initialize client, authenticate
    global client
    global token
    client = VcoClient(args.host, verify_ssl=(not args.insecure))

    try:
        client.authenticate(username, password, args.operator)
    except Exception as e:
        print("Encountered error while authenticating: " + str(e))
        sys.exit(-1)

    # Get enterprise edges
    enterprise_id = args.enterprise
    edges = get_edges(enterprise_id)
    edge_list = []

    # get edge list
    if (int(args.edge_list[0]) == 0):
        if (len(args.edge_list) > 1):
            print('If you want to run for all edges, just specify a 0 in edge list. If you want to run it for a subset, don\'t put a 0 as the first edge_list parameter')
            sys.exit(-1)
        else:
            edge_list = edges
            print('running for all edges in enterprise')
    else:
        for edge in edges:
            if str(edge['id']) in args.edge_list:
                print('Pushed edge %s into the remote diagnostics list' % edge['name'])
                edge_list.append(edge)

    # create results directory if it doesn't exist
    try:
        if not os.path.exists('/results'):
            os.makedirs('results')
    except:
        print('results directory already exists, skipping...')

    # execute action for each edge, one by one
    for edge in edge_list:
        # run this just for those edges online
        if (edge['edgeState'] == "CONNECTED"):
            # 1 : Enter live mode
            method = "liveMode/enterLiveMode"
            params = { "edgeId": edge['id'], "enterpriseId": enterprise_id }
            try:
                entry_result = client.request(method, params)
                token = entry_result["token"]
            except ApiException as e:
                print("Encountered API error in call to %s: %s" % (method, e))
                sys.exit(-1)
            print("==========\nEdge %s entered live mode...\n==========" % edge['name'])
            # 2 : Enqueue remote diagnostic edge action
            if(args.test == "BW_TEST"):
                for link in edge['links']:
                    if(link['state'] == "STABLE"):
                        print('Requesting bandwidth test for link %s' % link['displayName'] )
                        format_link = "{\"link\":\"" + link['internalId'] + "\"}"
                        test = make_test(args.test, format_link)
                        action = { "action": "runDiagnostics", "parameters": { "tests": [test] } }
                        method = "liveMode/requestLiveActions"
                        params = { "token": token, "actions": [action] }
                        run_diagnostics(method, params, args.test, edge, enterprise_id)
            else:
                test = make_test(args.test, args.test_params)    
                action = { "action": "runDiagnostics",
                        "parameters": { "tests": [test] } }
                method = "liveMode/requestLiveActions"
                params = { "token": token,
                        "actions": [action] }
                run_diagnostics(method, params, args.test, edge, enterprise_id)
    print("Script ran for: ")
    for edge in successful_run:
        print("\t-%s" % edge)


if __name__ == "__main__":
    main()
