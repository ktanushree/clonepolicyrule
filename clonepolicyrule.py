#!/usr/bin/env python
"""
CGNX script to clone Network or Priority Policy Rule to another Policy Set

tanushree@cloudgenix.com

"""
import cloudgenix
import os
import sys
import argparse


# Global Vars
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Clone Policy Rule'

try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # will get caught below.
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None


def createrulemaps(cgx_session):
    global nwset_id_name_dict
    global nwset_name_id_dict
    global qosset_id_name_dict
    global qosset_name_id_dict
    global nwpolicyid_ruleidnamedict_dict
    global nwpolicyid_rulenameiddict_dict
    global qospolicyid_ruleidnamedict_dict
    global qospolicyid_rulenameiddict_dict

    nwset_id_name_dict = {}
    nwset_name_id_dict = {}
    qosset_id_name_dict = {}
    qosset_name_id_dict = {}

    nwpolicyid_ruleidnamedict_dict = {}
    nwpolicyid_rulenameiddict_dict = {}
    qospolicyid_ruleidnamedict_dict = {}
    qospolicyid_rulenameiddict_dict = {}

    resp = cgx_session.get.networkpolicysets()
    if resp.cgx_status:
        npsets = resp.cgx_content.get("items", None)
        for np in npsets:
            npid = np['id']
            npname = np['name']
            nwset_id_name_dict[npid] = npname
            nwset_name_id_dict[npname] = npid

            ruleid_rulename_dict = {}
            rulename_ruleid_dict = {}
            resp = cgx_session.get.networkpolicyrules(networkpolicyset_id=npid)
            if resp.cgx_status:
                rules = resp.cgx_content.get("items", None)

                for rule in rules:
                    rid = rule['id']
                    rname = rule['name']
                    ruleid_rulename_dict[rid] = rname
                    rulename_ruleid_dict[rname] = rid

                nwpolicyid_ruleidnamedict_dict[npid] = ruleid_rulename_dict
                nwpolicyid_rulenameiddict_dict[npid] = rulename_ruleid_dict

    resp = cgx_session.get.prioritypolicysets()
    if resp.cgx_status:
        qpsets = resp.cgx_content.get("items", None)
        for qp in qpsets:
            qpid = qp['id']
            qpname = qp['name']
            qosset_id_name_dict[qpid] = qpname
            qosset_name_id_dict[qpname] = qpid

            ruleid_rulename_dict = {}
            rulename_ruleid_dict = {}
            resp = cgx_session.get.prioritypolicyrules(prioritypolicyset_id=qpid)
            if resp.cgx_status:
                rules = resp.cgx_content.get("items", None)

                for rule in rules:
                    rid = rule['id']
                    rname = rule['name']
                    ruleid_rulename_dict[rid] = rname
                    rulename_ruleid_dict[rname] = rid

                qospolicyid_ruleidnamedict_dict[qpid] = ruleid_rulename_dict
                qospolicyid_rulenameiddict_dict[qpid] = rulename_ruleid_dict

    return


def createnewrule(cgx_session, TYPE,SRC_POLICY_SET,SRC_POLICY_RULE,DST_POLICY_SET,DST_POLICY_RULE):
    if TYPE == "NW":
        if SRC_POLICY_SET in nwset_name_id_dict.keys():
            nwpid = nwset_name_id_dict[SRC_POLICY_SET]

            rulesidname = nwpolicyid_rulenameiddict_dict[nwpid]
            rulesnameid = nwpolicyid_rulenameiddict_dict[nwpid]

            if SRC_POLICY_RULE in rulesnameid.keys():
                print("INFO: Rule {} found in Network Policy Set {}".format(SRC_POLICY_RULE, SRC_POLICY_SET))
                rid = rulesnameid[SRC_POLICY_RULE]
                resp = cgx_session.get.networkpolicyrules(networkpolicyset_id=nwpid, networkpolicyrule_id=rid)
                if resp.cgx_status:
                    rule = resp.cgx_content

                    if DST_POLICY_SET in nwset_name_id_dict.keys():
                        dstpolid = nwset_name_id_dict[DST_POLICY_SET]
                        print("INFO: Destination Network Policy Set {} found".format(DST_POLICY_SET))
                        print("INFO: Creating rule {} in policy {}".format(DST_POLICY_RULE, DST_POLICY_SET))

                        nwrulepayload = {
                            "name": DST_POLICY_RULE,
                            "description": rule.get("description", None),
                            "tags": rule.get("tags", None),
                            "network_context_id": rule.get("network_context_id", None),
                            "source_prefixes_id": rule.get("source_prefixes_id", None),
                            "destination_prefixes_id": rule.get("destination_prefixes_id", None),
                            "app_def_ids": rule.get("app_def_ids", None),
                            "paths_allowed": rule.get("paths_allowed", None),
                            "service_context": rule.get("service_context", None),
                            "order_number": rule.get("order_number", None),
                            "enabled": rule.get("enabled", None)
                        }

                        resp = cgx_session.post.networkpolicyrules(networkpolicyset_id=dstpolid, data=nwrulepayload)
                        if resp.cgx_status:
                            print("SUCCESS: Rule {} created on Network Policy Set {}".format(DST_POLICY_RULE,
                                                                                             DST_POLICY_SET))

                        else:
                            print("ERR: Could not create the rule")
                            cloudgenix.jd_detailed(resp)

                    else:
                        print("ERR: Invalid Destination {} Policy set name: {}".format(TYPE, DST_POLICY_SET))
                        print("Please select from the following:")
                        for x in nwset_name_id_dict.keys():
                            print("\t{}".format(x))
            else:
                print("ERR: Rule {} does not exist in Network Policy Set {}".format(SRC_POLICY_RULE, SRC_POLICY_SET))
                print("Please select from the following rules:")
                for x in rulesnameid.keys():
                    print("\t{}".format(x))

        else:
            print("ERR: Invalid Source {} Policy set name: {}".format(TYPE, SRC_POLICY_SET))
            print("Please select from the following:")
            for x in nwset_name_id_dict.keys():
                print("\t{}".format(x))

    elif TYPE == "QOS":
        if SRC_POLICY_SET in qosset_name_id_dict.keys():
            qospid = qosset_name_id_dict[SRC_POLICY_SET]

            rulesidname = qospolicyid_rulenameiddict_dict[qospid]
            rulesnameid = qospolicyid_rulenameiddict_dict[qospid]

            if SRC_POLICY_RULE in rulesnameid.keys():
                print("INFO: Rule {} found in Priority Policy Set {}".format(SRC_POLICY_RULE, SRC_POLICY_SET))
                rid = rulesnameid[SRC_POLICY_RULE]
                resp = cgx_session.get.prioritypolicyrules(prioritypolicyset_id=qospid, prioritypolicyrule_id=rid)
                if resp.cgx_status:
                    rule = resp.cgx_content

                    if DST_POLICY_SET in qosset_name_id_dict.keys():
                        dstpolid = qosset_name_id_dict[DST_POLICY_SET]

                        print("INFO: Destination Priority Policy Set {} found".format(DST_POLICY_SET))
                        print("INFO: Creating rule {} in policy {}".format(DST_POLICY_RULE, DST_POLICY_SET))

                        qosrulepayload = {
                            "name": DST_POLICY_RULE,
                            "description": rule.get("description", None),
                            "tags": rule.get("tags", None),
                            "network_context_id": rule.get("network_context_id", None),
                            "source_prefixes_id": rule.get("source_prefixes_id", None),
                            "destination_prefixes_id": rule.get("destination_prefixes_id", None),
                            "app_def_ids": rule.get("app_def_ids", None),
                            "priority_number": rule.get("priority_number", None),
                            "dscp": rule.get("dscp", None),
                            "order_number": rule.get("order_number", None),
                            "enabled": rule.get("enabled", None)
                        }

                        resp = cgx_session.post.prioritypolicyrules(prioritypolicyset_id=dstpolid, data=qosrulepayload)
                        if resp.cgx_status:
                            print("SUCCESS: Rule {} created on Priority Policy Set {}".format(DST_POLICY_RULE,
                                                                                              DST_POLICY_SET))

                        else:
                            print("ERR: Could not create the rule")
                            cloudgenix.jd_detailed(resp)

                    else:
                        print("ERR: Invalid Destination {} Policy set name: {}".format(TYPE, DST_POLICY_SET))
                        print("Please select from the following:")
                        for x in qosset_name_id_dict.keys():
                            print("\t{}".format(x))
            else:
                print("ERR: Rule {} does not exist in Priority Policy Set {}".format(SRC_POLICY_RULE, SRC_POLICY_SET))
                print("Please select from the following rules:")
                for x in rulesnameid.keys():
                    print("\t{}".format(x))

        else:
            print("ERR: Invalid Source {} Policy set name: {}".format(TYPE, SRC_POLICY_SET))
            print("Please select from the following:")
            for x in qosset_name_id_dict.keys():
                print("\t{}".format(x))

    else:
        print("ERR: Invalid Policy Type: {}. Please pick NW or QOS".format(TYPE))

    return


def cleanexit(cgx_session):
    print("Logging out")
    cgx_session.get.logout()

    sys.exit()




def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-P", help="Use this Password instead of prompting",
                             default=None)

    # Commandline for entering Site info
    policy_group = parser.add_argument_group('Policy Set & Rule Specific Information',
                                           'Name policy set, rule and policy type that needs to be cloned')
    policy_group.add_argument("--type", "-T", help="Type of Policy Set. Allowed values: NW or QOS", default=None)
    policy_group.add_argument("--srcpolicy", "-SP", help="Source Policy Set Name", default=None)
    policy_group.add_argument("--srcrule", "-SR", help="Source Policy Rule. This is the rule that will be cloned", default=None)
    policy_group.add_argument("--dstpolicy", "-DP", help="Destination Policy Set Name", default=None)
    policy_group.add_argument("--dstrule", "-DR", help="Destination Policy Rule. This new rule will be created in the destination policy set", default=None)

    args = vars(parser.parse_args())

    ############################################################################
    # Instantiate API & Login
    ############################################################################

    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=False)
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SDK_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # Parse Arguments
    ############################################################################
    TYPE = args['type']
    if TYPE not in ["NW","QOS"]:
        print("ERR: Invalid policy type: {}. Please choose NW or QOS".format(TYPE))
        cleanexit(cgx_session)

    SRC_POLICY_SET = args['srcpolicy']
    SRC_POLICY_RULE = args['srcrule']
    DST_POLICY_SET = args['dstpolicy']
    DST_POLICY_RULE = args['dstrule']

    if (SRC_POLICY_RULE == None) or (SRC_POLICY_SET == None) or (DST_POLICY_RULE == None) or (DST_POLICY_SET==None):
        print("ERR: Please provide both source and destination policy set and rule name")
        cleanexit(cgx_session)

    ############################################################################
    # Build Translation Dicts
    ############################################################################
    createrulemaps(cgx_session)

    ############################################################################
    # Create Rule
    ############################################################################
    createnewrule(cgx_session,TYPE,SRC_POLICY_SET,SRC_POLICY_RULE,DST_POLICY_SET,DST_POLICY_RULE)

    ############################################################################
    # Logout to clear session.
    ############################################################################
    cgx_session.get.logout()

    print("INFO: Logging Out")
    sys.exit()

if __name__ == "__main__":
    go()
