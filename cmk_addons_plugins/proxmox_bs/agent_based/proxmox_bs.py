#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2021 inett GmbH
# License: GNU General Public License v2
# A file is subject to the terms and conditions defined in the file LICENSE,
# which is part of this source code package.
from typing import Mapping, Any

from cmk.agent_based.v2 import (
    StringTable,
    DiscoveryResult,
    Service,
    Result,
    State,
    CheckResult,
    AgentSection,
    CheckPlugin,
    Metric,
    ServiceLabel,
    render,
    get_value_store,
)
from cmk.plugins.lib.df import df_check_filesystem_single, FILESYSTEM_DEFAULT_LEVELS
import re
import json

import time
from datetime import datetime

proxmox_bs_subsection_start = re.compile("^===")
proxmox_bs_subsection_int = re.compile("===.*$")
proxmox_bs_subsection_end = re.compile("^=")

Section = dict

# depends on OUTPUT_FORMAT="--output-format json" in agent. Other output formats crashing the check
def parse_proxmox_bs(string_table: StringTable) -> Section:
    parsed = {'tasks': {}, 'data_stores': {}}
    key = ""
    for line in string_table:
        if line == ["="] or line == [""]:
            continue
        elif line[0].startswith("==="):
            key = "_".join(line).strip("=")
            if key.__contains__("===") and not key.__contains__("proxmox-backup-manager_task_log"):
                keys = key.split("===")
                if not parsed['data_stores'].__contains__(keys[1]):
                    parsed['data_stores'][keys[1]] = {keys[0]: {}}
        elif key == "requirements":
            continue
        else:
            if key.__contains__("==="):
                if not key.__contains__("proxmox-backup-manager_task_log"):
                    keys = key.split("===")
                    try:
                        parsed['data_stores'][keys[1]][keys[0]] = json.loads(" ".join(line))
                    except json.decoder.JSONDecodeError:
                        pass
                else:
                    tmp_key = key.split("===")[1]
                    line = " ".join(line)
                    if not parsed['tasks'].__contains__(tmp_key):
                        parsed['tasks'][tmp_key] = {}
                    if line.__contains__(":"):
                        line = line.split(":")
                        parsed['tasks'][tmp_key][line[0]] = line[1]
                    else:
                        if line == "TASK OK":
                            parsed['tasks'][tmp_key]['task_ok'] = True
                        else:
                            parsed['tasks'][tmp_key]['task_ok'] = False
            else:
                try:
                    parsed[key.split("_", 1)[1]] = json.loads(" ".join(line))
                except json.decoder.JSONDecodeError:
                    pass
    return parsed


agent_section_proxmox_bs = AgentSection(
    name="proxmox_bs",
    parse_function=parse_proxmox_bs,
)


def discover_proxmox_bs(section: Section) -> DiscoveryResult:
    for key in section['data_stores'].keys():
        yield Service(
            item=key,
            labels=[ServiceLabel('pbs/datastore', 'yes')],
        )


def check_proxmox_bs(item: str, params: Mapping[str, Any], section: Section) -> CheckResult:
    data_store = section['data_stores'][item]

    running_tasks = []
    gc_running = False
    for task in section['task_list']:                                                                   # proxmox-backup-manager task list
        if "starttime" in task and "endtime" not in task:
            running_tasks.append(task['upid'])
            if task.get('worker_id', None) is not None and task['worker_id'].__contains__(item):
                gc_running = True

    garbage_collection = data_store['proxmox-backup-manager_garbage-collection_status']                 # proxmox-backup-manager garbage-collection status
    upid = None
    if garbage_collection.get('upid', None) is not None:
        upid = garbage_collection['upid']
    if len(data_store.keys()) != 4:
        yield Result(
            state=State.CRIT,
            summary=f"Authorization failed. Please check to make sure the Given Credentials were correct."
        )
        return
    b_list = data_store['proxmox-backup-client_list']                                                   # proxmox-backup-client list
    group_count = 0
    total_backups = 0
    for e in b_list:
        group_count += 1
        total_backups += int(e['backup-count'])

    yield Metric(
        name="group_count",
        value=group_count,
    )
    yield Metric(
        name="total_backups",
        value=total_backups,
    )

    snapshot_list = data_store['proxmox-backup-client_snapshot_list']                                   # proxmox-backup-client snapshot list
    nr, np, ok, nok = 0, [], 0, []
    for e in snapshot_list:
        if e.get("verification", None) is not None:
            verify_state = e['verification'].get("state", "na")
            if verify_state == "ok":
                ok += 1
            elif verify_state == "failed":
                nok.append(e)
            else:
                np.append(e)
        else:
            nr += 1

    yield Metric(
        name="verify_ok",
        value=ok,
    )
    yield Metric(
        name="verify_failed",
        value=len(nok),
    )
    yield Metric(
        name="verify_unknown",
        value=len(np)
    )
    yield Metric(
        name="verify_none",
        value=nr,
        levels=(group_count, group_count * 2)
    )
    yield Result(
        state=State.OK,
        summary=f"Snapshots Verified: {ok}"
    )
    yield Result(
        state=State.OK,
        summary=f"Snapshots not verified yet: {nr}"
    )

    for e in np:
        group = f"{e['backup-type']}/{e['backup-id']}"
        stat = e['verification']['state']
        upid = e['verification']['upid']
        yield Result(
            state=State.UNKNOWN,
            summary=f"{group} ({upid}) unknown state {stat}"
        )
    for e in nok:
        group = f"{e['backup-type']}/{e['backup-id']}"
        stat = e['verification']['state']
        upid = e['verification']['upid']
        yield Result(
            state=State.CRIT,
            summary=f"Verification of {group} ({upid}) {stat}",
        )

    status = data_store['proxmox-backup-client_status']                                                 # proxmox-backup-client status

    try:
        size_mb = float(status['total'])/1024/1024      #status['total'] returning bytes instead of mb
        avail_mb = float(status['avail'])/1024/1024     #status['avail'] returning bytes instead of mb
        value_store = get_value_store()

        yield from df_check_filesystem_single(
            value_store=value_store,
            mountpoint=item,
            filesystem_size=size_mb,
            free_space=avail_mb,
            reserved_space=0, # See df.py: ... if (filesystem_size is None) or (free_space is None) or (reserved_space is None): yield Result(state=State.OK, summary="no filesystem size information")
            inodes_total=None,
            inodes_avail=None,
            params=params,
            this_time=None,
        )
    except:
        yield Result(
            state=State.UNKNOWN,
            summary=f"error checking datastore status"
        )

    gc_ok = False
    if section['tasks'].get(upid, None) is not None:                                                    # proxmox-backup-manager task log
        gc_ok = section['tasks'][upid].get('task_ok', False)

    if gc_running:
        yield Result(
            state=State.OK,
            summary=f"GC running",
        )
    elif gc_ok:
        yield Result(
            state=State.OK,
            summary=f"GC ok"
        )
    elif upid is None:
        yield Result(
            state=State.UNKNOWN,
            summary=f"GC not run yet",
        )
    else:
        yield Result(
            state=State.WARN,
            summary=f"GC Task failed",
        )


check_plugin_proxmox_bs = CheckPlugin(
    name="proxmox_bs",
    service_name="PBS Datastore %s",
    sections=["proxmox_bs"],
    discovery_function=discover_proxmox_bs,
    check_function=check_proxmox_bs,
    check_default_parameters=FILESYSTEM_DEFAULT_LEVELS,
    check_ruleset_name="filesystem",
)















# Proxmox Client Checks added by:
# E-Mail: matthias.maderer@web.de
# License: GPLv2

# convert old pre Checkmk 2.4 parameters to new format
def params_parser(params):
    params_new = {}

    for p in params:
        if params[p] is not None and isinstance(params[p], tuple):
            if params[p][0] in ("fixed", "no_levels", "predictive"):
                params_new[p] = params[p]
            elif isinstance(params[p][0], (int, float)) and isinstance(params[p][1], (int, float)):
                params_new[p] = ('fixed', (params[p][0], params[p][1]))
            else:
                params_new[p] = params[p]
        else:
           params_new[p] = params[p]

    return params_new




# generate Service names with this function. -> Get identical names in discovery and check
def proxmox_bs_gen_clientname(client_json):
    if "comment" in client_json and "backup-id" in client_json:
        return str(client_json["backup-id"]) + "-" + str(client_json["comment"])


# generate Checkmk Service Items
def proxmox_bs_clients_discovery(section):
    if 'data_stores' not in section:
        return

    clients = []

    #structure results from check output
    for data_store in section['data_stores']:
        if 'proxmox-backup-client_snapshot_list' not in section['data_stores'][data_store]:
            continue

        #collect all clientnames and backup-id's
        for client_section in section['data_stores'][data_store]['proxmox-backup-client_snapshot_list']:
            if "comment" in client_section and "backup-id" in client_section:
                cn = proxmox_bs_gen_clientname(client_section)

                if not cn in clients:
                    clients.append(cn)

    for client_name in clients:
        yield Service(
            item=client_name,
            #labels=[ServiceLabel('pbs/datastore', 'yes')]
        )


# Example JSON output from check
#[
#{
#    "backup-id":"103",
#    "backup-time":1742890730,
#    "backup-type":"vm",
#    "comment":"pfsense01",
#    "files":[
#        {
#            "crypt-mode":"none",
#            "filename":"qemu-server.conf.blob",
#            "size":487
#        },
#        {
#            "crypt-mode":"none",
#            "filename":"drive-scsi0.img.fidx",
#            "size":34359738368
#        },
#        {
#            "crypt-mode":"none",
#            "filename":"index.json.blob",
#            "size":414
#        },
#        {
#            "filename":"client.log.blob"
#        }
#    ],
#    "owner":"user",
#    "protected":false,
#    "size":34359739269
#},
#{
#    "backup-id":"103",
#    "backup-time":1742550846,
#    "backup-type":"vm",
#    "comment":"pfsense01",
#    "files":[
#       {
#           "crypt-mode":"none",
#           "filename":"qemu-server.conf.blob",
#           "size":487
#        },
#        {
#            "crypt-mode":"none",
#            "filename":"drive-scsi0.img.fidx",
#            "size":34359738368
#        },
#        {
#            "crypt-mode":"none",
#            "filename":"index.json.blob",
#            "size":514
#        },
#        {
#            "filename":"client.log.blob"
#        }
#    ],
#    "owner":"user",
#    "protected":false,
#    "size":34359739369,
#    "verification":{
#        "state":"ok",
#        "upid":"UPID:pbs:000002C0:000007BA:00000001:67DE4FC4:verificationjob:fs01\\x3av\\x2dee54fa7e\\x2d61f0:root@pam:"
#    }
#}
#]



# Check function
def proxmox_bs_clients_checks(item, params, section):
    clients = {}

    # Only work with new params
    params_cmk_24 = params_parser(params)

    if 'data_stores' not in section:
            yield Result(state=State.UNKNOWN, summary=(
                'No section data_stores found in agent output'
                ))
            return

    #structure results from check output
    for data_store in section['data_stores']:
        if 'proxmox-backup-client_snapshot_list' not in section['data_stores'][data_store]:
            yield Result(state=State.UNKNOWN, summary=(
                'No section proxmox-backup-client_snapshot_list found in agent output'
                ))
            return

        for e in section['data_stores'][data_store]['proxmox-backup-client_snapshot_list']:
            #Get clientname
            cn = proxmox_bs_gen_clientname(e)

            #Only process do fruther processing for current item
            if cn != item:
                continue

            if not cn in clients:
                clients[cn] = {}

            #Verification states
            if not "verification" in clients[cn]:
                clients[cn]["verification"] = {}

                clients[cn]["verification"]["ok"] = {}
                clients[cn]["verification"]["ok"]["newest_date"] = None
                clients[cn]["verification"]["ok"]["count"] = 0

                clients[cn]["verification"]["failed"] = {}
                clients[cn]["verification"]["failed"]["newest_date"] = None
                clients[cn]["verification"]["failed"]["count"] = 0

                clients[cn]["verification"]["notdone"] = {}
                clients[cn]["verification"]["notdone"]["newest_date"] = None
                clients[cn]["verification"]["notdone"]["count"] = 0

            #Backup age
            dt = int(e["backup-time"])

            if "verification" in e:
                verify_state = e.get("verification", {}).get("state", "na")
                if verify_state == "ok":
                    clients[cn]["verification"]["ok"]["count"] += 1
                    if clients[cn]["verification"]["ok"]["newest_date"] == None:
                        clients[cn]["verification"]["ok"]["newest_date"] = dt
                    elif clients[cn]["verification"]["ok"]["newest_date"] < dt:
                        clients[cn]["verification"]["ok"]["newest_date"] = dt

                else:
                    clients[cn]["verification"]["failed"]["count"] += 1
                    if clients[cn]["verification"]["failed"]["newest_date"] == None:
                        clients[cn]["verification"]["failed"]["newest_date"] = dt
                    elif clients[cn]["verification"]["failed"]["newest_date"] < dt:
                        clients[cn]["verification"]["failed"]["newest_date"] = dt
            else:
                    clients[cn]["verification"]["notdone"]["count"] += 1
                    if clients[cn]["verification"]["notdone"]["newest_date"] == None:
                        clients[cn]["verification"]["notdone"]["newest_date"] = dt
                    elif clients[cn]["verification"]["notdone"]["newest_date"] < dt:
                        clients[cn]["verification"]["notdone"]["newest_date"] = dt


        #Process client result and yield results (in the clients array should only be the client matching the item)
        for cn in clients:
            if cn != item: #useless, because filtering for the right item is done above. But leave it there for safty.
                continue

            #OK
            dpt = ""
            if clients[cn]["verification"]["ok"]["count"] < params_cmk_24["snapshot_min_ok"]:
                s=State.WARN
                dpt= " (minimum of %s backups not reached)" % params_cmk_24["snapshot_min_ok"]
            elif clients[cn]["verification"]["ok"]["count"] >= params_cmk_24["snapshot_min_ok"]:
                s=State.OK
                dpt= ""

            yield Result(state=s, summary=(
                'Snapshots verify OK: %d%s' % (clients[cn]["verification"]["ok"]["count"],dpt)
                ))

            #Age Check OK
            if clients[cn]["verification"]["ok"]["newest_date"] != None:
                age = int(time.time() - clients[cn]["verification"]["ok"]["newest_date"])

                warn_age, critical_age = params_cmk_24['bkp_age'][1]

                if age >= critical_age:
                    s = State.CRIT
                elif age >= warn_age:
                    s = State.WARN
                else:
                    s = State.OK

                yield Result(state=s, summary=(
                    'Timestamp latest verify OK: %s, Age: %s' % (render.datetime(clients[cn]["verification"]["ok"]["newest_date"]), render.timespan(age))
                    ))
            else:
                s = State.WARN
                yield Result(state=s, summary=(
                    'Timestamp latest verify OK: No verified snapshot found'
                    ))

            #Not verified
            yield Result(state=State.OK, summary=(
                'Snapshots verify notdone: %d' % clients[cn]["verification"]["notdone"]["count"]
                ))

            if clients[cn]["verification"]["notdone"]["newest_date"] != None:
                age = int(time.time() - clients[cn]["verification"]["notdone"]["newest_date"])

                yield Result(state=State.OK, summary=(
                    'Timestamp latest unverified: %s, Age: %s' % (render.datetime(clients[cn]["verification"]["notdone"]["newest_date"]), render.timespan(age))
                    ))
            else:
                s = State.WARN
                yield Result(state=State.OK, summary=(
                    'Timestamp latest unverified: No unverified snapshot found'
                    ))


            #Failed
            if clients[cn]["verification"]["failed"]["count"] > 0:
                s=State.CRIT
            else:
                s=State.OK

            yield Result(state=s, summary=(
                'Snapshots verify failed: %d' % clients[cn]["verification"]["failed"]["count"]
                ))


check_plugin_proxmox_bs_clients = CheckPlugin(
    name="proxmox_bs_clients",
    service_name="PBS Client %s",
    sections=["proxmox_bs"],
    discovery_function=proxmox_bs_clients_discovery,
    check_function=proxmox_bs_clients_checks,
    check_default_parameters={
                                'bkp_age': ('fixed', (172800, 259200)),
                                'snapshot_min_ok': 1
                            },
    check_ruleset_name="proxmox_bs_clients",
)