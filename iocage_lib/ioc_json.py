# Copyright (c) 2014-2018, iocage
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
"""Convert, load or write JSON."""
import collections
import datetime
import fileinput
import json
import logging
import os
import re
import shutil
import subprocess as su
import sys

import iocage_lib.ioc_common
import iocage_lib.ioc_create
import iocage_lib.ioc_exec
import iocage_lib.ioc_list
import iocage_lib.ioc_stop
import iocage_lib.ioc_exceptions as ioc_exceptions
import libzfs
import netifaces


class IOCJson(dict):

    """
    Migrates old iocage configurations(UCL and ZFS Props) to the new JSON

    format, will set and get properties.
    """

    _hostid = None
    CONFIG_VERSION = "14"
    loaded: bool

    def __init__(
        self,
        location="",
        silent=False,
        cli=False,
        stop=False,
        callback=None
    ):
        dict.__init__(self, {})
        self.loaded = False

        self.location = location
        self.lgr = logging.getLogger('ioc_json')
        self.cli = cli
        self.stop = stop
        self.silent = silent
        self.callback = callback

        try:
            force_env = os.environ["IOCAGE_FORCE"]
        except KeyError:
            # FreeNAS or an API user, due to the sheer web of calls to this
            # module we are assuming they are OK with any renaming operations

            force_env = "TRUE"

        self.force = True if force_env == "TRUE" else False
        self.zfs = libzfs.ZFS(history=True, history_prefix="<iocage>")

    def __getitem__(self, key):
        if self.loaded is False:
            self.json_load()

        if key == "host_hostuuid":
            return dict.get(self, key, self.hostid)

        try:
            return dict.__getitem__(self, key)
        except KeyError:
            return self.global_default_properties[key]

    def __setitem__(self, key, value):
        if self.loaded is False:
            self.json_load()
        dict.__setitem__(self, key, value)

    def json_convert_from_ucl(self):
        """Convert to JSON. Accepts a location to the ucl configuration."""

        if os.geteuid() != 0:
            raise RuntimeError("You need to be root to convert the"
                               " configurations to the new format!")

        with open(self.location + "/config", "r") as conf:
            lines = conf.readlines()

        key_and_value = {}

        for line in lines:
            line = line.partition("=")
            key = line[0].rstrip()
            value = line[2].replace(";", "").replace('"', '').strip()

            key_and_value[key] = value

        self.json_write(key_and_value)

    def json_convert_from_zfs(self, uuid, skip=False):
        """Convert to JSON. Accepts a jail UUID"""
        dataset = f"{self.pool.name}/iocage/jails/{uuid}"
        jail_zfs_prop = "org.freebsd.iocage:jail_zfs_dataset"

        if os.geteuid() != 0:
            raise RuntimeError("You need to be root to convert the"
                               " configurations to the new format!")

        props = self.zfs.get_dataset(dataset).properties

        # Filter the props we want to convert.
        prop_prefix = "org.freebsd.iocage"

        key_and_value = {"host_domainname": "none"}

        for key, prop in props.items():

            if not key.startswith(prop_prefix):
                continue

            key = key.partition(":")[2]
            value = prop.value

            if key == "type":
                if value == "basejail":
                    # These were just clones on master.
                    value = "jail"
                    key_and_value["basejail"] = "yes"
            elif key == "hostname":
                hostname = props[f'{prop_prefix}:host_hostname']

                if value != hostname:
                    # This is safe to replace at this point.
                    # The user changed the wrong hostname key, we will move
                    # it to the right one now.

                    if hostname == uuid:
                        key_and_value["host_hostname"] = prop.value

                continue

            key_and_value[key] = value

        if not skip:
            # Set jailed=off and move the jailed dataset.
            try:
                self.zfs_set_property(f"{dataset}/root/data", "jailed", "off")
                self.zfs.get_dataset(f"{dataset}/root/data").rename(
                    f"{dataset}/data", False, True)
                self.zfs_set_property(f"{dataset}/data", jail_zfs_prop,
                                      f"iocage/jails/{uuid}/data")
                self.zfs_set_property(f"{dataset}/data", "jailed", "on")
            except libzfs.ZFSException as err:
                # The jailed dataset doesn't exist, which is OK.
                pass

        key_and_value["jail_zfs_dataset"] = f"iocage/jails/{uuid}/data"

        self.json_write(key_and_value)

    def _zfs_get_properties(self, identifier):
        if "/" in identifier:
            dataset = self.zfs.get_dataset(identifier)
            return dataset.properties
        else:
            pool = self.zfs.get(identifier)
            return pool.root_dataset.properties

    def zfs_get_property(self, identifier, key):
        try:
            return self._zfs_get_properties(identifier)[key].value
        except Exception:
            return "-"

    def zfs_set_property(self, identifier, key, value):
        props = self._zfs_get_properties(identifier)
        if ":" in key:
            props[key] = libzfs.ZFSUserProperty(value)
        else:
            props[key].value = value

    def json_load(self):
        """Load the JSON at the location given. Returns a JSON object."""
        jail_type, jail_uuid = self.location.rsplit("/", 2)[-2:]
        full_uuid = jail_uuid  # Saves jail_uuid for legacy ZFS migration
        legacy_short = False

        try:
            dataset_name = f"{self.pool.name}/iocage/{jail_type}/{jail_uuid}"
            jail_dataset = self.zfs.get_dataset(dataset_name)
        except libzfs.ZFSException as err:
            if err.code == libzfs.Error.NOENT:
                if os.path.isfile(self.location + "/config"):
                    iocage_lib.ioc_common.logit(
                        {
                            "level": "EXCEPTION",
                            "message": "iocage_legacy develop had a broken"
                            " hack88 implementation.\nPlease manually rename"
                            f" {jail_uuid} or destroy it with zfs."
                        },
                        _callback=self.callback,
                        silent=self.silent)

                jail_dataset = self.zfs.get_dataset_by_path(self.location)
                full_uuid = jail_dataset.name.rsplit("/")[-1]
                legacy_short = True
            else:
                raise()

        skip = False

        if jail_dataset.mountpoint is None:
            try:
                jail_dataset.mount_recursive()
            except libzfs.ZFSException as err:
                iocage_lib.ioc_common.logit(
                    {
                        "level": "EXCEPTION",
                        "message": err
                    },
                    _callback=self.callback,
                    silent=self.silent)

        try:
            conf = self.json_read("/config.json")
        except FileNotFoundError:
            try:
                # If this is a legacy jail, it will be missing this file but
                # not this key.
                jail_dataset.properties["org.freebsd.iocage:host_hostuuid"]
            except KeyError:
                if os.path.isfile(f"{self.location}/config"):
                    # iocage legacy develop jail, not missing configuration
                    pass
                else:
                    iocage_lib.ioc_common.logit(
                        {
                            "level":
                            "EXCEPTION",
                            "message":
                            f"{jail_uuid} is missing it's configuration,"
                            " please destroy this jail and recreate it."
                        },
                        _callback=self.callback,
                        silent=self.silent)

            if not self.force:
                iocage_lib.ioc_common.logit(
                    {
                        "level":
                        "EXCEPTION",
                        "message":
                        "A renaming operation is required to continue.\n"
                        f"Please run iocage -f {sys.argv[-1]} as root."
                    },
                    _callback=self.callback,
                    silent=self.silent)

            if os.path.isfile(self.location + "/config"):
                self.json_convert_from_ucl()
                conf = self.json_read(self.location + "/config.json")
            else:
                try:
                    dataset = self.location.split("/")

                    for d in dataset:
                        if len(d) == 36:
                            uuid = d
                        elif len(d) == 8:
                            # Hack88 migration to a perm short UUID.
                            short_uuid = full_uuid[:8]
                            jails_ds_name = f"{self.root_dataset.name}/jails"
                            full_dataset = f"{jails_ds_name}/{full_uuid}"
                            short_dataset = f"{jails_ds_name}/{short_uuid}"

                            jail_hostname = self.zfs_get_property(
                                full_dataset,
                                'org.freebsd.iocage:host_hostname')

                            self.json_convert_from_zfs(full_uuid)
                            conf = self.json_read(
                                self.location + "/config.json"
                            )

                            iocage_lib.ioc_common.logit(
                                {
                                    "level":
                                    "INFO",
                                    "message":
                                    "hack88 is no longer supported."
                                    f"\n{full_dataset} is being "
                                    f"converted to {short_dataset}"
                                    f" permanently."
                                },
                                _callback=self.callback,
                                silent=self.silent)

                            status, _ = iocage_lib.ioc_list.IOCList(
                            ).list_get_jid(full_uuid)

                            if status:
                                iocage_lib.ioc_common.logit(
                                    {
                                        "level":
                                        "INFO",
                                        "message":
                                        "Stopping jail to migrate UUIDs."
                                    },
                                    _callback=self.callback,
                                    silent=self.silent)
                                iocage_lib.ioc_stop.IOCStop(
                                    full_uuid,
                                    self.location,
                                    conf,
                                    silent=True)

                            jail_zfs_prop = \
                                "org.freebsd.iocage:jail_zfs_dataset"
                            uuid_prop = "org.freebsd.iocage:host_hostuuid"
                            host_prop = "org.freebsd.iocage:host_hostname"

                            # Set jailed=off and move the jailed dataset.
                            self.zfs_set_property(f"{full_dataset}/data",
                                                  'jailed', 'off')

                            # We don't want to change a real hostname.

                            if jail_hostname == full_uuid:
                                self.zfs_set_property(full_dataset, host_prop,
                                                      short_uuid)

                            self.zfs_set_property(
                                full_dataset,
                                uuid_prop,
                                short_uuid
                            )
                            self.zfs_set_property(
                                f"{full_dataset}/data",
                                jail_zfs_prop,
                                f"iocage/jails/{short_uuid}/data"
                            )

                            self.zfs.get_dataset(full_dataset).rename(
                                short_dataset,
                                False,
                                True
                            )
                            self.zfs_set_property(
                                f"{short_dataset}/data",
                                "jailed",
                                "on"
                            )

                            uuid = short_uuid
                            self.location = (
                                f"{self.iocroot.mountpoint}/jails/{uuid}"
                            )
                            skip = True

                    if uuid is None:
                        iocage_lib.ioc_common.logit(
                            {
                                "level": "EXCEPTION",
                                "message": "Configuration could not be loaded,"
                                " is the jail dataset mounted?"
                            },
                            _callback=self.callback,
                            silent=self.silent)

                    self.json_convert_from_zfs(uuid, skip=skip)
                    conf = self.json_read(self.location + "/config.json")

                    if legacy_short:
                        messages = collections.OrderedDict(
                            [("1-NOTICE", "*" * 80),
                             ("2-WARNING",
                              f"Jail: {full_uuid} was renamed to {uuid}"),
                             ("3-NOTICE",
                              f"{'*' * 80}\n"),
                             ("4-EXCEPTION",
                              "Please issue your command again.")])

                        for level, msg in messages.items():
                            level = level.partition("-")[2]

                            iocage_lib.ioc_common.logit(
                                {
                                    "level": level,
                                    "message": msg
                                },
                                _callback=self.callback,
                                silent=self.silent)
                except su.CalledProcessError:
                    # At this point it should be a real misconfigured jail
                    raise RuntimeError("Configuration is missing!"
                                       f" Please destroy {uuid} and recreate"
                                       " it.")

        conf_key = "CONFIG_VERSION"
        own_version = self.CONFIG_VERSION
        if (conf_key in conf.keys()) and (conf[conf_key] == own_version):
            self.update_data(conf)
        else:
            self.update_data(self.json_check_config(conf))
        self.loaded = True

    def update_data(self, data):
        self.clear()
        dict.__init__(self, data)
        self.loaded = True

    def json_write(self, data, _file="/config.json", location=None):
        """Write a JSON file at the location given with supplied data."""
        location = self.location if (location is None) else location
        filepath = location + _file
        with iocage_lib.ioc_common.open_atomic(filepath, 'w') as out:
            json.dump(data, out, sort_keys=True, indent=4, ensure_ascii=False)

    def json_read(self, _file="/config.json", location=None):
        location = self.location if (location is None) else location
        filepath = location + _file
        with open(filepath, "r") as f:
            return json.load(f)

    def _upgrade_pool(self, pool):
        if os.geteuid() != 0:
            raise RuntimeError("Run as root to migrate old pool"
                               " activation property!")

        self.zfs_set_property(pool, "org.freebsd.ioc:active", "yes")
        self.zfs_set_property(pool, "comment", "-")

    def json_get_value(self, prop, default=False):
        """Returns a string with the specified prop's value."""
        if default is True:
            return self._json_get_default_value(prop)
        elif prop == "pool":
            return self.pool
        elif prop == "iocroot":
            return self.iocroot.mountpoint
        elif prop == "all":
            raise Exception("Access the IOCJson instance directly")
        else:
            return self._json_get_user_value(prop)

    def _json_get_default_value(self, prop):
        if prop == "all":
            return self
        return self[prop]

    @property
    def iocroot(self):
        return self.root_dataset

    @property
    def root_dataset(self):
        return self.zfs.get_dataset(f"{self.pool.name}/iocage")

    @property
    def pool(self):
        zpools = list(self.zfs.pools)
        old = False
        match = 0
        for pool in zpools:
            prop_ioc_active = self.zfs_get_property(
                pool.name,
                "org.freebsd.ioc:active"
            )
            prop_comment = self.zfs_get_property(pool, "comment")

            if prop_ioc_active == "yes":
                _dataset = pool.name
                match += 1
            elif prop_comment == "iocage":
                _dataset = pool.name
                match += 1
                old = True

        if match == 1:
            if old:
                self._upgrade_pool(_dataset)
            return pool

        elif match >= 2:
            iocage.lib.ioc_common.logit(
                {
                    "level": "ERROR",
                    "message": "Pools:"
                },
                _callback=self.callback,
                silent=self.silent)

                if prop_ioc_active == "yes":
                    _dataset = pool
                    match += 1
                elif prop_comment == "iocage":
                    _dataset = pool
                    match += 1
                    old = True

            if match == 1:
                if old:
                    self._upgrade_pool(_dataset)

                return _dataset

            elif match >= 2:
                iocage_lib.ioc_common.logit(
                    {
                        "level": "ERROR",
                        "message": f"  {zpool.name}"
                    },
                    _callback=self.callback,
                    silent=self.silent)
            raise RuntimeError(f"You have {match} pools marked active"
                               " for iocage usage.\n Run \"iocage"
                               f" activate ZPOOL\" on the preferred"
                               " pool.\n")
        else:
            if len(sys.argv) >= 2 and "activate" in sys.argv[1:]:
                pass
            else:
                # We use the first zpool the user has, they are free to
                # change it.
                try:
                    zpool = zpools[0]
                except IndexError:
                    iocage_lib.ioc_common.logit(
                        {
                            "level":
                            "EXCEPTION",
                            "message":
                            "No zpools found! Please create one "
                            "before using iocage."
                        },
                        _callback=self.callback,
                        silent=self.silent)

                if os.geteuid() != 0:
                        iocage_lib.ioc_common.logit(
                            {
                                'level': 'EXCEPTION',
                                'message': 'Run as root to automatically'
                                ' activate the first zpool!'
                            },
                            _callback=self.callback,
                            silent=self.silent,
                            exception=ioc_exceptions.PoolNotActivated)

                iocage_skip = os.environ.get("IOCAGE_SKIP", "FALSE")
                if iocage_skip == "TRUE":
                    iocage_lib.ioc_common.logit(
                            {
                                'level': 'EXCEPTION',
                                'message': 'IOCAGE_SKIP is TRUE or an RC'
                                ' operation, not activating a pool.\nPlease'
                                ' manually issue iocage activate POOL'
                            },
                            _callback=self.callback,
                            silent=self.silent,
                            exception=ioc_exceptions.PoolNotActivated)

                    if zpool == "freenas-boot":
                        try:
                            zpool = zpools[1]
                        except IndexError:
                            iocage_lib.ioc_common.logit(
                                {
                                    'level': 'EXCEPTION',
                                    'message': 'Please specify a pool to'
                                    ' activate with iocage activate POOL'
                                },
                                _callback=self.callback,
                                silent=self.silent,
                                exception=ioc_exceptions.PoolNotActivated)

                    iocage_lib.ioc_common.logit(
                        {
                            "level":
                            "EXCEPTION",
                            "message":
                            "IOCAGE_SKIP is TRUE or an RC operation, not"
                            " activating a pool.\nPlease manually issue"
                            " iocage activate POOL"
                        },
                        _callback=self.callback,
                        silent=self.silent)

                if zpool.name == "freenas-boot":
                    try:
                        zpool = zpools[1]
                    except IndexError:
                        raise RuntimeError("Please specify a pool to "
                                           "activate with iocage activate "
                                           "POOL")

                iocage.lib.ioc_common.logit(
                    {
                        "level":
                        "INFO",
                        "message":
                        f"Setting up zpool [{zpool.name}] for"
                        " iocage usage\n If you wish to change"
                        " please use \"iocage activate\""
                    },
                    _callback=self.callback,
                    silent=self.silent)

                self.zfs_set_property(
                    zpool.name,
                    "org.freebsd.ioc:active",
                    "yes"
                )

                return zpool

    def _json_get_user_value(self, prop):
        if prop == "last_started" and self[prop] == "none":
            return "never"
        else:
            return self[prop]

    def json_set_value(self, prop, _import=False, default=False):
        """Set a property for the specified jail."""
        key, _, value = prop.partition("=")

        if not default:
            uuid = self["host_hostuuid"]
            status, jid = iocage_lib.ioc_list.IOCList().list_get_jid(uuid)
            self[key] = value
            sysctls_cmd = ["sysctl", "-d", "security.jail.param"]
            jail_param_regex = re.compile("security.jail.param.")
            sysctls_list = su.Popen(
                sysctls_cmd,
                stdout=su.PIPE).communicate()[0].decode("utf-8").split()
            jail_params = [
                p.replace("security.jail.param.", "").replace(":", "")

                for p in sysctls_list if re.match(jail_param_regex, p)
            ]
            single_period = [
                "allow_raw_sockets", "allow_socket_af", "allow_set_hostname"
            ]

            if key == "template":
                old_location = f"{self.root_dataset.name}/jails/{uuid}"
                new_location = f"{self.root_dataset.name}/templates/{uuid}"

                if status:
                    iocage_lib.ioc_common.logit(
                        {
                            "level": "EXCEPTION",
                            "message":
                            f"{uuid} is running.\nPlease stop it first!"
                        },
                        _callback=self.callback,
                        silent=self.silent)

                jails = iocage_lib.ioc_list.IOCList("uuid").list_datasets()

                for j in jails:
                    _uuid = jails[j]
                    _path = f"{jails[j]}/root"
                    t_old_path = f"{old_location}/root@{_uuid}"
                    t_path = f"{new_location}/root@{_uuid}"

                    if _uuid == uuid:
                        continue

                    origin = self.zfs_get_property(_path, 'origin')

                    if origin == t_old_path or origin == t_path:
                        _status, _ = iocage_lib.ioc_list.IOCList(
                        ).list_get_jid(_uuid)

                        if _status:
                            iocage_lib.ioc_common.logit(
                                {
                                    "level":
                                    "EXCEPTION",
                                    "message":
                                    f"{uuid} is running.\n"
                                    "Please stop it first!"
                                },
                                _callback=self.callback,
                                silent=self.silent)

                if value == "yes":
                    try:
                        jail_zfs_dataset = (
                            f"{self.pool.name}/"
                            f"{self['jail_zfs_dataset']}"
                        )
                        self.zfs_set_property(
                            jail_zfs_dataset,
                            "jailed",
                            "off"
                        )
                    except libzfs.ZFSException as err:
                        # The dataset doesn't exist, that's OK

                        if err.code == libzfs.Error.NOENT:
                            pass
                        else:
                            iocage_lib.ioc_common.logit(
                                {
                                    "level": "EXCEPTION",
                                    "message": err
                                },
                                _callback=self.callback)

                    try:
                        self.zfs.get_dataset(old_location).rename(
                            new_location, False, True)
                    except libzfs.ZFSException as err:
                        # cannot rename
                        iocage_lib.ioc_common.logit(
                            {
                                "level": "EXCEPTION",
                                "message": f"Cannot rename zfs dataset: {err}"
                            },
                            _callback=self.callback)

                    conf["type"] = "template"

                    self.location = new_location.lstrip(pool).replace(
                        "/iocage",
                        self.iocroot.mountpoint
                    )

                    iocage_lib.ioc_common.logit(
                        {
                            "level": "INFO",
                            "message": f"{uuid} converted to a template."
                        },
                        _callback=self.callback,
                        silent=self.silent)

                    # Writing these now since the dataset will be readonly
                    self.json_check_prop(key, value, conf)
                    self.json_write(conf)

                    iocage_lib.ioc_common.logit(
                        {
                            "level":
                            "INFO",
                            "message":
                            f"Property: {key} has been updated to {value}"
                        },
                        _callback=self.callback,
                        silent=self.silent)

                    self.zfs_set_property(new_location, "readonly", "on")

                    return
                elif value == "no":
                    if not _import:
                        self.zfs.get_dataset(new_location).rename(
                            old_location, False, True)
                        conf["type"] = "jail"
                        self.location = old_location.lstrip(pool).replace(
                            "/iocage",
                            self.iocroot.mountpoint
                        )
                        self.zfs_set_property(old_location, "readonly", "off")

                        iocage_lib.ioc_common.logit(
                            {
                                "level": "INFO",
                                "message": f"{uuid} converted to a jail."
                            },
                            _callback=self.callback,
                            silent=self.silent)
                        self.lgr.disabled = True

            if key[:8] == "jail_zfs":
                if status:
                    iocage_lib.ioc_common.logit(
                        {
                            "level": "EXCEPTION",
                            "message":
                            f"{uuid} is running.\nPlease stop it first!"
                        },
                        _callback=self.callback,
                        silent=self.silent)
            elif key == "dhcp":
                if status:
                    iocage_lib.ioc_common.logit(
                        {
                            "level": "EXCEPTION",
                            "message":
                            f"{uuid} is running.\nPlease stop it first!"
                        },
                        _callback=self.callback,
                        silent=self.silent)
        else:
            conf = self.json_read(f"{self.iocroot.mountpoint}/defaults.json")

        if not default:
            value, conf = self.json_check_prop(key, value, self)
            self.json_write(conf)
            iocage_lib.ioc_common.logit(
                {
                    "level": "INFO",
                    "message": f"Property: {key} has been updated to {value}"
                },
                _callback=self.callback,
                silent=self.silent)

            # We can attempt to set a property in realtime to jail.

            if status:
                if key in single_period:
                    key = key.replace("_", ".", 1)
                else:
                    key = key.replace("_", ".")

                if key in jail_params:
                    if conf["vnet"] == "on" and key == "ip4.addr" or key == \
                            "ip6.addr":

                        return

                    try:
                        ip = True if key == "ip4.addr" or key == "ip6.addr" \
                            else False

                        if ip and value.lower() == "none":
                            return

                        if key == "vnet":
                            # We can't switch vnet dynamically
                            iocage_lib.ioc_common.logit(
                                {
                                    "level":
                                    "INFO",
                                    "message":
                                    "vnet changes require a jail restart"
                                },
                                _callback=self.callback,
                                silent=self.silent)

                            return

                        iocage_lib.ioc_common.checkoutput(
                            ["jail", "-m", f"jid={jid}", f"{key}={value}"],
                            stderr=su.STDOUT)
                    except su.CalledProcessError as err:
                        raise RuntimeError(
                            f"{err.output.decode('utf-8').rstrip()}")
        else:
            if key in conf:
                conf[key] = value
                self.json_write(conf, "/defaults.json")

                iocage_lib.ioc_common.logit(
                    {
                        "level":
                        "INFO",
                        "message":
                        f"Default Property: {key} has been updated to {value}"
                    },
                    _callback=self.callback,
                    silent=self.silent)
            else:
                iocage_lib.ioc_common.logit(
                    {
                        "level": "EXCEPTION",
                        "message":
                        f"{key} is not a valid property for default!"
                    },
                    _callback=self.callback,
                    silent=self.silent)

    def json_check_config(self, conf, default=False):
        """
        Takes JSON as input and checks to see what is missing and adds the
        new keys with their default values if missing.
        """
        renamed = False

        if os.geteuid() != 0:
            iocage_lib.ioc_common.logit(
                {
                    "level":
                    "EXCEPTION",
                    "message":
                    "You need to be root to convert the"
                    " configurations to the new format!"
                },
                _callback=self.callback,
                silent=self.silent)

        # Version 2 keys
        try:
            sysvmsg = conf["sysvmsg"]
            sysvsem = conf["sysvsem"]
            sysvshm = conf["sysvshm"]
        except KeyError:
            sysvmsg = "new"
            sysvsem = "new"
            sysvshm = "new"

        # Set all keys, even if it's the same value.
        conf["sysvmsg"] = sysvmsg
        conf["sysvsem"] = sysvsem
        conf["sysvshm"] = sysvshm

        # Version 3 keys
        release = conf.get("release", None)

        if release is None:
            err_name = self.location.rsplit("/", 1)[-1]
            iocage.lib.ioc_common.logit(
                {
                    "level":
                    "EXCEPTION",
                    "message":
                    f"{err_name} has a corrupt configuration,"
                    " please destroy the jail."
                },
                _callback=self.callback,
                silent=self.silent)

        release = release.rsplit("-p", 1)[0]
        cloned_release = conf.get("cloned_release", "LEGACY_JAIL")

        host_hostuuid = self["host_hostuuid"]
        freebsd_version_files = [
            (
                f"{self.iocroot.mountpoint}/releases/{release}"
                "/root/bin/freebsd-version"
            ),
            (
                f"{self.iocroot.mountpoint}/templates/{host_hostuuid}"
                "/root/bin/freebsd-version"
            )
        ]

        selected_freebsd_version_file = None
        for freebsd_version_file in freebsd_version_files:
            if os.path.exists(freebsd_version_file) is False:
                continue
            selected_freebsd_version_file = freebsd_version_file
            break

        if selected_freebsd_version_file is None:
            # At this point it should be a real misconfigured jail
            uuid = self.location.rsplit("/", 1)[-1]
            raise RuntimeError(
                "Configuration is missing!"
                f" Please destroy {uuid} and recreate it."
            )

        if release[:4].endswith("-"):
            # 9.3-RELEASE and under don't actually have this binary.
            release = conf["release"]
        else:
            release = self.host_release
            cloned_release = conf["release"]

        # Set all Version 3 keys
        conf["release"] = release
        conf["cloned_release"] = cloned_release

        # Version 4 keys
        try:
            basejail = conf["basejail"]
        except KeyError:
            basejail = "no"
        # Set all keys, even if it's the same value.

        conf["basejail"] = basejail

        # Version 5 keys
        try:
            comment = conf["comment"]
        except KeyError:
            comment = "none"

        # Set all keys, even if it's the same value.
        conf["comment"] = comment

        # Version 6 keys
        conf["host_time"] = "yes"

        # Version 7 keys
        conf["depends"] = "none"

        # Version 8 migration from uuid to tag named dataset
        try:
            tag = conf["tag"]
            uuid = self["host_hostuuid"]

            try:
                state = iocage_lib.ioc_common.checkoutput(
                    ["jls", "-j", f"ioc-{uuid.replace('.', '_')}"],
                    stderr=su.PIPE).split()[5]
            except su.CalledProcessError:
                state = False

            if tag != uuid:
                if not self.force:
                    iocage_lib.ioc_common.logit(
                        {
                            "level":
                            "EXCEPTION",
                            "message":
                            "A renaming operation is required to continue.\n"
                            f"Please run iocage -f {sys.argv[-1]} as root."
                        },
                        _callback=self.callback,
                        silent=self.silent)

                conf, rtrn, date = self.json_migrate_uuid_to_tag(
                    uuid, tag, state, conf)

                conf["jail_zfs_dataset"] = f"iocage/jails/{tag}/data"

                if not date:
                    # The jail's tag was not a date, so it was renamed. Fix
                    # fstab

                    for line in fileinput.input(
                        f"{self.iocroot.mountpoint}/jails/{tag}/fstab",
                        inplace=1
                    ):
                        print(line.replace(f'{uuid}', f'{tag}').rstrip())

                    renamed = True

                if rtrn:
                    # They want to stop the jail, not attempt to migrate before
                    return conf

        except KeyError:
            # New jail creation
            pass

        # Version 9 keys
        try:
            dhcp = conf["dhcp"]
            bpf = conf["bpf"]
        except KeyError:
            dhcp = "off"
            bpf = "no"

        # Set all keys, even if it's the same value.
        conf["dhcp"] = dhcp
        conf["bpf"] = bpf

        # Version 10 keys
        try:
            vnet_interfaces = conf["vnet_interfaces"]
        except KeyError:
            vnet_interfaces = "none"

        # Set all keys, even if it's the same value.
        conf["vnet_interfaces"] = vnet_interfaces

        # Set all keys, even if it's the same value.
        conf["CONFIG_VERSION"] = self.CONFIG_VERSION

        # Version 11 keys
        try:
            hostid_strict_check = conf["hostid_strict_check"]
        except KeyError:
            hostid_strict_check = "off"

        # Set all keys, even if it's the same value.
        conf["hostid_strict_check"] = hostid_strict_check

        # Version 12 keys
        try:
            allow_mlock = conf["allow_mlock"]
        except KeyError:
            allow_mlock = "0"

        # Set all keys, even if it's the same value.
        conf["allow_mlock"] = allow_mlock

        # Version 13 keys
        if not conf.get('vnet_default_interface'):
            conf['vnet_default_interface'] = 'none'

        # Version 14 keys
        if not conf.get('allow_tun'):
            conf['allow_tun'] = '0'

        if not default:
            try:
                if not renamed:
                    self.json_write(conf)
            except FileNotFoundError:
                # Dataset was renamed.
                self.location = f"{self.iocroot.mountpoint}/jails/{tag}"

                self.json_write(conf)
                messages = collections.OrderedDict(
                    [("1-NOTICE", "*" * 80),
                     ("2-WARNING", f"Jail: {uuid} was renamed to {tag}"),
                     ("3-NOTICE",
                      f"{'*' * 80}\n"), ("4-EXCEPTION",
                                         "Please issue your command again.")])

                for level, msg in messages.items():
                    level = level.partition("-")[2]

                    iocage_lib.ioc_common.logit(
                        {
                            "level": level,
                            "message": msg
                        },
                        _callback=self.callback,
                        silent=self.silent)

        # The above doesn't get triggered with legacy short UUIDs

        if renamed:
            self.location = f"{self.iocroot}/jails/{tag}"

            self.json_write(conf)

            messages = collections.OrderedDict(
                [("1-NOTICE", "*" * 80),
                 ("2-WARNING", f"Jail: {uuid} was renamed to {tag}"),
                 ("3-NOTICE",
                  f"{'*' * 80}\n"), ("4-EXCEPTION",
                                     "Please issue your command again.")])

            for level, msg in messages.items():
                level = level.partition("-")[2]

                iocage_lib.ioc_common.logit(
                    {
                        "level": level,
                        "message": msg
                    },
                    _callback=self.callback,
                    silent=self.silent)

        return conf

    def json_check_prop(self, key, value, conf):
        """
        Checks if the property matches known good values, if it's the
        CLI, deny setting any properties not in this list.
        """
        props = {
            # Network properties
            "interfaces": (":", ","),
            "host_domainname": ("string", ),
            "host_hostname": ("string", ),
            "exec_fib": ("string", ),
            "ip4_addr": ("string", ),
            "ip4_saddrsel": (
                "0",
                "1", ),
            "ip4": ("new", "inherit", "none"),
            "ip6_addr": ("string", ),
            "ip6_saddrsel": ("0", "1"),
            "ip6": ("new", "inherit", "none"),
            "defaultrouter": ("string", ),
            "defaultrouter6": ("string", ),
            "resolver": ("string", ),
            "mac_prefix": ("string", ),
            "vnet0_mac": ("string", ),
            "vnet1_mac": ("string", ),
            "vnet2_mac": ("string", ),
            "vnet3_mac": ("string", ),
            # Jail Properties
            "devfs_ruleset": ("string", ),
            "exec_start": ("string", ),
            "exec_stop": ("string", ),
            "exec_prestart": ("string", ),
            "exec_poststart": ("string", ),
            "exec_prestop": ("string", ),
            "exec_poststop": ("string", ),
            "exec_clean": ("0", "1"),
            "exec_timeout": ("string", ),
            "stop_timeout": ("string", ),
            "exec_jail_user": ("string", ),
            "exec_system_jail_user": ("string", ),
            "exec_system_user": ("string", ),
            "mount_devfs": ("0", "1"),
            "mount_fdescfs": ("0", "1"),
            "enforce_statfs": ("0", "1", "2"),
            "children_max": ("string", ),
            "login_flags": ("string", ),
            "securelevel": ("string", ),
            "sysvmsg": ("new", "inherit", "disable"),
            "sysvsem": ("new", "inherit", "disable"),
            "sysvshm": ("new", "inherit", "disable"),
            "allow_set_hostname": ("0", "1"),
            "allow_sysvipc": ("0", "1"),
            "allow_raw_sockets": ("0", "1"),
            "allow_chflags": ("0", "1"),
            "allow_mlock": ("0", "1"),
            "allow_mount": ("0", "1"),
            "allow_mount_devfs": ("0", "1"),
            "allow_mount_nullfs": ("0", "1"),
            "allow_mount_procfs": ("0", "1"),
            "allow_mount_tmpfs": ("0", "1"),
            "allow_mount_zfs": ("0", "1"),
            "allow_quotas": ("0", "1"),
            "allow_socket_af": ("0", "1"),
            "vnet_interfaces": ("string", ),
            # RCTL limits
            "cpuset": ("off", "on"),
            "rlimits": ("off", "on"),
            "memoryuse": ":",
            "memorylocked": ("off", "on"),
            "vmemoryuse": ("off", "on"),
            "maxproc": ("off", "on"),
            "cputime": ("off", "on"),
            "pcpu": ":",
            "datasize": ("off", "on"),
            "stacksize": ("off", "on"),
            "coredumpsize": ("off", "on"),
            "openfiles": ("off", "on"),
            "pseudoterminals": ("off", "on"),
            "swapuse": ("off", "on"),
            "nthr": ("off", "on"),
            "msgqqueued": ("off", "on"),
            "msgqsize": ("off", "on"),
            "nmsgq": ("off", "on"),
            "nsemop": ("off", "on"),
            "nshm": ("off", "on"),
            "shmsize": ("off", "on"),
            "wallclock": ("off", "on"),
            # Custom properties
            "bpf": ("no", "yes"),
            "dhcp": ("off", "on"),
            "boot": ("off", "on"),
            "notes": ("string", ),
            "owner": ("string", ),
            "priority": str(tuple(range(1, 100))),
            "hostid": ("string", ),
            "hostid_strict_check": ("no", "yes"),
            "jail_zfs": ("off", "on"),
            "jail_zfs_dataset": ("string", ),
            "jail_zfs_mountpoint": ("string", ),
            "mount_procfs": ("0", "1"),
            "mount_linprocfs": ("0", "1"),
            "vnet": ("off", "on"),
            "vnet_default_interface": ("string",),
            "template": ("no", "yes"),
            "comment": ("string", ),
            "host_time": ("no", "yes"),
            "depends": ("string", ),
            "allow_tun": ("0", "1")
        }

        zfs_props = {
            # ZFS Props
            "compression": "lz4",
            "origin": "readonly",
            "quota": "none",
            "mountpoint": "readonly",
            "compressratio": "readonly",
            "available": "readonly",
            "used": "readonly",
            "dedup": "off",
            "reservation": "none",
        }

        if key in zfs_props.keys():
            _type = "templates" if conf["template"] == "yes" else "jails"
            uuid = self["host_hostuuid"]

            if key == "quota":
                if value != "none" and not \
                        value.upper().endswith(("M", "G", "T")):
                    err = f"{value} should have a suffix ending in" \
                        " M, G, or T."
                    iocage_lib.ioc_common.logit(
                        {
                            "level": "EXCEPTION",
                            "message": err
                        },
                        _callback=self.callback,
                        silent=self.silent)

            self.zfs_set_property(
                f"{self.root_dataset.name}/{_type}/{uuid}",
                key,
                value
            )

            return value, conf

        elif key in props.keys():
            # Either it contains what we expect, or it's a string.

            for k in props[key]:
                if k in value:
                    return value, conf

            if props[key][0] == "string":
                if key == "ip4_addr":
                    try:
                        interface, ip = value.split("|")

                        if interface == "DEFAULT":
                            gws = netifaces.gateways()
                            def_iface = gws["default"][netifaces.AF_INET][1]

                            value = f"{def_iface}|{ip}"
                            conf[key] = value
                    except ValueError:
                        pass
                elif key in [f'vnet{i}_mac' for i in range(0, 4)]:
                    if value and value != 'none':
                        value = value.replace(',', ' ')
                        if (
                            any(
                                not re.match(
                                    "[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$",
                                    v.lower()
                                ) for v in value.split()
                            ) or
                            len(value.split()) != 2 or
                            any(value.split().count(v) > 1 for v in value.split())
                        ):
                            iocage_lib.ioc_common.logit(
                                {
                                    'level': 'EXCEPTION',
                                    'message': 'Please Enter two valid and different '
                                               f'space/comma-delimited MAC addresses for {key}.'
                                },
                                _callback=self.callback,
                                silent=self.silent
                            )
                    elif not value:
                        # Let's standardise the value to none in case
                        # vnetX_mac is not provided
                        value = 'none'
                elif key == 'vnet_default_interface' and value != 'none':
                    if value not in netifaces.interfaces():
                        iocage_lib.ioc_common.logit(
                            {
                                'level': 'EXCEPTION',
                                'message': 'Please provide a valid NIC to be used '
                                           'with vnet'
                            },
                            _callback=self.callback,
                            silent=self.silent
                        )

                return value, conf
            else:
                err = f"{value} is not a valid value for {key}.\n"

                if key not in ("interfaces", "memoryuse"):
                    msg = f"Value must be {' or '.join(props[key])}"

                elif key == "interfaces":
                    msg = "Interfaces must be specified as a pair.\n" \
                          "EXAMPLE: vnet0:bridge0, vnet1:bridge1"
                elif key == "memoryuse":
                    msg = "memoryuse requires at minimum a pair.\nEXAMPLE: " \
                          "8g:log"

                msg = err + msg
                iocage_lib.ioc_common.logit(
                    {
                        "level": "EXCEPTION",
                        "message": msg
                    },
                    _callback=self.callback,
                    silent=self.silent)
        else:
            if self.cli:
                msg = f"{key} cannot be changed by the user."
            else:
                if key not in conf.keys():
                    msg = f"{key} is not a valid property!"
                else:
                    return value, conf

            iocage_lib.ioc_common.logit(
                {
                    "level": "EXCEPTION",
                    "message": msg
                },
                _callback=self.callback,
                silent=self.silent)

    def json_plugin_load(self):
        try:
            return self.json_read(f"{self.location}/plugin/settings.json")
        except FileNotFoundError:
            msg = f"No settings.json exists in {self.location}/plugin!"

            iocage_lib.ioc_common.logit(
                {
                    "level": "EXCEPTION",
                    "message": msg
                },
                _callback=self.callback,
                silent=self.silent)

    def json_plugin_get_value(self, prop):
        uuid = self["host_hostuuid"]
        _path = self.zfs_get_property(
            f"{self.root_dataset.name}/jails/{uuid}",
            "mountpoint"
        )

        # Plugin variables
        settings = self.json_plugin_load()
        serviceget = settings["serviceget"]
        prop_error = ".".join(prop)

        if "options" in prop:
            _prop = prop[1:]
        else:
            _prop = prop

        prop_cmd = f"{serviceget},{','.join(_prop)}".split(",")
        try:
            if prop[0] != "all":
                if len(_prop) > 1:
                    return iocage_lib.ioc_common.get_nested_key(settings, prop)
                else:
                    return iocage_lib.ioc_exec.IOCExec(
                        prop_cmd,
                        uuid,
                        _path,
                        plugin=True,
                        msg_return=True,
                        silent=True).exec_jail()
            else:
                return settings
        except KeyError:
            msg = f"Key: \"{prop_error}\" does not exist!"

            iocage_lib.ioc_common.logit(
                {
                    "level": "EXCEPTION",
                    "message": msg
                },
                _callback=self.callback,
                silent=self.silent)

    def json_plugin_set_value(self, prop):
        uuid = self["host_hostuuid"]
        _path = self.zfs_get_property(
            f"{self.root_dataset.name}/jails/{uuid}",
            "mountpoint"
        )
        status, _ = iocage_lib.ioc_list.IOCList().list_get_jid(uuid)

        # Plugin variables
        settings = self.json_plugin_load()
        serviceset = settings["serviceset"]
        servicerestart = settings["servicerestart"].split()
        keys, _, value = ".".join(prop).partition("=")
        prop = keys.split(".")
        restart = False
        readonly = False

        if "options" in prop:
            prop = keys.split(".")[1:]

        prop_cmd = f"{serviceset},{','.join(prop)},{value}".split(",")
        setting = settings["options"]

        try:
            while prop:
                current = prop[0]
                key = current
                prop.remove(current)

                if not prop:
                    if setting[current]:
                        try:
                            restart = setting[current]["requirerestart"]
                            readonly = setting[current]["readonly"]
                        except KeyError:
                            pass
                else:
                    setting = setting[current]

            if readonly:
                iocage_lib.ioc_common.logit({
                    "level": "ERROR",
                    "message": "This key is readonly!"
                })

                return True

            if status:
                # IOCExec will not show this if it doesn't start the jail.
                iocage_lib.ioc_common.logit(
                    {
                        "level": "INFO",
                        "message": "Command output:"
                    },
                    _callback=self.callback,
                    silent=self.silent)
            iocage_lib.ioc_exec.IOCExec(
                prop_cmd, uuid, _path).exec_jail()

            if restart:
                iocage_lib.ioc_common.logit(
                    {
                        "level": "INFO",
                        "message": "\n-- Restarting service --"
                    },
                    _callback=self.callback,
                    silent=self.silent)
                iocage_lib.ioc_common.logit(
                    {
                        "level": "INFO",
                        "message": "Command output:"
                    },
                    _callback=self.callback,
                    silent=self.silent)
                iocage_lib.ioc_exec.IOCExec(
                    servicerestart,
                    uuid,
                    _path).exec_jail()

            iocage_lib.ioc_common.logit(
                {
                    "level": "INFO",
                    "message": f"\nKey: {keys} has been updated to {value}"
                },
                _callback=self.callback,
                silent=self.silent)
        except KeyError:
            iocage_lib.ioc_common.logit(
                {
                    "level": "EXCEPTION",
                    "message": f"Key: \"{key}\" does not exist!"
                },
                _callback=self.callback,
                silent=self.silent)

    def json_migrate_uuid_to_tag(self, uuid, tag, state, conf):
        """This will migrate an old uuid + tag jail to a tag only one"""

        date_fmt = "%Y-%m-%d@%H:%M:%S:%f"
        date_fmt_legacy = "%Y-%m-%d@%H:%M:%S"

        # We don't want to rename datasets to a bunch of dates.
        try:
            datetime.datetime.strptime(tag, date_fmt)

            # For writing later
            tag = uuid
        except ValueError:
            try:
                # This may fail the first time with legacy jails,
                # making sure one more time that it's not a legacy jail
                datetime.datetime.strptime(tag, date_fmt_legacy)

                # For writing later
                tag = uuid
            except ValueError:
                try:
                    if self.stop and state:
                        # This will allow the user to actually stop
                        # the running jails before migration.

                        return (conf, True, False)

                    if state:
                        iocage_lib.ioc_common.logit(
                            {
                                "level":
                                "EXCEPTION",
                                "message":
                                f"{uuid} ({tag}) is running,"
                                " all jails must be stopped"
                                " before iocage will"
                                " continue migration"
                            },
                            _callback=self.callback,
                            silent=self.silent)

                    try:
                        # Can't rename when the child is
                        # in a non-global zone
                        jail_parent_ds = f"{pool}/iocage/jails/{uuid}"
                        data_dataset = self.zfs.get_dataset(
                            f"{jail_parent_ds}/data")
                        dependents = data_dataset.dependents

                        self.zfs_set_property(f"{jail_parent_ds}/data",
                                              "jailed", "off")

                        for dep in dependents:
                            if dep.type != "FILESYSTEM":
                                continue

                            d = dep.name
                            self.zfs_set_property(d, "jailed", "off")

                    except libzfs.ZFSException:
                        # No data dataset exists
                        pass

                    jail = self.zfs.get_dataset(jail_parent_ds)

                    try:
                        jail.snapshot(
                            f"{jail_parent_ds}@{tag}", recursive=True)
                    except libzfs.ZFSException as err:
                        if err.code == libzfs.Error.EXISTS:
                            err_msg = \
                                f"Snapshot {jail_parent_ds}@{tag} already" \
                                " exists!"
                            iocage_lib.ioc_common.logit(
                                {
                                    "level": "EXCEPTION",
                                    "message": err_msg
                                },
                                _callback=self.callback,
                                silent=self.silent)
                        else:
                            raise ()

                    for snap in jail.snapshots_recursive:
                        snap_name = snap.name.rsplit("@", 1)[1]

                        # We only want our snapshot for this, the rest will
                        # follow

                        if snap_name == tag:
                            new_dataset = snap.name.replace(uuid,
                                                            tag).split("@")[0]
                            snap.clone(new_dataset)

                    # Datasets are not mounted upon creation
                    new_jail_parent_ds = f"{pool}/iocage/jails/{tag}"
                    new_jail = self.zfs.get_dataset(new_jail_parent_ds)
                    new_jail.mount()
                    new_jail.promote()

                    for new_ds in new_jail.children_recursive:
                        new_ds.mount()
                        new_ds.promote()

                    # Easier.
                    su.check_call([
                        "zfs", "rename", "-r", f"{pool}/iocage@{uuid}",
                        f"@{tag}"
                    ])

                    try:
                        # The childern will also inherit this
                        self.zfs_set_property(
                            f"{new_jail_parent_ds}/data",
                            "jailed",
                            "on"
                        )
                    except libzfs.ZFSException:
                        # No data dataset exists
                        pass

                    rc_conf_path = (
                        f"{self.root_dataset.name}/jails/{tag}"
                        "/root/etc/rc.conf"
                    )
                    for line in fileinput.input(rc_conf_path, inplace=1):
                        print(line.replace(
                            f"hostname=\"{uuid}\"",
                            f"hostname=\"{tag}\""
                        ).rstrip())

                    fstab_path = f"{self.root_dataset.name}/jails/{tag}/fstab"
                    if conf["basejail"] == "yes":
                        for line in fileinput.input(fstab_path, inplace=1):
                            print(line.replace(str(uuid), str(tag)).rstrip())

                    # Cleanup old datasets, dependents is like
                    # children_recursive but in reverse, useful for root/*
                    # datasets
                    for old_ds in jail.dependents:
                        if old_ds.type == libzfs.DatasetType.FILESYSTEM:
                            old_ds.umount(force=True)
                        old_ds.delete()

                    jail.umount(force=True)
                    jail.delete()

                    try:
                        shutil.rmtree(
                            f"{self.root_dataset.mountpoint}/jails/{uuid}"
                        )
                    except Exception:
                        # Sometimes it becomes a directory when legacy short
                        # UUIDs are involved
                        pass

                    # Cleanup our snapshot from the cloning process

                    for snap in new_jail.snapshots_recursive:
                        snap_name = snap.name.rsplit("@", 1)[1]

                        if snap_name == tag:
                            s = self.zfs.get_snapshot(snap.name)
                            s.delete()

                except libzfs.ZFSException:
                    # A template, already renamed to a TAG
                    pass

        conf["host_hostuuid"] = tag

        if conf["host_hostname"] == uuid:
            # They may have set their own, we don't want to trample it.
            conf["host_hostname"] = tag

        return (conf, False, True)

    def json_check_default_config(self):
        """This sets up the default configuration for jails."""
        return self.default_properties

    @property
    def hostid(self):
        if self._hostid is None:
            with open("/etc/hostid", "r") as f:
                self._hostid = f.read().strip()
        return self._hostid

    @property
    def user_default_properties(self):
        try:
            return self.json_read(
                "/defaults.json",
                location=self.root_dataset.mountpoint
            )
        except FileNotFoundError:
            return None

    @property
    def default_properties(self):
        merged_default_props = self.global_default_properties
        user_default_props = self.user_default_properties
        if user_default_props is None:
            updated = True
            user_default_props = []
        else:
            updated = False

        # override hardcoded defaults
        for key, value in user_default_props.items():
            if key not in merged_default_props:
                continue
            if value != merged_default_props[key]:
                updated = True
            merged_default_props[key] = value

        if updated is True:
            self.json_write(
                merged_default_props,
                "/defaults.json",
                location=self.root_dataset.mountpoint
            )

        return merged_default_props

    @property
    def global_default_properties(self):
        """Return the hardcoded defaults."""
        return {
            "CONFIG_VERSION": self.CONFIG_VERSION,
            "interfaces": "vnet0:bridge0",
            "host_domainname": "none",
            "exec_fib": "0",
            "ip4_addr": "none",
            "ip4_saddrsel": "1",
            "ip4": "new",
            "ip6_addr": "none",
            "ip6_saddrsel": "1",
            "ip6": "new",
            "defaultrouter": "none",
            "defaultrouter6": "none",
            "resolver": "/etc/resolv.conf",
            "mac_prefix": "02ff60",
            "vnet0_mac": "none",
            "vnet1_mac": "none",
            "vnet2_mac": "none",
            "vnet3_mac": "none",
            "vnet_default_interface": "none",
            "devfs_ruleset": "4",
            "exec_start": "/bin/sh /etc/rc",
            "exec_stop": "/bin/sh /etc/rc.shutdown",
            "exec_prestart": "/usr/bin/true",
            "exec_poststart": "/usr/bin/true",
            "exec_prestop": "/usr/bin/true",
            "exec_poststop": "/usr/bin/true",
            "exec_clean": "1",
            "exec_timeout": "60",
            "stop_timeout": "30",
            "exec_jail_user": "root",
            "exec_system_jail_user": "0",
            "exec_system_user": "root",
            "mount_devfs": "1",
            "mount_fdescfs": "1",
            "enforce_statfs": "2",
            "children_max": "0",
            "login_flags": "-f root",
            "securelevel": "2",
            "sysvmsg": "new",
            "sysvsem": "new",
            "sysvshm": "new",
            "allow_set_hostname": "1",
            "allow_sysvipc": "0",
            "allow_raw_sockets": "0",
            "allow_chflags": "0",
            "allow_mlock": "0",
            "allow_mount": "0",
            "allow_mount_devfs": "0",
            "allow_mount_nullfs": "0",
            "allow_mount_procfs": "0",
            "allow_mount_tmpfs": "0",
            "allow_mount_zfs": "0",
            "allow_quotas": "0",
            "allow_socket_af": "0",
            "allow_tun": "0",
            "cpuset": "off",
            "rlimits": "off",
            "memoryuse": "off",
            "memorylocked": "off",
            "vmemoryuse": "off",
            "maxproc": "off",
            "cputime": "off",
            "pcpu": "off",
            "datasize": "off",
            "stacksize": "off",
            "coredumpsize": "off",
            "openfiles": "off",
            "pseudoterminals": "off",
            "swapuse": "off",
            "nthr": "off",
            "msgqqueued": "off",
            "msgqsize": "off",
            "nmsgq": "off",
            "nsemop": "off",
            "nshm": "off",
            "shmsize": "off",
            "wallclock": "off",
            "type": "jail",
            "bpf": "no",
            "dhcp": "off",
            "boot": "off",
            "notes": "none",
            "owner": "root",
            "priority": "99",
            "last_started": "none",
            "template": "no",
            "hostid": self.hostid,
            "hostid_strict_check": "off",
            "jail_zfs": "off",
            "jail_zfs_mountpoint": "none",
            "mount_procfs": "0",
            "mount_linprocfs": "0",
            "count": "1",
            "vnet": "off",
            "basejail": "no",
            "comment": "none",
            "host_time": "yes",
            "sync_state": "none",
            "sync_target": "none",
            "sync_tgt_zpool": "none",
            "compression": "lz4",
            "origin": "readonly",
            "quota": "none",
            "mountpoint": "readonly",
            "compressratio": "readonly",
            "available": "readonly",
            "used": "readonly",
            "dedup": "off",
            "reservation": "none"
        }

    @property
    def host_release(self):
        with open("/bin/freebsd-version", "r") as r:
            for line in r:
                if line.startswith("USERLAND_VERSION") is False:
                    continue
                return line.rstrip().partition("=")[2].strip("\"")
        raise Exception("Could not determine host release.")

