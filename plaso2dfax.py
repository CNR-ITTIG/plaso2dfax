#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# The MIT License (MIT)
#
# Copyright (c) 2016 CNR-ITTIG
#
# Developed under the Grant Agreement Number 608185 Collaborative Project
#                            EVIDENCE Project
# "European Informatics Data Exchange Framework for Courts and Evidence"
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""Plaso l2tcsv format to CybOX/DFax conversion."""

import argparse
import codecs
import csv
import dateutil
import fileinput
import logging
import os
import pprint
import re
import sys

from cybox.bindings import url_history_object as cyboxUrlHistory
from cybox.common import Hash as cyboxHash
from cybox.common import measuresource as cyboxMeasureSource
from cybox.common import object_properties as cyboxObjectProperties
from cybox.common import properties as cyboxProperties
from cybox.common import tools as cyboxTools
from cybox.core import action as cyboxAction
from cybox.core import AssociatedObject as cyboxAssociatedObject
from cybox.core import Event as cyboxEvent
from cybox.core import Observable as cyboxObservable
from cybox.core import Observables as cyboxObservables
from cybox.objects.file_object import File as cyboxFile
from cybox.objects.uri_object import URI as cyboxURI
from cybox.objects import win_event_log_object as cyboxWinEventLog
from cybox.objects.win_file_object import WinFile as cyboxWinFile
from cybox.objects import win_registry_key_object as cyboxWinRegistry


# ----------------------------------------------------------------------------

L2TCSV_HEADER = [
    u'date', u'time', u'timezone', u'MACB', u'source', u'sourcetype', u'type',
    u'user', u'host', u'short', u'desc', u'version', u'filename', u'inode',
    u'notes', u'format', u'extra'
]

PLASO_DEFAULT_OBSERVABLES = {
    u'major_version': 1,
    u'minor_version': 4,
    u'update_version': 1,
    u'observables': [{}],
    u'observable_package_source': {
        u'name': u'Plaso',
        u'information_source_type': u'l2tcsv',
    },
}

# ----------------------------------------------------------------------------


def AddCustomProperty(cybox_object, name, description, value):
    """Helper function to add a custom property to a CybOX object.
       This function is used to take into account unmanged Plaso events.

    Args:
        cybox_object: the CybOX object to be updated.
        name: custom property name.
        description: custom property description.
        value: custom property value.
    """
    custom_property = cyboxObjectProperties.Property()
    custom_property.name = name
    custom_property.description = description
    custom_property._value = value

    if not cybox_object.custom_properties:
        cybox_object.custom_properties = (
            cyboxObjectProperties.CustomProperties())
    cybox_object.custom_properties.append(custom_property)


def FieldsToDict(l2tcsv_field):
    """Parses a l2tcsv string (eg: extra) to return a name,value dictionary.

    Args:
        l2tcsv_field: l2tcsv input string (eg: extra).

    Returns:
        A name,value dictionary.
    """
    fields_dict = {}
    if l2tcsv_field:
        regexp = r'(\w+): (.*?)[ ]?($|(?= \w+?: ))'
        fields_dict = dict((match.group(1), match.group(2))
                           for match in re.finditer(regexp, l2tcsv_field))
    return fields_dict


def GetDatetime(date, time, timezone):
    """Creates a datetime object from l2tcsv date, time and timestamp.

    Args:
        date: l2tcsv date field.
        time: l2tcsv time field.
        timezone: l2tcsv timezone field.

    Returns:
        A datetime object (instance of datetime.datetime).
    """
    return dateutil.parser.parse(u' '.join((date, time, timezone)))


def GetRelatedObjects(cybox_object, klass):
    """Returns all related objects of the provided type.

    Args:
        cybox_object: the CybOX object from which to get related.
        klass: related object class seached for.

    Returns:
        Generates all objects of the target type related to source.
    """
    for related in cybox_object.parent.related_objects:
        related_object = related.properties
        if isinstance(related_object, klass):
            yield related_object


def SplitWinRegistryEvent(event_registry_description):
    """Split a Windows Registry event in its hive, key name and data parts.

    Args:
        event_registry_description: l2tcsv registry key event description.

    Returns:
        The hive, the registry key name and the registry_data.
    """
    regexp = r'^\[([^\\]+)\\([^\]]+)\] (.*)$'
    re_match = re.match(regexp, event_registry_description)

    registry_hive = re_match.group(1)
    registry_key = re_match.group(2)
    registry_data = re_match.group(3)

    return registry_hive, registry_key, registry_data


def WinEventSearch(regexp, event_string, remove=True):
    """Searches inside an event string for a matching regular expression.
       Note: it assumes the regexp has one group search.

    Args:
        regexp: the regular expression string to be used.
        event_string: the search target string.
        remove: flag, if True causes the matching substring to be removed

    Returns:
        The matched group and the source string, stripped if remove is True.
    """
    match_group1 = u''
    re_match = re.search(regexp, event_string)
    if re_match:
        match_group1 = re_match.group(1)
        if remove:
            event_string = event_string.replace(re_match.group(0), u'')

    return match_group1, event_string

# ----------------------------------------------------------------------------


def CreateCyboxFile(filename, extra_dict, row):
    """Creates a new CybOX file object.
       Depending on the input, it can create a Windows file object, a Unix file
       object or a generic one.

    Args:
        filename: filename as extracted from l2tcsv row.
        extra_dict: l2tcsv extra fields dictionary.
        row: a l2tcsv row.

    Returns:
        A CybOX generic/Windows/Unix file object depending on input.
    """
    logging.debug(u'Creating new Cybox File: {0:s}'.format(filename))

    # If the plaso event is a filestat, we tiplically have file related
    # information useful to describe the file.
    if u'filestat' == row[u'format']:
        file_system_type = row[u'sourcetype'].split(u' ')[0]

        if file_system_type == u'NTFS_DETECT':
            cybox_file = cyboxWinFile()
        if file_system_type == u'FAT16':
            cybox_file = cyboxFile()
        else:
            cybox_file = cyboxFile()

        file_size_string = extra_dict.get(u'file_size', None)
        if file_size_string:
            file_size = int(file_size_string.strip(u'[]L'))
            cybox_file.size_in_bytes = file_size
    else:
        cybox_file = cyboxFile()

    file_path, file_name_ext = os.path.split(filename)
    file_name, file_extension = os.path.splitext(file_name_ext)

    cybox_file.file_name = file_name
    cybox_file.file_path = file_path
    cybox_file.file_extension = file_extension.lstrip(u'.')

    if u'sha256_hash' in extra_dict:
        cybox_file.add_hash(cyboxHash(hash_value=extra_dict[u'sha256_hash'],
                            type_=cyboxHash.TYPE_SHA256))
    if u'sha1_hash' in extra_dict:
        cybox_file.add_hash(cyboxHash(
            hash_value=extra_dict[u'sha1_hash'], type_=cyboxHash.TYPE_SHA1))
    if u'md5_hash' in extra_dict:
        cybox_file.add_hash(cyboxHash(
            hash_value=extra_dict[u'md5_hash'], type_=cyboxHash.TYPE_MD5))

    return cybox_file


def CopyFileObjectData(dst_file_object, src_file_object):
    """Copies source file object information to a file object destination.

    Args:
        dst_file_object: the destination CybOX file object.
        src_file_object: the source CybOX file object.
    """
    dst_file_object.file_name = src_file_object.file_name
    dst_file_object.file_path = src_file_object.file_path
    dst_file_object.file_extension = src_file_object.file_extension
    dst_file_object.device_path = src_file_object.device_path
    dst_file_object.full_path = src_file_object.full_path
    dst_file_object.size_in_bytes = src_file_object.size_in_bytes
    dst_file_object.hashes = src_file_object.hashes
    dst_file_object.digital_signatures = src_file_object.digital_signatures
    dst_file_object.modified_time = src_file_object.modified_time
    dst_file_object.accessed_time = src_file_object.accessed_time
    dst_file_object.created_time = src_file_object.created_time
    dst_file_object.custom_properties = src_file_object.custom_properties


def UpgradeFileObjectType(cybox_file, extra_dict, row):
    """Creates a new CybOX Windows or Unix file object and it copies
       the data available from the actual CybOX file object.

    Args:
        cybox_file: the actual CybOX file object.
        extra_dict: l2tcsv extra fields dictionary.
        row: a l2tcsv row.

    Returns:
        A CybOX Windows/Unix file object depending on input.
    """
    if u'filestat' == row[u'format']:
        file_system_type = row[u'sourcetype'].split(u' ')[0]

        # Only Windows file upgrades are actually managed.
        if file_system_type == u'NTFS_DETECT':
            if u'WinFile' != cybox_file.__class__.__name__:
                cybox_win_file = cyboxWinFile()
                CopyFileObjectData(cybox_win_file, cybox_file)
                cybox_file = cybox_win_file

    return cybox_file

# ----------------------------------------------------------------------------


def PlasoEventCallback(cybox_file, row, cybox_related):
    """TODO"""
    timestamp = GetDatetime(row[u'date'], row[u'time'], row[u'timezone'])
    AddCustomProperty(cybox_file, row[u'type'], row[u'sourcetype'],
                      timestamp.isoformat())
    return cybox_file, cybox_related


def FileStatCallback(cybox_file, row, cybox_related):
    """TODO"""
    timestamp = GetDatetime(row[u'date'], row[u'time'], row[u'timezone'])

    for desc in row[u'type'].split(u';'):
        if desc == u'crtime':
            cybox_file.created_time = timestamp
        elif desc == u'atime':
            cybox_file.accessed_time = timestamp
        elif desc == u'mtime':
            cybox_file.modified_time = timestamp
        elif desc == u'ctime':
            # Cybox File Object does not support it.
            pass
        else:
            logging.warning(
                u'Unknown timestamp description [{}], event {}'.format(desc))
    return cybox_file, cybox_related


def HachoirCallback(cybox_file, row, cybox_related):
    """Callback to handle Hachoir events.
       Actually it does no more than the default callback.

    Args:
        cybox_file: the CybOX object file to be updated.
        row: a l2tcsv row.
        cybox_related: helper dictionary for related objects fast lookup.

    Returns:
        The updated cybox_file and its cybox_related.
    """
    timestamp = GetDatetime(row[u'date'], row[u'time'], row[u'timezone'])
    AddCustomProperty(cybox_file, row[u'type'], row[u'sourcetype'],
                      timestamp.isoformat())
    return cybox_file, cybox_related


def InternetExplorerHistoryCallback(cybox_file, row, cybox_related):
    """Callback to handle msiecf events.

    Args:
        cybox_file: the CybOX object file to be updated.
        row: a l2tcsv row.
        cybox_related: helper dictionary for related objects fast lookup.

    Returns:
        The updated cybox_file and its cybox_related.
    """
    timestamp = GetDatetime(row[u'date'], row[u'time'], row[u'timezone'])

    row_desc = row[u'desc']

    regexp = r'(\w+@[^ ]+)'
    re_match = re.search(regexp, row_desc)

    user_and_url = re_match.group(0)
    user, url = user_and_url.split(u'@')
    description = row_desc.replace(user_and_url, u'')

    for related in GetRelatedObjects(cybox_file, cyboxURI):
        if related.value._value == url:
            AddCustomProperty(related, row[u'type'], row[u'sourcetype'],
                              timestamp.isoformat())
            break
    else:
        # Actually there is no a URLHistory Object, only its bindings, using
        # custom properties to enrich the URI object.
        cybox_uri = cyboxURI(value=url, type_=u'URLHistoryObjectType')
        AddCustomProperty(cybox_uri, name=u'user', description=u'', value=user)
        AddCustomProperty(cybox_uri, name=u'URL history information',
                          description=u'msiecf event data', value=description)

        cybox_file.add_related(cybox_uri, u'Contains', inline=True)

    return cybox_file, cybox_related


def WinEventCallback(cybox_file, row, cybox_related):
    """Callback to handle Windows Events.

    Args:
        cybox_file: the CybOX object file to be updated.
        row: a l2tcsv row.
        cybox_related: helper dictionary for related objects fast lookup.

    Returns:
        The updated cybox_file and its cybox_related.
    """
    timestamp = GetDatetime(row[u'date'], row[u'time'], row[u'timezone'])
    src = row[u'desc']
    rkey = hash(row[u'desc'] + row[u'format'])

    if rkey in cybox_related:
        win_event_object = cybox_related[rkey]
    else:
        win_event_object = cyboxWinEventLog.WinEventLog()

        eid, src = WinEventSearch(r'^\[([0-9]+) \/ 0x[0-9a-z]+\] ', src)
        severity, src = WinEventSearch(r'Severity: (\w+) ', src)
        index, src = WinEventSearch(r'Record Number: ([0-9]+) ', src)
        type, src = WinEventSearch(r'Event Type: (.*?)(?= event ) event ', src)
        category_num, src = WinEventSearch(r'Event Category: ([0-9]+) ', src)
        source_name, src = WinEventSearch(
            r'Source Name: (.*?)(?= Computer Name: ) ', src)
        computer_name, src = WinEventSearch('Computer Name: ([^ ]+) ', src)
        msg, src = WinEventSearch(r'Message string: (.*?)(?= Strings: ) ', src)
        unf_strings, src = WinEventSearch(r'Strings: \[([^\]]*)\]', src)

        win_event_object.eid = int(eid)
        win_event_object.type = type
        win_event_object.index = int(index)
        win_event_object.category_num = int(category_num)
        win_event_object.source = source_name
        win_event_object.machine = computer_name
        if msg:
            win_event_object.message = msg

        if unf_strings:
            umsg_cybox = cyboxWinEventLog.UnformattedMessageList()
            for match in re.finditer(r'\'([^\']*)\'[ ]?', unf_strings):
                umsg_cybox.append(match.group(1))
            win_event_object.unformatted_message_list = umsg_cybox

        cybox_related[rkey] = win_event_object
        cybox_file.add_related(win_event_object, u'Contains', inline=True)

    if row[u'type'] == u'Content Modification Time':
        win_event_object.write_time = timestamp
    elif row[u'type'] == u'Creation Time':
        win_event_object.generation_time = timestamp
    else:
        logging.warning(
            u'Windows Event uknown timestamp type: {0:s}'.format(row[u'type']))

    return cybox_file, cybox_related


def WinRegDefaultCallback(cybox_file, row, cybox_related):
    """Callback to handle Windows Registry default events.

    Args:
        cybox_file: the CybOX object file to be updated.
        row: a l2tcsv row.
        cybox_related: helper dictionary for related objects fast lookup.

    Returns:
        The updated cybox_file and its cybox_related.
    """
    timestamp = GetDatetime(row[u'date'], row[u'time'], row[u'timezone'])

    hive, name, data = SplitWinRegistryEvent(row[u'desc'])

    cybox_reg_key = cyboxWinRegistry.WinRegistryKey()
    cybox_reg_key.values = cyboxWinRegistry.RegistryValues()
    cybox_reg_key.key = name
    cybox_reg_key.hive = hive
    cybox_reg_key.modified_time = timestamp

    regexp = r'[ ]?([^:]+): \[([^\]]+)\] (.+?)[ ]?($|(?= \w+?: ))'
    for match in re.finditer(regexp, data):
        cybox_reg_value = cyboxWinRegistry.RegistryValue()
        cybox_reg_value.name = match.group(1)
        cybox_reg_value.datatype = match.group(2)
        cybox_reg_value.data = match.group(3)
        cybox_reg_key.values.append(cybox_reg_value)

    cybox_file.add_related(cybox_reg_key, u'Contains', inline=True)

    return cybox_file, cybox_related


def WinRegMruListExCallback(cybox_file, row, cybox_related):
    """Callback to handle Windows Registry MRUlistext events.

    Args:
        cybox_file: the CybOX object file to be updated.
        row: a l2tcsv row.
        cybox_related: helper dictionary for related objects fast lookup.

    Returns:
        The updated cybox_file and its cybox_related.
    """
    timestamp = GetDatetime(row[u'date'], row[u'time'], row[u'timezone'])

    hive, name, data = SplitWinRegistryEvent(row[u'desc'])

    cybox_reg_key = cyboxWinRegistry.WinRegistryKey()
    cybox_reg_key.values = cyboxWinRegistry.RegistryValues()
    cybox_reg_key.key = name
    cybox_reg_key.hive = hive
    cybox_reg_key.modified_time = timestamp

    regexp = r'Index: [0-9] \[MRU Value ([0-9]+)\]: (.+?)[ ]?(?=Index:|$)'
    for match in re.finditer(regexp, data):
        cybox_reg_value = cyboxWinRegistry.RegistryValue()
        cybox_reg_value.name = match.group(1)
        cybox_reg_value.datatype = u'REG_BINARY'
        cybox_reg_value.data = match.group(2)
        cybox_reg_key.values.append(cybox_reg_value)

    cybox_file.add_related(cybox_reg_key, u'Contains', inline=True)

    return cybox_file, cybox_related


def WinRegMruExShellItemCallback(cybox_file, row, cybox_related):
    """Callback to handle Windows Registry MRUlistext with Shell Items events.

    Args:
        cybox_file: the CybOX object file to be updated.
        row: a l2tcsv row.
        cybox_related: helper dictionary for related objects fast lookup.

    Returns:
        The updated cybox_file and its cybox_related.
    """
    timestamp = GetDatetime(row[u'date'], row[u'time'], row[u'timezone'])

    hive, name, data = SplitWinRegistryEvent(row[u'desc'])

    cybox_reg_key = cyboxWinRegistry.WinRegistryKey()
    cybox_reg_key.values = cyboxWinRegistry.RegistryValues()
    cybox_reg_key.key = name
    cybox_reg_key.hive = hive
    cybox_reg_key.modified_time = timestamp

    regexp = (r'[ ]?Index: [0-9] \[MRU Value ([0-9]+)\]: '
              'Path: (.+?)[ ]+(?=Shell item: )[ ]?Shell item: \[([^\]]+)\]')
    for match in re.finditer(regexp, data):
        cybox_reg_value = cyboxWinRegistry.RegistryValue()
        cybox_reg_value.name = match.group(1)
        cybox_reg_value.datatype = u'REG_BINARY'
        cybox_reg_value.data = u'Path: [{0:s}] ShellItem: [{1:s}]'.format(
            match.group(2), match.group(3))
        cybox_reg_key.values.append(cybox_reg_value)

    cybox_file.add_related(cybox_reg_key, u'Contains', inline=True)

    return cybox_file, cybox_related


# A dict containing mappings between the name of event source and
# a callback function used for the conversion to a Cybox object.
EVENT_TO_CYBOX_CALLBACKS = {
    u'filestat': FileStatCallback,
    u'hachoir': HachoirCallback,
    u'msiecf': InternetExplorerHistoryCallback,
    u'winevt': WinEventCallback,
    u'winreg/mrulistex_string_and_shell_item': WinRegMruExShellItemCallback,
    u'winreg/winreg_default': WinRegDefaultCallback,
}

# ----------------------------------------------------------------------------


def EventToCybox(row, cybox_files, cybox_files_related):
    """Converts a Plaso event using CybOX formalism.

    Args:
        row: l2tcsv row.
        cybox_files: the CybOX file objects dictionary.
        cybox_files_related: the CybOX objects related to files dictionary.
    """
    filename = row[u'filename']
    extra_dict = FieldsToDict(row[u'extra'])

    if not filename:
        logging.warning(u'Skipping row, filename is empty.')
        return

    cybox_file = cybox_files.get(filename, None)
    if not cybox_file:
        logging.debug(u'New Cybox File, file {0:s}'.format(filename))
        cybox_file = CreateCyboxFile(filename, extra_dict, row)
    else:
        cybox_file = UpgradeFileObjectType(cybox_file, extra_dict, row)

    if filename not in cybox_files_related:
        cybox_files_related[filename] = {}
    cybox_related = cybox_files_related[filename]

    callback_function = EVENT_TO_CYBOX_CALLBACKS.get(row[u'format'], None)
    if not callback_function:
        callback_function = PlasoEventCallback

    cybox_files[filename], cybox_files_related[filename] = (
        callback_function(cybox_file, row, cybox_related))


def Convert(description=u'', output=u'sys.stdout', input=u'sys.stdin'):
    """The main loop routine in charge to read the data and to report results.

    Args:
        description: todo.
        output: the output channel to be used for the results.
        input: the input channel to be used to feed l2tcsv data.
    """
    cybox_files = {}
    cybox_files_related = {}
    rows = []

    openhook = fileinput.hook_encoded(u'utf8')
    file_in = fileinput.FileInput(input, openhook=openhook)

    try:
        reader = csv.DictReader(file_in, fieldnames=L2TCSV_HEADER)
        # Check if input file or stdin has l2tcsv headers.
        first_row = reader.next()
        if first_row[u'date'] != u'date' and first_row[u'extra'] != u'extra':
            EventToCybox(first_row, cybox_files, cybox_files_related)
        # Process lines.
        for row in reader:
            EventToCybox(row, cybox_files, cybox_files_related)
    except IOError as exception_io:
        logging.error(u'IO error: {0:s}'.format(exception_io))
        return

    observables = cyboxObservables()

    # Actually hard coded.
    tool = cyboxTools.ToolInformation(u'Plaso')
    tool.version = u'1.4.1'
    tool_list = cyboxTools.ToolInformationList()
    tool_list.append(tool)
    observables.observable_package_source = cyboxMeasureSource.MeasureSource()
    observables.observable_package_source.tools = tool_list

    for key, cybox_file in cybox_files.iteritems():
        observables.add(cyboxObservable(cybox_file))

    try:
        if output != u'sys.stdout':
            file_out = open(output, u'w')
        else:
            file_out = sys.stdout
        file_out.write(observables.to_xml().encode(u'utf8'))
    except IOError as exception_io:
        logging.error(u'IO error: {0:s}'.format(exception_io))


if __name__ == u'__main__':

    tool_description = u'plaso2dfax converter'
    tool_usage = None  # TODO: add usage.

    parser = argparse.ArgumentParser(description=tool_description,
                                     usage=tool_usage)
    parser.add_argument(u'-d', action=u'store', dest=u'description',
                        default=u'', type=unicode)
    parser.add_argument(u'-o', action=u'store', dest=u'output',
                        default=u'sys.stdout', type=unicode)
    parser.add_argument(u'-v', action=u'store_true', dest=u'verbose',
                        default=False)
    parser.add_argument(u'input', nargs=u'?', default=u'-', type=unicode)

    options = parser.parse_args()

    if options.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    Convert(options.description, options.output, options.input)
