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
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
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

from cybox.bindings import custom_object as cyboxCustom
from cybox.bindings.url_history_object import (
    URLHistoryEntryType as cyboxUrlHistoryEntry)
from cybox.common import Hash as cyboxHash
from cybox.common import object_properties as cyboxObjectProperties
from cybox.core import Observable as cyboxObservable
from cybox.core import Observables as cyboxObservables
from cybox.objects.file_object import File as cyboxFile
from cybox.objects.win_file_object import WinFile as cyboxWinFile

from plaso.cli import analysis_tool
from plaso.frontend import analysis_frontend
from plaso.lib import errors
from plaso.lib import timelib

# ----------------------------------------------------------------------------

def GetExtraDict(extra_string):
    """TODO."""
    extra_dict = {}
    if extra_string:
        regexp = r'(\w*): ([^ ]*)[ ]*'
        extra_dict = dict((match.group(1), match.group(2))
                          for match in re.finditer(regexp, extra_string))
    return extra_dict


def FieldsToDict(fields):
    fields_dict = {}
    if fields:
        regexp = r'(\w+): (.*?)[ ]?($|(?= \w+?: ))'
        fields_dict = dict((match.group(1),match.group(2)) 
                          for match in re.finditer(regexp, fields))
    return fields_dict


def GetDatetime(row):
    return dateutil.parser.parse(
        u' '.join((row[u'date'], row[u'time'], row[u'timezone'])))


def CopyFileObject(dst, src):
    """TODO."""
    dst.file_name = src.file_name
    dst.file_path = src.file_path
    dst.file_extension = src.file_extension
    dst.device_path = src.device_path
    dst.full_path = src.full_path
    dst.size_in_bytes = src.size_in_bytes
    dst.hashes = src.hashes
    dst.digital_signatures = src.digital_signatures
    dst.modified_time = src.modified_time
    dst.accessed_time = src.accessed_time
    dst.created_time = src.created_time

# ----------------------------------------------------------------------------

def GetPlasoStorageInformation(pbfilename):
    """Prints the storage information. TODO"""
    try:
        front_end = analysis_frontend.AnalysisFrontend()
        storage_file = front_end.OpenStorage(pbfilename)
    except IOError as exception:
        logging.error(
            u'Unable to open storage file: {0:s} with error: {1:s}'.format(
                pbfilename, exception))
        return

    storage_information_list = storage_file.GetStorageInformation()

    if not storage_information_list:
        logging.warning(u'No storage information found!')
        return

    # TODO: Actually considering only the first Collection Information.
    storage_information = storage_information_list[0]

    collection_information = getattr(
        storage_information, u'collection_information', None)
    if not collection_information:
      logging.warning(u'Missing collection information.')
      return

    filename = collection_information.get(u'file_processed', u'N/A')
    time_of_run = collection_information.get(u'time_of_run', 0)
    time_of_run = timelib.Timestamp.CopyToIsoFormat(time_of_run)

    lines_of_text.append(u'Storage file:\t\t{0:s}'.format(
        self._storage_file_path))
    lines_of_text.append(u'Serialization format:\t{0:s}'.format(
        storage_file.serialization_format))
    lines_of_text.append(u'Source processed:\t{0:s}'.format(filename))
    lines_of_text.append(u'Time of processing:\t{0:s}'.format(time_of_run))

    lines_of_text.append(u'')
    lines_of_text.append(u'Collection information:')

    for key, value in collection_information.iteritems():
      if key in [u'file_processed', u'time_of_run']:
        continue
      if key == u'parsers':
        value = u', '.join(sorted(value))
      lines_of_text.append(u'\t{0:s} = {1!s}'.format(key, value))

    storage_file.Close()

# ----------------------------------------------------------------------------

def CreateCyboxFile(filename, extra_dict, row):
    '''todo'''
    logging.debug(u'Creating new Cybox File: {0:s}'.format(filename))

    if u'FILE' == row[u'source']:
        file_system_type = row[u'sourcetype'].split(u' ')[0]

        # TODO: add Unix files.
        if file_system_type == u'NTFS_DETECT':
            cybox_file = cyboxWinFile()
        if file_system_type == u'FAT16':
            cybox_file = cyboxFile()
        else:
            logging.debug(u'Unmanaged FS [{0:s}], using default CybOX file '
                          'object.'.format(file_system_type))
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
        cybox_file.add_hash(cyboxHash(
            hash_value=extra_dict[u'sha256_hash'], type_=cyboxHash.TYPE_SHA256))
    if u'sha1_hash' in extra_dict:
        cybox_file.add_hash(cyboxHash(
            hash_value=extra_dict[u'sha1_hash'], type_=cyboxHash.TYPE_SHA1))
    if u'md5_hash' in extra_dict:
        cybox_file.add_hash(cyboxHash(
            hash_value=extra_dict[u'md5_hash'], type_=cyboxHash.TYPE_MD5))

    return cybox_file


def UpdateObjectFileType(cybox_file, extra_dict, row):
    """TODO."""
    if u'FILE' == row[u'source']:
        file_system_type = row[u'sourcetype'].split(u' ')[0]

        # TODO: add Unix files.
        if file_system_type == u'NTFS_DETECT':
            if u'WinFile' != cybox_file.__class__.__name__:
                cybox_win_file = cyboxWinFile()
                CopyFileObject(cybox_win_file, cybox_file)
                cybox_file = cybox_win_file

    return cybox_file

# ----------------------------------------------------------------------------

def Dummy(cybox_file, extra_dict, row):
    '''TODO'''
    logging.debug(u'Called Dummy callback.')


def FileStat(cybox_file, extra_dict, row):
    '''TODO'''
    date_use = GetDatetime(row)

    for desc in row[u'type'].split(u';'):
      if desc == u'crtime':
        cybox_file.created_time = date_use
      elif desc == u'atime':
        cybox_file.accessed_time = date_use
      elif desc == u'mtime':
        cybox_file.modified_time = date_use
      elif desc == u'ctime':
        # Cybox File Object does not support it.
        pass
      else:
        logging.warning(u'Unknown timestamp description [{}], event {}'.format(
            desc))


def Hachoir(cybox_file, extra_dict, row):
    '''TODO'''
    date_use = GetDatetime(row)


# A dict containing mappings between the name of event source and
# a callback function used for the conversion to a Cybox object.
EVENT_TO_CYBOX_CALLBACKS = {
  u'filestat': FileStat,
  u'hachoir': Hachoir,
}

# ----------------------------------------------------------------------------

def EventToCybox(row, cybox_files):
    """Converts a plaso event to Cybox.

    Args:
      event_object: the event object (instance of EventObject).
    """
    filename = row[u'filename']
    extra_dict = GetExtraDict(row[u'extra'])

    cybox_file = cybox_files.get(filename, None)
    if not cybox_file:
        logging.debug(u'New Cybox File, file {0:s}'.format(filename))
        cybox_file = CreateCyboxFile(filename, extra_dict, row)
    else:
        cybox_file = UpdateObjectFileType(cybox_file, extra_dict, row)

    callback_function = EVENT_TO_CYBOX_CALLBACKS.get(row[u'format'], None)
    if not callback_function:
        callback_function = Dummy

    callback_function(cybox_file, extra_dict, row)

    cybox_files[filename] = cybox_file


def Convert(description=u'', output=u'sys.stdout', input=u'sys.stdin',
            pbfilename=u''):
    """TODO: add a description."""
    cybox_files = {}
    rows = []

    openhook = fileinput.hook_encoded(u'utf8')
    # TODO: add check on file existance.
    file_in = fileinput.FileInput(input, openhook=openhook)
    reader = csv.DictReader(file_in)
    # TODO: add check that csv has the expected plaso headers.

    for row in reader:
        EventToCybox(row, cybox_files)

    observables = cyboxObservables()
    for key, cybox_file in cybox_files.iteritems():
      observables.add(cyboxObservable(cybox_file))
    print observables.to_xml()

    # TODO do something with that!
    #GetPlasoStorageInformation(pbfilename)


if __name__ == u'__main__':

    tool_description = u'plaso2dfax converter'
    tool_usage = None  # TODO: add usage.

    parser = argparse.ArgumentParser(description=tool_description,
                                     usage=tool_usage)
    parser.add_argument(u'-d', action=u'store', dest=u'description',
                        default=u'', type=unicode)
    parser.add_argument(u'-o', action=u'store', dest=u'output',
                        default=u'sys.stdout', type=unicode)
    parser.add_argument(u'-s', action=u'store', dest=u'pbfilename',
                        default=u'', type=unicode)
    parser.add_argument(u'input', nargs=u'?', default=u'-', type=unicode)

    options = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)  # TBR

    Convert(options.description, options.output, options.input,
            options.pbfilename)
    sys.exit()
