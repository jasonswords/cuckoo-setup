
import networkx
import os
import pandas
import plotly.graph_objs as go
import re
import json
from objects import Exceptions
from plotly.offline import plot

class CuckooJSONReport(object):

    jsonreportfile = None
    jsonreportdata = None
    DiGraph = None
    graphvizprog = None
    nodemetadata = dict()
    edgemetadata = dict()
    rootpid = None
    ignorepaths = []
    includepaths = []


    IPProto = {
                0: 'IPPROTO_IP',
                1: 'IPPROTO_ICMP',
                4: 'IPPROTO_IGMP',
                6: 'IPPROTO_TCP',
                8: 'IPPROTO_EGP',
                12: 'IPPROTO_PUP',
                17: 'IPPROTO_UDP',
                29: 'IPPROTO_IDP',
                33: 'IPPROTO_DCCP',
                41: 'IPPROTO_IPV6',
                46: 'IPPROTO_RSVP',
                47: 'IPPROTO_GRE',
                50: 'IPPROTO_ESP',
                51: 'IPPROTO_AH',
                92: 'IPPROTO_MTP',
                94: 'IPPROTO_BEETPH',
                98: 'IPPROTO_ENCAP',
                103: 'IPPROTO_PIM',
                108: 'IPPROTO_COMP',
                132: 'IPPROTO_SCTP',
                136: 'IPPROTO_UDPLITE',
                137: 'IPPROTO_MPLS',
                255: 'IPPROTO_RAW'
                }


    def __init__(self, jsonreportfile=None,
                 jsonreportdict=None,
                 plotnetwork=True,
                 plotfiles=True,
                 plotfilecreates=True,
                 plotfiledeletes=True,
                 plotfilemoves=True,
                 plotfilecopies=True,
                 plotfilewrites=True,
                 plotfilereads=True,
                 plotregistry=True,
                 plotregistrywrites=True,
                 plotregistryreads=True,
                 plotregistrydeletes=True,
                 plotregistrycreates=True,
                 ignorepaths=None,
                 includepaths=None):
        """
       The JSON report file is read and parsed using this class.  This
       could take a whiel depending on how big your JSON report is.

       This has been tested with the cuckoo-modifed version, but it may
       work with Cuckoo (proper) as well.

       :param jsonreportfile: The path to the JSON report file.  Set to
           None to use a jsonreportstring.
       :type jsonreportfile: A string.
       :param jsonreportdict: A dict containing a JSON
           report file loaded with JSON load.
           Set to None to use a jsonreportfile.
       :param plotnetwork: Set to False to ignore network activity.
       :param plotfiles: Set to False to ignore file activity.
       :param plotfilecreates: Set to False to ignore file creates.
       :param plotfiledeletes: Set to False to ignore file deletes.
       :param plotfilemoves: Set to False to ignore file moves.
       :param plotfilecopies: Set to False to ignore file copies.
       :param plotfilewrites: Set to False to ignore file writes.
       :param plotfilereads: Set to False to ignore file reads.
       :param plotregistry: Set to False to ignore registry activity.
       :param plotregistrywrites: Set to False to ignore registry writes.
       :param plotregistryreads: Set to False to ignore registry reads.
       :param plotregistrydeletes: Set to False to ignore registry deletes.
       :param plotregistrycreates: Set to False to ignore registry creates.
       :param ignorepaths: A list of regular expressions to ignore for
           files and registry values.
       :param includepaths: A list of regular expressions to include for
           files and registry values.  Overrides ignore paths.
       :returns: An object.
       :rtype: CuckooJSONReport object.
       """

        self.file_data = dict()
        self.plotfilecreates = plotfilecreates
        self.plotfiledeletes = plotfiledeletes
        self.plotfilemoves = plotfilemoves
        self.plotfilecopies = plotfilecopies
        self.plotfilewrites = plotfilewrites
        self.plotfilereads = plotfilereads

        self.plotregistrywrites = plotregistrywrites
        self.plotregistryreads = plotregistryreads
        self.plotregistrydeletes = plotregistrydeletes
        self.plotregistrycreates = plotregistrycreates

        if ignorepaths is not None and isinstance(ignorepaths, list):
            self.ignorepaths = ignorepaths

        if includepaths is not None and isinstance(includepaths, list):
            self.includepaths = includepaths

        if jsonreportfile is not None:
            if not os.path.exists(jsonreportfile):
                raise Exceptions.VisualizeLogsInvalidFile(jsonreportfile)
            else:
                self.jsonreportfile = jsonreportfile

            with open(self.jsonreportfile, 'r') as jsonfile:
                self.jsonreportdata = json.load(jsonfile)
        elif jsonreportdict is not None:
            self.jsonreportfile = None
            self.jsonreportdata = jsonreportdict
        else:
            raise Exceptions.VisualizeLogsBadFunctionInput("jsonreportfile")

        # Create a network graph...
        self.digraph = networkx.DiGraph()

        # Add all the processes to the graph...
        self._add_all_processes()

        if plotnetwork is True:
            # Add network activity to the graph...
            self._add_network_activity()

        if plotfiles is True:
        #     # Add file activity to the graph...
            self._add_file_activity()

        if plotregistry is True:
        #     # Add registry activity to the graph...
            self._add_registry_activity()

    def _search_re(self, string, expressions):
        """
        Internal function to check if string is selected
        by regular expressions in expression list.
        Ignores case!
        :param string:  String to search.
        :param expressions: List of regular expressions to search.
        :returns: True if expressions fire on string, False otherwise.
        """
        for e in expressions:
            m = re.search(string, e, re.IGNORECASE)
            if m:
                return True
        return False

    def _add_all_processes(self):
        """
        Internal function to add processess from JSON report
        process tree.
        :returns: Nothing.
        """
        self._processtree = self.jsonreportdata['behavior']['processtree']
        self._processes = self.jsonreportdata['behavior']['processes']
        self.rootpid = "PID {0}".format(self._processtree[0]['pid'])

        for process in self._processtree:
            self._add_processes_recursive(process)

        # Add the rest of the metadata...
        self._add_process_metadata()

    def _add_processes_recursive(self, processtreedict):
        """
        Internal function to add processes recursively from
        a dict representing the JSON process tree.
        :param processtreedict:  A dict of data from the process tree.
        :returns: Nothing.
        """
        pid = processtreedict['pid']
        ppid = processtreedict['ppid']
        nodename = "PID {0}".format(pid)
        ppid_node = "PID {0}".format(ppid)
        self.digraph.add_node(nodename,
                         type='PID',
                         pid=pid,
                         parent_id=ppid)

        self.nodemetadata[nodename] = dict()
        self.nodemetadata[nodename]['node_type'] = 'PID'
        self.nodemetadata[nodename]['pid'] = pid
        self.nodemetadata[nodename]['parent_id'] = ppid
        self.nodemetadata[nodename]['name'] = processtreedict['process_name']
        self.nodemetadata[nodename]['command_line'] = processtreedict['command_line']
        self.nodemetadata[nodename]['children'] = list()

        if ppid_node not in self.nodemetadata:
            self.nodemetadata[ppid_node] = dict()
            self.nodemetadata[ppid_node]['node_type'] = 'PID'
            self.nodemetadata[ppid_node]['children'] = list()
            self.nodemetadata[ppid_node]['command_line'] = ""

        self.nodemetadata[ppid_node]['children'].append(nodename)
        if ppid_node in self.digraph:
            self.digraph.add_edge(ppid_node, nodename)

        for child in processtreedict['children']:
            self._add_processes_recursive(child)

    def _add_process_metadata(self):
        """
       Internal function that ties the extra process metadata
       to the nodemetadata dict.

       :returns: Nothing.
       """
        for process in self._processes:
            nodename = "PID {0}".format(process['pid'])
            self.nodemetadata[nodename]['first_seen'] = process['first_seen']

            if not process['calls']:
                self.nodemetadata[nodename]['calls'] = pandas.DataFrame(columns=['category', 'status', 'stacktrace', 'api', 'return_value', 'arguments',
       'time', 'tid', 'flags', 'last_error', 'nt_status'])
            else:
                self.nodemetadata[nodename]['calls'] = pandas.DataFrame(process['calls'])

            self.nodemetadata[nodename]['calls']['time'] = pandas.to_datetime(self.nodemetadata[nodename]['calls']['time'], unit='s')
            self.nodemetadata[nodename]['calls'] = self.nodemetadata[nodename]['calls'].sort_values(['time'])

            calls = self.nodemetadata[nodename]['calls']
            createprocs = calls[calls['api'] == 'CreateProcessInternalW']

            for i, createproc in createprocs.iterrows():
                childpid = None
                cmdline = None

                for arg, val in createproc['arguments'].items():
                    if arg == 'process_identifier':
                        if val <= 0:
                            continue
                        else:
                            childpid = val

                    if arg == 'command_line':
                        cmdline = val

                if cmdline is None:
                    cmdline = "Not Available"

                if childpid is not None:
                    childnode = "PID {0}".format(childpid)
                    self.nodemetadata[childnode]['cmdline'] = cmdline

    def _add_file_activity(self):
        """
        Internal function that adds file data to the graph.
        Assumes processes have already been plotted.

        :returns:  Nothing.
        """
        self.filedata = self.jsonreportdata['behavior']['generic']
        metadata = self.nodemetadata.copy()

        for node in metadata:
            for process in self.filedata:
                if 'PID {}'.format(process['pid']) == node:
                    if 'summary' in process:
                        self.file_written = list()
                        self.file_created = list()
                        self.file_deleted = list()
                        self.file_read = list()
                        self.file_copied = list()
                        self.file_moved = list()

                        if 'file_written' in process['summary']:
                            self.file_written = process['summary']['file_written'].copy()

                        if 'file_read' in process['summary']:
                            self.file_read = process['summary']['file_read'].copy()

                        if 'file_deleted' in process['summary']:
                            self.file_deleted = process['summary']['file_deleted'].copy()

                        if 'file_copied' in process['summary']:
                            self.file_copied = process['summary']['file_copied'].copy()

                        if 'file_moved' in process['summary']:
                            self.file_moved = process['summary']['file_moved'].copy()

                        if 'file_created' in process['summary']:
                            self.file_created = process['summary']['file_created'].copy()


                    # Get file creates...
                    if self.plotfilecreates is True:
                        self._add_file_creates(node, self.file_created)

                    # # # Get file writes...
                    if self.plotfilewrites is True:
                        self._add_file_writes(node, self.file_written)

                    # # Get file reads...
                    if self.plotfilereads is True:
                        self._add_file_reads(node, self.file_read)

                    # # Get file deletes...
                    if self.plotfiledeletes is True:
                        self._add_file_deletes(node, self.file_deleted)

                    # # Get file copies...
                    if self.plotfilecopies is True:
                        self._add_file_copies(node, self.file_copied)

                    # # # # Get file moves...
                    if self.plotfilemoves is True:
                        self._add_file_moves(node, self.file_moved)

    def _add_file_deletes(self, node, files):
        """
        Internal function that adds the file deleted in files
        for the PID node.
        :param node: PID node name
        :param files: list of files deleted
        :return: Nothing
        """
        for file in files:
            if file:
                nextid = len(self.nodemetadata)
                fdnodename = "FILE DELETE {0}".format(nextid)
                self.nodemetadata[fdnodename] = dict()
                self.nodemetadata[fdnodename]['pid'] = node
                self.nodemetadata[fdnodename]['file'] = file
                self.nodemetadata[fdnodename]['node_type'] = 'FILEDELETE'
                self.digraph.add_node(fdnodename, type='FILEDELETE')
                self.digraph.add_edge(node, fdnodename)

    def _add_file(self, filename):
        """
        Internal function to add a file if it does not exist.

        :param ip: File path.
        :returns: Node name for the file.
        """
        origfilename = filename
        filename = filename.replace('\\', '\\\\')
        filenodename = '"FILE {0}"'.format(filename)
        if filenodename not in self.nodemetadata:
            self.nodemetadata[filenodename] = dict()
            self.nodemetadata[filenodename]['node_type'] = 'FILE'
            self.nodemetadata[filenodename]['file'] = origfilename
            self.digraph.add_node(filenodename, type='FILE')

        return filenodename

    def _add_file_creates(self, node, files):
        """
        Internal function that adds the file creates in files
        for the PID node.
        :param node: PID node name
        :param files: list of files created
        :return:Nothing
        """
        for file in files:
            if file:
                nextid = len(self.nodemetadata)
                fcnodename = "FILE CREATE {0}".format(nextid)
                self.nodemetadata[fcnodename] = dict()
                self.nodemetadata[fcnodename]['pid'] = node
                self.nodemetadata[fcnodename]['file'] = file
                self.nodemetadata[fcnodename]['node_type'] = 'FILECREATE'
                self.digraph.add_node(fcnodename, type='FILECREATE')
                self.digraph.add_edge(node, fcnodename)

    def _add_file_writes(self, node, files):
        """
        Internal function that adds the file writes in files for
        the PID node.
        :param node: PID node name
        :param files: list of file writes
        :return: Nothing
        """
        for file in files:
            if file:
                nextid = len(self.nodemetadata)
                fwnodename = "FILE WRITE {0}".format(nextid)
                self.nodemetadata[fwnodename] = dict()
                self.nodemetadata[fwnodename]['pid'] = node
                self.nodemetadata[fwnodename]['file'] = file
                self.nodemetadata[fwnodename]['node_type'] = 'FILEWRITE'
                self.digraph.add_node(fwnodename, type='FILEWRITE')
                self.digraph.add_edge(node, fwnodename)

    def _add_file_reads(self, node, files):
        """
        Internal function that adds the file reads in files for
        the PID node.

        :param node: PID node name
        :param files: list of deleted files
        :return:Nothing
        """
        for file in files:
            if file:
                nextid = len(self.nodemetadata)
                frnodename = "FILE READ {0}".format(nextid)
                self.nodemetadata[frnodename] = dict()
                self.nodemetadata[frnodename]['pid'] = node
                self.nodemetadata[frnodename]['file'] = file
                self.nodemetadata[frnodename]['node_type'] = 'FILEREAD'
                self.digraph.add_node(frnodename, type='FILEREAD')
                self.digraph.add_edge(node, frnodename)

    def _add_file_copies(self, node, files):
        """
        Internal function that adds the file copies in files for
        the PID node.

        :param node:PID node name
        :param files:List of lists containing files copied (Source, Destination)
        :return:Nothing
        """
        for file in files:
            if file:
                file_original = file[0]
                file_new = file[1]
                nextid = len(self.nodemetadata)
                fcnodename = "FILE COPY {0}".format(nextid)
                self.nodemetadata[fcnodename] = dict()
                self.nodemetadata[fcnodename]['pid'] = node
                self.nodemetadata[fcnodename]['file_original'] = file_original
                self.nodemetadata[fcnodename]['file_new'] = file_new
                self.nodemetadata[fcnodename]['node_type'] = 'FILECOPY'
                self.digraph.add_node(fcnodename, type='FILECOPY')
                self.digraph.add_edge(node, fcnodename)

    def _add_file_moves(self, node, files):
        """
        Internal function that adds the file moved in files for
        the PID node.

        :param node: PID node name
        :param files: List of lists containing files moved (Source, Destination)
        :return: Nothing
        """
        for file in files:
            if file:
                file_original = file[0]
                file_new = file[1]
                nextid = len(self.nodemetadata)
                fmnodename = "FILE MOVE {0}".format(nextid)
                self.nodemetadata[fmnodename] = dict()
                self.nodemetadata[fmnodename]['pid'] = node
                self.nodemetadata[fmnodename]['file_original'] = file_original
                self.nodemetadata[fmnodename]['file_new'] = file_new
                self.nodemetadata[fmnodename]['node_type'] = 'FILEMOVE'
                self.digraph.add_node(fmnodename, type='FILEMOVE')
                self.digraph.add_edge(node, fmnodename)















    def _add_network_activity(self):
        """
        Internal function that adds network data to the graph.
        Assumes processes have already been plotted.

        :return:Nothing
        """
        self.domains = pandas.DataFrame(self.jsonreportdata['network']['domains'])
        self.dns = pandas.DataFrame(self.jsonreportdata['network']['dns'])
        tcp = pandas.DataFrame(self.jsonreportdata['network']['tcp'])

        for i, dns in self.dns.iterrows():
            self.dns.loc[i]['answers'] = pandas.DataFrame(self.dns.loc[i]['answers'])
        metadata = self.nodemetadata.copy()
        for node in metadata:
            if metadata[node]['node_type'] == 'PID':
                if 'calls' in metadata[node]:
                    calls = metadata[node]['calls']

                    # # Get DNS lookups...
                    # self._add_dns_lookups(node, tcp)

                    # # # # # Add socket activity...
                    self._add_sockets(node, calls)

                    # # # # # Add internet activity outside sockets...
                    # self._add_internet(node, calls)
                    #
                    # # # # # Resolve...
                    # self._add_resolve_hosts()

    def _add_sockets(self, node, calls):
        """
        Internal function to add Sockets to the graph.

        :param node:  The node name for the calls.
        :param calls:  A pandas.DataFrame of process calls.
        :returns: Nothing.
        """
        sockets = calls[calls['api'] == 'socket']
        for i, sock in sockets.iterrows():
            socketid = None
            socketproto = None

            for arg, val in sock['arguments'].items():
                if arg == 'socket':
                    socketid = val
                if arg == 'protocol':
                    if int(val) in self.IPProto:
                        socketproto = self.IPProto[int(val)]
                    else:
                        socketproto = val

            if socketid is not None:
                nextid = len(self.nodemetadata)
                socketname = 'SOCKET {0}'.format(nextid)
                self.digraph.add_node(socketname, type='SOCKET')
                self.nodemetadata[socketname] = dict()
                self.nodemetadata[socketname]['node_type'] = 'SOCKET'
                self.nodemetadata[socketname]['socket'] = socketid
                self.nodemetadata[socketname]['protocol'] = socketproto
                self.nodemetadata[socketname]['opentime'] = sock['time']
                closesockets = calls[(calls['api'] == 'closesocket') & (calls['time'] > sock['time'])]
                try:
                    closetime = next(closesockets.iterrows())[1]['time']
                except StopIteration:
                    closetime = None
                self.nodemetadata[socketname]['closetime'] = closetime
                self.digraph.add_edge(node, socketname)
                self._add_tcp_connects(socketname, calls, socketid,sock['time'], closetime)

    def _add_tcp_connects(self, node, calls, socketid, opentime, closetime):
        """
        Internal function to add TCP connections to the graph.

        :param node:  The socket node name for the calls.
        :param calls:  A pandas.DataFrame of process calls.
        :param socketid:  The socket opened for these connections.
        :param opentime:  The time the socket opened.
        :param closetime:  The time the socket closed.
        :returns: Nothing.
        """
        if closetime is not None:
            tcpconnects = calls[(calls['api'] == 'connect') &
                                (calls['time'] >= opentime) &
                                (calls['time'] <= closetime)]
        else:
            tcpconnects = calls[(calls['api'] == 'connect') &
                                (calls['time'] >= opentime)]

        for i, tcpconnect in tcpconnects.iterrows():
            PlotConnect = False
            for a, v in tcpconnect['arguments'].items():
                if (a == 'socket' and
                        a == socketid):
                    PlotConnect = True

            if PlotConnect is True:
                ipaddr = None
                socketid = None
                port = None
                for arg, val in tcpconnect['arguments'].items():
                    if arg == 'ip':
                        ipaddr = val
                    if arg == 'socket':
                        socketid = val
                    if arg == 'port':
                        port = val

                if ipaddr is not None:
                    ipnodename = self._add_ip(ipaddr)

                    # Get a sequential number for the event...
                    nextid = len(self.nodemetadata)

                    connnodename = 'TCP CONNECT {0}'.format(nextid)
                    self.digraph.add_node(connnodename, type='TCPCONNECT')
                    self.nodemetadata[connnodename] = dict()
                    self.nodemetadata[connnodename]['node_type'] = \
                        "TCPCONNECT"
                    self.nodemetadata[connnodename]['timestamp'] = \
                        tcpconnect['timestamp']
                    self.nodemetadata[connnodename]['ip'] = ipaddr
                    self.nodemetadata[connnodename]['socket'] = socketid
                    self.nodemetadata[connnodename]['port'] = port

                    # Connect them up...
                    self.digraph.add_edge(node, connnodename)
                    self.digraph.add_edge(connnodename, ipnodename)

    def _add_ip(self, ip):
        """
        Internal function to add an IP if it does not exist.

        :param ip: IP address.
        :returns: Node name for the IP address.
        """
        ipnodename = '"IP {0}"'.format(ip)
        if ipnodename not in self.nodemetadata:
            self.nodemetadata[ipnodename] = dict()
            self.nodemetadata[ipnodename]['node_type'] = 'IP'
            self.nodemetadata[ipnodename]['ip'] = ip
            self.digraph.add_node(ipnodename, type='IP')
        return ipnodename

    def _add_registry_activity(self):
        """
        Internal function that adds registry data to the graph.
        Assumes processes have already been plotted.

        :returns:  Nothing.
        """
        metadata = self.nodemetadata.copy()
        for node in metadata:
            if metadata[node]['node_type'] == 'PID':
                if 'calls' in metadata[node]:
                    calls = metadata[node]['calls']

                    # Get registry writes...
                    if self.plotregistrywrites is True:
                        self._add_registry_writes(node, calls)

                    # Get registry deletes
                    if self.plotregistrydeletes is True:
                        self._add_registry_deletes(node, calls)

                    # Get registry creates
                    if self.plotregistrycreates is True:
                        self._add_registry_creates(node, calls)

                    # Get registry reads
                    if self.plotregistryreads is True:
                        self._add_registry_reads(node, calls)


    def _add_registry_writes(self, node, calls):
        """
        Internal function that adds registry writes to the graph.

        :param node:  The PID node name for the calls.
        :param calls:  The api calls.
        :returns:  Nothing.
        """
        regwrites = calls[((calls['api'] == 'RegSetValueExA') |
                          (calls['api'] == 'RegSetValueExW') |
                          (calls['api'] == 'NtSetValueKey')) &
                          (calls['status'] == True)]

        for i, regwrite in regwrites.iterrows():
            regname = None
            regbuff = None

            for arg, val in regwrite['arguments'].items():
                if arg == 'regkey':
                    regname = val
                if arg == 'value':
                    regbuff = val

            if regname is not None:
                if (self._search_re(regname, self.ignorepaths) and
                        not self._search_re(regname, self.includepaths)):
                    continue

                nextid = len(self.nodemetadata)
                rwnodename = "REGISTRY WRITE {0}".format(nextid)

                self.nodemetadata[rwnodename] = dict()
                self.nodemetadata[rwnodename]['pid'] = node
                self.nodemetadata[rwnodename]['registry'] = regname
                self.nodemetadata[rwnodename]['node_type'] = 'REGISTRYWRITE'
                self.nodemetadata[rwnodename]['time'] = regwrite['time']
                self.nodemetadata[rwnodename]['buffer'] = regbuff
                self.digraph.add_node(rwnodename, type='REGISTRYWRITE')
                self.digraph.add_edge(node, rwnodename)


    def _add_registry_deletes(self, node, calls):
        """
        Internal function that adds registry deletes to the graph.

        :param node:  The PID node name for the calls.
        :param calls:  The api calls.
        :returns:  Nothing.
        """
        regdeletes = calls[((calls['api'] == 'RegDeleteValueA') |
                            (calls['api'] == 'RegDeleteValueW') |
                            (calls['api'] == 'NtDeleteKey')) &
                           (calls['status'] == True)]

        for i, regdelete in regdeletes.iterrows():
            regname = None

            for arg, val in regdelete['arguments'].items():
                if arg == 'regkey':
                    regname = val

            if regname is not None:
                if (self._search_re(regname, self.ignorepaths) and
                        not self._search_re(regname, self.includepaths)):
                    continue
                # Get a sequential number for the event...
                nextid = len(self.nodemetadata)
                rdnodename = "REGISTRY DELETE {0}".format(nextid)
                self.nodemetadata[rdnodename] = dict()
                self.nodemetadata[rdnodename]['pid'] = node
                self.nodemetadata[rdnodename]['registry'] = regname
                self.nodemetadata[rdnodename]['node_type'] = 'REGISTRYDELETE'
                self.nodemetadata[rdnodename]['time'] =   regdelete['time']
                self.digraph.add_node(rdnodename, type='REGISTRYDELETE')
                self.digraph.add_edge(node, rdnodename)

    def _add_registry_creates(self, node, calls):
        """
        Internal function that adds registry creates to the graph.

        :param node:  The PID node name for the calls.
        :param calls:  The api calls.
        :returns:  Nothing.
        """
        regcreates = calls[((calls['api'] == 'RegCreateKeyExA') |
                            (calls['api'] == 'RegCreateKeyExW') |
                            (calls['api'] == 'NtCreateKey')) &
                           (calls['status'] == True)]

        for i, regcreate in regcreates.iterrows():
            regname = None

            for arg, val in regcreate['arguments'].items():
                if arg == 'regkey':
                    regname = val

            if regname is not None:
                if (self._search_re(regname, self.ignorepaths) and
                        not self._search_re(regname, self.includepaths)):
                    continue

                nextid = len(self.nodemetadata)
                rcnodename = "REGISTRY CREATE {0}".format(nextid)

                self.nodemetadata[rcnodename] = dict()
                self.nodemetadata[rcnodename]['pid'] = node
                self.nodemetadata[rcnodename]['registry'] = regname
                self.nodemetadata[rcnodename]['node_type'] = 'REGISTRYCREATE'
                self.nodemetadata[rcnodename]['time'] = regcreate['time']
                self.digraph.add_node(rcnodename, type='REGISTRYCREATE')
                self.digraph.add_edge(node, rcnodename)

    def _add_registry_reads(self, node, calls):
        """
        Internal function that adds registry reads to the graph.

        :param node:  The PID node name for the calls.
        :param calls:  The api calls.
        :returns:  Nothing.
        """
        regreads = calls[((calls['api'] == 'RegQueryValueExA') |
                          (calls['api'] == 'RegQueryValueExW') |
                          (calls['api'] == 'NtQueryValueKey')) &
                         (calls['status'] == True)]

        for i, regread in regreads.iterrows():
            regname = None

            for arg, val in regread['arguments'].items():
                if arg == 'regkey':
                    regname = val

            if regname is not None:
                if (self._search_re(regname, self.ignorepaths) and
                        not self._search_re(regname, self.includepaths)):
                    continue

                # Get a sequential number for the event...
                nextid = len(self.nodemetadata)
                rrnodename = "REGISTRY READ {0}".format(nextid)

                self.nodemetadata[rrnodename] = dict()
                self.nodemetadata[rrnodename]['pid'] = node
                self.nodemetadata[rrnodename]['registry'] = regname
                self.nodemetadata[rrnodename]['node_type'] = 'REGISTRYREAD'
                self.nodemetadata[rrnodename]['time'] = regread['time']
                self.digraph.add_node(rrnodename, type='REGISTRYREAD')
                self.digraph.add_edge(node, rrnodename)

    def _create_positions_digraph(self):
        """
        Internal function to create the positions of the graph.

        :returns: Nothing.
        """
        # Create the positions...
        if self.graphvizprog is None:
            self.pos = networkx.spring_layout(self.digraph)
        else:
            self.pos = \
                networkx.drawing.nx_pydot.graphviz_layout(
                    self.digraph, prog=self.graphvizprog,
                    root=self.rootpid)

    def _generategraph(self):
        """
        Internal function to create the output data for plotly.

        :returns: The data that can be plotted with plotly scatter
        plots.
        """

        # Node coordinates...
        ProcessX = []
        ProcessY = []
        HostX = []
        HostY = []
        IPX = []
        IPY = []
        SocketX = []
        SocketY = []
        TCPConnectX = []
        TCPConnectY = []
        FileX = []
        FileY = []
        FileCreateX = []
        FileCreateY = []
        FileWriteX = []
        FileWriteY = []
        FileCopyX = []
        FileCopyY = []
        FileDeleteX = []
        FileDeleteY = []
        FileMoveX = []
        FileMoveY = []
        FileReadX = []
        FileReadY = []
        RegistryX = []
        RegistryY = []
        RegistryWriteX = []
        RegistryWriteY = []
        RegistryDeleteX = []
        RegistryDeleteY = []
        RegistryCreateX = []
        RegistryCreateY = []
        RegistryReadX = []
        RegistryReadY = []
        URLX = []
        URLY = []
        ServerX = []
        ServerY = []
        IPConnX = []
        IPConnY = []

        # Edge coordinates...
        ProcessXe = []
        ProcessYe = []
        GetNameXe = []
        GetNameYe = []
        DNSXe = []
        DNSYe = []
        SocketXe = []
        SocketYe = []
        TCPConnectXe = []
        TCPConnectYe = []
        FileCreateXe = []
        FileCreateYe = []
        LoadImageXe = []
        LoadImageYe = []
        FileWriteXe = []
        FileWriteYe = []
        FileCopyXe = []
        FileCopyYe = []
        FileDeleteXe = []
        FileDeleteYe = []
        FileMoveXe = []
        FileMoveYe = []
        FileReadXe = []
        FileReadYe = []
        RegistryWriteXe = []
        RegistryWriteYe = []
        RegistryDeleteXe = []
        RegistryDeleteYe = []
        RegistryCreateXe = []
        RegistryCreateYe = []
        RegistryReadXe = []
        RegistryReadYe = []
        URLXe = []
        URLYe = []
        ServerXe = []
        ServerYe = []
        IPConnXe = []
        IPConnYe = []

        # Hover Text...
        proctxt = []
        hosttxt = []
        iptxt = []
        sockettxt = []
        tcpconnecttxt = []
        filetxt = []
        filecreatetxt = []
        filewritetxt = []
        filecopytxt = []
        filedeletetxt = []
        filemovetxt = []
        filereadtxt = []
        registrytxt = []
        registrywritetxt = []
        registrydeletetxt = []
        registrycreatetxt = []
        registryreadtxt = []
        urltxt = []
        servertxt = []
        ipconntxt = []

        # Traverse nodes...
        for node in self.digraph:
            if self.digraph.nodes[node]['type'] == 'PID':
                ProcessX.append(self.pos[node][0])
                ProcessY.append(self.pos[node][1])
                if 'command_line' in self.nodemetadata[node]:
                    cmdline = self.nodemetadata[node]['command_line']
                else:
                    cmdline = "Not Available"
                proctxt.append(
                    "PID: {0}<br>"
                    "Name: {1}<br>"
                    "Command Line: {2}<br>"
                    "Parent PID: {3}<br>"
                    "First Seen: {4}"
                    .format(
                        self.nodemetadata[node]['pid'],
                        self.nodemetadata[node]['name'],
                        cmdline,
                        self.nodemetadata[node]['parent_id'],
                        pandas.to_datetime(self.nodemetadata[node]['first_seen'], unit='s')
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'HOST':
                HostX.append(self.pos[node][0])
                HostY.append(self.pos[node][1])
                hosttxt.append(
                    "HOST: {0}"
                    .format(
                        self.nodemetadata[node]['host']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'SERVERCONNECT':
                ServerX.append(self.pos[node][0])
                ServerY.append(self.pos[node][1])
                servertxt.append(
                    "Server Connect: {0}<br>"
                    "Port: {1}<br>"
                    "Time: {2}"
                    .format(
                        self.nodemetadata[node]['server'],
                        self.nodemetadata[node]['port'],
                        self.nodemetadata[node]['time']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'IPCONNECT':
                IPConnX.append(self.pos[node][0])
                IPConnY.append(self.pos[node][1])
                ipconntxt.append(
                    "IP Connect: {0}<br>"
                    "Port: {1}<br>"
                    "Time: {2}"
                    .format(
                        self.nodemetadata[node]['ip'],
                        self.nodemetadata[node]['port'],
                        self.nodemetadata[node]['time']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'IP':
                IPX.append(self.pos[node][0])
                IPY.append(self.pos[node][1])
                iptxt.append(
                    "IP: {0}"
                    .format(
                        self.nodemetadata[node]['ip']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'SOCKET':
                SocketX.append(self.pos[node][0])
                SocketY.append(self.pos[node][1])
                sockettxt.append(
                    "Socket: {0}<br>"
                    "Protocol: {1}<br>"
                    "Open Time: {2}<br>"
                    "Close TIme: {3}"
                    .format(
                        self.nodemetadata[node]['socket'],
                        self.nodemetadata[node]['protocol'],
                        self.nodemetadata[node]['opentime'],
                        self.nodemetadata[node]['closetime']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'TCPCONNECT':
                TCPConnectX.append(self.pos[node][0])
                TCPConnectY.append(self.pos[node][1])
                tcpconnecttxt.append(
                    "TCP Connect:<br>"
                    "IP: {0}<br>"
                    "Port: {1}<br>"
                    "Socket: {2}<br>"
                    "Time: {3}"
                    .format(
                        self.nodemetadata[node]['ip'],
                        self.nodemetadata[node]['port'],
                        self.nodemetadata[node]['socket'],
                        self.nodemetadata[node]['time']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'FILECREATE':
                FileCreateX.append(self.pos[node][0])
                FileCreateY.append(self.pos[node][1])
                filecreatetxt.append(
                    "File Created:<br>"
                    "File: {0}<br>"
                    "{1}:"
                    .format(
                        self.nodemetadata[node]['file'],
                        self.nodemetadata[node]['pid']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'FILEWRITE':
                FileWriteX.append(self.pos[node][0])
                FileWriteY.append(self.pos[node][1])
                filewritetxt.append(
                    "File Write:<br>"
                    "File: {0}<br>"
                    "{1}"
                    .format(
                        self.nodemetadata[node]['file'],
                        self.nodemetadata[node]['pid']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'FILECOPY':
                FileCopyX.append(self.pos[node][0])
                FileCopyY.append(self.pos[node][1])
                filecopytxt.append(
                    "File Copy:<br>"
                    "Existing File: {0}<br>"
                    "New File: {1}<br>"
                    "{2}"
                    .format(
                        self.nodemetadata[node]['file_original'],
                        self.nodemetadata[node]['file_new'],
                        self.nodemetadata[node]['pid'],
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'FILEDELETE':
                FileDeleteX.append(self.pos[node][0])
                FileDeleteY.append(self.pos[node][1])
                filedeletetxt.append(
                    "File Delete:<br>"
                    "File: {0}"
                    "{1}"
                    .format(
                        self.nodemetadata[node]['file'],
                        self.nodemetadata[node]['pid']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'FILEMOVE':
                FileMoveX.append(self.pos[node][0])
                FileMoveY.append(self.pos[node][1])
                filemovetxt.append(
                    "File Moved:<br>"
                    "Existing File: {0}<br>"
                    "New File: {1}<br>"
                    "{2}"
                    .format(
                        self.nodemetadata[node]['file_original'],
                        self.nodemetadata[node]['file_new'],
                        self.nodemetadata[node]['pid']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'FILEREAD':
                FileReadX.append(self.pos[node][0])
                FileReadY.append(self.pos[node][1])
                filereadtxt.append(
                    "File Read: {0}<br>"
                    "{1}"
                    .format(
                        self.nodemetadata[node]['file'],
                        self.nodemetadata[node]['pid']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'REGISTRY':
                RegistryX.append(self.pos[node][0])
                RegistryY.append(self.pos[node][1])
                newreg = self.nodemetadata[node]['link']

                registrytxt.append(
                    "Registry: {0}"
                    .format(
                        self.nodemetadata[newreg]['registry']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'REGISTRYWRITE':
                RegistryWriteX.append(self.pos[node][0])
                RegistryWriteY.append(self.pos[node][1])
                registrywritetxt.append(
                    "Registry Write: {0}<br>"
                    "Buffer: {1}<br>"
                    "Time: {2}<br>"
                    "{3}"
                    .format(
                        self.nodemetadata[node]['registry'],
                        self.nodemetadata[node]['buffer'],
                        self.nodemetadata[node]['time'],
                        self.nodemetadata[node]['pid']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'REGISTRYDELETE':
                RegistryDeleteX.append(self.pos[node][0])
                RegistryDeleteY.append(self.pos[node][1])
                registrydeletetxt.append(
                    "Registry Delete: {0}<br>"
                    "Time: {1}<br>"
                    "{2}"
                    .format(
                        self.nodemetadata[node]['registry'],
                        self.nodemetadata[node]['time'],
                        self.nodemetadata[node]['pid']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'REGISTRYCREATE':
                RegistryCreateX.append(self.pos[node][0])
                RegistryCreateY.append(self.pos[node][1])
                registrycreatetxt.append(
                    "Registry Create: {0}<br>"
                    "Time: {1}<br>"
                    "{2}"
                    .format(
                        self.nodemetadata[node]['registry'],
                        self.nodemetadata[node]['time'],
                        self.nodemetadata[node]['pid']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'REGISTRYREAD':
                RegistryReadX.append(self.pos[node][0])
                RegistryReadY.append(self.pos[node][1])
                registryreadtxt.append(
                    "Registry Read: {0}<br>"
                    "Time: {1}<br>"
                    "{2}"
                    .format(
                        self.nodemetadata[node]['registry'],
                        self.nodemetadata[node]['time'],
                        self.nodemetadata[node]['pid']
                        )
                               )
            if self.digraph.nodes[node]['type'] == 'URL':
                URLX.append(self.pos[node][0])
                URLY.append(self.pos[node][1])
                urltxt.append(
                    "URL: {0}"
                    .format(
                        self.nodemetadata[node]['url']
                        )
                               )

        # Traverse edges...
        for edge in self.digraph.edges():
            if (self.digraph.nodes[edge[0]]['type'] == 'PID' and
                    self.digraph.nodes[edge[1]]['type'] == 'PID'):
                ProcessXe.append(self.pos[edge[0]][0])
                ProcessXe.append(self.pos[edge[1]][0])
                ProcessXe.append(None)
                ProcessYe.append(self.pos[edge[0]][1])
                ProcessYe.append(self.pos[edge[1]][1])
                ProcessYe.append(None)
            if (self.digraph.nodes[edge[0]]['type'] == 'PID' and
                    self.digraph.nodes[edge[1]]['type'] == 'HOST'):
                GetNameXe.append(self.pos[edge[0]][0])
                GetNameXe.append(self.pos[edge[1]][0])
                GetNameXe.append(None)
                GetNameYe.append(self.pos[edge[0]][1])
                GetNameYe.append(self.pos[edge[1]][1])
                GetNameYe.append(None)
            if ((self.digraph.nodes[edge[0]]['type'] == 'PID' and
                self.digraph.nodes[edge[1]]['type'] == 'SERVERCONNECT') or
                (self.digraph.nodes[edge[0]]['type'] == 'SERVERCONNECT' and
                    self.digraph.nodes[edge[1]]['type'] == 'HOST')):
                ServerXe.append(self.pos[edge[0]][0])
                ServerXe.append(self.pos[edge[1]][0])
                ServerXe.append(None)
                ServerYe.append(self.pos[edge[0]][1])
                ServerYe.append(self.pos[edge[1]][1])
                ServerYe.append(None)
            if ((self.digraph.nodes[edge[0]]['type'] == 'PID' and
                self.digraph.nodes[edge[1]]['type'] == 'IPCONNECT') or
                (self.digraph.nodes[edge[0]]['type'] == 'IPCONNECT' and
                    self.digraph.nodes[edge[1]]['type'] == 'IP')):
                IPConnXe.append(self.pos[edge[0]][0])
                IPConnXe.append(self.pos[edge[1]][0])
                IPConnXe.append(None)
                IPConnYe.append(self.pos[edge[0]][1])
                IPConnYe.append(self.pos[edge[1]][1])
                IPConnYe.append(None)
            if (self.digraph.nodes[edge[0]]['type'] == 'HOST' and
                    self.digraph.node[edge[1]]['type'] == 'IP'):
                DNSXe.append(self.pos[edge[0]][0])
                DNSXe.append(self.pos[edge[1]][0])
                DNSXe.append(None)
                DNSYe.append(self.pos[edge[0]][1])
                DNSYe.append(self.pos[edge[1]][1])
                DNSYe.append(None)
            if (self.digraph.nodes[edge[0]]['type'] == 'PID' and
                    self.digraph.nodes[edge[1]]['type'] == 'SOCKET'):
                SocketXe.append(self.pos[edge[0]][0])
                SocketXe.append(self.pos[edge[1]][0])
                SocketXe.append(None)
                SocketYe.append(self.pos[edge[0]][1])
                SocketYe.append(self.pos[edge[1]][1])
                SocketYe.append(None)
            if ((self.digraph.nodes[edge[0]]['type'] == 'SOCKET' and
                self.digraph.nodes[edge[1]]['type'] == 'TCPCONNECT') or
                (self.digraph.nodes[edge[0]]['type'] == 'TCPCONNECT' and
                    self.digraph.nodes[edge[1]]['type'] == 'IP')):
                TCPConnectXe.append(self.pos[edge[0]][0])
                TCPConnectXe.append(self.pos[edge[1]][0])
                TCPConnectXe.append(None)
                TCPConnectYe.append(self.pos[edge[0]][1])
                TCPConnectYe.append(self.pos[edge[1]][1])
                TCPConnectYe.append(None)
            if ((self.digraph.nodes[edge[0]]['type'] == 'PID' and
                self.digraph.nodes[edge[1]]['type'] == 'FILECREATE') or
                (self.digraph.nodes[edge[0]]['type'] == 'FILECREATE' and
                    self.digraph.nodes[edge[1]]['type'] == 'FILE')):
                FileCreateXe.append(self.pos[edge[0]][0])
                FileCreateXe.append(self.pos[edge[1]][0])
                FileCreateXe.append(None)
                FileCreateYe.append(self.pos[edge[0]][1])
                FileCreateYe.append(self.pos[edge[1]][1])
                FileCreateYe.append(None)
            if ((self.digraph.nodes[edge[0]]['type'] == 'PID' and
                self.digraph.nodes[edge[1]]['type'] == 'FILEWRITE') or
                (self.digraph.nodes[edge[0]]['type'] == 'FILEWRITE' and
                    self.digraph.nodes[edge[1]]['type'] == 'FILE')):
                FileWriteXe.append(self.pos[edge[0]][0])
                FileWriteXe.append(self.pos[edge[1]][0])
                FileWriteXe.append(None)
                FileWriteYe.append(self.pos[edge[0]][1])
                FileWriteYe.append(self.pos[edge[1]][1])
                FileWriteYe.append(None)
            if (self.digraph.nodes[edge[0]]['type'] == 'FILE' and
                    self.digraph.nodes[edge[1]]['type'] == 'PID'):
                LoadImageXe.append(self.pos[edge[0]][0])
                LoadImageXe.append(self.pos[edge[1]][0])
                LoadImageXe.append(None)
                LoadImageYe.append(self.pos[edge[0]][1])
                LoadImageYe.append(self.pos[edge[1]][1])
                LoadImageYe.append(None)
            if ((self.digraph.nodes[edge[0]]['type'] == 'PID' and
                self.digraph.nodes[edge[1]]['type'] == 'FILECOPY') or
                (self.digraph.nodes[edge[0]]['type'] == 'FILECOPY' and
                    self.digraph.nodes[edge[1]]['type'] == 'FILE')):
                FileCopyXe.append(self.pos[edge[0]][0])
                FileCopyXe.append(self.pos[edge[1]][0])
                FileCopyXe.append(None)
                FileCopyYe.append(self.pos[edge[0]][1])
                FileCopyYe.append(self.pos[edge[1]][1])
                FileCopyYe.append(None)
            if ((self.digraph.nodes[edge[0]]['type'] == 'PID' and
                self.digraph.nodes[edge[1]]['type'] == 'FILEDELETE') or
                (self.digraph.nodes[edge[0]]['type'] == 'FILEDELETE' and
                    self.digraph.nodes[edge[1]]['type'] == 'FILE')):
                FileDeleteXe.append(self.pos[edge[0]][0])
                FileDeleteXe.append(self.pos[edge[1]][0])
                FileDeleteXe.append(None)
                FileDeleteYe.append(self.pos[edge[0]][1])
                FileDeleteYe.append(self.pos[edge[1]][1])
                FileDeleteYe.append(None)
            if ((self.digraph.nodes[edge[0]]['type'] == 'PID' and
                self.digraph.nodes[edge[1]]['type'] == 'FILEREAD') or
                (self.digraph.nodes[edge[0]]['type'] == 'FILEREAD' and
                    self.digraph.nodes[edge[1]]['type'] == 'FILE')):
                FileReadXe.append(self.pos[edge[0]][0])
                FileReadXe.append(self.pos[edge[1]][0])
                FileReadXe.append(None)
                FileReadYe.append(self.pos[edge[0]][1])
                FileReadYe.append(self.pos[edge[1]][1])
                FileReadYe.append(None)
            if ((self.digraph.nodes[edge[0]]['type'] == 'PID' and
                self.digraph.nodes[edge[1]]['type'] == 'REGISTRYWRITE') or
                (self.digraph.nodes[edge[0]]['type'] == 'REGISTRYWRITE' and
                    self.digraph.nodes[edge[1]]['type'] == 'REGISTRY')):
                RegistryWriteXe.append(self.pos[edge[0]][0])
                RegistryWriteXe.append(self.pos[edge[1]][0])
                RegistryWriteXe.append(None)
                RegistryWriteYe.append(self.pos[edge[0]][1])
                RegistryWriteYe.append(self.pos[edge[1]][1])
                RegistryWriteYe.append(None)
            if ((self.digraph.nodes[edge[0]]['type'] == 'PID' and
                self.digraph.nodes[edge[1]]['type'] == 'REGISTRYDELETE') or
                (self.digraph.nodes[edge[0]]['type'] == 'REGISTRYDELETE' and
                    self.digraph.nodes[edge[1]]['type'] == 'REGISTRY')):
                RegistryDeleteXe.append(self.pos[edge[0]][0])
                RegistryDeleteXe.append(self.pos[edge[1]][0])
                RegistryDeleteXe.append(None)
                RegistryDeleteYe.append(self.pos[edge[0]][1])
                RegistryDeleteYe.append(self.pos[edge[1]][1])
                RegistryDeleteYe.append(None)
            if ((self.digraph.nodes[edge[0]]['type'] == 'PID' and
                self.digraph.nodes[edge[1]]['type'] == 'REGISTRYCREATE') or
                (self.digraph.nodes[edge[0]]['type'] == 'REGISTRYCREATE' and
                    self.digraph.nodes[edge[1]]['type'] == 'REGISTRY')):
                RegistryCreateXe.append(self.pos[edge[0]][0])
                RegistryCreateXe.append(self.pos[edge[1]][0])
                RegistryCreateXe.append(None)
                RegistryCreateYe.append(self.pos[edge[0]][1])
                RegistryCreateYe.append(self.pos[edge[1]][1])
                RegistryCreateYe.append(None)
            if ((self.digraph.nodes[edge[0]]['type'] == 'PID' and
                self.digraph.nodes[edge[1]]['type'] == 'REGISTRYREAD') or
                (self.digraph.nodes[edge[0]]['type'] == 'REGISTRYREAD' and
                    self.digraph.nodes[edge[1]]['type'] == 'REGISTRY')):
                RegistryReadXe.append(self.pos[edge[0]][0])
                RegistryReadXe.append(self.pos[edge[1]][0])
                RegistryReadXe.append(None)
                RegistryReadYe.append(self.pos[edge[0]][1])
                RegistryReadYe.append(self.pos[edge[1]][1])
                RegistryReadYe.append(None)
            if (self.digraph.nodes[edge[0]]['type'] == 'PID' and
                self.digraph.nodes[edge[1]]['type'] == 'URL'):
                URLXe.append(self.pos[edge[0]][0])
                URLXe.append(self.pos[edge[1]][0])
                URLXe.append(None)
                URLYe.append(self.pos[edge[0]][1])
                URLYe.append(self.pos[edge[1]][1])
                URLYe.append(None)

        nodes = []
        edges = []

        # PROCESSES...

        marker =dict(symbol='circle', size=10)

        # Create the nodes...
        ProcNodes = go.Scatter(x=ProcessX,
                            y=ProcessY,
                            mode='markers',
                            marker=marker,
                            name='Process',
                            text=proctxt,
                            hoverinfo='text')

        # Create the edges for the nodes...
        ProcEdges = go.Scatter(x=ProcessXe,
                            y=ProcessYe,
                            mode='lines',
                            line=dict(shape='linear',
                                      color='rgb(214,39,20)'),
                            name='Process Start',
                            hoverinfo='none')

        nodes.append(ProcNodes)
        edges.append(ProcEdges)

        # HOSTS...

        marker = dict(symbol='square', size=10)

        # Create the nodes...
        HostNodes = go.Scatter(x=HostX,
                            y=HostY,
                            mode='markers',
                            marker=marker,
                            name='Host',
                            text=hosttxt,
                            hoverinfo='text',
                            visible='legendonly')

        nodes.append(HostNodes)

        # Create the edges for the nodes...
        GetNameEdges = go.Scatter(x=GetNameXe,
                               y=GetNameYe,
                               mode='lines',
                               line=dict(shape='linear',
                                         color='rgb(174,199,232)'),
                               name='DNS Query',
                               hoverinfo='none',
                               visible='legendonly')

        edges.append(GetNameEdges)

        # SERVERS...

        marker = dict(symbol='diamond', size=7)

        # Create the nodes...
        ServerNodes = go.Scatter(x=ServerX,
                              y=ServerY,
                              mode='markers',
                              marker=marker,
                              name='Server Connections',
                              text=servertxt,
                              hoverinfo='text',
                              visible='legendonly')

        nodes.append(ServerNodes)

        # Create the edges for the nodes...
        ServerEdges = go.Scatter(x=ServerXe,
                              y=ServerYe,
                              mode='lines',
                              line=dict(shape='linear'),
                              name='Server Connect',
                              hoverinfo='none',
                              visible='legendonly')

        edges.append(ServerEdges)

        # IP CONNECTS...

        marker = dict(symbol='diamond', size=7)

        # Create the nodes...
        IPConnNodes = go.Scatter(x=IPConnX,
                              y=IPConnY,
                              mode='markers',
                              marker=marker,
                              name='IP Connections',
                              text=ipconntxt,
                              hoverinfo='text',
                              visible='legendonly')

        nodes.append(IPConnNodes)

        # Create the edges for the nodes...
        IPConnEdges = go.Scatter(x=IPConnXe,
                              y=IPConnYe,
                              mode='lines',
                              line=dict(shape='linear'),
                              name='IP Connect',
                              hoverinfo='none',
                              visible='legendonly')

        edges.append(IPConnEdges)

        # IPS...

        marker = dict(symbol='square', size=10)

        # Create the nodes...
        IPNodes = go.Scatter(x=IPX,
                          y=IPY,
                          mode='markers',
                          marker=marker,
                          name='IP',
                          text=iptxt,
                          hoverinfo='text',
                          visible='legendonly')

        nodes.append(IPNodes)

        # Create the edges for the nodes...
        DNSEdges = go.Scatter(x=DNSXe,
                           y=DNSYe,
                           mode='lines',
                           line=dict(shape='linear',
                                     color='rgb(23,190,207)'),
                           name='DNS Response',
                           hoverinfo='none',
                           visible='legendonly')

        edges.append(DNSEdges)

        # SOCKETS...

        marker = dict(symbol='diamond', size=7, color='rgb(277,119,194)')

        # Create the nodes...
        SocketNodes = go.Scatter(x=SocketX,
                              y=SocketY,
                              mode='markers',
                              marker=marker,
                              name='Socket',
                              text=sockettxt,
                              hoverinfo='text',
                              visible='legendonly')

        # Create the edges for the nodes...
        SocketEdges = go.Scatter(x=SocketXe,
                              y=SocketYe,
                              mode='lines',
                              line=dict(shape='linear',
                                        color='rgb(227,119,194)'),
                              name='Create Socket',
                              hoverinfo='none',
                              visible='legendonly')

        nodes.append(SocketNodes)
        edges.append(SocketEdges)

        # TCP CONNECTS...

        marker = dict(symbol='diamond', size=7, color='rgb(44,160,44)')

        # Create the nodes...
        TCPConnectNodes = go.Scatter(x=TCPConnectX,
                                  y=TCPConnectY,
                                  mode='markers',
                                  marker=marker,
                                  name='TCP Connection',
                                  text=tcpconnecttxt,
                                  hoverinfo='text',
                                  visible='legendonly')

        # Create the edges for the nodes...
        TCPConnectEdges = go.Scatter(x=TCPConnectXe,
                                  y=TCPConnectYe,
                                  mode='lines',
                                  line=dict(shape='linear',
                                            color='rgb(44,160,44)'),
                                  name='TCP Connect',
                                  hoverinfo='none',
                                  visible='legendonly')

        nodes.append(TCPConnectNodes)
        edges.append(TCPConnectEdges)

        # URLS...

        marker = dict(symbol='square', size=10)

        # Create the nodes...
        URLNodes = go.Scatter(x=URLX,
                           y=URLY,
                           mode='markers',
                           marker=marker,
                           name='URL',
                           text=urltxt,
                           hoverinfo='text',
                           visible='legendonly')

        nodes.append(URLNodes)

        # Create the edges for the nodes...
        URLEdges = go.Scatter(x=URLXe,
                           y=URLYe,
                           mode='lines',
                           line=dict(shape='linear'),
                           name='URL Connect',
                           hoverinfo='none',
                           visible='legendonly')

        edges.append(URLEdges)

        # FILES...

        marker = dict(symbol='hexagon', size=10)

        # Create the nodes...
        FileNodes = go.Scatter(x=FileX,
                            y=FileY,
                            mode='markers',
                            marker=marker,
                            name='File',
                            text=filetxt,
                            hoverinfo='text',
                            visible='legendonly')

        nodes.append(FileNodes)

        marker = dict(symbol='triangle-down', size=7,
                        color='rgb(123,102,210)')

        # Create the nodes...
        FileCreateNodes = go.Scatter(x=FileCreateX,
                                  y=FileCreateY,
                                  mode='markers',
                                  marker=marker,
                                  name='File Create',
                                  text=filecreatetxt,
                                  hoverinfo='text',
                                  visible='legendonly')

        nodes.append(FileCreateNodes)

        # Create the edges for the nodes...
        FileCreateEdges = go.Scatter(x=FileCreateXe,
                                  y=FileCreateYe,
                                  mode='lines',
                                  line=dict(shape='linear',
                                            color='rgb(123,102,210)'),
                                  name='File Create',
                                  hoverinfo='none',
                                  visible='legendonly')

        edges.append(FileCreateEdges)

        marker = dict(symbol='triangle-down', size=7,
                        color='rgb(255,187,120)')

        # Create the nodes...
        FileWriteNodes = go.Scatter(x=FileWriteX,
                                 y=FileWriteY,
                                 mode='markers',
                                 marker=marker,
                                 name='File Write',
                                 text=filewritetxt,
                                 hoverinfo='text',
                                 visible='legendonly')

        nodes.append(FileWriteNodes)

        # Create the edges for the nodes...
        FileWriteEdges = go.Scatter(x=FileWriteXe,
                                 y=FileWriteYe,
                                 mode='lines',
                                 line=dict(shape='linear',
                                           color='rgb(255,187,120)'),
                                 name='File Write',
                                 hoverinfo='none',
                                 visible='legendonly')

        edges.append(FileWriteEdges)

        marker = dict(symbol='triangle-down', size=7,
                        color='rgb(65,68,81)')

        # Create the nodes...
        FileCopyNodes = go.Scatter(x=FileCopyX,
                                y=FileCopyY,
                                mode='markers',
                                marker=marker,
                                name='File Copy',
                                text=filecopytxt,
                                hoverinfo='text',
                                visible='legendonly')

        nodes.append(FileCopyNodes)

        # Create the edges for the nodes...
        FileCopyEdges = go.Scatter(x=FileCopyXe,
                                y=FileCopyYe,
                                mode='lines',
                                line=dict(shape='linear',
                                          color='rgb(65,68,81)'),
                                name='File Copy',
                                hoverinfo='none',
                                visible='legendonly')

        edges.append(FileCopyEdges)

        marker = dict(symbol='triangle-down', size=7,
                        color='rgb(255,128,14)')

        # Create the nodes...
        FileDeleteNodes = go.Scatter(x=FileDeleteX,
                                  y=FileDeleteY,
                                  mode='markers',
                                  marker=marker,
                                  name='File Delete',
                                  text=filedeletetxt,
                                  hoverinfo='text',
                                  visible='legendonly')

        nodes.append(FileDeleteNodes)

        # Create the edges for the nodes...
        FileDeleteEdges = go.Scatter(x=FileDeleteXe,
                                  y=FileDeleteYe,
                                  mode='lines',
                                  line=dict(shape='linear',
                                            color='rgb(255,128,14)'),
                                  name='File Delete',
                                  hoverinfo='none',
                                  visible='legendonly')

        edges.append(FileDeleteEdges)

        marker = dict(symbol='triangle-down', size=7,
                        color='rgb(171,171,171)')

        # Create the nodes...
        FileMoveNodes = go.Scatter(x=FileMoveX,
                                y=FileMoveY,
                                mode='markers',
                                marker=marker,
                                name='File Move',
                                text=filemovetxt,
                                hoverinfo='text',
                                visible='legendonly')

        nodes.append(FileMoveNodes)

        # Create the edges for the nodes...
        FileMoveEdges = go.Scatter(x=FileMoveXe,
                                y=FileMoveYe,
                                mode='lines',
                                line=dict(shape='linear',
                                          color='rgb(171,171,171)'),
                                name='File Move',
                                hoverinfo='none',
                                visible='legendonly')

        edges.append(FileMoveEdges)

        marker = dict(symbol='triangle-up', size=7,
                        color='rgb(207,207,207)')

        # Create the nodes...
        FileReadNodes = go.Scatter(x=FileReadX,
                                y=FileReadY,
                                mode='markers',
                                marker=marker,
                                name='File Read',
                                text=filereadtxt,
                                hoverinfo='text',
                                visible='legendonly')

        nodes.append(FileReadNodes)

        # Create the edges for the nodes...
        FileReadEdges = go.Scatter(x=FileReadXe,
                                y=FileReadYe,
                                mode='lines',
                                line=dict(shape='linear',
                                          color='rgb(207,207,207)'),
                                name='File Read',
                                hoverinfo='none',
                                visible='legendonly')

        edges.append(FileReadEdges)

        # Create the edges for the nodes...
        LoadImageEdges = go.Scatter(x=LoadImageXe,
                                 y=LoadImageYe,
                                 mode='lines',
                                 line=dict(shape='linear',
                                           dash='dot'),
                                 name='Process Load Image',
                                 hoverinfo='none',
                                 visible='legendonly')

        edges.append(LoadImageEdges)

        # REGISTRY...

        marker = dict(symbol='star', size=10)

        # Create the nodes...
        RegistryNodes = go.Scatter(x=RegistryX,
                                y=RegistryY,
                                mode='markers',
                                marker=marker,
                                name='Registry',
                                text=registrytxt,
                                hoverinfo='text',
                                visible='legendonly')

        nodes.append(RegistryNodes)

        marker = dict(symbol='triangle-down', size=7,
                        color='rgb(255,187,120)')

        # Create the nodes...
        RegistryWriteNodes = go.Scatter(x=RegistryWriteX,
                                     y=RegistryWriteY,
                                     mode='markers',
                                     marker=marker,
                                     name='Registry Write',
                                     text=registrywritetxt,
                                     hoverinfo='text',
                                     visible='legendonly')

        nodes.append(RegistryWriteNodes)

        # Create the edges for the nodes...
        RegistryWriteEdges = go.Scatter(x=RegistryWriteXe,
                                     y=RegistryWriteYe,
                                     mode='lines',
                                     line=dict(shape='linear',
                                               color='rgb(255,187,120)'),
                                     name='Registry Write',
                                     hoverinfo='none',
                                     visible='legendonly')

        edges.append(RegistryWriteEdges)

        marker = dict(symbol='triangle-down', size=7,
                        color='rgb(255,128,14)')

        # Create the nodes...
        RegistryDeleteNodes = go.Scatter(x=RegistryDeleteX,
                                      y=RegistryDeleteY,
                                      mode='markers',
                                      marker=marker,
                                      name='Registry Delete',
                                      text=registrydeletetxt,
                                      hoverinfo='text',
                                      visible='legendonly')

        nodes.append(RegistryDeleteNodes)

        # Create the edges for the nodes...
        RegistryDeleteEdges = go.Scatter(x=RegistryDeleteXe,
                                      y=RegistryDeleteYe,
                                      mode='lines',
                                      line=dict(shape='linear',
                                                color='rgb(255,128,14)'),
                                      name='Registry Delete',
                                      hoverinfo='none',
                                      visible='legendonly')

        edges.append(RegistryDeleteEdges)

        marker = dict(symbol='triangle-down', size=7,
                        color='rgb(123,102,210)')

        # Create the nodes...
        RegistryCreateNodes = go.Scatter(x=RegistryCreateX,
                                      y=RegistryCreateY,
                                      mode='markers',
                                      marker=marker,
                                      name='Registry Create',
                                      text=registrycreatetxt,
                                      hoverinfo='text',
                                      visible='legendonly')

        nodes.append(RegistryCreateNodes)

        # Create the edges for the nodes...
        RegistryCreateEdges = go.Scatter(x=RegistryCreateXe,
                                      y=RegistryCreateYe,
                                      mode='lines',
                                      line=dict(shape='linear',
                                                color='rgb(123,102,210)'),
                                      name='Registry Create',
                                      hoverinfo='none',
                                      visible='legendonly')

        edges.append(RegistryCreateEdges)

        marker = dict(symbol='triangle-up', size=7,
                        color='rgb(207,207,207)')

        # Create the nodes...
        RegistryReadNodes = go.Scatter(x=RegistryReadX,
                                    y=RegistryReadY,
                                    mode='markers',
                                    marker=marker,
                                    name='Registry Read',
                                    text=registryreadtxt,
                                    hoverinfo='text',
                                    visible='legendonly')

        nodes.append(RegistryReadNodes)

        # Create the edges for the nodes...
        RegistryReadEdges = go.Scatter(x=RegistryReadXe,
                                    y=RegistryReadYe,
                                    mode='lines',
                                    line=dict(shape='linear',
                                              color='rgb(207,207,207)'),
                                    name='Registry Read',
                                    hoverinfo='none',
                                    visible='legendonly')

        edges.append(RegistryReadEdges)

        # Reverse the order and mush...
        output = []
        output += edges[::-1]
        output += nodes[::-1]

        # Return the plot data...
        return output

    def _generateannotations(self):
        """
        Internal function to generate annotations on the graph.

        :returns: A list of annotations for plotly.
        """
        annotations = []

        for node in self.digraph:
            if self.digraph.nodes[node]['type'] == 'PID':
                annotations.append(
                    dict(
                        text="{0}<br>PID: {1}".format(
                            self.nodemetadata[node]['name'],
                            self.nodemetadata[node]['pid']
                            ),
                        x=self.pos[node][0],
                        y=self.pos[node][1],
                        xref='x',
                        yref='y',
                        showarrow=True,
                        ax=-40,
                        ay=-40
                        )
                )
            if self.digraph.nodes[node]['type'] == 'HOST':
                annotations.append(
                    dict(
                        text="HOST: {0}".format(
                            self.nodemetadata[node]['host']
                            ),
                        x=self.pos[node][0],
                        y=self.pos[node][1],
                        xref='x',
                        yref='y',
                        showarrow=True,
                        ax=-40,
                        ay=-40
                        )
                )
            if self.digraph.nodes[node]['type'] == 'IP':
                annotations.append(
                    dict(
                        text="IP: {0}".format(
                            self.nodemetadata[node]['ip']
                            ),
                        x=self.pos[node][0],
                        y=self.pos[node][1],
                        xref='x',
                        yref='y',
                        showarrow=True,
                        ax=-40,
                        ay=-40
                        )
                )

        return annotations

    def plotgraph(self,
                  graphvizprog='sfdp',
                  filename='temp-plot.html',
                  title=None, auto_open=True,
                  image=None, image_filename='plot_image',
                  image_height=600, image_width=800):
        """

        Function to plot the graph of the ProcMon CSV.

        :param graphvizprog: The graphviz program to use for layout, valid
            options are 'dot', 'neato', 'twopi', 'circo', 'fdp',
            'sfdp', 'patchwork', and 'osage'.  Graphviz is REQUIRED to be
            installed and in your path to use this library!  The associated
            layout programs must be available in your path as well.  More
            information for the layout types can be found here:
            http://www.graphviz.org/Documentation.php
            If this value is None, the internal networkx layout algorithms
            will be used.
        :param filename: A file name for the interactive HTML plot.
        :param title: A title for the plot.
        :param auto_open: Set to false to not open the file in a web browser.
        :param image: An image type of 'png', 'jpeg', 'svg', 'webp', or None.
        :param image_filename: The file name for the exported image.
        :param image_height: The number of pixels for the image height.
        :param image_width: The number of pixels for the image width.
        :returns: Nothing
        """

        self.graphvizprog = graphvizprog

        # Layout the positions...
        self._create_positions_digraph()

        outputdata = self._generategraph()
        annotations = self._generateannotations()

        # Hide axis line, grid, ticklabels and title...
        axis = dict(showline=False,
                    zeroline=False,
                    showgrid=False,
                    showticklabels=False,
                    title='')

        plotlayout = go.Layout(showlegend=True, title=title,
                            xaxis=dict(axis),
                            yaxis=dict(axis),
                            hovermode='closest',
                            annotations=annotations)

        plotfigure = go.Figure(data=outputdata,
                            layout=plotlayout)

        # Plot without the plotly annoying link...
        plot(plotfigure, show_link=False, filename=filename,
             auto_open=auto_open, image=image,
             image_filename=image_filename,
             image_height=image_height,
             image_width=image_width)
