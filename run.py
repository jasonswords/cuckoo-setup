import argparse
import os
from objects.CuckooJSONReport import CuckooJSONReport as CuckooJSONReport


parser = argparse.ArgumentParser(
    description='Application to graph cuckoo JSON reports')

parser.add_argument('CuckooJSONReportFile',
                    help='cuckoo-modified JSON report file')

parser.add_argument('-f',
                    '--file', metavar='HTMLFile',
                    default='cuckoojson.html',
                    help='Create the html report. Default name '
                    'is cuckoojson.html')

parser.add_argument('-t',
                    '--title',
                    help='The title for the plot')

parser.add_argument('-na',
                    '--nonetwork', action='store_true',
                    help='Turn off all network activity')

parser.add_argument('-fa',
                    '--nofiles', action='store_true',
                    help='Turn off all file activity')

parser.add_argument('-fc',
                    '--nofilecreates', action='store_true',
                    help='Turn off file create activity')

parser.add_argument('-fm',
                    '--nofilemoves', action='store_true',
                    help='Turn off file move activity')

parser.add_argument('-fp',
                    '--nofilecopies', action='store_true',
                    help='Turn off file copy activity')

parser.add_argument('-fd',
                    '--nofiledeletes', action='store_true',
                    help='Turn off file delete activity')

parser.add_argument('-fw',
                    '--nofilewrites', action='store_true',
                    help='Turn off file write activity')

parser.add_argument('-fr',
                    '--nofilereads', action='store_true',
                    help='Turn off file read activity')

parser.add_argument('-ra',
                    '--noregistry', action='store_true',
                    help='Turn off all registry activity')

parser.add_argument('-rc',
                    '--noregcreates', action='store_true',
                    help='Turn off registry create activity')

parser.add_argument('-rd',
                    '--noregdeletes', action='store_true',
                    help='Turn off registry delete activity')

parser.add_argument('-rw',
                    '--noregwrites', action='store_true',
                    help='Turn off registry write activity')

parser.add_argument('-rr',
                    '--noregreads', action='store_true',
                    help='Turn off registry read activity')

parser.add_argument('-ignpaths',
                    '--ignorepathsfile', metavar='IgnPathsFile.txt',
                    help='File containing regular expressions to ignore '
                    'for files and registry.  One RE per line.')

parser.add_argument('-inclpaths',
                    '--includepathsfile', metavar='InclPathsFile.txt',
                    help='File containing regular expressions to include '
                    'for files and registry.  Overrides ignores. '
                    'One RE per line.')

parser.add_argument('-gp',
                    '--graphvizprog', default='sfdp',
                    help='The graphviz layout program to use.  Valid '
                         'options are dot, neato, twopi, circo, fdp, '
                         'sfdp, patchwork and osage.  Research the '
                         'graphviz website for more information on '
                         'these types of layouts.  IF YOU SUPPLY AN '
                         'INVALID VALUE THIS PROGRAM WILL NOT WORK! '
                         'Default: sfdp')

# Parse command line arguments.
args = parser.parse_args()

jsonfile = args.CuckooJSONReportFile
filename = args.file

if not os.path.exists(jsonfile):
    print('File does not exist: {0}'.format(jsonfile))
    exit(1)

if args.includepathsfile is not None:
    inclfile = args.includepathsfile
    if not os.path.exists(inclfile):
        print('Include file does not exist: {0}'.format(inclfile))
        exit(1)
    with open(inclfile) as infile:
        try:
            includepaths = infile.read().splitlines()
        except:
            print('ERROR:  File problem: {0}'.format(inclfile))
            exit(1)
else:
    includepaths = None

if args.ignorepathsfile is not None:
    ignfile = args.ignorepathsfile
    if not os.path.exists(ignfile):
        print('Ignore file does not exist: {0}'.format(ignfile))
        exit(1)
    with open(ignfile) as infile:
        try:
            ignorepaths = infile.read().splitlines()
        except:
            print('ERROR:  File problem: {0}'.format(ignfile))
            exit(1)
else:
    ignorepaths = None

print('Reading log: {0}'.format(jsonfile))
vl = CuckooJSONReport(jsonfile, plotnetwork=not(args.nonetwork),
                      plotfiles=not(args.nofiles),
                      plotfilecreates=not(args.nofilecreates),
                      plotfilemoves=not(args.nofilemoves),
                      plotfiledeletes=not(args.nofiledeletes),
                      plotfilecopies=not(args.nofilecopies),
                      plotfilereads=not(args.nofilereads),
                      plotfilewrites=not(args.nofilewrites),
                      plotregistry=not(args.noregistry),
                      plotregistrycreates=not(args.noregcreates),
                      plotregistrydeletes=not(args.noregdeletes),
                      plotregistrywrites=not(args.noregwrites),
                      plotregistryreads=not(args.noregreads),
                      ignorepaths=ignorepaths,
                      includepaths=includepaths)

print('Plotting log: {0}'.format(jsonfile))
vl.plotgraph(filename=filename, title=args.title,
             graphvizprog=args.graphvizprog)
