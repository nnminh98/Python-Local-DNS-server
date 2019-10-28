#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit, maxsize as MAXINT
import time
from time import sleep
import sys
from threading import Thread

from libs.collections_backport import OrderedDict
from libs.dnslib.RR import *
from libs.dnslib.Header import Header
from libs.dnslib.QE import QE
from libs.inetlib.types import *
from libs.util import *

from random import randint

# timeout in seconds to wait for reply
TIMEOUT = 5

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."
ROOTNS_IN_ADDR = "192.5.5.241"

# cache objects
class RR_A_Cache:
    def __init__(self):
        self.cache = dict()  # domain_name -> [(ip_address, expiration_time, authoritative)]

    def put(self, domain_name, ip_addr, expiration, authoritative=False):
        if domain_name not in self.cache:
            self.cache[domain_name] = dict()
        self.cache[domain_name][ip_addr] = (expiration, authoritative)

    def contains(self, domain_name):
        return domain_name in self.cache

    def getIpAddresses(self, domain_name):
        return list(self.cache[domain_name].keys())

    def getExpiration(self, domain_name, ip_address):
        return self.cache[domain_name][ip_address][0]

    def getAuthoritative(self, domain_name, ip_address):
        return self.cache[domain_name][ip_address][1]

    def __str__(self):
        return str(self.cache)


class CN_Cache:
    def __init__(self):
        self.cache = dict()  # domain_name -> (cname, expiration_time)

    def put(self, domain_name, canonical_name, expiration):
        self.cache[domain_name] = (canonical_name, expiration)

    def contains(self, domain_name):
        return domain_name in self.cache

    def getCanonicalName(self, domain_name):
        return self.cache[domain_name][0]

    def getCanonicalNameExpiration(self, domain_name):
        return self.cache[domain_name][1]

    def __str__(self):
        return str(self.cache)


class RR_NS_Cache:
    def __init__(self):
        self.cache = dict()  # domain_name -> (NS_record,expiration_time, authoritative)

    def put(self, zone_domain_name, name_server_domain_name, expiration, authoritative):
        if zone_domain_name not in self.cache:
            self.cache[zone_domain_name] = OrderedDict()
        self.cache[zone_domain_name][name_server_domain_name] = (expiration, authoritative)

    def get(self, zone_domain_name):
        list_name_servers = []
        for name_server in self.cache[zone_domain_name]:
            list_name_servers += [(name_server, self.cache[zone_domain_name][name_server][0],
                                   self.cache[zone_domain_name][name_server][1])]
        return list_name_servers

    def get_nsdn(self, zone_domain_name):
        return list(self.cache[zone_domain_name].keys())

    def contains(self, zone_domain_name):
        return zone_domain_name in self.cache

    def __str__(self):
        return str(self.cache)

# >>> entry point of ncsdns.py <<<

# Seed random number generator with current time of day:
'''now = int(time())
seed(now)'''

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

# Initialize the cache data structures
acache = RR_A_Cache()
acache.put(DomainName(ROOTNS_DN), InetAddr(ROOTNS_IN_ADDR), expiration=MAXINT, authoritative=True)

nscache = RR_NS_Cache()
nscache.put(DomainName("."), DomainName(ROOTNS_DN), expiration=MAXINT, authoritative=True)

cnamecache = CN_Cache()

# Parse the command line and assign us an ephemeral port to listen on:
def check_port(option, opt_str, value, parser):
    if value < 32768 or value > 61000:
        raise OptionValueError("need 32768 <= port <= 61000")
    parser.values.port = value

'''************** My Functions ****************'''

def resolve_query(header_id, initial_domain_name, domain_name, current_ip, initial_ip, is_cname):

    print("iteration")
    '''
    This is the main "powerhouse" function that serves a client request. Upon receiveing a domain name, it first checks
    if it is contained in tha cache. If the cache contains information about the requested domain name, the function
    returns it. The function will recursively search for the domain name asked for as specified in the lecture notes.
    Cache also helps reducing queries by providing sub-domains for a domain name.

    :param header_id: ID of the initial client query
    :param initial_domain_name: the domain name the client was requesting
    :param domain_name: the domain name this function is currently trying to resolve
    :param current_ip: the current IP address we want to send a follow-up query to
    :param initial_ip: the first IP address that our LNS sends a query to (always the Root Server in our case)
    :param is_cname:
    :return: a dictionary of lists containing RRs categorized by the section they belong to in the packet
    '''

    global acache
    global cnamecache
    global nscache
    global global_cname

    rr_return = {'answers': [], 'authorities': [], 'additional': [], 'additional_A': []}

    # Only for the very first iteration (where domain_name == initial_domain_name) check if the requested domain name
    # is inside the cache
    if acache.contains(domain_name) and domain_name == initial_domain_name and not global_cname:
        print("containsx")
        # Get the IP and ttl from the cache and construct an RR_A object for answer section
        ip = acache.getIpAddresses(domain_name)
        ttl = acache.getExpiration(domain_name, ip[0])
        rr_answer = RR_A(domain_name, ttl, ip[0]) #ip[0].toNetwork() if ip[0] is not in byte form

        # Append the RR_A into the dictionary's answer section
        rr_return['answers'].append(rr_answer)

        # Constructing the authority section by looping through all possible sub-domains of domain_name and get the
        # highest-qualified one that exists in the nscache
        lowest_domain = get_subdomain_order(domain_name)
        for i in range(len(lowest_domain)):
            this_domain = DomainName(lowest_domain[i])
            if nscache.contains(this_domain):

                # Get the list of name servers associated with this domain name
                something = nscache.get(this_domain)
                for j in range(len(something)):

                    # For each name server associated with this domain name, retrieve the ttl and construct an
                    # RR_NS object and add it to the authority section of the dictionary
                    ttl = something[j][1]
                    nsdn = nscache.get_nsdn(this_domain)
                    rr_authorities = RR_NS(this_domain, ttl, nsdn[j])
                    rr_return['authorities'].append(rr_authorities)

                    # Check the IP address of all the name servers in the authority section, create an RR_A object and
                    # add it to the additional section of the dictionary
                    if acache.contains(nsdn[j]):
                        this_ip = acache.getIpAddresses(nsdn[j])
                        this_ttl = acache.getExpiration(nsdn[j], this_ip[0])
                        rr_additional = RR_A(nsdn[j], this_ttl, this_ip[0])
                        rr_return['additional'].append((rr_additional))

                # If we found an existing sub-domain, look no further
                break
        return rr_return

    # During the first iteration check what is the highest-qualified sub-domain that exists in the cache. If we find such
    # sub-domain, jump straight to that sub-domain's IP address instead of doing more queries and causing traffic
    if current_ip == initial_ip and not is_cname and not global_cname:
        lowest_domain = get_subdomain_order(domain_name)
        for i in range(len(lowest_domain)):
            this_domain = DomainName(lowest_domain[i])
            if nscache.contains(this_domain):

                # Once we find that sub-domain, retrieve its IP address from the cache and recursively call
                # serve_request() using the new IP address as target
                nsdn = nscache.get_nsdn(this_domain)
                next_ip = acache.getIpAddresses(nsdn[0])
                return resolve_query(header_id, initial_domain_name, domain_name, next_ip, initial_ip, is_cname)

    # Construct the packet
    send_packet_header = Header(header_id, 0, 0, 1)
    send_packet_question = QE(1, domain_name)
    send_packet = send_packet_header.pack() + send_packet_question.pack()

    # Send the packet to the target IP address and wait for an answer
    cs.sendto(send_packet, (current_ip, 53))
    reply, a = cs.recvfrom(512)

    # Parse the reply and construct the RRs
    header_record = parse_header(reply)
    rr = get_records(reply, header_record['ancount'], header_record['nscount'])

    # Cache all the RRs; this stage is only reached when these RRs are not duplicate, otherwise we would have reached
    # them before, without needing to cause traffic
    if header_record['ancount'] != 0: #len(rr['answers']) != 0:
        for i in rr['answers']:
            if i._type == 1:
                acache.put(domain_name, i._addr, i._ttl)
            elif i._type == 5:
                cnamecache.put(domain_name, i._cname, i._ttl)

    if header_record['nscount'] != 0:
        for i in rr['authorities']:
            if i._type == 2:
                nscache.put(i._dn, i._nsdn, i._ttl, True)

    if len(rr['additional']) != 0:
        for i in rr['additional']:
            if i._type == 1:
                acache.put(i._dn, i._addr, i._ttl)

    '''print("acache is:")
    print(acache.__str__())
    print("nscache is:")
    print(nscache.__str__())
    print("cnamecache is:")
    print(cnamecache.__str__())'''

    # Main recursive part
    try:
        # If there is no answer section and there is an additional section, make the same query targetting the first
        # RR_A in additional section
        if len(rr['additional']) != 0:
            next_ip = bin_to_str(rr['additional_A'].pop(0)._addr)
            return resolve_query(header_id, initial_domain_name, domain_name, next_ip, initial_ip, is_cname)

         # If we have an answer section
        elif header_record['ancount'] != 0:

            # IF we found the domain name the client originally requested, return thr records
            if initial_domain_name == domain_name:
                return rr

            # If we found a domain name from an authority section, we target this new domain's IP address with our query
            else:
                next_ip = bin_to_str(rr['answers'][0]._addr)
                return resolve_query(header_id, initial_domain_name, initial_domain_name, next_ip, initial_ip, is_cname)

        # If there is no answer and no RR_A additional section, we need to search for a domain name of the first RR_NS
        # from the authority section recursively
        else:
            next_domain_name = rr['authorities'][0]._nsdn
            return resolve_query(header_id, initial_domain_name, next_domain_name, ROOTNS_IN_ADDR, initial_ip, is_cname)

    # If the server we send a question to does not respond, go ask the next server in the additional section
    except timeout:
        next_ip = bin_to_str(rr['additional_A'].pop(0)._addr)
        return resolve_query(header_id, initial_domain_name, initial_domain_name, next_ip, initial_ip, is_cname)


def parse_header(data):

    '''
    # Function for parsing binary data to construct header
    Construct a header object of the packet from the input binary data, then obtain all header elements and put them into a dictionary
    :param data: binary data received from a server as an answer for a request
    :return: dictionary containing all the header parameters
    '''

    header = Header.fromData(data)
    n_qe = header._qdcount
    n_ans = header._ancount
    n_auth = header._nscount
    n_add = header._arcount
    header_id = header._id
    return {'qdcount': n_qe, 'ancount': n_ans, 'nscount': n_auth, 'arcount': n_add, 'id': header_id}


def get_records(reply, n_ans, n_auth):

    '''
    #Function for gettting RR
    We parse the data by getting the question section and then one-by-one getting an RR until we parsed all the data
    and put them into lists and finally, one dictionary

    :param reply: binary data received from a server as an answer for our request
    :param n_ans: number of answer section RR records in the packet ('reply' is the binary representation of the packet)
    :param n_auth: number of authentication section RR records in the packet
    :return: return a dictionary where keys are labels of the RR types and values are lists containing all these resource
     records categorized by these keys
    '''

    # Get question section and set initial offset for the remaining RR
    reply_question = QE.fromData(reply, 12)
    lengthData = len(reply)
    offset_tmp = 12 + reply_question.__len__()

    records_resources = []

    # Looping through the data and constructing RR objects and append them to the list
    while offset_tmp < lengthData:
        record = RR.fromData(reply, offset_tmp)
        records_resources.append(record[0])
        offset_tmp += record[1]

    rr_length = len(records_resources)

    # Split up the list into multiple lists for all types of sections according to the length of each section
    answers = records_resources[0:n_ans]
    authorities = records_resources[n_ans:n_auth + n_ans]
    additional = records_resources[n_auth + n_ans:rr_length]
    additional_A = []

    # Putting all A type additional records into a different list
    if len(additional) != 0:
        for record in additional:
            if record._type == 1:
                additional_A.append(record)

    #Return dictionary with lists of sections
    return {'answers': answers, 'authorities': authorities, 'additional': additional, 'additional_A': additional_A}

def bin_to_str(data):

    '''
    #Funtion used to convert binary IP into stringIP
    :param data: binary representation of an IP address
    :return: string representation of IP address
    '''

    hex = data.hex()
    ip = ''
    p = ''
    t = 0
    for i in (hex):
        p += i
        t += 1
        if t == 2:
            p = str(int(p, 16))
            ip += p + '.'
            t = 0
            p = ''
    ip = ip[:-1]
    return ip

def get_subdomain_order(domain_name):

    '''
    This function takes a domain name and returns a list of subdomains associated with this domain name in order of
    most highly-qualified to least highly-qualifies

    Example:
        :param  -   www.aaa.bbb.ccc. (of type <DomainName>)
        :return -   ['aaa.bbb.ccc','bbb.ccc','ccc.']

    :param domain_name: domain name object
    :return: list of ordered subdomains the domain_name is in
    '''

    dn = domain_name.__str__()
    split = dn.split(".")
    list = []
    for i in range(1, len(split)):
        string = ""
        for j in range(i, len(split)):
            string += split[j] + "."
        list.append(string)
    for i in range(0, len(list)):
        list[i] = list[i][:-1]
    list.pop(len(list)-1)
    return list


def get_RR_end(record):

    '''
    Example:
        :param  -   yf1.yahoo.com.		86400	IN	A	68.142.254.15
        :return -   '68.142.254.15'
    :param record: any resource record
    :return: the last element of the resource record as a string
    '''

    split_str = str(record).split("\t")
    return split_str[-1]

global_cname = False

parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", action="callback",
                  callback=check_port, metavar="PORTNO", default=0,
                  help="UDP port to listen on (default: use an unused ephemeral port)")
(options, args) = parser.parse_args()

# Create a server socket to accept incoming connections from DNS
# client resolvers (stub resolvers):
ss = socket(AF_INET, SOCK_DGRAM)
ss.bind(("127.0.0.1", options.port))
serveripaddr, serverport = ss.getsockname()

# NOTE: In order to pass the test suite, the following must be the
# first line that your dns server prints and flushes within one
# second, to sys.stdout:
print("%s: listening on port %d" % (sys.argv[0], serverport))
sys.stdout.flush()

# Create a client socket on which to send requests to other DNS
# servers:
setdefaulttimeout(TIMEOUT)
cs = socket(AF_INET, SOCK_DGRAM)

# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:

while 1:
    (data, client_address,) = ss.recvfrom(512)  # DNS limits UDP msgs to 512 bytes
    if not data:
        logger.error("client provided no data")
        continue

    # Parse the header and answer section of the client query retrieving the domain name
    lengthData = len(data)
    query_header = Header.fromData(data)
    header_id = query_header._id
    question = QE.fromData(data, 12)
    initial_qe_dn = question._dn

    global_cname = False
    # Use a function to ask for the requested domain name
    packet = resolve_query(header_id, initial_qe_dn, initial_qe_dn, ROOTNS_IN_ADDR, ROOTNS_IN_ADDR, True)

    new_packet = packet

    # If the answer section contains CNAME then take that domain name and dig until there is no CNAME in the answer
    while packet['answers'][0]._type == 5:

        # Look for the new domain name and call the resolve_query function on it
        global_cname = True
        dn = packet['answers'][0]._cname
        packet = resolve_query(header_id, dn, dn, ROOTNS_IN_ADDR, ROOTNS_IN_ADDR, True)

        # Append the packet contents to the final response packet
        for i in packet['answers']:
            new_packet['answers'].append(i)
        for i in packet['authorities']:
            new_packet['authorities'].append(i)
        for i in packet['additional']:
            new_packet['additional'].append(i)

    # Pre defining length parameters
    ancount = len(new_packet['answers'])
    nscount = len(new_packet['authorities'])
    arcount = len(new_packet['additional'])

    # If there are no glue records and authority section is not empty, take the domain name from it and dig it
    if arcount == 0 and nscount != 0:
        for i in new_packet['authorities']:
            dn = DomainName(get_RR_end(i))

            append_packet = resolve_query(header_id, dn, dn, ROOTNS_IN_ADDR, ROOTNS_IN_ADDR, False)

            # Append the answer sections to the final response packet
            for j in append_packet['answers']:
                new_packet['additional'].append(j)

    # Construct the answer, authority and additional sections from 'packet' dictionary
    response_packet_RR_answer = bytes()
    response_packet_RR_authorities = bytes()
    response_packet_RR_additional = bytes()
    for i in new_packet['answers']:
        response_packet_RR_answer += i.pack()
    for i in new_packet['authorities']:
        response_packet_RR_authorities += i.pack()
    for i in new_packet['additional']:
        response_packet_RR_additional += i.pack()

    # From the received dictionary, construct the header and the question section
    response_packet_header = Header(header_id, 0, 0, 1, len(new_packet['answers']), len(new_packet['authorities']),
                                    len(new_packet['additional']), 1, 1, 0, 1, 1)
    response_packet_question = QE(1, initial_qe_dn)

    # Construct the final packet and send it back to the client
    response_packet_RR = bytes()
    response_packet_RR = response_packet_RR_answer + response_packet_RR_authorities + response_packet_RR_additional
    response_packet = response_packet_header.pack() + response_packet_question.pack() + response_packet_RR
    ss.sendto(response_packet, client_address)


    