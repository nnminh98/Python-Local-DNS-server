""" Representations of various DNS resource record (RR) types. """

from copy import copy
from libs.inetlib.types import DomainName
from libs.util import *
from socket import inet_ntoa, inet_ntop, inet_aton, AF_INET6
import struct

class RR:
  """ 
  Representation common to all DNS resource records.

  Member variables:

  _dn -- a DomainName *object* (see class libs.inetlib.DomainName)
  about which this RR stores information.

  _ttl -- an integer time-to-live, 16-bits long.

  _type -- The DNS type of this resource record; one of { RR.TYPE_A
  (DNS A record), RR.TYPE_NS (DNS NS record), RR.TYPE_CNAME (DNS CNAME
  record), RR.TYPE_SOA (DNS start-of-authority record), RR.TYPE_PTR
  (DNS PTR record), RR.TYPE_MX (DNS mail exchange record),
  RR.TYPE_AAAA (DNS IPv6 address record).

  _class - the DNS class type of this resource record.  Always
  RR.CLASS_IN for Internet in this implementation (other classes do
  exist in general).

  """
  TYPE_A = 1
  TYPE_NS = 2
  TYPE_CNAME = 5
  TYPE_SOA = 6
  TYPE_PTR = 12
  TYPE_MX = 15
  TYPE_AAAA = 28 # RFC 3596 IPv6 address

  TYPE_UNKNOWN = -1

  CLASS_IN = 1

  def __init__(self, dn, ttl, rdlength):
    """ Initialize a RR from a user-supplied DomainName, ttl, and
    rdlength.  Note that this RR class only handles RRs of class IN
    (Internet).

    dn -- a DomainName *object* (see class libs.inetlib.DomainName)
    that this RR represents.

    ttl -- a 16-bit integer time-to-live, measured in units of
      seconds.
    
    rdlength -- an integer length of the data field in the RR.  This
                is used to compute this RR's length, which is
                subsequently used by subclasses derived from RR.
    """
    self._class = RR.CLASS_IN
    self._ttl = ttl
    self._dn = dn
    self._rdlength = rdlength
    self._type = RR.TYPE_UNKNOWN

  def pack(self):
    """ Pack this RR into a packed-binary string rep and return that
    string. """
    ttl = int(self._ttl)
    l = [ self._dn.pack().decode('unicode-escape'), 
          struct.pack(">2HlH", self._type, self._class, ttl, self._rdlength).decode('unicode-escape')]
    return ("".join(l)).encode('ISO-8859-1')

  def __str__(self):
    """ Return a string rep. """
    if self._type == RR.TYPE_A:
      return "%-30s\t%d\tIN\tA" % (str(self._dn), self._ttl,)
    elif self._type == RR.TYPE_NS:
      return "%-30s\t%d\tIN\tNS" % (str(self._dn), self._ttl,)
    elif self._type == RR.TYPE_CNAME:
      return "%-30s\t%d\tIN\tCNAME" % (str(self._dn), self._ttl,)
    elif self._type == RR.TYPE_SOA:
      return "%-30s\t%d\tIN\tSOA" % (str(self._dn), self._ttl,)
    elif self._type == RR.TYPE_AAAA:
      return "%-30s\t%d\tIN\tAAAA" % (str(self._dn), self._ttl,)
    elif self._type == RR.TYPE_UNKNOWN:
      return "%-30s\t%d\tIN\t???" % (str(self._dn), self._ttl,)

  def __len__(self):
    """ Return the length of this RR. """
    return len(self._dn) + 10 + self._rdlength

  @staticmethod
  def fromData(data, offset = 0):
    """ 
    Given user-supplied packed binary data and an optional offset
    into that data, returns a two-tuple containing a 
    new RR-derived object and the (compact) length of that object. 
    """
    dn = DomainName.fromData(data, offset)
    (type, cls, ttl, rdlength) = struct.unpack_from(">2HlH", data, 
                                                    offset + len(dn))
    logger.log(DEBUG2, "RR.fromData: offset=%s; dn=%s; len(dn)=%d,\
               type=%d, cls=%d, ttl=%d, rdlength=%d" % \
               (hex(offset), dn, len(dn), type, cls, ttl, rdlength,))
    if type == RR.TYPE_A:
      (inaddr,) = struct.unpack_from(">4s", data, offset + len(dn) + 10)
      return (RR_A(copy(dn), ttl, inaddr), len(dn) + 10 + rdlength)
    elif type == RR.TYPE_NS:
      nsdn = DomainName.fromData(data, offset + len(dn) + 10)
      return (RR_NS(copy(dn), ttl, copy(nsdn)), len(dn) + 10 + rdlength)
    elif type == RR.TYPE_CNAME:
      cname = DomainName.fromData(data, offset + len(dn) + 10)
      return (RR_CNAME(copy(dn), ttl, copy(cname)), len(dn) + 10 + rdlength)
    elif type == RR.TYPE_SOA:
      mname = DomainName.fromData(data, offset + len(dn) + 10)
      rname = DomainName.fromData(data, offset + len(dn) + 10 + len(mname))
      (serial, refresh, retry, expire, minimum,) = \
        struct.unpack_from(">5L", data, 
                           offset + len(dn) + 10 + len(mname) + len(rname))
      soa = RR_SOA(copy(dn), ttl, copy(mname), copy(rname), serial, refresh, retry,
                   expire, minimum)
      return (soa, len(RR_SOA(dn, ttl, mname, rname, serial, refresh,
                              retry, expire, minimum)))
    elif type == RR.TYPE_AAAA:
      (inaddr,) = struct.unpack_from(">16s", data, offset + len(dn) + 10)
      return (RR_AAAA(copy(dn), ttl, inaddr), len(dn) + 10 + rdlength)
    else:
      return (RR(copy(dn), ttl, rdlength), len(dn) + 10 + rdlength)

class RR_A(RR):
  """ 
  Representation of a DNS RR of type A (address). 
  
  Member variables:

  _addr -- the Internet address (a packed four-byte quantity
           constructed using socket.inet_aton) that this A record
           points to.
  """
  
  def __init__(self, dn, ttl, addr):
    """ Initialize a RR_A based on a user-supplied parameters.
    
    dn -- a DomainName object
    ttl -- a 16-bit integer time to live, measured in units of
      seconds.
    addr -- an internet address (a packed four-byte quantity
            constructed using socket.inet_aton). 
    """
    
    RR.__init__(self, dn, ttl, 4)
    self._type = RR.TYPE_A
    self._addr = addr
    self._inaddr = addr

  def pack(self):
    """ Return a packed-binary rep. """
    l = [RR.pack(self).decode('unicode-escape'), 
         self._inaddr.decode('unicode-escape')]
    return ("".join(l)).encode('ISO-8859-1')


  def __str__(self):
    """ Return a pretty-printable string rep. """
    return "%s\t%s" % (RR.__str__(self), inet_ntoa(self._inaddr),)

  def __repr__(self):
    """ Return a diagnostic string rep. """
    return "(%s, %d, IN, A, %s)" % (str(self._dn), self._ttl, 
                                    inet_ntoa(self._inaddr),)

class RR_NS(RR):
  """ 
  Representation of a DNS RR of type NS (name server).
  
  Member variables:

  _nsdn -- the DomainName of the DNS name server that this RR_NS
  record points to.

  """

  def __init__(self, dn, ttl, nsdn):
    """ Initialize a RR_NS based on a user-supplied parameters.
    
    dn -- a DomainName object referring to the domain name for which 
      this NS record is about.
    ttl -- time to live
    nsdn -- the DomainName of the name server that serves dn
    """
    RR.__init__(self, dn, ttl, len(str(nsdn))+1)
    self._type = RR.TYPE_NS
    self._nsdn = nsdn

  def pack(self):
    """ Return a packed-binary rep. """
    packed_nsdn = self._nsdn.pack()
    l = [RR.pack(self).decode('unicode-escape'), 
         packed_nsdn.decode('unicode-escape')]
    return ("".join(l)).encode('ISO-8859-1')


  def __str__(self):
    """ Return a pretty-printable string rep. """
    return "%s\t%s" % (RR.__str__(self), str(self._nsdn),)

  def __repr__(self):
    """ Return a diagnostic rep. """
    return "(%s, %d, IN, NS, %s)" % (str(self._dn), self._ttl, 
                                     str(self._nsdn),)

class RR_CNAME(RR):
  """
  Representation of a DNS RR of type CNAME.
  
  Member variables:
  _cname -- the DomainName that this CNAME record points to.
  
  """

  def __init__(self, dn, ttl, cname):
    """ Initialize a RR_CNAME based on a user-supplied parameters.
    
    dn -- a DomainName object
    ttl -- a 16-bit integer time to live, measured in units of
      seconds.
    cname -- the DomainName target of the CNAME entry.
    """
    RR.__init__(self, dn, ttl, len(str(cname))+1)
    self._type = RR.TYPE_CNAME
    self._cname = cname

  def pack(self):
    """ Return a packed-binary rep. """
    packed_cname = self._cname.pack()
    l = [RR.pack(self).decode('unicode-escape'), 
         packed_cname.decode('unicode-escape')]
    return ("".join(l)).encode('ISO-8859-1')

  def __str__(self):
    """ Return a pretty-printable string rep. """
    return "%s\t%s" % (RR.__str__(self), str(self._cname),)

  def __repr__(self):
    """ Return an informative string rep. """
    return "(%s, %d, IN, CNAME, %s)" % (str(self._dn), self._ttl, 
                                        str(self._cname),)

class RR_SOA(RR):
  """ A start-of-authority (SOA) RR. """
  def __init__(self, dn, ttl, mname, rname, serial, refresh, retry,
               expire, minimum):
    RR.__init__(self, dn, ttl, len(mname) + len(rname) + 5*4)
    self._type = RR.TYPE_SOA
    self._mname = mname
    self._rname = rname
    self._serial = serial
    self._refresh = refresh
    self._retry = retry
    self._expire = expire
    self._minimum = minimum

  def pack(self):
    packed_mname = self._mname.pack().decode('unicode-escape')
    packed_rname = self._rname.pack().decode('unicode-escape')
    s = ("".join([ RR.pack(self).decode('unicode-escape'), packed_mname, packed_rname,
                  struct.pack(">5L", self._serial, self._refresh,
                              self._retry, self._expire,
                              self._minimum).decode('unicode-escape') ])).encode('ISO-8859-1')
    return s

  def __copy__(self):
    res = RR_SOA(copy(self._dn), self._ttl, copy(self._mname),
                 copy(self._rname), self._serial, self._refresh,
                 self._retry, self._expire, self._minimum)
    return res

  def __str__(self):
    return "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d" % (RR.__str__(self),
           self._mname, self._rname, self._serial, self._refresh,
           self._retry, self._expire, self._minimum)
  
  def __repr__(self):
    return "(%s, %d, %s, %s, %d, %d, %d, %d, %d)" % \
      (self._dn, self._ttl, self._mname, self._rname, self._serial,
      self._refresh, self._retry, self._expire, self._minimum)

class RR_AAAA(RR):
  """ An IPv6 RR. """

  def __init__(self, dn, ttl, addr):
    RR.__init__(self, dn, ttl, 16)
    self._type = RR.TYPE_AAAA
    self._inaddr = addr

  def __str__(self):
    return "%s\t%s" % (RR.__str__(self), inet_ntop(AF_INET6, self._inaddr),)

  def pack(self):
    """ Return a packed-binary rep. """
    s = [RR.pack(self).decode('unicode-escape'), 
         self._inaddr.decode('unicode-escape')]
    return ("".join(s)).encode('ISO-8859-1')

  def __repr__(self):
    """ Return a diagnostic string rep. """
    return "(%s, %d, IN, AAAA, %s)" % (str(self._dn), self._ttl, 
                                    inet_ntop(AF_INET6, self._inaddr),)


