# Copyright (c) 2011 Robert Mibus & Internode
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
#     The above copyright notice and this permission notice shall be
#     included in all copies or substantial portions of the Software.
#
#     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
#     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT


#
# A pymds source filter.
#
# pymdsautogen makes stuff up on the fly
#
# initializer: a "base domain" under which AAAA records go, and an IPv6 prefix
# (for which PTR records work).
#

import struct

from utils import *

import ipaddr

class Source(object):
    def __init__(self, basedomain, v6prefix):
        self._answers = {}
	self.basedomain = basedomain.split('.')
	# Note: The v6prefix as a string is awkward, because the config file doesn't allow literal ":"
	# Thus, we end up doing string mangling where we might otherwise do address parsing.
	self.v6prefix = v6prefix

    def get_response(self, query, domain, qtype, qclass, src_addr):
	if qtype == 28 or qtype == 255: # 'AAAA' or 'ANY':
		try:
			# Turn the address string into an address object
			addr = ipaddr.IPv6Address(query.replace('-',':'))
			# Make sure it's one of ours; else just bail with NXDOMAIN
			if not addr.exploded.replace(':','').startswith(self.v6prefix):
				return 3, []
			# All OK, return the data!
			return 0, [{
				'qtype': 28, # Hard-coded to 'AAAA', in case we're from an ANY query
				'qclass': qclass,
				'ttl': 86400,
				'rdata': addr.packed
				}]
		except:
			# Invalid AAAA
			return 3, []
	else: # NS, A, MX, etc. -- but don't return NXDOMAIN if there's an AAAA
		# Check if we have a valid AAAA record; if so then we NOERROR, else... error :)
		rcode_aaaa, resp = self.get_response(query, domain, 28, qclass, src_addr)
		if rcode_aaaa == 0:
			return 0, []
		else:
			return 3, []
