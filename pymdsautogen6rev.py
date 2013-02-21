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
import string
import re

class Source(object):
    def __init__(self, basedomain, v6prefix):
        self._answers = {}
	self.basedomain = basedomain.split('.')
	self.v6prefix = v6prefix

    def get_response(self, query, domain, qtype, qclass, src_addr):
	if qtype == 12: # 'PTR':
		# Build a copy of the whole address
		# "v6prefix" is the zone we handle, "query" is the end part
		# (remember that PTR requests have the data backwards to what we want;
		#  the "[::-1]" is to reverse it)
		raw_data = string.join(list(self.v6prefix) + list(query)[::-1],'')

		# NXDOMAIN if it has invalid characters
		if re.search('[^a-fA-F0-9]', raw_data):
			return 3, []

		# NOERROR if it looks valid, but it's the wrong length to be a full address
		if (len(query) + len(self.v6prefix)) != 32:
			return 0, []

		# Turn 20010db812341234... into 2001-0db8-1234-1234-...
		data = re.sub('(....)', r'\1-', raw_data, 7)
		return 0, [{
			'qtype': qtype,
			'qclass': qclass,
			'ttl': 86400,
			'rdata': labels2str([data] + self.basedomain),
			}]

	else: # NS, A, MX, etc. -- but don't return NXDOMAIN if there's a PTR
		# Check if we have a valid PTR record; if so then we NOERROR, else... error :)
		rcode_ptr, resp = self.get_response(query, domain, 12, qclass, src_addr)
		if rcode_ptr == 0:
			return 0, []
		else:
			return 3, []
