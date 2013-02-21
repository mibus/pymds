#!/usr/bin/python
# Copyright (c) 2013 Robert Mibus & Internode
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

import unittest

import struct
import ipaddr
import string

import pymdsautogen6fwd
import pymdsautogen6rev

testdomain = 'v6.example.net'
testdomain_packed = string.join([struct.pack('!B',len(x)) + x for x in testdomain.split('.')],'') + "\0"
fwd = pymdsautogen6fwd.Source(testdomain, '20010db8')
rev = pymdsautogen6rev.Source(testdomain, '20010db8')

class ForwardsTests(unittest.TestCase):
    def test_working_aaaa(self):
    	ret, resp = fwd.get_response('2001-db8--',testdomain,28,0,0)
	addr_resp = ipaddr.IPv6Address(resp[0]['rdata'])
    	self.assertEquals(addr_resp.compressed, '2001:db8::')
    def test_working_not_aaaa(self):
    	ret, resp = fwd.get_response('2001-db8--',testdomain,1,0,0)
    	self.assertEquals(ret, 0)
    	self.assertEquals(resp, [])
    def test_outside_aaaa(self):
    	ret, resp = fwd.get_response('2001-44b8--',testdomain,1,0,0)
    	self.assertEquals(ret, 3)
    	self.assertEquals(resp, [])
    def test_outside_not_aaaa(self):
    	ret, resp = fwd.get_response('2001-44b8--',testdomain,1,0,0)
    	self.assertEquals(ret, 3)
    	self.assertEquals(resp, [])
    def test_broken_aaaa(self):
    	ret, resp = fwd.get_response('2001-zzz--',testdomain,28,0,0)
    	self.assertEquals(ret, 3)
    	self.assertEquals(resp, [])
    def test_broken_not_aaaa(self):
    	ret, resp = fwd.get_response('2001-zzz--',testdomain,1,0,0)
    	self.assertEquals(ret, 3)
    	self.assertEquals(resp, [])

class ReverseTests(unittest.TestCase):
    def addr_to_list(self, addr):
        # This drops the shared prefix, drops the '-'s, and reverses the string into a list
	return [x for x in addr[:9:-1] if x != '-']
    def test_working_ptr(self):
        addr = '2001-0db8-4321-4321-4321-4321-4321-4321'
        ret, resp = rev.get_response(self.addr_to_list(addr),'',12,0,0)
	self.assertEquals(ret, 0)
	data = struct.pack('!B', len(addr)) + addr + testdomain_packed
	self.assertEquals(resp[0]['rdata'], data)
    def test_broken_ptr(self):
        addr = '2001-0db8-4321-4321-4321-4321-4321-432z'
        ret, resp = rev.get_response(self.addr_to_list(addr),'',12,0,0)
	data = struct.pack('!B', len(addr)) + addr + testdomain_packed
	self.assertEquals(ret, 3)

if __name__ == "__main__":
    unittest.main()   
