#!/usr/bin/python

import unittest

import pymdsautogen6fwd
import pymdsautogen6rev
import ipaddr

testdomain = 'v6.example.net'
fwd = pymdsautogen6fwd.Source(testdomain, '2001:db8::/32')
rev = pymdsautogen6rev.Source(testdomain, '2001:db8::/32')

class ForwardsTests(unittest.TestCase):
    def test_working_aaaa(self):
    	ret, resp = fwd.get_response('2001-db8--',testdomain,28,0,0)
	addr_resp = ipaddr.IPv6Address(resp[0]['rdata'])
    	self.assertEquals(addr_resp.compressed, '2001:db8::')
    def test_working_not_aaaa(self):
    	ret, resp = fwd.get_response('2001-db8--',testdomain,1,0,0)
    	self.assertEquals(ret, 0)
    	self.assertEquals(resp, [])
    def test_broken_aaaa(self):
    	ret, resp = fwd.get_response('2001-zzz--',testdomain,28,0,0)
    	self.assertEquals(ret, 3)
    	self.assertEquals(resp, [])
    def test_broken_not_aaaa(self):
    	ret, resp = fwd.get_response('2001-zzz--',testdomain,1,0,0)
    	self.assertEquals(ret, 3)
    	self.assertEquals(resp, [])

if __name__ == "__main__":
#    unittest.main()   
    suite = unittest.TestLoader().loadTestsFromTestCase(ForwardsTests)
    unittest.TextTestRunner(verbosity=2).run(suite)
