"""
Test the "external" interface.

The "external" interface is what the user sees. It should be pythonic and easy
to use.
"""

from datetime import timedelta
from unittest.mock import patch, call
import unittest

from puresnmp.client import Client, BulkResult
from puresnmp.const import Version
from puresnmp.exc import SnmpError, NoSuchOID, Timeout
from puresnmp.pdu import GetRequest, VarBind, GetNextRequest, BulkGetRequest
from puresnmp.transport import Transport
from puresnmp.x690.types import (
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
)

from . import readbytes


class TestTransport(unittest.TestCase):
    @patch('socket.socket.settimeout')
    @patch('socket.socket.sendto')
    @patch('socket.socket.recv')
    def test_sock_call_args(self, mck_recv, mck_sendtto, mck_settimeout):
        """
        Test the call arguments of "socket.socket.*" used by Transport
        """
        data = readbytes('dummy.hex')  # any dump would do
        expect_timeout_sec = 3
        expect_port = 1234
        expect_ip = '127.0.0.1'
        expect_buffer = 4000
        expect_retry = 2
        t = Transport(timeout=expect_timeout_sec, sock_buffer=expect_buffer, retry=expect_retry)

        import socket
        mck_recv.side_effect = socket.timeout  # Raise a timeout
        mck_recv.return_value = None  # Not used

        with self.assertRaises(Timeout):
            t.send(expect_ip, expect_port, data)

        mck_recv.assert_has_calls([call(expect_buffer)] * expect_retry)
        mck_settimeout.assert_called_with(expect_timeout_sec)
        mck_sendtto.assert_called_with(data, (expect_ip, expect_port))


class TestGet(unittest.TestCase):
    @patch('puresnmp.transport.Transport.send')
    @patch('puresnmp.client.Client._get_request_id')
    def test_get_call_args(self, mck_rid, mck_send):
        """
        Test the call arguments of "get"
        """
        data = readbytes('dummy.hex')  # any dump would do
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            GetRequest(0, ObjectIdentifier(1, 2, 3))
        )
        client = Client(transport=Transport(), community='public')
        mck_rid.return_value = 0
        mck_send.return_value = data
        client.get('::1', '1.2.3')
        mck_send.assert_called_with('::1', 161, bytes(packet))

    @patch('puresnmp.transport.Transport.send')
    def test_get_string(self, mck_send):
        data = readbytes('get_sysdescr_01.hex')
        client = Client(transport=Transport(), community='private')
        expected = (b'Linux d24cf7f36138 4.4.0-28-generic #47-Ubuntu SMP '
                    b'Fri Jun 24 10:09:13 UTC 2016 x86_64')
        mck_send.return_value = data
        result = client.get('::1', '1.2.3')
        self.assertEqual(result, expected)

    @patch('puresnmp.transport.Transport.send')
    def test_get_oid(self, mck_send):
        data = readbytes('get_sysoid_01.hex')
        expected = ('1.3.6.1.4.1.8072.3.2.10')
        client = Client(transport=Transport(), community='private')
        mck_send.return_value = data
        result = client.get('::1', '1.2.3')
        self.assertEqual(result, expected)

    @patch('puresnmp.transport.Transport.send')
    def test_get_multiple_return_binds(self, mck_send):
        """
        A "GET" response should only return one varbind.
        """
        data = readbytes('get_sysoid_01_error.hex')
        client = Client(transport=Transport(), community='private')
        mck_send.return_value = data
        with self.assertRaisesRegexp(SnmpError, 'varbind'):
            client.get('::1', '1.2.3')

    @patch('puresnmp.transport.Transport.send')
    def test_get_non_existing_oid(self, mck_send):
        """
        A "GET" response on a non-existing OID should raise an appropriate
        exception.
        """
        data = readbytes('get_non_existing.hex')
        client = Client(transport=Transport(), community='private')
        mck_send.return_value = data
        with self.assertRaises(NoSuchOID):
            client.get('::1', '1.2.3')


class TestWalk(unittest.TestCase):
    @patch('puresnmp.transport.Transport.send')
    def test_walk(self, mck_send):
        response_1 = readbytes('walk_response_1.hex')
        response_2 = readbytes('walk_response_2.hex')
        response_3 = readbytes('walk_response_3.hex')
        client = Client(transport=Transport(), community='public')

        expected = [VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.5.1'), 10000000
        ), VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.5.13'), 4294967295
        )]

        mck_send.side_effect = [response_1, response_2, response_3]
        result = list(client.walk('::1', '1.3.6.1.2.1.2.2.1.5'))
        self.assertEqual(result, expected)

    @patch('puresnmp.transport.Transport.send')
    def test_walk_multiple_return_binds(self, mck_send):
        """
        A "WALK" response should only return one varbind.
        """
        data = readbytes('get_sysoid_01_error.hex')
        client = Client(transport=Transport(), community='private')
        mck_send.return_value = data
        with self.assertRaisesRegexp(SnmpError, 'varbind'):
            next(client.walk('::1', '1.2.3'))


class TestSet(unittest.TestCase):
    def test_set_without_type(self):
        """
        As we need typing information, we have to hand in an instance of
        supported types (a subclass of puresnmp.x690.Type).
        """
        client = Client(transport=Transport(), community='private')
        with self.assertRaisesRegexp(TypeError, 'Type'):
            client.set('::1', '1.2.3', 12)

    @patch('puresnmp.transport.Transport.send')
    def test_set(self, mck_send):
        data = readbytes('set_response.hex')
        client = Client(transport=Transport(), community='private')
        mck_send.return_value = data
        client.set('::1', '1.3.6.1.2.1.1.4.0',
                   OctetString(b'hello@world.com'))

    @patch('puresnmp.transport.Transport.send')
    def test_set_multiple_varbind(self, mck_send):
        """
        SET responses should only contain one varbind.
        """
        data = readbytes('set_response_multiple.hex')
        client = Client(transport=Transport(), community='private')
        mck_send.return_value = data
        with self.assertRaisesRegexp(SnmpError, 'varbind'):
            client.set('::1', '1.3.6.1.2.1.1.4.0',
                       OctetString(b'hello@world.com'))


class TestMultiGet(unittest.TestCase):
    @patch('puresnmp.transport.Transport.send')
    def test_multiget(self, mck_send):
        data = readbytes('multiget_response.hex')
        expected = ['1.3.6.1.4.1.8072.3.2.10',
                    b"Linux 7fbf2f0c363d 4.4.0-28-generic #47-Ubuntu SMP Fri "
                    b"Jun 24 10:09:13 UTC 2016 x86_64"]
        client = Client(transport=Transport(), community='private')
        mck_send.return_value = data
        result = client.multiget('::1', [
            '1.3.6.1.2.1.1.2.0',
            '1.3.6.1.2.1.1.1.0',
        ])
        self.assertEqual(result, expected)


class TestMultiWalk(unittest.TestCase):
    @patch('puresnmp.transport.Transport.send')
    def test_multi_walk(self, mck_send):
        response_1 = readbytes('multiwalk_response_1.hex')
        response_2 = readbytes('multiwalk_response_2.hex')
        response_3 = readbytes('multiwalk_response_3.hex')

        expected = [VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.1.1'), 1
        ), VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.2.1'), b'lo'
        ), VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.1.78'), 78
        ), VarBind(
            ObjectIdentifier.from_string('1.3.6.1.2.1.2.2.1.2.78'), b'eth0'
        )]

        client = Client(transport=Transport(), community='public')
        mck_send.side_effect = [response_1, response_2, response_3]
        result = list(client.multiwalk('::1', [
            '1.3.6.1.2.1.2.2.1.1',
            '1.3.6.1.2.1.2.2.1.2'
        ]))
        # TODO (advanced): should order matter in the following result?
        self.assertCountEqual(result, expected)


class TestMultiSet(unittest.TestCase):
    @patch('puresnmp.transport.Transport.send')
    def test_multiset(self, mck_send):
        """
        Test setting multiple OIDs at once.

        NOTE: The OID '1.3.6.1.2.1.1.5.0' below is manually edited for
              unit-testing. It probably has a different type in the real world!
        """
        data = readbytes('multiset_response.hex')
        client = Client(transport=Transport(), community='private')
        mck_send.return_value = data
        result = client.multiset('::1', [
            ('1.3.6.1.2.1.1.4.0', OctetString(b'hello@world.com')),
            ('1.3.6.1.2.1.1.5.0', OctetString(b'hello@world.com')),
        ])
        expected = {
            '1.3.6.1.2.1.1.4.0': b'hello@world.com',
            '1.3.6.1.2.1.1.5.0': b'hello@world.com',
        }
        self.assertEqual(result, expected)


class TestGetNext(unittest.TestCase):
    @patch('puresnmp.transport.Transport.send')
    @patch('puresnmp.client.Client._get_request_id')
    def test_get_call_args(self, mck_rid, mck_send):
        data = readbytes('dummy.hex')
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            GetNextRequest(0, ObjectIdentifier(1, 2, 3))
        )
        client = Client(transport=Transport(), community='public')
        mck_rid.return_value = 0
        mck_send.return_value = data
        client.getnext('::1', '1.2.3')
        mck_send.assert_called_with('::1', 161, bytes(packet))

    @patch('puresnmp.transport.Transport.send')
    def test_getnext(self, mck_send):
        data = readbytes('getnext_response.hex')
        expected = VarBind('1.3.6.1.6.3.1.1.6.1.0', 354522558)

        client = Client(transport=Transport(), community='private')
        mck_send.return_value = data
        result = client.getnext('::1', '1.3.6.1.5')
        self.assertEqual(result, expected)


class TestGetBulkGet(unittest.TestCase):
    @patch('puresnmp.transport.Transport.send')
    @patch('puresnmp.client.Client._get_request_id')
    def test_get_call_args(self, mck_rid, mck_send):
        data = readbytes('dummy.hex')  # any dump would do
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            BulkGetRequest(0, 1, 2,
                           ObjectIdentifier(1, 2, 3),
                           ObjectIdentifier(1, 2, 4))
        )
        client = Client(transport=Transport(), community='public')
        mck_rid.return_value = 0
        mck_send.return_value = data
        client.bulkget('::1',
                       ['1.2.3'],
                       ['1.2.4'],
                       max_list_size=2)
        mck_send.assert_called_with('::1', 161, bytes(packet))

    @patch('puresnmp.transport.Transport.send')
    def test_bulkget(self, mck_send):
        data = readbytes('bulk_get_response.hex')
        expected = BulkResult(
            {'1.3.6.1.2.1.1.1.0': b'Linux 7e68e60fe303 4.4.0-28-generic '
                                  b'#47-Ubuntu SMP Fri Jun 24 10:09:13 UTC 2016 x86_64'},
            {'1.3.6.1.2.1.3.1.1.1.10.1.172.17.0.1': 10,
             '1.3.6.1.2.1.3.1.1.2.10.1.172.17.0.1': b'\x02B\xe2\xc5\x8d\t',
             '1.3.6.1.2.1.3.1.1.3.10.1.172.17.0.1': b'\xac\x11\x00\x01',
             '1.3.6.1.2.1.4.1.0': 1,
             '1.3.6.1.2.1.4.3.0': 57})
        client = Client(transport=Transport(), community='public')
        mck_send.return_value = data
        result = client.bulkget('::1',
                                ['1.3.6.1.2.1.1.1'],
                                ['1.3.6.1.2.1.3.1'],
                                max_list_size=5)
        self.assertEqual(result, expected)


class TestGetBulkWalk(unittest.TestCase):
    @patch('puresnmp.transport.Transport.send')
    @patch('puresnmp.client.Client._get_request_id')
    def test_get_call_args(self, mck_rid, mck_send):
        data = readbytes('dummy.hex')  # any dump would do
        packet = Sequence(
            Integer(Version.V2C),
            OctetString('public'),
            BulkGetRequest(0, 0, 2, ObjectIdentifier(1, 2, 3))
        )
        client = Client(transport=Transport(), community='public')
        mck_send.return_value = data
        mck_rid.return_value = 0

        # we need to wrap this in a list to consume the generator.
        list(client.bulkwalk('::1',
                             ['1.2.3'],
                             bulk_size=2))
        mck_send.assert_called_with('::1', 161, bytes(packet))

    @patch('puresnmp.transport.Transport.send')
    @patch('puresnmp.client.Client._get_request_id')
    def test_bulkwalk(self, mck_rid, mck_send):
        req1 = readbytes('bulkwalk_request_1.hex')
        req2 = readbytes('bulkwalk_request_2.hex')
        req3 = readbytes('bulkwalk_request_3.hex')

        client = Client(transport=Transport(), community='private')
        responses = [
            readbytes('bulkwalk_response_1.hex'),
            readbytes('bulkwalk_response_2.hex'),
            readbytes('bulkwalk_response_3.hex'),
        ]
        mck_send.side_effect = responses

        request_ids = [1001613222, 1001613223, 1001613224]
        mck_rid.side_effect = request_ids

        result = list(client.bulkwalk('127.0.0.1',
                                      ['1.3.6.1.2.1.2.2'],
                                      bulk_size=20))

        self.assertEqual(mck_send.mock_calls, [
            call('127.0.0.1', 161, req1),
            call('127.0.0.1', 161, req2),
            call('127.0.0.1', 161, req3),
        ])

        # TODO (advanced): Type information is lost for timeticks and OIDs
        expected = [
            VarBind('1.3.6.1.2.1.2.2.1.1.1', 1),
            VarBind('1.3.6.1.2.1.2.2.1.1.10', 10),
            VarBind('1.3.6.1.2.1.2.2.1.2.1', b"lo"),
            VarBind('1.3.6.1.2.1.2.2.1.2.10', b"eth0"),
            VarBind('1.3.6.1.2.1.2.2.1.3.1', 24),
            VarBind('1.3.6.1.2.1.2.2.1.3.10', 6),
            VarBind('1.3.6.1.2.1.2.2.1.4.1', 65536),
            VarBind('1.3.6.1.2.1.2.2.1.4.10', 1500),
            VarBind('1.3.6.1.2.1.2.2.1.5.1', 10000000),
            VarBind('1.3.6.1.2.1.2.2.1.5.10', 4294967295),
            VarBind('1.3.6.1.2.1.2.2.1.6.1', b""),
            VarBind('1.3.6.1.2.1.2.2.1.6.10', b"\x02\x42\xAC\x11\x00\x02"),
            VarBind('1.3.6.1.2.1.2.2.1.7.1', 1),
            VarBind('1.3.6.1.2.1.2.2.1.7.10', 1),
            VarBind('1.3.6.1.2.1.2.2.1.8.1', 1),
            VarBind('1.3.6.1.2.1.2.2.1.8.10', 1),
            VarBind('1.3.6.1.2.1.2.2.1.9.1', timedelta(0)),
            VarBind('1.3.6.1.2.1.2.2.1.9.10', timedelta(0)),
            VarBind('1.3.6.1.2.1.2.2.1.10.1', 172),
            VarBind('1.3.6.1.2.1.2.2.1.10.10', 60558),
            VarBind('1.3.6.1.2.1.2.2.1.11.1', 2),
            VarBind('1.3.6.1.2.1.2.2.1.11.10', 564),
            VarBind('1.3.6.1.2.1.2.2.1.12.1', 0),
            VarBind('1.3.6.1.2.1.2.2.1.12.10', 0),
            VarBind('1.3.6.1.2.1.2.2.1.13.1', 0),
            VarBind('1.3.6.1.2.1.2.2.1.13.10', 0),
            VarBind('1.3.6.1.2.1.2.2.1.14.1', 0),
            VarBind('1.3.6.1.2.1.2.2.1.14.10', 0),
            VarBind('1.3.6.1.2.1.2.2.1.15.1', 0),
            VarBind('1.3.6.1.2.1.2.2.1.15.10', 0),
            VarBind('1.3.6.1.2.1.2.2.1.16.1', 172),
            VarBind('1.3.6.1.2.1.2.2.1.16.10', 44295),
            VarBind('1.3.6.1.2.1.2.2.1.17.1', 2),
            VarBind('1.3.6.1.2.1.2.2.1.17.10', 442),
            VarBind('1.3.6.1.2.1.2.2.1.18.1', 0),
            VarBind('1.3.6.1.2.1.2.2.1.18.10', 0),
            VarBind('1.3.6.1.2.1.2.2.1.19.1', 0),
            VarBind('1.3.6.1.2.1.2.2.1.19.10', 0),
            VarBind('1.3.6.1.2.1.2.2.1.20.1', 0),
            VarBind('1.3.6.1.2.1.2.2.1.20.10', 0),
            VarBind('1.3.6.1.2.1.2.2.1.21.1', 0),
            VarBind('1.3.6.1.2.1.2.2.1.21.10', 0),
            VarBind('1.3.6.1.2.1.2.2.1.22.1', '0.0'),  # TODO: type info is lost
            VarBind('1.3.6.1.2.1.2.2.1.22.10', '0.0'),  # TODO: type info is lost
        ]

        # TODO: Expected types per OID:
        # 1.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
        # 1.3.6.1.2.1.2.2.1.1.10 = INTEGER: 10
        # 1.3.6.1.2.1.2.2.1.2.1 = STRING: "lo"
        # 1.3.6.1.2.1.2.2.1.2.10 = STRING: "eth0"
        # 1.3.6.1.2.1.2.2.1.3.1 = INTEGER: 24
        # 1.3.6.1.2.1.2.2.1.3.10 = INTEGER: 6
        # 1.3.6.1.2.1.2.2.1.4.1 = INTEGER: 65536
        # 1.3.6.1.2.1.2.2.1.4.10 = INTEGER: 1500
        # 1.3.6.1.2.1.2.2.1.5.1 = Gauge32: 10000000
        # 1.3.6.1.2.1.2.2.1.5.10 = Gauge32: 4294967295
        # 1.3.6.1.2.1.2.2.1.6.1 = ""
        # 1.3.6.1.2.1.2.2.1.6.10 = Hex-STRING: 02 42 AC 11 00 02
        # 1.3.6.1.2.1.2.2.1.7.1 = INTEGER: 1
        # 1.3.6.1.2.1.2.2.1.7.10 = INTEGER: 1
        # 1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1
        # 1.3.6.1.2.1.2.2.1.8.10 = INTEGER: 1
        # 1.3.6.1.2.1.2.2.1.9.1 = Timeticks: (0) 0:00:00.00
        # 1.3.6.1.2.1.2.2.1.9.10 = Timeticks: (0) 0:00:00.00
        # 1.3.6.1.2.1.2.2.1.10.1 = Counter32: 172
        # 1.3.6.1.2.1.2.2.1.10.10 = Counter32: 60558

        # 1.3.6.1.2.1.2.2.1.11.1 = Counter32: 2
        # 1.3.6.1.2.1.2.2.1.11.10 = Counter32: 564
        # 1.3.6.1.2.1.2.2.1.12.1 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.12.10 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.13.1 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.13.10 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.14.1 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.14.10 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.15.1 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.15.10 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.16.1 = Counter32: 172
        # 1.3.6.1.2.1.2.2.1.16.10 = Counter32: 44295
        # 1.3.6.1.2.1.2.2.1.17.1 = Counter32: 2
        # 1.3.6.1.2.1.2.2.1.17.10 = Counter32: 442
        # 1.3.6.1.2.1.2.2.1.18.1 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.18.10 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.19.1 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.19.10 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.20.1 = Counter32: 0
        # 1.3.6.1.2.1.2.2.1.20.10 = Counter32: 0

        # 1.3.6.1.2.1.2.2.1.21.1 = Gauge32: 0
        # 1.3.6.1.2.1.2.2.1.21.10 = Gauge32: 0
        # 1.3.6.1.2.1.2.2.1.22.1 = OID: ccitt.0
        # 1.3.6.1.2.1.2.2.1.22.10 = OID: ccitt.0
        self.assertEqual(result, expected)


class TestGetTable(unittest.TestCase):
    @patch('puresnmp.x690.util.tablify')
    @patch('puresnmp.client.Client.walk')
    @patch('puresnmp.client.Client._get_request_id')
    def test_table(self, mck_rid, mck_walk, mck_tablify):
        mck_rid.return_value = 0
        tmp = list()  # dummy iterable return value
        mck_walk.return_value = tmp

        client = Client(transport=Transport(), community='public')
        client.table('::1', '1.2.3.4', port=161, num_base_nodes=2)

        mck_walk.assert_called_with('::1', '1.2.3.4', port=161)
        mck_tablify.assert_called_with(tmp, num_base_nodes=2)

    @patch('puresnmp.client.Client.walk')
    @patch('puresnmp.client.Client._get_request_id')
    def test_table_num_base_nodes(self, mck_rid, mck_walk):
        res = [
            VarBind(ObjectIdentifier.from_string('1.2.3.4.1.1.192.168.0.2'), Integer(12)),
            VarBind(ObjectIdentifier.from_string('1.2.3.4.1.1.192.168.0.3'), Integer(13)),

            VarBind(ObjectIdentifier.from_string('1.2.3.4.1.2.192.168.0.2'), Integer(22)),
            VarBind(ObjectIdentifier.from_string('1.2.3.4.1.2.192.168.0.3'), Integer(23)),

            VarBind(ObjectIdentifier.from_string('1.2.3.4.1.3.192.168.0.2'), Integer(32)),
            VarBind(ObjectIdentifier.from_string('1.2.3.4.1.3.192.168.0.3'), Integer(33)),
        ]

        expect_192_168_0_2 = {
            '0': '192.168.0.2',
            '1': Integer(12),
            '2': Integer(22),
            '3': Integer(32),
        }
        expect_192_168_0_3 = {
            '0': '192.168.0.3',
            '1': Integer(13),
            '2': Integer(23),
            '3': Integer(33),
        }

        mck_rid.return_value = 0
        mck_walk.return_value = res

        client = Client(transport=Transport(), community='public')
        tbl = client.table('::1', '1.2.3.4.1', num_base_nodes=5)

        self.assertEqual(2, len(tbl))

        for entry in tbl:
            if entry['0'] == '192.168.0.2':
                self.assertDictEqual(entry, expect_192_168_0_2)
            elif entry['0'] == '192.168.0.3':
                self.assertDictEqual(entry, expect_192_168_0_3)
            else:
                raise AssertionError("Key \"{}\" should not be here".format(entry['0']))

    @patch('puresnmp.x690.util.tablify')
    @patch('puresnmp.client.Client.walk')
    @patch('puresnmp.client.Client._get_request_id')
    def test_table_auto_num_base_nodes(self, mck_rid, mck_walk, mck_tablify):
        mck_rid.return_value = 0
        tmp = list()  # dummy iterable return value
        mck_walk.return_value = tmp

        client = Client(transport=Transport(), community='public')
        tbl = client.table('::1', '1.2.3.4.1')

        mck_tablify.assert_called_with(tmp, num_base_nodes=5)