from collections import OrderedDict, namedtuple
from typing import List, Tuple
import logging

from . import types  # NOQA (must be here for type detection)
from .x690.types import (
    Integer,
    ObjectIdentifier,
    OctetString,
    Sequence,
    Type,
)
from .exc import SnmpError, NoSuchOID
from .pdu import (
    BulkGetRequest,
    GetNextRequest,
    GetRequest,
    SetRequest,
    VarBind,
)
from .const import Version, RowStatus
from .transport import Transport
from .util import (
    get_unfinished_walk_oids,
    group_varbinds,
)

LOG = logging.getLogger(__name__)

BulkResult = namedtuple('BulkResult', 'scalars listing')


class Client:
    """
    SNMP *Client* object used to send SNMP requests to target devices.
    """
    DEFAULT_SNMP_PORT = 161

    def __init__(self, transport: Transport, community: str = 'public', version: Version = Version.V2C):
        """
        A SNMP Client sending SNMP packets of a specific *community* and *version*
        The SNMP packets are send using *transport*
        """
        self._transport = transport
        self._community = community
        self._version = version

    def _get_request_id(self) -> int:  # pragma: no cover
        """
        Generates a SNMP request ID. This value should be locally unique for each request.
        RFC3413: "A PDU is constructed using a locally unique request-id value, [...]"
        """
        from time import time
        return int(time())

    def get(self, ip: str, oid: str, port: int = DEFAULT_SNMP_PORT):
        """
        Executes a simple SNMP GET request and returns a pure Python data structure.

        Example::

            >>> t = Transport()
            >>> c = Client(t, 'private')
            >>> c.get('192.168.1.1', '1.2.3.4')
            'non-functional example'
        """
        return self.multiget(ip, [oid], port)[0]

    def multiget(self, ip: str, oids: List[str], port: int = DEFAULT_SNMP_PORT):
        """
        Executes an SNMP GET request with multiple OIDs and returns a list of pure
        Python objects. The order of the output items is the same order as the OIDs
        given as arguments.

        Example::

            >>> t = Transport()
            >>> c = Client(t, 'private')
            >>> c.multiget('192.168.1.1', ['1.2.3.4', '1.2.3.5'])
            ['non-functional example', 'second value']
        """

        oids = [ObjectIdentifier.from_string(oid) for oid in oids]

        packet = Sequence(
            Integer(Version.V2C),
            OctetString(self._community),
            GetRequest(self._get_request_id(), *oids)
        )

        response = self._transport.send(ip, port, bytes(packet))
        raw_response = Sequence.from_bytes(response)

        output = [value.pythonize() for _, value in raw_response[2].varbinds]
        if len(output) != len(oids):
            raise SnmpError('Unexpected response. Expected %d varbind, '
                            'but got %d!' % (len(oids), len(output)))
        return output

    def getnext(self, ip: str, oid: str, port: int = DEFAULT_SNMP_PORT):
        """
        Executes a single SNMP GETNEXT request (used inside *walk*).

        Example::

            >>> t = Transport()
            >>> c = Client(t, 'private')
            >>> c.getnext('192.168.1.1', '1.2.3')
            VarBind(ObjectIdentifier(1, 2, 3, 0), 'non-functional example')
        """
        return self.multigetnext(ip, [oid], port)[0]

    def multigetnext(self, ip: str, oids: List[str], port: int = DEFAULT_SNMP_PORT):
        """
        Function to send a single multi-oid GETNEXT request.

        The request sends one packet to the remote host requesting the value of the
        OIDs following one or more given OIDs.

        Example::

            >>> t = Transport()
            >>> c = Client(t, 'private')
            >>> c.multigetnext('192.168.1.1', ['1.2.3', '1.2.4'])
            [
                VarBind(ObjectIdentifier(1, 2, 3, 0), 'non-functional example'),
                VarBind(ObjectIdentifier(1, 2, 4, 0), 'second value')
            ]
        """
        request = GetNextRequest(self._get_request_id(), *oids)
        packet = Sequence(
            Integer(Version.V2C),
            OctetString(self._community),
            request
        )
        response = self._transport.send(ip, port, bytes(packet))
        raw_response = Sequence.from_bytes(response)
        response_object = raw_response[2]
        if len(response_object.varbinds) != len(oids):
            raise SnmpError(
                'Invalid response! Expected exactly %d varbind, '
                'but got %d' % (len(oids), len(response_object.varbinds)))
        return [VarBind(oid, value.pythonize())
                for oid, value in response_object.varbinds]

    def walk(self, ip: str, oid: str, port: int = DEFAULT_SNMP_PORT):
        """
        Executes a sequence of SNMP GETNEXT requests and returns an generator over
        :py:class:`~puresnmp.pdu.VarBind` instances.

        The generator stops when hitting an OID which is *not* a sub-node of the
        given start OID or at the end of the tree (whichever comes first).

        Example::

            >>> t = Transport()
            >>> c = Client(t, 'private')
            >>> c.walk('127.0.0.1', '1.3.6.1.2.1.1')
            <generator object multiwalk at 0x7fa2f775cf68>

            >>> from pprint import pprint
            >>> pprint(list(c.walk('127.0.0.1', '1.3.6.1.2.1.3')))
            [VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 3, 1, 1, 1, 24, 1, 172, 17, 0, 1)), value=24),
             VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 3, 1, 1, 2, 24, 1, 172, 17, 0, 1)), value=b'\\x02B\\xef\\x14@\\xf5'),
             VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 3, 1, 1, 3, 24, 1, 172, 17, 0, 1)), value=64, b'\\xac\\x11\\x00\\x01')]
        """

        return self.multiwalk(ip, [oid], port)

    def multiwalk(self, ip: str, oids: List[str], port: int = DEFAULT_SNMP_PORT,
                  fetcher=None):
        """
        Executes a sequence of SNMP GETNEXT requests and returns an generator over
        :py:class:`~puresnmp.pdu.VarBind` instances.

        This is the same as :py:func:`~.walk` except that it is capable of iterating
        over multiple OIDs at the same time.

        The default fetcher is :py:func:`~.multigetnext`

        Example::

            >>> t = Transport()
            >>> c = Client(t, 'private')
            >>> c.multiwalk('127.0.0.1', ['1.3.6.1.2.1.1', '1.3.6.1.4.1.1'])
            <generator object multiwalk at 0x7fa2f775cf68>
        """

        if fetcher is None:
            fetcher = self.multigetnext

        LOG.debug('Walking on %d OIDs using %s', len(oids), fetcher.__name__)

        varbinds = fetcher(ip, oids, port)
        requested_oids = [ObjectIdentifier.from_string(oid) for oid in oids]
        grouped_oids = group_varbinds(varbinds, requested_oids)
        unfinished_oids = get_unfinished_walk_oids(grouped_oids)
        LOG.debug('%d of %d OIDs need to be continued',
                  len(unfinished_oids),
                  len(oids))
        output = group_varbinds(varbinds, requested_oids)

        # As long as we have unfinished OIDs, we need to continue the walk for
        # those.
        while unfinished_oids:
            next_fetches = [_[1].value.oid for _ in unfinished_oids]
            try:
                varbinds = fetcher(ip, [str(_) for _ in next_fetches], port)
            except NoSuchOID:
                # Reached end of OID tree, finish iteration
                break
            grouped_oids = group_varbinds(varbinds,
                                          next_fetches,
                                          user_roots=requested_oids)
            unfinished_oids = get_unfinished_walk_oids(grouped_oids)
            LOG.debug('%d of %d OIDs need to be continued',
                      len(unfinished_oids),
                      len(oids))
            for k, v in group_varbinds(varbinds, next_fetches).items():
                for ko, vo in output.items():
                    if k in ko:
                        vo.extend(v)

        yielded = set([])
        for v in output.values():
            for varbind in v:
                containment = [varbind.oid in _ for _ in requested_oids]
                if not any(containment) or varbind.oid in yielded:
                    continue
                yielded.add(varbind.oid)
                yield varbind

    def set(self, ip: str, oid: str, value: Type, port: int = DEFAULT_SNMP_PORT):
        """
        Executes a simple SNMP SET request. The result is returned as pure Python
        data structure. The value must be a subclass of
        :py:class:`~puresnmp.x690.types.Type`.

        Example::

            >>> t = Transport()
            >>> c = Client(t, 'private')
            >>> c.set('127.0.0.1', '1.3.6.1.2.1.1.4.0',
            ...     OctetString(b'I am contact'))
            b'I am contact'
        """

        result = self.multiset(ip, [(oid, value)], port)
        return result[oid]

    def multiset(self, ip: str, mappings: List[Tuple[str, Type]],
                 port: int = DEFAULT_SNMP_PORT):
        """

        Executes an SNMP SET request on multiple OIDs. The result is returned as
        pure Python data structure.

        Fake Example::

            >>> t = Transport()
            >>> c = Client(t, 'private')
            >>> c.multiset('127.0.0.1', [('1.2.3', OctetString(b'foo')),
...                                      ('2.3.4', OctetString(b'bar'))])
            {'1.2.3': b'foo', '2.3.4': b'bar'}
        """

        if any([not isinstance(v, Type) for k, v in mappings]):
            raise TypeError('SNMP requires typing information. The value for a '
                            '"set" request must be an instance of "Type"!')

        binds = [VarBind(ObjectIdentifier.from_string(k), v)
                 for k, v in mappings]

        request = SetRequest(self._get_request_id(), binds)
        packet = Sequence(Integer(Version.V2C),
                          OctetString(self._community),
                          request)
        response = self._transport.send(ip, port, bytes(packet))
        raw_response = Sequence.from_bytes(response)
        output = {
            str(oid): value.pythonize() for oid, value in raw_response[2].varbinds
            }
        if len(output) != len(mappings):
            raise SnmpError('Unexpected response. Expected %d varbinds, '
                            'but got %d!' % (len(mappings), len(output)))
        return output

    def bulkget(self, ip: str, scalar_oids: List[str], repeating_oids: List[str], max_list_size: int = 1,
                port: int = DEFAULT_SNMP_PORT):
        """
        Runs a "bulk" get operation and returns a :py:class:`~.BulkResult` instance.
        This contains both a mapping for the scalar variables (the "non-repeaters")
        and an OrderedDict instance containing the remaining list (the "repeaters").

        The OrderedDict is ordered the same way as the SNMP response (whatever the
        remote device returns).

        This operation can retrieve both single/scalar values *and* lists of values
        ("repeating values") in one single request. You can for example retrieve the
        hostname (a scalar value), the list of interfaces (a repeating value) and
        the list of physical entities (another repeating value) in one single
        request.

        Note that this behaves like a **getnext** request for scalar values! So you
        will receive the value of the OID which is *immediately following* the OID
        you specified for both scalar and repeating values!

        :param scalar_oids: contains the OIDs that should be fetched as single
            value.
        :param repeating_oids: contains the OIDs that should be fetched as list.
        :param max_list_size: defines the max length of each list.

        Example::

            >>> t = Transport()
            >>> c = Client(t, 'private')
            >>> result = c.bulkget(ip,
            ...                  scalar_oids=['1.3.6.1.2.1.1.1',
            ...                               '1.3.6.1.2.1.1.2'],
            ...                  repeating_oids=['1.3.6.1.2.1.3.1',
            ...                                  '1.3.6.1.2.1.5.1'],
            ...                  max_list_size=10)
            BulkResult(
                scalars={'1.3.6.1.2.1.1.2.0': '1.3.6.1.4.1.8072.3.2.10',
                         '1.3.6.1.2.1.1.1.0': b'Linux aafa4dce0ad4 4.4.0-28-'
                                              b'generic #47-Ubuntu SMP Fri Jun 24 '
                                              b'10:09:13 UTC 2016 x86_64'},
                listing=OrderedDict([
                    ('1.3.6.1.2.1.3.1.1.1.10.1.172.17.0.1', 10),
                    ('1.3.6.1.2.1.5.1.0', b'\x01'),
                    ('1.3.6.1.2.1.3.1.1.2.10.1.172.17.0.1', b'\x02B\x8e>\x9ee'),
                    ('1.3.6.1.2.1.5.2.0', b'\x00'),
                    ('1.3.6.1.2.1.3.1.1.3.10.1.172.17.0.1', b'\xac\x11\x00\x01'),
                    ('1.3.6.1.2.1.5.3.0', b'\x00'),
                    ('1.3.6.1.2.1.4.1.0', 1),
                    ('1.3.6.1.2.1.5.4.0', b'\x01'),
                    ('1.3.6.1.2.1.4.3.0', b'\x00\xb1'),
                    ('1.3.6.1.2.1.5.5.0', b'\x00'),
                    ('1.3.6.1.2.1.4.4.0', b'\x00'),
                    ('1.3.6.1.2.1.5.6.0', b'\x00'),
                    ('1.3.6.1.2.1.4.5.0', b'\x00'),
                    ('1.3.6.1.2.1.5.7.0', b'\x00'),
                    ('1.3.6.1.2.1.4.6.0', b'\x00'),
                    ('1.3.6.1.2.1.5.8.0', b'\x00'),
                    ('1.3.6.1.2.1.4.7.0', b'\x00'),
                    ('1.3.6.1.2.1.5.9.0', b'\x00'),
                    ('1.3.6.1.2.1.4.8.0', b'\x00'),
                    ('1.3.6.1.2.1.5.10.0', b'\x00')]))
        """

        scalar_oids = scalar_oids or []  # protect against empty values
        repeating_oids = repeating_oids or []  # protect against empty values

        oids = [
                   ObjectIdentifier.from_string(oid) for oid in scalar_oids
                   ] + [
                   ObjectIdentifier.from_string(oid) for oid in repeating_oids
                   ]

        non_repeaters = len(scalar_oids)

        packet = Sequence(
            Integer(Version.V2C),
            OctetString(self._community),
            BulkGetRequest(self._get_request_id(), non_repeaters, max_list_size, *oids)
        )

        response = self._transport.send(ip, port, bytes(packet))
        raw_response = Sequence.from_bytes(response)

        # See RFC=3416 for details of the following calculation
        n = min(non_repeaters, len(oids))
        m = max_list_size
        r = max(len(oids) - n, 0)
        expected_max_varbinds = n + (m * r)

        if len(raw_response[2].varbinds) > expected_max_varbinds:
            raise SnmpError('Unexpected response. Expected no more than %d '
                            'varbinds, but got %d!' % (
                                expected_max_varbinds, len(oids)))

        # cut off the scalar OIDs from the listing(s)
        scalar_tmp = raw_response[2].varbinds[0:len(scalar_oids)]
        repeating_tmp = raw_response[2].varbinds[len(scalar_oids):]

        # prepare output for scalar OIDs
        scalar_out = {str(oid): value.pythonize() for oid, value in scalar_tmp}

        # prepare output for listing
        repeating_out = OrderedDict()
        for oid, value in repeating_tmp:
            repeating_out[str(oid)] = value.pythonize()

        return BulkResult(scalar_out, repeating_out)

    def _bulkwalk_fetcher(self, bulk_size: int = 10):
        """
        Create a bulk fetcher with a fixed limit on "repeatable" OIDs.
        """

        def fun(ip: str, oids: List[str], port: int = Client.DEFAULT_SNMP_PORT):
            result = self.bulkget(ip, [], oids, max_list_size=bulk_size, port=port)
            return [VarBind(ObjectIdentifier.from_string(k), v)
                    for k, v in result.listing.items()]

        fun.__name__ = '_bulkwalk_fetcher(%d)' % bulk_size
        return fun

    def bulkwalk(self, ip: str, oids: List[str], bulk_size: int = 10, port: int = DEFAULT_SNMP_PORT):
        """
        More efficient implementation of :py:func:`~.walk`. It uses
        :py:func:`~.bulkget` under the hood instead of :py:func:`~.getnext`.

        Just like :py:func:`~.multiwalk`, it returns a generator over
        :py:class:`~puresnmp.pdu.VarBind` instances.

        :param ip: The IP address of the target host.
        :param community: The community string for the SNMP connection.
        :param oids: A list of base OIDs to use in the walk operation.
        :param bulk_size: How many varbinds to request from the remote host with
            one request.
        :param port: The TCP port of the remote host.

        Example::


            >>> t = Transport()
            >>> c = Client(t, 'private')
            >>> oids = [
            ...     '1.3.6.1.2.1.2.2.1.2',   # name
            ...     '1.3.6.1.2.1.2.2.1.6',   # MAC
            ...     '1.3.6.1.2.1.2.2.1.22',  # ?
            ... ]
            >>> result = c.bulkwalk(ip, oids)
            >>> for row in result:
            ...     print(row)
            VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1)), value=b'lo')
            VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 6, 1)), value=b'')
            VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 22, 1)), value='0.0')
            VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 38)), value=b'eth0')
            VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 6, 38)), value=b'\x02B\xac\x11\x00\x02')
            VarBind(oid=ObjectIdentifier((1, 3, 6, 1, 2, 1, 2, 2, 1, 22, 38)), value='0.0')
        """

        result = self.multiwalk(ip, oids, port=port,
                                fetcher=self._bulkwalk_fetcher(bulk_size))
        for oid, value in result:
            yield VarBind(oid, value)

    def table(self, ip: str, oid: str, port: int = DEFAULT_SNMP_PORT, num_base_nodes: int = 0):
        """
        Run a series of GETNEXT requests on an OID and construct a table from the
        result.

        The table is a row of dicts. The key of each dict is the row ID. By default
        that is the **last** node of the OID tree.

        If the rows are identified by multiple nodes, the number of base nodes is computed from *oid*
        (an *oid* of '1.2.3.4' would set the *num_base_nodes* to 4).
        You can overwrite this by setting *num_base_nodes* to a non-zero value.

        Example::


            >>> from pprint import pprint
            >>> t = Transport()
            >>> c = Client(t, 'private')
            >>> wlk = c.walk('::1', '1.2.3.4.1')
            >>> pprint(wlk)
            [VarBind(oid=ObjectIdentifier((1, 2, 3, 4, 1, 1, 192, 168, 0, 2)), value=Integer(12)),
             VarBind(oid=ObjectIdentifier((1, 2, 3, 4, 1, 1, 192, 168, 0, 3)), value=Integer(13)),
             VarBind(oid=ObjectIdentifier((1, 2, 3, 4, 1, 2, 192, 168, 0, 2)), value=Integer(22)),
             VarBind(oid=ObjectIdentifier((1, 2, 3, 4, 1, 2, 192, 168, 0, 3)), value=Integer(23)),
             VarBind(oid=ObjectIdentifier((1, 2, 3, 4, 1, 3, 192, 168, 0, 2)), value=Integer(32)),
             VarBind(oid=ObjectIdentifier((1, 2, 3, 4, 1, 3, 192, 168, 0, 3)), value=Integer(33))]

            >>> tbl = c.table('::1',  '1.2.3.4.1')
            >>> pprint(tbl)
            [{'0': '192.168.0.2', '1': Integer(12), '2': Integer(22), '3': Integer(32)},
             {'0': '192.168.0.3', '1': Integer(13), '2': Integer(23), '3': Integer(33)}]

        """
        from puresnmp.x690 import util

        if num_base_nodes == 0:
            num_base_nodes = len(oid.split('.'))

        tmp = self.walk(ip, oid, port=port)
        as_table = util.tablify(tmp, num_base_nodes=num_base_nodes)
        return as_table

    def table_row_count(self, ip: str, oid: str, port: int = DEFAULT_SNMP_PORT, num_base_nodes: int = 0) -> int:
        return len(self.table(ip, oid, port, num_base_nodes))

    def table_add_row(self, ip: str, table_oid: str, row_identifier: str, row_status_column: int,
                      fields: List[Tuple[int, Type]], port: int = DEFAULT_SNMP_PORT):
        """
        The *row_identifier* (or Instance-Identifier per the RFC2579) can be a simple number that designate
        the row (like '1' for the first row, '2' for the second, etc.) or be more complexe (like
        ('192.168.0.1' for the first row, '192.168.0.2' for the second, etc.)

        The *row_status_column* is the index of the column where the RowStatus information can be found.

        The *fields* is a list tuple where the first element is the index of a column and the second
        is the value of the column to set.

        The row is added using the 'createAndGo' method, creating the row in only one transaction,
        instead of the 'createAndWait' method which use multiple, coordinated set requests.

        Example::


            >>> t = Transport()
            >>> c = Client(t, community='private')
            >>> fields = [
            ...     (1, Integer(1)),
            ...     (2, OctetString('Test'.encode('ascii'))),
            ...     (3, Integer(2)),
            ...     (4, Integer(22)),
            ...     (5, Integer(23)),
            ...     (6, IpAddress.from_str('192.168.0.10')),
            ...     (7, Integer(22)),
            ...     (8, Integer(23)),
            ...     (9, IpAddress.from_str('192.168.0.9')),
            ... ]
            >>> c.table_add_row('::1', '1.2.3.4.1', row_identifier='3', row_status_column=10, fields=fields)

        """

        # Specs:
        #   - RFC 2579 Page 10-16: https://tools.ietf.org/html/rfc2579
        #   - Webnms docs: https://www.webnms.com/snmp/help/snmpapi/snmpv3/table_handling/snmptables_addrow.html

        # Interaction 1: Selecting an Instance-Identifier
        # This should be done by the application
        # ---
        row_identifier = row_identifier

        # Interaction 2a: Creating and Activating the Conceptual Row
        # ---
        #     RFC:
        #     the management station issues a management protocol get
        #     operation to examine all columns in the conceptual row that
        #     it wishes to create.  In response, for each column, there
        #     are three possible outcomes:
        #             - a value is returned, indicating that some other
        #              management station has already created this conceptual
        #              row. [...]
        #              - the exception `noSuchInstance' is returned,
        #              indicating that the agent implements the object-type
        #              associated with this column [...]
        #              - the exception `noSuchObject' is returned, indicating
        #              that the agent does not implement the object-type
        #              associated with this column [...]

        # Per the RFC, we should check each column for the column requirements.
        # We only GET on the column rowStatus to check if the *row_identifier* already exist.
        row_status_oid = table_oid + '.' + str(row_status_column) + '.' + row_identifier
        try:
            row_status = self.get(ip, row_status_oid, port)
            raise SnmpError("An other management station has already created this row. "
                            "identifier: {}".format(row_identifier))
        except SnmpError:
            # Todo: We should check the SNMP exception ! (noSuchInstance: Ok or noSuchObject: not OK)
            pass

        # RFC:
        # Once the column requirements have been determined, a
        # management protocol set operation is accordingly issued.
        # This operation also sets the new instance of the status
        # column to `createAndGo'.

        # Prepare the mapping of the inserted row
        mappings = []
        for column_idx, value in fields:
            if column_idx == row_status_column:
                raise ValueError('The value of the column rowStatus is handled by add_row()')
            oid = table_oid + '.' + str(column_idx) + '.' + row_identifier
            mappings.append((oid, value))

        # The rowStatus is set to createAndGo
        mappings.append((row_status_oid, Integer(RowStatus.CREATE_AND_GO)))

        # Send the PDU
        output = self.multiset(ip, mappings, port)

        # RFC:
        # [...] If there is sufficient
        # information available, then the conceptual row is created, a
        # `noError' response is returned, the status column is set to
        # `active', and no further interactions are necessary (i.e.,
        # interactions 3 and 4 are skipped).  If there is insufficient
        # information, then the conceptual row is not created, and the
        # set operation fails with an error of `inconsistentValue'.
        row_status = self.get(ip, row_status_oid, port)
        if row_status != RowStatus.ACTIVE:
            raise SnmpError("Could not add the row, rowStatus: {}".format(row_status))

        return output

    def table_delete_row(self, ip: str, table_oid: str, row_identifier: str, row_status_column: int,
                         port: int = DEFAULT_SNMP_PORT):

        row_status_oid = table_oid + '.' + str(row_status_column) + '.' + row_identifier
        self.set(ip, row_status_oid, Integer(RowStatus.DESTROY), port)
