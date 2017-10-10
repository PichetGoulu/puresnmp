"""
Low-Level network transport.

This module mainly exist to enable a "seam" for mocking/patching out during
testing.
"""

import socket
import logging

from .exc import Timeout

LOG = logging.getLogger(__name__)


class Transport:
    def __init__(self, timeout: int = 2, retry: int = 3,
                 sock_buffer: int = 4096, with_dns: bool = True):
        self.timeout = timeout
        self.retry = retry
        self.sock_buffer = sock_buffer
        self.with_dns = with_dns

    def send(self, ip: str, port: int, packet: bytes) -> bytes:
        """
        Opens a TCP connection to *ip:port*, sends a packet with *bytes* and
        returns the raw bytes as returned from the remote host.

        If the connection fails due to a timeout after *self.timeout*,
        the connection is retried *self.retry* times.
        If it still failed, a Timeout exception is raised.
        """
        if self.with_dns:
            addrinf = socket.getaddrinfo(ip, port, proto=socket.IPPROTO_UDP)
        else:
            addrinf = socket.getaddrinfo(ip, port, proto=socket.IPPROTO_UDP,
                                         flags=socket.AI_NUMERICHOST)

        # Use the first DNS result
        address_family = addrinf[0][0]
        ip = addrinf[0][4][0]

        sock = socket.socket(address_family, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        if LOG.isEnabledFor(logging.DEBUG):
            from .x690.util import visible_octets
            hexdump = visible_octets(packet)
            LOG.debug('Sending packet to %s:%s\n%s', ip, port, hexdump)

        for _ in range(self.retry):
            try:
                sock.sendto(packet, (ip, port))
                response = sock.recv(self.sock_buffer)
                break
            except socket.timeout:
                # TODO add more details ?
                LOG.error('Timeout after %d sec for ip %s', self.timeout, ip)
                continue
        else:
            raise Timeout("Max of %d retries reached" % self.retry)
        sock.close()

        if LOG.isEnabledFor(logging.DEBUG):
            from .x690.util import visible_octets
            hexdump = visible_octets(response)
            LOG.debug('Received packet:\n%s', hexdump)

        return response
