"""
This file contains various values used to avoid magic numbers and strings in
the application.
"""
# pylint: disable=too-few-public-methods


class Version:
    """
    The SNMP Version identifier. This is used in the SNMP :term:`PDU`.
    """

    V2C = 0x01
    V1 = 0x00


class Length:
    """
    A simple "namespace" to avoid magic values for indefinite lengths.
    """

    INDEFINITE = "indefinite"


class RowStatus:
    """
    Define the status of a row in a SNMP :term:`Table`.
    Defined in RFC 2579

    active(1) - indicates that the conceptual row with all columns is
                available for use by the managed device.
    notInService(2) - indicates that the conceptual row exists in the agent,
                      but is unavailable for use by the managed device.
    notReady(3) - indicates that the conceptual row exists in the agent,
                  one or more required columns in the row are not instantiated.
    createAndGo(4) - supplied by a manager wishing to create a new instance of
                     a conceptual row and make it available for use.
    createAndWait(5) - supplied by a manager wishing to create a new instance
                       of a conceptual row but not making it available for use.
    destroy(6) - supplied by a manager wishing to delete all of the instances
                 associated with an existing conceptual row.
    """
    ACTIVE = 1
    NOT_IN_SERVICE = 2
    NOT_READY = 3
    CREATE_AND_GO = 4
    CREATE_AND_WAIT = 5
    DESTROY = 6


MAX_VARBINDS = 2147483647  # Defined in RFC 3416
