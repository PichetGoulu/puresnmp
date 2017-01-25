from collections import namedtuple


WalkRow = namedtuple('WalkRow', 'value unfinished')


def group_varbinds(varbinds, effective_roots, user_roots=None):
    """
    Takes a list of varbinds and a list of base OIDs and returns a mapping from
    those base IDs to lists of varbinds.

    :param varbinds: A list of VarBind instnaces.
    :param effective_roots: The list of OIDs that were requested from the SNMP
        agent.
    :param user_roots: The list of VarBind instances that were requested by the
        user. This is used internally for walk requests. On each requests
        following the first, the requested OIDs will differ from the OIDs
        requested by the user. This list will keep track of the original OIDs
        to determine when the walk needs to terminate.
    """
    user_roots = user_roots or {}
    n = len(effective_roots)

    results = {}
    for i in range(n):
        results[effective_roots[i]] = varbinds[i::n]

    if user_roots:
        new_results = {}
        for k, v in results.items():
            containment = [base for base in user_roots if k in base]
            if len(containment) > 1:
                raise RuntimeError('Unexpected OID result. A value was '
                                   'contained in more than one base than '
                                   'should be possible!')
            if not containment:
                continue
            new_results[containment[0]] = v
            results = new_results

    return results


def get_unfinished_walk_oids(grouped_oids):
    """
    :param grouped_oids: A dictionary containing VarBinds as values. The keys
        are the base OID of those VarBinds as requested by the user. We need to
        keep track of the base to be able to tell when a walk over OIDs is
        finished (that is, when we hit the first OID outside the base).
    """

    # grouped_oids contains a list of values for each requested OID. We need to
    # determine if we need to continue fetching: Inspect the last item of each
    # list if those OIDs are still children of the requested IDs we need to
    # continue fetching using *those* IDs (as we're using GetNext behaviour).
    # If they are *not* children of the requested OIDs, we went too far (in the
    # case of a bulk operation) and need to remove all outliers.
    #
    # The above behaviour is the same for both bulk and simple operations. For
    # simple operations we simply have a list of 1 element per OID, but the
    # behaviour is identical

    # Build a mapping from the originally requested OID to the last fetched OID
    # from that tree.
    last_received_oids = {k: WalkRow(v[-1], v[-1].oid in k)
                          for k, v in grouped_oids.items()}

    output = [
        item for item in last_received_oids.items() if item[1].unfinished
    ]
    return output
