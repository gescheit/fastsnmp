#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys

if sys.version_info[0] < 3:
    sys.stderr.write("This program work only with python3. Sorry.")
    sys.exit(1)
import select

if hasattr(select, 'epoll'):
    from select import epoll as poll
    from select import EPOLLOUT as POLLOUT
    from select import EPOLLIN as POLLIN
    from select import EPOLLERR as POLLERR
elif hasattr(select, 'poll'):
    from select import poll
    from select import POLLOUT
    from select import POLLIN
    from select import POLLERR
else:
    print("The current platform does not support epoll", file=sys.stderr)
    sys.exit(1)

import logging
import socket
import queue
import collections
from fastsnmp import snmp_parser
from time import time
import random
from itertools import cycle

try:
    import mass_resolver
except ImportError:
    mass_resolver = None

DEBUG = False
logger = logging.getLogger('fastsnmp.snmp_poller')
MAX_SOCKETS_COUNT = 100


def resolve(hosts):
    if mass_resolver:
        res = mass_resolver.resolve(hosts)
    else:
        # slow way
        res = dict()
        for host in hosts:
            host_ips = res.setdefault(host, list())
            try:
                ips = [x[4][0] for x in socket.getaddrinfo(host, 0, proto=socket.IPPROTO_TCP)]
            except socket.gaierror:
                logger.error("unable to resolve %s. skipping this host" % host)
                continue
            host_ips.extend(ips)
    return res


def poller(hosts, oids_groups, community, timeout=3, backoff=2, retry=2, msg_type="GetBulk", include_ts=False):
    """
    A generator that yields SNMP data

    :param hosts: hosts
    :param oids_groups: oids_groups
    :param community: community
    :type hosts: list | tuple
    :type oids_groups: list | tuple
    :type community: str
    :return: host, main_oid, index_part, value
    :rtype: tuple
    """
    job_queue = queue.Queue()
    socksize = 0x2000000
    retried_req = collections.defaultdict(int)

    # message cache
    reqid_to_msg = {}
    pending_query = {}
    # ip => fqdn
    target_info = {}

    # fqdn => ips
    target_info_r = resolve(hosts)

    varbinds_cache = {}

    for fqdn, ips in list(target_info_r.items()):
        if ips:
            ip = ips[0]
            if ":" not in ip:
                ip = "::ffff:" + ip
            target_info[ip] = fqdn
            varbinds_cache[ip] = collections.UserDict()
            varbinds_cache[ip].by_oids = {}
        else:
            logger.error("unable to resolve %s. skipping this host", fqdn)
            del target_info_r[fqdn]

    # preparation of targets
    start_reqid = random.randint(1, 999) * 10000
    for oids_group in oids_groups:
        if isinstance(oids_group, list):
            oids_group = tuple(oids_group)
        target_oid_group = (oids_group, oids_group)
        for fqdn, ips in target_info_r.items():
            ip = ips[0]
            if ":" not in ip:
                ip = "::ffff:" + ip
            varbinds_cache[ip][start_reqid] = target_oid_group
            varbinds_cache[ip].by_oids[target_oid_group] = start_reqid
        start_reqid += 10000

    # add initial jobs
    for ip, poll_data in varbinds_cache.items():
        for reqid in poll_data:
            if ":" not in ip:
                ip = "::ffff:" + ip
            job_queue.put((ip, reqid))

    # preparation of sockets
    socket_map = {}
    epoll = poll()
    socket_count = min((MAX_SOCKETS_COUNT, len(target_info_r)))
    for _ in range(socket_count):
        new_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        new_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
        new_sock.bind(("::", 0))
        socket_map[new_sock.fileno()] = new_sock
        epoll.register(new_sock, POLLOUT)

    # main loop
    while True:
        try:
            events = epoll.poll(0.1)
            for fileno, event in events:
                if event & POLLOUT:
                    fdfmt = POLLIN
                    if not job_queue.empty():
                        host, pdudata_reqid = job_queue.get()
                        oids_to_poll, main_oids = varbinds_cache[host][pdudata_reqid]
                        q = (pdudata_reqid, oids_to_poll)
                        if q in reqid_to_msg:
                            message = reqid_to_msg[q]
                        else:
                            message = snmp_parser.msg_encode(pdudata_reqid, community, oids_to_poll, max_repetitions=20,
                                                             msg_type=msg_type)
                            reqid_to_msg[q] = message
                        socket_map[fileno].sendto(message, (host, 161))

                        pending_query[(host, pdudata_reqid)] = int(time())

                        if DEBUG:
                            logger.debug('sendto %s reqid=%s get oids=%s', host, pdudata_reqid, oids_to_poll)
                        job_queue.task_done()
                    if not job_queue.empty():
                        fdfmt = fdfmt | POLLOUT
                    epoll.modify(fileno, fdfmt)
                elif event & POLLIN:
                    data, remotehost = socket_map[fileno].recvfrom(socksize)
                    ts = time()
                    host_ip = remotehost[0]
                    if ":" not in host_ip:
                        host_ip = "::ffff:" + host_ip
                    try:
                        pdudata_reqid, error_status, error_index, var_bind_list = snmp_parser.msg_decode(data)
                    except Exception as e:
                        logger.critical("%r. unable to decode PDU from %s. data=%r", e, host_ip, data)
                        continue

                    if pending_query.pop((host_ip, pdudata_reqid), None) is None:
                        if DEBUG:
                            logger.debug("received answer after timeout from %s reqid=%s", host_ip, pdudata_reqid)
                        continue

                    if error_status:
                        logger.error('%s get error_status %s at %s. query=%s',
                                     target_info[host_ip],
                                     error_status, error_index,
                                     varbinds_cache[host_ip][pdudata_reqid][0])
                        continue
                    if DEBUG:
                        logger.debug('%s recv reqid=%s' % (host_ip, pdudata_reqid))
                    if pdudata_reqid not in varbinds_cache[host_ip]:
                        if DEBUG:
                            logger.debug('received unknown reqid=%s for host=%s. skipping', pdudata_reqid, host_ip)
                        continue
                    oids_to_poll, main_oids = varbinds_cache[host_ip][pdudata_reqid]

                    main_oids_len = len(main_oids)
                    main_oids_positions = cycle(range(main_oids_len))
                    var_bind_list_len = len(var_bind_list)

                    skip_column = {}
                    # if some oid in requested oids is not supported, column with it is index will
                    # be filled with another oid. need to skip
                    last_seen_index = {}

                    for var_bind_pos in range(var_bind_list_len):
                        oid, value = var_bind_list[var_bind_pos]
                        # oids in received var_bind_list in round-robin order respectively query
                        main_oids_pos = next(main_oids_positions)
                        if value is None:
                            if DEBUG:
                                logger.debug('found none value %s %s %s' % (host_ip, oid, value))
                            skip_column[main_oids_pos] = True
                        if main_oids_pos in skip_column:
                            continue
                        main_oid = main_oids[main_oids_pos]
                        if msg_type == "GetBulk":
                            if oid.startswith(main_oid + '.'):
                                index_part = oid[len(main_oid) + 1:]
                                last_seen_index[main_oids_pos] = index_part
                                if include_ts:
                                    yield (target_info[host_ip], main_oid, index_part, value, ts)
                                else:
                                    yield (target_info[host_ip], main_oid, index_part, value)
                            else:
                                if DEBUG:
                                    logger.debug(
                                        'host_ip=%s column_pos=%s skip oid %s=%s, reqid=%s. Not found in %s' % (host_ip,
                                                                                                                main_oids_pos,
                                                                                                                oid,
                                                                                                                value,
                                                                                                                pdudata_reqid,
                                                                                                                main_oids))
                                    logger.debug('vp=%s oid=%s main_oid=%s main_oids_pos=%s main_oids=%s', var_bind_pos,
                                                 oid, main_oid, main_oids_pos, main_oids)
                                skip_column[main_oids_pos] = True
                                if len(skip_column) == var_bind_list_len:
                                    break
                        else:
                            yield (target_info[host_ip], main_oid, "", value)
                            skip_column[main_oids_pos] = True
                    if len(skip_column) < main_oids_len:
                        if len(skip_column):
                            oids_to_poll = list()
                            new_main_oids = list()
                            for pos in range(main_oids_len):
                                if pos in skip_column:
                                    continue
                                oids_to_poll.append("%s.%s" % (main_oids[pos], last_seen_index[pos]))
                                new_main_oids.append(main_oids[pos])
                            oids_to_poll = tuple(oids_to_poll)
                            new_main_oids = tuple(new_main_oids)
                        else:
                            oids_to_poll = tuple(
                                "%s.%s" % (main_oids[p], last_seen_index[p]) for p in range(main_oids_len))
                            new_main_oids = main_oids

                        oid_group = (oids_to_poll, new_main_oids)

                        if oid_group in varbinds_cache[host_ip]:
                            next_reqid = varbinds_cache[host_ip][oid_group]
                        else:
                            next_reqid = pdudata_reqid + 10
                            varbinds_cache[host_ip][next_reqid] = oid_group
                            varbinds_cache[host_ip].by_oids[oid_group] = next_reqid
                        job_queue.put((host_ip, next_reqid))
                    else:
                        if DEBUG:
                            logger.debug('found not interested in oid=%s value=%s host=%s reqid=%s' % (
                            oid, value, host_ip, pdudata_reqid))

                    epoll.modify(fileno, POLLOUT | POLLIN)
                elif event & POLLERR:
                    logger.critical('socket error')
                    raise Exception('epoll error')
            if not events and job_queue.empty() and not pending_query:
                break

            if pending_query:  # check timeouts
                cur_time = int(time())
                timeouted_querys = []
                for query, query_time in pending_query.items():
                    attempt = retried_req.get(query, 1)
                    if attempt == 1:
                        query_timeout = attempt * timeout
                    else:
                        query_timeout = attempt * backoff * timeout
                    if cur_time - query_time > query_timeout:
                        timeouted_querys.append(query)
                        if DEBUG:
                            logger.warning('timeout %s > %s. attempt=%s, %s', cur_time - query_time, query_timeout,
                                           attempt, query)
                for timeouted_query in timeouted_querys:
                    if timeouted_query not in retried_req or retried_req[timeouted_query] < retry:
                        if DEBUG:
                            logger.debug('resend %s', timeouted_query)
                        job_queue.put(timeouted_query)
                        retried_req[timeouted_query] += 1
                    else:
                        logger.warning("%s ip=%s query timeout for OID's: %s",
                                       target_info[timeouted_query[0]],
                                       timeouted_query[0],
                                       varbinds_cache[timeouted_query[0]][timeouted_query[1]][0])
                    del pending_query[timeouted_query]
            if not job_queue.empty():
                sockets_write_count = min(job_queue.qsize(), len(socket_map))
                for sock in list(socket_map.values())[0:sockets_write_count]:
                    epoll.modify(sock, POLLOUT | POLLIN)

        except InterruptedError:  # signal in syscall. suppressed by default on python 3.5
            pass
