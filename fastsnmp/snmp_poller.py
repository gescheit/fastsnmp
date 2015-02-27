#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys
if sys.version_info[0] < 3:
    print >> sys.stderr, "This program work only with python3. Sorry."
    sys.exit(1)
import select
if not hasattr(select, 'epoll'):
    print("The current platform does not support epoll", file=sys.stderr)
    sys.exit(1)
import logging
import socket
import queue
import collections
from fastsnmp import snmp_parser
from time import time

DEBUG = False
logging.basicConfig(format='%(asctime)s.%(msecs)d %(module)s:%(lineno)d :%(levelname)s:%(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
MAX_SOCKETS_COUNT = 100


def make_base_reqid(value, mask_len):
    """
    Return value with last set_len numbers set to zero

    :param value: target value
    :param mask_len: length of mask
    :type value: int
    :type mask_len: int
    :return: value
    :rtype: int

    :Example:
    >>> make_base_reqid(123456789, 3)
    123456000
    """
    offset = 10 ** mask_len
    res = value // offset * offset
    return res


def poller(hosts, oids_groups, community):
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
    reqid_offset_len = 6  # last nth rank used for offset
    start_reqid = 1000000000
    check_timeout = 10
    socksize = 0x200000
    check_retry = 1
    pending_querys = collections.defaultdict(list)
    retried_req = collections.defaultdict(int)
    global_target_varbinds = {}
    query_reqid = start_reqid

    # preparation of targets

    for oids_group in oids_groups:
        oids_to_poll = main_oids = oids_group
        global_target_varbinds[query_reqid] = (oids_to_poll, main_oids)
        query_reqid += 1000000

    reqid_to_msg = {}
    target_info = {}
    pending_query = {}
    target_info_r = {}
    bad_hosts = []
    for host in hosts:
        try:
            host_ip = socket.gethostbyname(host)  # TODO: bottleneck
        except socket.gaierror:
            logging.warning("unable to resolve %s. skiping this host" % host)
            bad_hosts.append(host)
            continue
        target_info[host_ip] = host
        target_info_r[host] = host_ip
    for bad_host in bad_hosts:
        hosts.remove(bad_host)
    for reqid in global_target_varbinds.keys():
        for host in hosts:
            host_ip = target_info_r[host]
            job_queue.put((target_info_r[host], reqid))

    # preparation of sockets
    socket_map = {}
    epoll = select.epoll()
    socket_count = min((MAX_SOCKETS_COUNT, len(hosts)))
    for _ in range(socket_count):
        new_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        new_sock.bind(('0.0.0.0', 0))
        socket_map[new_sock.fileno()] = new_sock
        epoll.register(new_sock, select.EPOLLOUT)

    # main loop
    while True:
        try:
            events = epoll.poll(0.1)
            for fileno, event in events:
                if event & select.EPOLLOUT:
                    fdfmt = select.EPOLLIN
                    if not job_queue.empty():
                        host, pdudata_reqid = job_queue.get()
                        if pdudata_reqid:
                            oids_to_poll, main_oids = global_target_varbinds[pdudata_reqid]
                            if pdudata_reqid in reqid_to_msg:
                                message = reqid_to_msg[pdudata_reqid]
                            else:
                                message = snmp_parser.msg_encode(pdudata_reqid, community, oids_to_poll, max_repetitions=20)
                                reqid_to_msg[pdudata_reqid] = message
                        socket_map[fileno].sendto(message, (host, 161))
                        pending_querys[host].append(pdudata_reqid)

                        pending_query[(host, pdudata_reqid)] = time()

                        if DEBUG:
                            logging.debug('sendto %s %s reqid=%s' % (host, oids_to_poll, pdudata_reqid))
                        job_queue.task_done()
                    if not job_queue.empty():
                        fdfmt = fdfmt | select.EPOLLOUT
                    #fdfmt = fdfmt | select.EPOLLOUT
                    epoll.modify(fileno, fdfmt)
                elif event & select.EPOLLIN:
                    data, remotehost = socket_map[fileno].recvfrom(socksize)
                    host_ip = remotehost[0]
                    pdudata_reqid, error_status, error_index, varBindList = snmp_parser.msg_decode(data)
                    if error_status:
                        logging.error('%s get error_status %s at %s' % (host_ip, error_status, error_index))
                    if DEBUG:
                        logging.debug('%s recv reqid=%s' % (host_ip, pdudata_reqid))
                    oids_to_poll, main_oids = global_target_varbinds[pdudata_reqid]
                    try:
                        del pending_query[(host_ip, pdudata_reqid)]
                    except KeyError:
                        continue  # dup
                    intrested_oids = True
                    for oid, value in varBindList:
                        if value is None:
                            intrested_oids = False
                            break
                        found = False
                        for main_oid in main_oids:
                            if oid.startswith(main_oid):
                                found = True
                                index_part = oid[len(main_oid) + 1:]
                                yield (target_info[host_ip], main_oid, index_part, value)
                                break
                        if not found:
                            if DEBUG:
                                logging.debug('skip %s %s=%s, reqid=%s. Not found in %s' % (host_ip, oid, value, pdudata_reqid, main_oids))
                            intrested_oids = False
                            break
                    base_req_id = make_base_reqid(pdudata_reqid, reqid_offset_len)
                    if intrested_oids:
                        oids_to_poll = []
                        new_req_id = base_req_id + int(str(hash(index_part))[-reqid_offset_len:])
                        if DEBUG:
                            logging.debug('new_req_id = %s' % new_req_id)
                        for target_oid in main_oids:
                            new_target_oid = "%s.%s" % (target_oid, index_part)
                            oids_to_poll.append(new_target_oid)

                        global_target_varbinds[new_req_id] = (oids_to_poll, main_oids)
                        job_queue.put((host_ip, new_req_id))
                    else:
                        if DEBUG:
                            logging.error('found not intrested in oid=%s host=%s' % (oid, host_ip))

                    epoll.modify(fileno, select.EPOLLOUT | select.EPOLLIN)
                elif event & select.EPOLLERR:
                    logging.critical('socket error')
                    raise
            if not events and job_queue.empty() and not pending_query:
                break

            if pending_query:  # check timeouts
                cur_time = time()
                timeouted_querys = []
                for query, query_time in pending_query.items():
                    if cur_time - query_time > check_timeout:
                        timeouted_querys.append(query)
                        logging.info('timeout %s %s' % (query))
                for timeouted_query in timeouted_querys:
                    if timeouted_query not in retried_req or retried_req[timeouted_query] < check_retry:
                        logging.debug('resend %s %s' % (timeouted_query))
                        job_queue.put(timeouted_query)
                        retried_req[timeouted_query] += 1
                    else:
                        logging.warning('stop timeout %s %s' % (timeouted_query))
                    del pending_query[timeouted_query]
            if not job_queue.empty():
                sockets_write_count = min(job_queue.qsize(), len(socket_map))
                for sock in list(socket_map.values())[0:sockets_write_count]:
                    epoll.modify(sock, select.EPOLLOUT | select.EPOLLIN)

        except InterruptedError:  # signal in syscall. supressed by default on python 3.5
            pass
