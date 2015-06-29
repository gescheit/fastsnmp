#!/usr/bin/python3
# -*- coding: utf-8 -*-
#  multiprocess SNMP poller and graphite sender
from multiprocessing import Process, Queue
import socket
import sys
import logging
import re
from fastsnmp import snmp_poller
from time import time, sleep
from collections import defaultdict
import urllib.parse
import urllib.request
import setproctitle
import signal
import textwrap


GRAPHITE_SERVER = "localhost"
GRAPHITE_PORT = 2003
COMMUNITY = 'public'
logger = logging.getLogger(__name__)

poller_logger = logging.getLogger('fastsnmp.snmp_poller')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - l:%(lineno)d - p:%(processName)s - %(funcName)s() - %(levelname)s - %(message)s')
ch = logging.StreamHandler()
ch.setFormatter(formatter)
logger.addHandler(ch)

poller_logger.setLevel(logging.DEBUG)
poller_logger.addHandler(ch)
defaultdict_rec = lambda: defaultdict(defaultdict_rec)


def signal_handler(signal, frame):
    print ('Signal %s recv' % signal)
    sys.exit(0)


def normalize_oid(oid):
    if oid.startswith('.'):
        return oid[1:]
    else:
        return oid


def normalize_hostname(host=""):
    host = host.replace(".", "_")
    return host


def normalize_ifname(ifname=""):
    ifname = ifname.replace(".", "_")
    ifname = ifname.replace("/", "_")
    return ifname


def parse_config(config):
    res = {}
    index_oids = {}
    target_oids = []
    for line in config.split("\n"):
        line = re.sub('#.*', '', line).strip()
        if not line:
            continue
        pline = re.split("\s+", line.strip())
        option_key = pline[0]
        if option_key == 'key':
            _, index_key, index_oid = pline
            index_oids[normalize_oid(index_oid)] = index_key
        elif option_key == 'table':
            if len(pline) == 5:
                _, metric_prefix, target_oid, _, index_name = pline
            elif len(pline) == 3:
                _, metric_prefix, target_oid, = pline
                index_name = None
            else:
                logger.error("unable to parse line='%s'" % line)
                continue
            target_oids.append({'index_name': index_name, 'oid': target_oid, 'metric_prefix': metric_prefix})
        else:
            logger.error("unknown option %s" % option_key)
    res['indexes'] = index_oids
    res['target_oids'] = target_oids
    return res


def start_poller(proc_id, carbon_queue, job_queue):
    proc_title = setproctitle.getproctitle()
    setproctitle.setproctitle("%s - poller#%s" % (proc_title, proc_id))
    logger.debug("start start_poller()")

    while True:
        lauch_time, job = job_queue.get()
        launch_timedelta = lauch_time - int(time())
        if launch_timedelta > 0:
            logger.debug("sleep %s", launch_timedelta)
            sleep(launch_timedelta)
        else:
            logger.warning("lateness %s's", launch_timedelta)
        poll_start = int(time())
        logger.warning("--polling--")

        config = job.config
        hosts = job.hosts

        # get indexes in first poll
        index_oids = config['indexes'].keys()
        if index_oids:
            index_oids_group = [(oid,) for oid in list(index_oids)]
            snmp_data = snmp_poller.poller(hosts, index_oids_group, COMMUNITY)
            index_table = defaultdict_rec()
            for snmp_res in snmp_data:
                host, base_oid, index_part, value = snmp_res
                index_name = config['indexes'][base_oid]
                index_table[host][index_name][index_part] = normalize_ifname(value)
            target_oid_indexes = {}
            target_oid_metric_pfx = {}
            for target_oid in config['target_oids']:
                if 'index_name' in target_oid:
                    target_oid_indexes[target_oid['oid']] = target_oid['index_name']
                    target_oid_metric_pfx[target_oid['oid']] = target_oid['metric_prefix']

        # get other in second poll
        oids_group = [(oid['oid'],) for oid in config['target_oids']]
        snmp_data = snmp_poller.poller(hosts, oids_group, COMMUNITY)
        request_time = int(time())
        for snmp_res in snmp_data:
            host, base_oid, index_part, value = snmp_res
            if index_table[host][target_oid_indexes[base_oid]][index_part]:
                oid_index_name = index_table[host][target_oid_indexes[base_oid]][index_part]
            else:
                oid_index_name = '%s' % index_part
            metric_pfx = target_oid_metric_pfx[base_oid]
            short_hostname = normalize_hostname(host)
            if "{index}" in metric_pfx:
                metric = ("%s.%s" % (short_hostname, metric_pfx.format(index=oid_index_name)))
            else:
                metric = ("%s.%s.%s" % (short_hostname, metric_pfx, oid_index_name))
            # print (metric, value, request_time)
            msg = "%s %s %s\n" % (metric, value, request_time)
            carbon_queue.put(msg)
        logger.debug("polling executed in %s's", int(time()) - poll_start)


def get_poller_jobs():
    res = []
    config = """key ifName 1.3.6.1.2.1.2.2.1.2 # ifDescr
    table ifaces.{index}.ifInOctets 1.3.6.1.2.1.31.1.1.1.6 key ifName # ifHCInOctets
    table ifaces.{index}.ifOutOctets 1.3.6.1.2.1.31.1.1.1.10 key ifName # ifHCOutOctets
    table ifaces.{index}.ifInErrors 1.3.6.1.2.1.2.2.1.14 key ifName # ifInErrors
    table ifaces.{index}.ifOutErrors 1.3.6.1.2.1.2.2.1.20 key ifName # ifOutErrors
    table cpu.{index}.hwAvgDuty5min 1.3.6.1.4.1.2011.6.3.4.1.4
    """
    config = textwrap.dedent(config)
    config = parse_config(config)
    hostsa = ('host1', 'host2')
    hostsb = ('host3', 'host4')
    res.append(Job(name="per30", interval=30, config=config, hosts=hostsa))
    res.append(Job(name="per20", interval=20, config=config, hosts=hostsb))
    return tuple(res)


def graphite_writer(q):
    proc_title = setproctitle.getproctitle()
    setproctitle.setproctitle("%s - graphite writer" % proc_title)
    logger.debug("start graphite_writer")
    while q:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (GRAPHITE_SERVER, GRAPHITE_PORT)
        prev_msg = None

        logger.debug("start connect loop")
        while True:
            try:
                sock.connect(server_address)
                break
            except socket.error:
                logger.debug("unable to connect")
                time.sleep(1)

        logger.debug("connected to server %s", sock.getpeername())
        for msg in iter(q.get, None):
            try:
                s = sock.send(msg.encode())
                # logger.debug("sended msg %s, send return %s", msg.strip(), s)

            except socket.error:
                if prev_msg:  # workaround
                    q.put(prev_msg)
                q.put(msg)
                logger.error("error while writing in socket")
                break
            prev_msg = msg
        else:
            logger.error("---------")
            sock.close()
            q = None
            break
    logger.error("graphite_writer is done")


class Job(object):
    def __init__(self, interval, config, hosts, name='', offset=0):
        self.interval = interval
        self.config = config
        self.hosts = hosts
        self.name = name
        self.offset = offset

    def next_launch_time(self, from_time=None):
        if from_time is None:
            from_time = int(time())
        remain = self.interval - from_time % self.interval + self.offset
        if remain == self.interval:  # now
            remain = 0
        return from_time + remain

    def get_time_table(self, from_, until):
        res = []
        time_pos = self.next_launch_time(from_)
        while True:
            res.append(time_pos)
            time_pos += self.interval + self.offset
            if time_pos > until:
                break
        return tuple(res)

    def __str__(self):
        return "job: interval=%s config=%s hosts=%s" % (self.job['interval'], self.job['config'], ",".join(self.job['hosts']))

    def __repr__(self, *args, **kwargs):
        return "%s name=%s" % (self.__class__.__name__, self.name)


class Scheduler(object):
    jobs = []

    def get_next_job(self):
        ret_job = None
        ret_job_launch_time = 0
        for j in self.jobs:
            j_next_launch = j.next_launch_time()
            if j_next_launch < ret_job_launch_time or ret_job_launch_time == 0:
                ret_job = j
                ret_job_launch_time = j_next_launch
        return ret_job_launch_time, ret_job

    def get_jobs_list(self, from_=None, until=None):
        res = []
        for j in self.jobs:
            j_time_table = j.get_time_table(from_=int(time()), until=int(time() + 600))
            for j_time_row in j_time_table:
                res.append((j_time_row, j))
        res.sort(key=lambda x: x[0])
        return tuple(res)

    def set_jobs(self, job_obj):
        self.jobs = job_obj


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    scheduler = Scheduler()
    jobs = get_poller_jobs()
    scheduler.set_jobs(jobs)
    carbon_queue = Queue()
    job_queue = Queue()

    graphite_writer_p = Process(target=graphite_writer, args=(carbon_queue,), name="graphite writer", daemon=True)
    graphite_writer_p.start()
    pollers = []
    for i in range(1):
        proc_id = i
        proc_name = "poller#%s" % proc_id
        p = Process(target=start_poller, args=(proc_id, carbon_queue, job_queue), name=proc_name, daemon=True)
        p.start()
        pollers.append(p)

    recalc_period = 600
    ct = int(time())
    for j in scheduler.get_jobs_list(from_=ct, until=ct + recalc_period):  # init
        job_queue.put(j)

    while True:
        for j in scheduler.get_jobs_list(from_=ct + recalc_period, until=ct + recalc_period * 2):
            job_queue.put(j)
        sleep(recalc_period)

    for p in pollers:
        p.join()
    carbon_queue.put(None)
    graphite_writer_p.join()

