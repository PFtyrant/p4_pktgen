################################################################################
# BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
#
# Copyright (c) 2019-present Barefoot Networks, Inc.
#
# All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
# technical concepts contained herein are proprietary to Barefoot Networks, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in
# process, and are protected by trade secret or copyright law.  Dissemination of
# this information or reproduction of this material is strictly forbidden unless
# prior written permission is obtained from Barefoot Networks, Inc.
#
# No warranty, explicit or implicit is provided, unless granted under a written
# agreement with Barefoot Networks, Inc.
#
################################################################################

import logging

import ptf
from ptf import config
from ptf.thriftutils import *
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
import time
from timeit import default_timer as timer

g_is_tofino = testutils.test_param_get("arch") == "tofino"
g_is_tofino2 = testutils.test_param_get("arch") == "tofino2"
assert g_is_tofino or g_is_tofino2

g_num_pipes = int(testutils.test_param_get("num_pipes"))
g_timer_app_id = 1
g_port_down_app_id = 2

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())


def port_to_pipe(port):
    local_port = port & 0x7F
    pipe = port >> 7
    return pipe


def make_port(pipe, local_port):
    return (pipe << 7) | local_port


swports = []
for device, port, ifname in config["interfaces"]:
    pipe = port_to_pipe(port)
    if pipe < g_num_pipes:
        swports.append(port)
        swports.sort()

swports_0 = []
swports_1 = []
swports_2 = []
swports_3 = []
# the following method categorizes the ports in ports.json file as belonging to either of the pipes (0, 1, 2, 3)
for port in swports:
    pipe = port_to_pipe(port)
    if pipe == 0:
        swports_0.append(port)
    elif pipe == 1:
        swports_1.append(port)
    elif pipe == 2:
        swports_2.append(port)
    elif pipe == 3:
        swports_3.append(port)


def take_port_down(port_num):
    logger.info("Take port %d down", port_num)
    device = 0
    pm = config['port_map']
    veth = pm[(device, port_num)]
    veth_idx = veth.strip('veth')
    veth_num = int(veth_idx)
    veth_pair = "veth%d" % (veth_num - 1)
    print()
    port_num, veth, veth_pair
    subprocess.call(['port_ifdown', str(veth_pair)])


def bring_port_up(port_num):
    logger.info("Bring port %d up", port_num)
    device = 0
    pm = config['port_map']
    veth = pm[(device, port_num)]
    veth_idx = veth.strip('veth')
    veth_num = int(veth_idx)
    veth_pair = "veth%d" % (veth_num - 1)
    subprocess.call(['port_ifup', str(veth_pair)])


def verify_multiple_packets(test, port, pkts=[], pkt_lens=[], device_number=0, tmo=None, slack=0):
    # tmo: time out; slack: nonezero-allow getting slack number packets less than expected.
    rx_pkt_status = [False] * len(pkts)
    if tmo is None:
        tmo = ptf.ptfutils.default_negative_timeout
    rx_pkts = 0
    while rx_pkts < len(pkts):
        (rcv_device, rcv_port, rcv_pkt, pkt_time) = testutils.dp_poll(
            test,
            device_number=device_number,
            port_number=port,
            timeout=tmo)
        if not rcv_pkt:
            if slack:
                test.assertTrue((slack > (len(pkts) - rx_pkts)),
                                "Timeout:Port[%d]:Got:[%d]:Allowed slack[%d]:Left[%d]\n" % (
                                port, rx_pkts, slack, len(pkts) - rx_pkts))
                return
            else:
                logger.info("No more packets but still expecting",
                            len(pkts) - rx_pkts)
                for i, a_pkt in enumerate(pkts):
                    # print rx_pkt_status[i] #can be used for future debug when test case cannot pass.
                    # print format_packet(a_pkt) #can be used for future debug when test case cannot pass.
                    if not rx_pkt_status[i]:
                        logger.error("%s", str(a_pkt))
                test.assertTrue(False, "Timeout:Port:[%d]:Got[%d]:Left[%d]\n" % (
                    port, rx_pkts, len(pkts) - rx_pkts))
                return
        rx_pkts = rx_pkts + 1
        found = False
        for i, a_pkt in enumerate(pkts):
            if str(a_pkt) == str(rcv_pkt[:pkt_lens[i]]) and not rx_pkt_status[i]:
                rx_pkt_status[i] = True
                found = True
                break
        if not found:
            test.assertTrue(False, "RxPort:[%u]:Pkt#[%u]:Pkt:%s:Unmatched\n" % (
                port, rx_pkts, ":".join("{:02x}".format(ord(c)) for c in rcv_pkt[:pkt_lens[0]])))


def CfgTimerTable(self, target, i_port, pipe_id, batch_id, packet_id, o_port):
    logger.info("configure forwarding table")
    logger.info("ingress_port : %s\napp_id : %s\nbatch_id : %s\npacket_id : %s\npipe_id : %s\n",
                i_port, g_timer_app_id, batch_id, packet_id, pipe_id)
    self.i_t_table.entry_add(
        target,
        [self.i_t_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', i_port),
                                  gc.KeyTuple('hdr.timer.pipe_id', pipe_id),
                                  gc.KeyTuple('hdr.timer.app_id',
                                              g_timer_app_id),
                                  gc.KeyTuple('hdr.timer.batch_id', batch_id),
                                  gc.KeyTuple('hdr.timer.packet_id', packet_id)])],
        [self.i_t_table.make_data([gc.DataTuple('port', o_port)],
                                  'SwitchIngress.match')]
    )


def CleanupTimerTable(self, target=None):
    if not target:
        target = gc.Target(device_id=0, pipe_id=0xFFFF)
    resp = self.i_t_table.entry_get(target, [], {"from_hw": False})
    for _, key in resp:
        if key:
            self.i_t_table.entry_del(target, [key])


def CfgPortDownTable(self, target, i_port, pipe_id, port_num, packet_id, o_port):
    logger.info("IgPort %d Pipe %d App %d PortNum %d PktId %d Fwds-to %d", i_port, pipe_id, g_port_down_app_id,
                port_num, packet_id, o_port)
    self.i_p_table.entry_add(
        target,
        [self.i_p_table.make_key([gc.KeyTuple('ig_intr_md.ingress_port', i_port),
                                  gc.KeyTuple(
                                      'hdr.port_down.pipe_id', pipe_id),
                                  gc.KeyTuple('hdr.port_down.app_id',
                                              g_port_down_app_id),
                                  gc.KeyTuple(
                                      'hdr.port_down.port_num', port_num),
                                  gc.KeyTuple('hdr.port_down.packet_id', packet_id)])],
        [self.i_p_table.make_data([gc.DataTuple('port', o_port)],
                                  'SwitchIngress.match')]
    )


def CleanupPortDownTable(self, target=None):
    if not target:
        target = gc.Target(device_id=0, pipe_id=0xFFFF)
    resp = self.i_p_table.entry_get(target, [], {"from_hw": False})
    for _, key in resp:
        if key:
            self.i_p_table.entry_del(target, [key])


def ValueCheck(self, field, data_dict, expect_value):
    value = data_dict[field]
    if (value != expect_value):
        logger.info("Error: data %d, expect %d", value, expect_value)
        # assert(0)


def pgen_timer_hdr_to_dmac(pipe_id, app_id, batch_id, packet_id):
    """
    Given the fields of a 6-byte packet-gen header return an Ethernet MAC address
    which encodes the same values.
    """
    if g_is_tofino:
        pipe_shift = 3
    else:
        pipe_shift = 4
    return '%02x:00:%02x:%02x:%02x:%02x' % ((pipe_id << pipe_shift) | app_id,
                                            batch_id >> 8,
                                            batch_id & 0xFF,
                                            packet_id >> 8,
                                            packet_id & 0xFF)


def pgen_port_down_hdr_to_dmac(pipe_id, app_id, down_port, packet_id):
    """
    Given the fields of a 6-byte packet-gen header return an Ethernet MAC address
    which encodes the same values.
    """
    if g_is_tofino:
        pipe_shift = 3
    else:
        pipe_shift = 4
    return '%02x:00:%02x:%02x:%02x:%02x' % ((pipe_id << pipe_shift) | app_id,
                                            down_port >> 8,
                                            down_port & 0xFF,
                                            packet_id >> 8,
                                            packet_id & 0xFF)


def pgen_port(pipe_id):
    """
    Given a pipe return a port in that pipe which is usable for packet
    generation.  Note that Tofino allows ports 68-71 in each pipe to be used for
    packet generation while Tofino2 allows ports 0-7.  This example will use
    either port 68 or port 6 in a pipe depending on chip type.
    """
    if g_is_tofino:
        pipe_local_port = 68
    if g_is_tofino2:
        pipe_local_port = 6
    return make_port(pipe_id, pipe_local_port)


class TimerPktgenTest(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        p4_name = "tna_pktgen_test"
        BfRuntimeTest.setUp(self, client_id, p4_name)

    def runTest(self):
        logger.info(
            "=============== Testing Packet Generator trigger by Timer ===============")
        bfrt_info = self.interface.bfrt_info_get("tna_pktgen_test")

        pktgen_app_cfg_table = bfrt_info.table_get("app_cfg")
        pktgen_pkt_buffer_table = bfrt_info.table_get("pkt_buffer")
        pktgen_port_cfg_table = bfrt_info.table_get("port_cfg")

        self.i_t_table = bfrt_info.table_get("SwitchIngress.t")

        # timer pktgen app_id = 1 one shot 0
        target = gc.Target(device_id=0, pipe_id=0xffff)
        app_id = g_timer_app_id
        pktlen = 100
        pgen_pipe_id = 0
        src_port = make_port(pgen_pipe_id, 6)
        p_count = 1  # packets per batch
        b_count = 1  # batch number
        buff_offset = 0  # generated packets' payload will be taken from the offset in buffer

        out_port = None
        if g_is_tofino:
            out_port = 0
        if g_is_tofino2:
            out_port = 5

        # build expected generated packets
        p = testutils.simple_ip_packet(
            pktlen=pktlen, eth_dst="99:99:99:99:99:99")
        pkt_lst = []
        pkt_len = [pktlen] * p_count * b_count
        print(p.show())

        try:
            for batch in range(b_count):
                for pkt_num in range(p_count):
                    CfgTimerTable(self, target, src_port, 0,
                                  batch, pkt_num, out_port)

            # Enable packet generation on the port
            logger.info("enable pktgen port")
            pktgen_port_cfg_table.entry_add(
                target,
                [pktgen_port_cfg_table.make_key(
                    [gc.KeyTuple('dev_port', src_port)])],
                [pktgen_port_cfg_table.make_data([gc.DataTuple('pktgen_enable', bool_val=True)])])

            # Read back the enable status after configuring
            resp = pktgen_port_cfg_table.entry_get(
                target,
                [pktgen_port_cfg_table.make_key(
                    [gc.KeyTuple('dev_port', src_port)])],
                {"from_hw": False},
                pktgen_port_cfg_table.make_data([gc.DataTuple("pktgen_enable")], get=True))
            data_dict = next(resp)[0].to_dict()
            self.assertTrue(data_dict["pktgen_enable"])

            # Configure the packet generation timer application
            logger.info("configure pktgen application")
            if g_is_tofino:
                data = pktgen_app_cfg_table.make_data([gc.DataTuple('timer_nanosec', 100),
                                                       gc.DataTuple(
                                                           'app_enable', bool_val=False),
                                                       gc.DataTuple(
                                                           'pkt_len', (pktlen - 0)),
                                                       gc.DataTuple(
                                                           'pkt_buffer_offset', buff_offset),
                                                       gc.DataTuple(
                                                           'pipe_local_source_port', src_port),
                                                       gc.DataTuple(
                                                           'increment_source_port', bool_val=False),
                                                       gc.DataTuple(
                                                           'batch_count_cfg', b_count - 1),
                                                       gc.DataTuple(
                                                           'packets_per_batch_cfg', p_count - 1),
                                                       gc.DataTuple('ibg', 1),
                                                       gc.DataTuple(
                                                           'ibg_jitter', 0),
                                                       gc.DataTuple(
                                                           'ipg', 1000),
                                                       gc.DataTuple(
                                                           'ipg_jitter', 500),
                                                       gc.DataTuple(
                                                           'batch_counter', 0),
                                                       gc.DataTuple(
                                                           'pkt_counter', 0),
                                                       gc.DataTuple('trigger_counter', 0)],
                                                      'trigger_timer_periodic')
            if g_is_tofino2:
                data = pktgen_app_cfg_table.make_data([gc.DataTuple('timer_nanosec', 100),
                                                       gc.DataTuple(
                                                           'app_enable', bool_val=False),
                                                       gc.DataTuple(
                                                           'pkt_len', (pktlen - 0)),
                                                       gc.DataTuple(
                                                           'pkt_buffer_offset', buff_offset),
                                                       gc.DataTuple(
                                                           'pipe_local_source_port', src_port),
                                                       gc.DataTuple(
                                                           'increment_source_port', bool_val=False),
                                                       gc.DataTuple(
                                                           'batch_count_cfg', b_count - 1),
                                                       gc.DataTuple(
                                                           'packets_per_batch_cfg', p_count - 1),
                                                       gc.DataTuple('ibg', 1),
                                                       gc.DataTuple(
                                                           'ibg_jitter', 0),
                                                       gc.DataTuple(
                                                           'ipg', 1000),
                                                       gc.DataTuple(
                                                           'ipg_jitter', 500),
                                                       gc.DataTuple(
                                                           'batch_counter', 0),
                                                       gc.DataTuple(
                                                           'pkt_counter', 0),
                                                       gc.DataTuple(
                                                           'trigger_counter', 0),
                                                       gc.DataTuple('assigned_chnl_id', pgen_port(0))],
                                                      'trigger_timer_periodic')
            pktgen_app_cfg_table.entry_add(
                target,
                [pktgen_app_cfg_table.make_key(
                    [gc.KeyTuple('app_id', g_timer_app_id)])],
                [data])

            logger.info("configure packet buffer")
            pktgen_pkt_buffer_table.entry_add(
                target,
                [pktgen_pkt_buffer_table.make_key([gc.KeyTuple('pkt_buffer_offset', buff_offset),
                                                   gc.KeyTuple('pkt_buffer_size', (pktlen))])],
                [pktgen_pkt_buffer_table.make_data([gc.DataTuple('buffer', bytearray(bytes(p)[:]))])])

            logger.info("enable pktgen")
            pktgen_app_cfg_table.entry_mod(
                target,
                [pktgen_app_cfg_table.make_key(
                    [gc.KeyTuple('app_id', g_timer_app_id)])],
                [pktgen_app_cfg_table.make_data([gc.DataTuple('app_enable', bool_val=True)],
                                                'trigger_timer_periodic')]
            )
            time.sleep(5)
            # Disable the application.
            logger.info("disable pktgen")
            pktgen_app_cfg_table.entry_mod(
                target,
                [pktgen_app_cfg_table.make_key(
                    [gc.KeyTuple('app_id', g_timer_app_id)])],
                [pktgen_app_cfg_table.make_data([gc.DataTuple('app_enable', bool_val=False)],
                                                'trigger_timer_periodic')])
            # Disable packet generation on the port
            pktgen_port_cfg_table.entry_mod(
                target,
                [pktgen_port_cfg_table.make_key(
                    [gc.KeyTuple('dev_port', src_port)])],
                [pktgen_port_cfg_table.make_data([gc.DataTuple('pktgen_enable', bool_val=False)])])
            CleanupTimerTable(self, target)
        except gc.BfruntimeRpcException as e:
            raise e
        finally:
            pass
