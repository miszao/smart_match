from operator import attrgetter

# import simple_switch_L4
import simple_switch_L4_stp
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from NaiveBayes import NaiveBayes


class SmartMatch(simple_switch_L4_stp.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SmartMatch, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.naive_bayes = NaiveBayes()
        self.naive_bayes.init_classifier()
        self.logger.info('instantiated Naive Bayes classifier, its accuracy score is: %0.2f',
                         self.naive_bayes.get_accuracy_score())
        self.flow_container = {}

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        # dodac flow tutaj, priority = 65535
        actions = [parser.OFPActionOutput(out_port)] ?????
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
                self._mod_flow(dp,command=of.OFPFC_ADD,match=match, actions=actions,priority=65535)
                READY_TO_OPTIMIZE_FLAG = bool(self.flow_container) and self.flow_container['ip_src_list']
                if READY_TO_OPTIMIZE_FLAG:
                    # self.logger.info('self.flow_container should not be empty:')
                    # self.logger.info(self.flow_container)
                    self.logger.info(self.naive_bayes.inspect_flow(self.flow_container))
                    self.logger.info(self.naive_bayes.get_label_encoding())
            hub.sleep(5)

    def _mod_flow(self, datapath, command, match, actions, priority):
         ofproto = datapath.ofproto
         parser = datapath.ofproto_parser
         #priority = 3
         inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                actions)]
         if command is None:
             command = dp.ofproto.OFPFC_ADD

         if isinstance(match, list):
             for m in match:
                 mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                   match=m, instructions=inst, command=command)
                 datapath.send_msg(mod)
         else:
             mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                   match=match, instructions=inst, command=command)
             datapath.send_msg(mod)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        ip_src_list = list()
        ip_dst_list = list()
        ip_proto_list = list()
        src_port_list = list()
        dst_port_list = list()
        avg_pkt_size_list = list()
        body = ev.msg.body

        self.logger.info('datapath         '
                         'ipv4_src         ipv4_dst         '
                         'ip_proto out-port packets  bytes         ')
        self.logger.info('---------------- '
                         '---------------- ---------------- '
                         '-------- -------- --------- ----------------')
        for stat in sorted([flow for flow in body if (flow.priority == 1)],
                           key=lambda flow: (flow.match['ipv4_src'],
                                             flow.match['ipv4_dst'],
                                             flow.match['ip_proto'],
                                             )):
            self.logger.info('%016x %16s %16s %8d %8d %8i %16d',
                             ev.msg.datapath.id, stat.match['ipv4_src'],
                             stat.match['ipv4_dst'], stat.match['ip_proto'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)
            if stat.duration_sec >= 3:
                ip_src_list.append(stat.match['ipv4_src'])
                ip_dst_list.append(stat.match['ipv4_dst'])
                if stat.match['ip_proto'] == 1:
                    ip_proto_list.append(stat.match['ip_proto'])
                    src_port_list.append(0)
                    dst_port_list.append(0)
                    if stat.packet_count:
                        avg_pkt_size_list.append(stat.byte_count / stat.packet_count)
                    else:
                        avg_pkt_size_list.append(0)
                elif stat.match['ip_proto'] == 6:
                    ip_proto_list.append(stat.match['ip_proto'])
                    src_port_list.append(stat.match['tcp_src'])
                    dst_port_list.append(stat.match['tcp_dst'])
                    if stat.packet_count:
                        avg_pkt_size_list.append(stat.byte_count / stat.packet_count)
                    else:
                        avg_pkt_size_list.append(0)
                elif stat.match['ip_proto'] == 17:
                    ip_proto_list.append(stat.match['ip_proto'])
                    src_port_list.append(stat.match['udp_src'])
                    dst_port_list.append(stat.match['udp_dst'])
                    if stat.packet_count:
                        avg_pkt_size_list.append(stat.byte_count / stat.packet_count)
                    else:
                        avg_pkt_size_list.append(0)

            self.flow_container = {'ip_src_list': ip_src_list,
                                   'ip_dst_list': ip_dst_list,
                                   'ip_proto_list': ip_proto_list,
                                   'src_port_list': src_port_list,
                                   'dst_port_list': dst_port_list,
                                   'avg_pkt_size_list': avg_pkt_size_list}
        # self.logger.info(ip_proto_list)
        # self.logger.info(src_port_list)
        # self.logger.info(dst_port_list)
        # self.logger.info(avg_pkt_size_list)
