from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import ipv4, ipv6, arp
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import inet
from ryu.lib.ofctl_v1_0 import get_flow_stats
from threading import Thread
import sys
import time

def getPeriodicStats(dp):
    """show periodic stats on screen

    :param dp: the datapath from which the stats shall be shown
    """
    waiters = {}
    while True:
        get_flow_stats(dp, waiters)
        #print stats
        time.sleep(1)


class L2Switch(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = Packet(msg.data)
        dp = msg.datapath
        
        
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        dp.send_msg(out)
       
        self.stats_reply_handler(ev)
        
       
       
        P_ip = pkt.get_protocol(ipv4.ipv4)
        if P_ip:
            print(P_ip.ttl)
            pkt.add_protocol(ipv4.ipv4(dst=P_ip.dst,
                                       src=P_ip.src,
                                       proto=inet.IPPROTO_TCP,
                                       ttl=1))
            if ofproto_v1_0.OFP_VERSION == ofp.OFP_VERSION:
                port = ofp.OFPP_NONE
            else:
                port = ofp.OFPP_ANY
        
            self._send_packet(dp, port, pkt)
            
            
        
        
    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        '''actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]'''
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
        
                
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        body = msg.body
        