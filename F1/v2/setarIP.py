from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import ipv4, ipv6, arp
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import inet
import sys
import pdb

class L2Switch(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = Packet(msg.data)
        dp = msg.datapath
        
        in_port = msg.match['in_port']
        
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        
        #pdb.set_trace()

        actions = []
        
        #dp.send_msg(out)
        
        ip = pkt.get_protocol(ipv4.ipv4)
        
        print ip
            
        if ip:
            print ip
            #actions.append(ofp.OFPActionDecNwTtl()) 
                        
        
        actions.append(ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD))
        
        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions)
        dp.send_msg(out)
                
            
        
        
            
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
        
