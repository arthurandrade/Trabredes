from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import ipv4, ipv6, arp, tcp
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import inet
from random import randint
import sys
import pdb

class L2Switch(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.tabelaPacotesGrandes=[]
        self.tabelaPacotesPequenos=[]
        self.total = 0;
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = Packet(msg.data)
        dp = msg.datapath
        #self._request_stats(dp)
        in_port = msg.match['in_port']
        
        #self._request_stats(dp)
        
        
        
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        
        #pdb.set_trace()

        actions = []
        
        #dp.send_msg(out)
        
        ip = pkt.get_protocol(ipv4.ipv4)
                
        pk_tcp = pkt.get_protocol(tcp.tcp)
        #self.total = self.total + pk_tcp.window_size
           
        
        actions.append(ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD))
        
        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions)
        dp.send_msg(out)
        
        op = randint(0,1)
                    
        if ip:
            #print ip
            ip.ttl = op
            #print ip
            #actions.append(ofp.OFPActionDecNwTtl()) 
            
            if ip.ttl == 1:
                
                self.tabelaPacotesGrandes.append(ip)
                self.total = self.total + ip.total_length
                print "----------------------------------TTL COM 1----------------------------------"
                
                
            
            else:
                self.tabelaPacotesPequenos.append(ip)
                self.total = self.total + ip.total_length
                print "----------------------------------TTL COM 0----------------------------------"
                
       
        self._send_packet(dp, in_port, pkt)   
           
            
    def _send_packet(self, datapath, port, pkt):
        self.logger.info("packet-out %s" % (pkt,))
        
     
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
            
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
            
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)   
        
        
        
   