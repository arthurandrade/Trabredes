from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import ipv4, ipv6, arp, tcp
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import inet
from random import randint
from ryu.lib import hub
import sys
import pdb

class L2Switch(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.tabelaPacotesGrandes=[]
        self.tabelaPacotesPequenos=[]
        self.total = 0;
        self.monitor_thread = hub.spawn(self._monitor)
        
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
        
        
        
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        #pdb.set_trace()
        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)
    
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
        
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        #pdb.set_trace()
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]      
        
   