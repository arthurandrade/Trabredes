from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import ipv4, ipv6, arp, tcp, ethernet
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
        self.mac_to_port = {}
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = Packet(msg.data)
        dp = msg.datapath
        buffer_id = msg.buffer_id
        in_port = msg.match['in_port']
        match_old = msg.match
        
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        
        #pdb.set_trace()

        actions = []
        instructions = []
        #dp.send_msg(out)
        
        ip = pkt.get_protocol(ipv4.ipv4)
        tcp1 = pkt.get_protocol(tcp.tcp)       
        pk_tcp = pkt.get_protocol(tcp.tcp)
        #self.total = self.total + pk_tcp.window_size
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst  # destination MAC
        src = eth.src  # source MAC   
        
        actions.append(ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD))
        
        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions)
        dp.send_msg(out)
        
        op = randint(0,1)
        actions = []
        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            #if destination is know send it to the right port
            out_port = self.mac_to_port[dpid][dst]
        else:
            #otherwise, flood
            out_port = ofp.OFPP_FLOOD
                    
        if ip and tcp1:
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
        self._send_packet(pkt)
        if ip and tcp1:
            actions.append(dp.ofproto_parser.OFPActionSetNwTtl(10))
            match = dp.ofproto_parser.OFPMatch(dl_dst=ip.dst,dl_src=ip.src,src_port = tcp1.src_port, dst_port =tcp1.dst_port)
            instructions =[OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions=actions)]
            prio = 100 
        else:
            match = match_old
            prio = 1
            
        actions.append(dp.ofproto_parser.OFPActionOutput(out_port))
        
        if out_port != ofp.OFPP_FLOOD:
            mod = dp.ofproto_parser.OFPFlowMod(datapath=dp, cookie=0, cookie_mask=0, table_id=0, command=0,buffer_id = buffer_id,
                                                     idle_timeout=0, hard_timeout=0, priority=prio, out_port=out_port,
                                                     flags=ofp.OFPFF_SEND_FLOW_REM, match=match, instructions=instructions)
            dp.send_msg(mod)
        out = dp.ofproto_parser.OFPPacketOut(datapath=dp, in_port=in_port,buffer_id = buffer_id, actions=actions)
        dp.send_msg(out)  
            
    def _send_packet(self,pkt):
        self.logger.info("packet-out %s" % (pkt,))
        
     
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
            
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
            
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)