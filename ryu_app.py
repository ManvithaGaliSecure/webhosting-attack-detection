"""
Patent Implementation Reference

Patent Number: 5566676
Patentees: Manvitha Gali and Aditya Mahamkali

Description:
This code demonstrates a reference implementation of Claim 4 from the granted
patent "A Method and a System for Detecting a Malicious Attack on a Network."
It applies DBN-based detection of packet attributes to classify malicious traffic
in a web hosting backend environment.

Copyright (c) 2025 Manvitha Gali and Aditya Mahamkali.
All rights reserved.

Usage of this code is for demonstration, research, and authorized development
purposes only. Any commercial use requires proper licensing of the above patent.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
import requests

DBN_URL = "http://127.0.0.1:8000/score"

class HostingController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)

        if not ip:
            return

        features = {
            "packet_size": len(msg.data),
            "packet_length": len(msg.data),
            "bytes_so_far": len(msg.data),
            "mean_packet_length": len(msg.data)
        }

        try:
            r = requests.post(DBN_URL, json=features, timeout=0.5)
            result = r.json()
        except Exception:
            result = {"malicious": False}

        if result["malicious"]:
            self.logger.info("Malicious traffic dropped")
            return
        else:
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)
            datapath.send_msg(out)
