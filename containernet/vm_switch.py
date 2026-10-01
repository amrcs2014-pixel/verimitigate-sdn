"""Ryu app mirroring the emulator's pipeline: table 0 = security table (responder rules, default goto 1),
table 1 = L2 learning forwarding (as ryu.app.simple_switch_13, but in table 1)."""
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types


class VMSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.mac_to_port = {}

    def add_flow(self, dp, table, prio, match, inst):
        p = dp.ofproto_parser
        dp.send_msg(p.OFPFlowMod(datapath=dp, table_id=table, priority=prio, match=match, instructions=inst))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features(self, ev):
        dp = ev.msg.datapath; o = dp.ofproto; p = dp.ofproto_parser
        self.add_flow(dp, 0, 0, p.OFPMatch(), [p.OFPInstructionGotoTable(1)])                  # security default
        self.add_flow(dp, 1, 0, p.OFPMatch(), [p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS,
                                                [p.OFPActionOutput(o.OFPP_CONTROLLER, o.OFPCML_NO_BUFFER)])])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg; dp = msg.datapath; o = dp.ofproto; p = dp.ofproto_parser
        in_port = msg.match["in_port"]
        eth = packet.Packet(msg.data).get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        tbl = self.mac_to_port.setdefault(dp.id, {})
        tbl[eth.src] = in_port
        out = tbl.get(eth.dst, o.OFPP_FLOOD)
        actions = [p.OFPActionOutput(out)]
        if out != o.OFPP_FLOOD:
            self.add_flow(dp, 1, 1, p.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src),
                          [p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS, actions)])
        data = msg.data if msg.buffer_id == o.OFP_NO_BUFFER else None
        dp.send_msg(p.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data))
