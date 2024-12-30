from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class CustomController(object):
    def __init__(self):
        # Listen to connection events
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s has connected", event.dpid)
        # Install a rule to flood all unmatched packets
        msg = of.ofp_flow_mod()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

    def _handle_PacketIn(self, event):
        log.info("Packet received from switch %s", event.dpid)
        packet = event.parsed  # The parsed packet
        if not packet:
            log.warning("Ignoring incomplete packet")
            return

        # Create a flow rule for this packet
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = 10  # Rule expiration in seconds
        msg.hard_timeout = 30  # Absolute expiration in seconds
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)
        log.info("Installed flow for packet from %s", packet.src)

def launch():
    log.info("Launching Custom Controller")
    core.registerNew(CustomController)
