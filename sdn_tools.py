from pox.core import core
import pox.openflow.libopenflow_01 as of
from sklearn.cluster import KMeans
import numpy as np

log = core.getLogger()

class CustomController(object):
    def __init__(self):
        self.blocked_ips = set()  # For security features
        self.traffic_stats = {}  # For traffic monitoring
        self.ml_model = self.train_ml_model()  # For basic anomaly detection
        
        # Listen to connection events
        core.openflow.addListeners(self)

    def train_ml_model(self):
        # Simple KMeans clustering to classify normal vs. abnormal traffic patterns
        data = np.array([[10], [20], [15], [30], [1000]])  # Sample data (e.g., packet counts)
        labels = [0, 0, 0, 0, 1]  # 0 = normal, 1 = abnormal
        model = KMeans(n_clusters=2)
        model.fit(data)
        return model

    def is_anomalous(self, value):
        # Predict if a value (e.g., packet count) is abnormal
        cluster = self.ml_model.predict(np.array([[value]]))[0]
        return cluster == 1  # Cluster 1 is treated as abnormal

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s has connected", event.dpid)
        # Install a rule to flood all unmatched packets
        msg = of.ofp_flow_mod()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet:
            log.warning("Ignoring incomplete packet")
            return
        
        src_ip = str(packet.next.srcip) if packet.next else None
        dst_ip = str(packet.next.dstip) if packet.next else None

        # Security: Block traffic from specific IPs
        if src_ip in self.blocked_ips:
            log.info("Blocking traffic from %s", src_ip)
            return

        # Application-Aware: Prioritize ICMP traffic
        if packet.type == packet.IP_TYPE and packet.payload.protocol == packet.payload.ICMP_PROTOCOL:
            log.info("Prioritizing ICMP traffic from %s to %s", src_ip, dst_ip)
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet)
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            event.connection.send(msg)
            return

        # Machine Learning: Detect abnormal traffic
        packet_count = self.traffic_stats.get(src_ip, 0) + 1
        self.traffic_stats[src_ip] = packet_count
        if self.is_anomalous(packet_count):
            log.warning("Anomalous traffic detected from %s! Blocking it.", src_ip)
            self.blocked_ips.add(src_ip)
            return

        # Default: Flood packet
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)
        log.info("Installed flow for packet from %s to %s", src_ip, dst_ip)

def launch():
    log.info("Launching Custom Controller with Security, Application-Aware Networking, and ML Features")
    core.registerNew(CustomController)
