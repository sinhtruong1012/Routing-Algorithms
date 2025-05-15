####################################################
# LSrouter.py
# Name:
# HUID:
#####################################################

import json
import logging
import heapq
from router import Router
from packet import Packet

class LSrouter(Router):
    """Giao thức định tuyến Link-State."""

    def __init__(self, addr, heartbeat_time):
        super().__init__(addr)
        self.heartbeat_time = heartbeat_time  # Thời gian gửi LSP định kỳ (ms)
        self.last_time = 0  # Thời điểm xử lý cuối
        self.link_state_db = {addr: (0, {})}  # {router: (số thứ tự, {hàng xóm: chi phí})}
        self.sequence_number = 0  # Số thứ tự LSP
        self.forwarding_table = {}  # {đích: cổng}
        self.neighbors = {}  # {cổng: (địa chỉ, chi phí)}

        # Thiết lập logging
        self.logger = logging.getLogger(f"LS_{addr}")
        self.logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler(f"router_{addr}.log", mode='w')
        formatter = logging.Formatter('[%(asctime)s] [LS_%(name)s] %(message)s')
        file_handler.setFormatter(formatter)
        self.logger.handlers = []
        self.logger.addHandler(file_handler)
        self.logger.info(f"Khoi dong router {addr} voi thoi gian phat {heartbeat_time} ms")

    def handle_packet(self, port, packet):
        """Xử lý gói tin đến từ cổng."""
        self.logger.info(f"Nhan goi tu cong {port}, nguon {packet.src_addr}, dich {packet.dst_addr}, traceroute: {packet.is_traceroute}")
        if packet.is_traceroute:
            if packet.dst_addr in self.forwarding_table:
                out_port = self.forwarding_table[packet.dst_addr]
                self.logger.info(f"Chuyen goi traceroute den {packet.dst_addr} qua cong {out_port}")
                self.send(out_port, packet)
            else:
                self.logger.info(f"Khong co duong den dich {packet.dst_addr}")
            return

        try:
            ls_info = json.loads(packet.content)
            src_addr = ls_info['src_addr']
            sequence_number = ls_info['sequence_number']
            link_state = ls_info['link_state']
            self.logger.info(f"Nhan LSP tu {src_addr}, so thu tu {sequence_number}, lien ket: {link_state}")
            is_new_or_updated = False
            if src_addr not in self.link_state_db or sequence_number > self.link_state_db[src_addr][0]:
                is_new_or_updated = True
                self.link_state_db[src_addr] = (sequence_number, link_state)
                self.logger.info(f"Cap nhat link_state_db cho {src_addr}, so thu tu {sequence_number}")
                self.update_forwarding_table()
                for neighbor_port in self.neighbors:
                    if neighbor_port != port:
                        self.logger.info(f"Phat LSP tu {src_addr} den hang xom qua cong {neighbor_port}")
                        self.send(neighbor_port, packet)
            else:
                self.logger.info(f"Bo LSP cu tu {src_addr}, so thu tu {sequence_number}")
        except json.JSONDecodeError:
            self.logger.info(f"Goi tu cong {port} khong dung dinh dang")

    def handle_new_link(self, port, endpoint, cost):
        """Thêm liên kết mới đến hàng xóm."""
        self.neighbors[port] = (endpoint, cost)
        self.logger.info(f"Them lien ket den {endpoint} qua cong {port}, chi phi {cost}")
        self.update_own_link_state()
        self.update_forwarding_table()
        self.broadcast_link_state()

    def handle_remove_link(self, port):
        """Xóa liên kết với hàng xóm."""
        if port not in self.neighbors:
            self.logger.info(f"Cong {port} khong co lien ket")
            return
        neighbor, _ = self.neighbors[port]
        self.logger.info(f"Xoa lien ket den {neighbor} tai cong {port}")
        del self.neighbors[port]
        self.update_own_link_state()
        self.update_forwarding_table()
        self.broadcast_link_state()

    def handle_time(self, time_ms):
        """Xử lý thời gian để gửi LSP định kỳ."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.logger.info(f"Phat LSP dinh ky tai {time_ms} ms")
            self.broadcast_link_state()

    def update_own_link_state(self):
        """Cập nhật trạng thái liên kết của router."""
        new_link_state = {neighbor: cost for _, (neighbor, cost) in self.neighbors.items()}
        self.sequence_number += 1
        self.link_state_db[self.addr] = (self.sequence_number, new_link_state)
        self.logger.info(f"Cap nhat link_state_db cua {self.addr}, so thu tu {self.sequence_number}")

    def update_forwarding_table(self):
        """Tính bảng chuyển tiếp bằng Dijkstra."""
        self.logger.info(f"Tinh bang chuyen tiep voi link_state_db: {self.link_state_db}")
        graph = {}
        for router, (_, link_state) in self.link_state_db.items():
            graph[router] = link_state
            for neighbor in link_state:
                if neighbor not in graph:
                    graph[neighbor] = {}
        distances, predecessors = self.dijkstra(graph, self.addr)
        new_forwarding_table = {}
        for dest in distances:
            if dest == self.addr or distances[dest] == float('inf'):
                continue
            next_hop = dest
            while predecessors.get(next_hop) and predecessors[next_hop] != self.addr:
                next_hop = predecessors[next_hop]
            for port, (neighbor, _) in self.neighbors.items():
                if neighbor == next_hop:
                    new_forwarding_table[dest] = port
                    self.logger.info(f"Them duong den {dest} qua cong {port}, buoc nhay {next_hop}, chi phi {distances[dest]}")
                    break
        self.forwarding_table = new_forwarding_table
        self.logger.info(f"Bang chuyen tiep moi: {self.forwarding_table}")

    def dijkstra(self, graph, source):
        """Tìm đường ngắn nhất bằng thuật toán Dijkstra."""
        distances = {node: float('inf') for node in graph}
        predecessors = {node: None for node in graph}
        distances[source] = 0
        pq = [(0, source)]
        visited = set()
        while pq:
            current_distance, current_node = heapq.heappop(pq)
            if current_node in visited:
                continue
            visited.add(current_node)
            for neighbor, weight in graph.get(current_node, {}).items():
                distance = current_distance + weight
                if distance < distances[neighbor]:
                    distances[neighbor] = distance
                    predecessors[neighbor] = current_node
                    heapq.heappush(pq, (distance, neighbor))
                    self.logger.info(f"Cap nhat chi phi den {neighbor}: {distance} qua {current_node}")
        return distances, predecessors

    def broadcast_link_state(self):
        """Gửi LSP đến tất cả hàng xóm."""
        _, link_state = self.link_state_db[self.addr]
        ls_content = {
            'src_addr': self.addr,
            'sequence_number': self.sequence_number,
            'link_state': link_state
        }
        content_str = json.dumps(ls_content)
        packet = Packet(Packet.ROUTING, self.addr, None, content_str)
        for port, (neighbor, _) in self.neighbors.items():
            self.logger.info(f"Gui LSP den {neighbor} qua cong {port}, so thu tu {self.sequence_number}")
            self.send(port, packet)

    def __repr__(self):
        """Trạng thái router."""
        output = f"LSrouter(addr={self.addr}, seq={self.sequence_number})\n"
        output += "Link State:\n"
        _, link_state = self.link_state_db.get(self.addr, (0, {}))
        for neighbor, cost in link_state.items():
            output += f"  {neighbor}: {cost}\n"
        output += "Forwarding Table:\n"
        for dest, port in self.forwarding_table.items():
            output += f"  {dest} -> Port {port}\n"
        return output
