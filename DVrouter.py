####################################################
# DVrouter.py
# Name:
# HUID:
#####################################################

import json
import logging
from router import Router
from packet import Packet

class DVrouter(Router):
    """Giao thức định tuyến Distance Vector."""

    INFINITY = 16  # Giới hạn khoảng cách tối đa để ngăn count-to-infinity

    def __init__(self, addr, heartbeat_time):
        super().__init__(addr)
        self.heartbeat_time = heartbeat_time  # Thời gian gửi bảng định tuyến định kỳ (ms)
        self.last_time = 0  # Thời điểm xử lý cuối
        self.distance_vector = {addr: 0}  # Bảng định tuyến: {đích: khoảng cách}
        self.forwarding_table = {}  # Bảng chuyển tiếp: {đích: cổng}
        self.neighbors = {}  # Hàng xóm: {cổng: (địa chỉ, chi phí)}
        self.neighbor_dv = {}  # Bảng định tuyến của hàng xóm: {địa chỉ: {đích: khoảng cách}}
        self.INFINITY = 16  # Giới hạn khoảng cách
        self.last_broadcast_dv = {}  # Lưu bảng định tuyến đã gửi để tránh gửi trùng

        # Thiết lập logging
        self.logger = logging.getLogger(f"DV_{addr}")
        self.logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler(f"router_{addr}.log", mode='w')
        formatter = logging.Formatter('[%(asctime)s] [DV_%(name)s] %(message)s')
        file_handler.setFormatter(formatter)
        self.logger.handlers = []
        self.logger.addHandler(file_handler)
        self.logger.info(f"Khởi động router {addr} với thời gian phát {heartbeat_time} ms")

    def handle_packet(self, port, packet):
        """Xử lý gói tin đến từ cổng."""
        self.logger.info(f"Nhận gói từ cổng {port}, nguồn {packet.src_addr}, đích {packet.dst_addr}")
        if packet.is_traceroute:
            if packet.dst_addr in self.forwarding_table:
                out_port = self.forwarding_table[packet.dst_addr]
                self.logger.info(f"Chuyển gói traceroute đến {packet.dst_addr} qua cổng {out_port}")
                self.send(out_port, packet)
            else:
                self.logger.info(f"Không có đường đến đích {packet.dst_addr}")
            return

        try:
            src = packet.src_addr
            received_dv = json.loads(packet.content)
            if src not in [addr for _, (addr, _) in self.neighbors.items()]:
                self.logger.info(f"Bỏ bảng từ {src} vì không phải hàng xóm")
                return
            if src not in self.neighbor_dv or self.neighbor_dv[src] != received_dv:
                self.neighbor_dv[src] = received_dv
                self.logger.info(f"Nhận bảng định tuyến từ {src}: {received_dv}")
                self.update_distance_vector()
                self.broadcast_distance_vector()
        except json.JSONDecodeError:
            self.logger.info(f"Gói từ cổng {port} không đúng định dạng")

    def handle_new_link(self, port, endpoint, cost):
        """Thêm liên kết mới đến hàng xóm."""
        self.neighbors[port] = (endpoint, cost)
        self.distance_vector[endpoint] = cost
        self.forwarding_table[endpoint] = port
        self.logger.info(f"Thêm liên kết đến {endpoint} qua cổng {port}, chi phí {cost}")
        self.update_distance_vector()
        self.broadcast_distance_vector()

    def handle_remove_link(self, port):
        """Xóa liên kết với hàng xóm."""
        if port not in self.neighbors:
            self.logger.info(f"Cổng {port} không có liên kết")
            return
        neighbor, _ = self.neighbors[port]
        self.logger.info(f"Xóa liên kết đến {neighbor} tại cổng {port}")
        del self.neighbors[port]
        self.neighbor_dv.pop(neighbor, None)
        self.distance_vector.pop(neighbor, None)
        self.forwarding_table.pop(neighbor, None)
        self.update_distance_vector()
        self.broadcast_distance_vector()

    def handle_time(self, time_ms):
        """Xử lý thời gian để gửi bảng định tuyến định kỳ."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            current_dv = {dst: dist for dst, dist in self.distance_vector.items() if dist < self.INFINITY}
            if self.update_distance_vector() or current_dv != self.last_broadcast_dv:
                self.broadcast_distance_vector()

    def update_distance_vector(self):
        """Cập nhật bảng định tuyến và bảng chuyển tiếp, trả về True nếu có thay đổi."""
        changed = False
        new_dv = {self.addr: 0}
        new_ft = {}

        # Thêm hàng xóm trực tiếp
        for port, (neighbor, cost) in self.neighbors.items():
            new_dv[neighbor] = cost
            new_ft[neighbor] = port

        # Cập nhật các đích khác qua hàng xóm
        for neighbor, routes in self.neighbor_dv.items():
            neighbor_cost = float('inf')
            neighbor_port = None
            for port, (addr, cost) in self.neighbors.items():
                if addr == neighbor:
                    neighbor_cost = cost
                    neighbor_port = port
                    break
            if neighbor_cost < float('inf'):
                for dest, dest_cost in routes.items():
                    total_cost = neighbor_cost + dest_cost
                    if total_cost >= self.INFINITY:
                        total_cost = self.INFINITY
                    if dest not in new_dv or total_cost < new_dv[dest]:
                        new_dv[dest] = total_cost
                        if total_cost < self.INFINITY and dest != self.addr:
                            new_ft[dest] = neighbor_port

        # Kiểm tra thay đổi
        if new_dv != self.distance_vector or new_ft != self.forwarding_table:
            changed = True
            self.distance_vector = new_dv
            self.forwarding_table = new_ft
            self.logger.info(f"Cập nhật bảng định tuyến: {self.distance_vector}")
            self.logger.info(f"Cập nhật bảng chuyển tiếp: {self.forwarding_table}")

        return changed

    def broadcast_distance_vector(self):
        """Gửi bảng định tuyến đến tất cả hàng xóm."""
        dv_content = {dst: dist for dst, dist in self.distance_vector.items() if dist < self.INFINITY}
        packet = Packet(Packet.ROUTING, self.addr, None, json.dumps(dv_content))
        for port in self.neighbors:
            self.send(port, packet)
            self.logger.info(f"Đã gửi bảng định tuyến đến hàng xóm qua cổng {port}: {dv_content}")
        self.last_broadcast_dv = dv_content

    def __repr__(self):
        """Trạng thái router."""
        output = f"DVrouter(addr={self.addr})\n"
        output += "Distance Vector:\n"
        for dest, cost in self.distance_vector.items():
            output += f"  {dest}: {cost}\n"
        output += "Forwarding Table:\n"
        for dest, port in self.forwarding_table.items():
            output += f"  {dest} -> Port {port}\n"
        return output
