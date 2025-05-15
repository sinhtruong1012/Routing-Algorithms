from router import Router
from packet import Packet
import json
import heapq
import logging

class LSrouter(Router):
    """Triển khai giao thức định tuyến trạng thái liên kết."""

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Khởi tạo lớp cha
        self.heartbeat_time = heartbeat_time  # Thời gian giữa các lần gửi tín hiệu heartbeat
        self.last_time = 0  # Thời điểm cuối cùng gửi tín hiệu heartbeat
        self.ls_db = {addr: [0, {}]}  # Cơ sở dữ liệu trạng thái liên kết: {địa chỉ router: [số thứ tự, {hàng xóm: chi phí}]}
        self.forwarding_table = {}    # Bảng chuyển tiếp: {đích: (bước nhảy tiếp theo, chi phí)}
        self.neighbors = {}           # Các hàng xóm: {cổng: địa chỉ hàng xóm}
        self.neighbor_costs = {}      # Chi phí đến các hàng xóm: {địa chỉ hàng xóm: chi phí}
        self.seq_num = 0              # Số thứ tự cho các gói trạng thái liên kết

        # Thiết lập logging
        self.logger = logging.getLogger(str(addr))  # Tạo logger với tên là địa chỉ router
        self.logger.setLevel(logging.INFO)  # Đặt mức log là INFO
        file_handler = logging.FileHandler(f"router_{addr}.log", mode='w')  # Tạo file log, ghi đè mỗi lần chạy
        formatter = logging.Formatter('[%(asctime)s] [LSrouter_%(name)s] %(message)s')  # Định dạng: [thời gian] [LSrouter_addr] thông điệp
        file_handler.setFormatter(formatter)  # Áp dụng định dạng
        self.logger.handlers = []  # Xóa handler cũ để tránh trùng lặp
        self.logger.addHandler(file_handler)  # Thêm handler
        self.logger.info(f"Khởi tạo router {addr} với heartbeat_time {heartbeat_time} ms")

    def handle_packet(self, port, packet):
        """Xử lý gói tin đến."""
        self.logger.info(f"Nhận gói tin trên cổng {port} từ {packet.src_addr} (đích: {packet.dst_addr}, là traceroute: {packet.is_traceroute})")
        if packet.is_traceroute:
            # Xử lý gói tin dữ liệu
            dst = packet.dst_addr
            if dst in self.forwarding_table:
                next_hop, cost = self.forwarding_table[dst]
                for neighbor_port, neighbor_addr in self.neighbors.items():
                    if neighbor_addr == next_hop:
                        self.logger.info(f"Chuyển tiếp gói tin dữ liệu đến {dst} qua cổng {neighbor_port} (bước nhảy tiếp theo: {next_hop}, chi phí: {cost})")
                        self.send(neighbor_port, packet)
                        break
            else:
                self.logger.info(f"Không có tuyến đến đích {dst} (bảng chuyển tiếp: {self.forwarding_table}), hủy gói tin")
        else:
            # Xử lý gói tin định tuyến (gói trạng thái liên kết)
            try:
                lsp = json.loads(packet.content)
                src = packet.src_addr
                seq_num = lsp['seq_num']
                links = lsp['links']
                self.logger.info(f"Xử lý gói tin trạng thái liên kết từ {src} với số thứ tự {seq_num}, liên kết: {links}")
            except (json.JSONDecodeError, KeyError) as e:
                self.logger.info(f"Gói tin trạng thái liên kết không hợp lệ từ {packet.src_addr}: {str(e)}")
                return

            # Cập nhật cơ sở dữ liệu trạng thái liên kết nếu gói tin là mới
            if src not in self.ls_db or seq_num > self.ls_db[src][0]:
                self.logger.info(f"Cập nhật cơ sở dữ liệu trạng thái liên kết cho {src} với số thứ tự {seq_num}, liên kết: {links}")
                self.ls_db[src] = [seq_num, links]
                # Phát tán đến các hàng xóm khác (loại trừ người gửi)
                for neighbor_port, neighbor_addr in self.neighbors.items():
                    if neighbor_addr != src:
                        self.logger.info(f"Chuyển tiếp gói tin trạng thái liên kết từ {src} đến {neighbor_addr} qua cổng {neighbor_port}")
                        self.send(neighbor_port, packet)
                # Cập nhật bảng chuyển tiếp
                self._compute_forwarding_table()
            else:
                self.logger.info(f"Bỏ qua gói tin trạng thái liên kết cũ/hết hạn từ {src} với số thứ tự {seq_num}")

    def handle_new_link(self, port, endpoint, cost):
        """Xử lý liên kết mới."""
        self.logger.info(f"Thêm liên kết mới: cổng {port} đến {endpoint} với chi phí {cost}")
        # Cập nhật danh sách hàng xóm và cơ sở dữ liệu trạng thái liên kết
        self.neighbors[port] = endpoint
        self.neighbor_costs[endpoint] = cost
        self.ls_db[self.addr][1][endpoint] = cost
        # Thêm hàng xóm vào ls_db với một mục giả nếu là máy khách
        if endpoint not in self.ls_db:
            self.ls_db[endpoint] = [0, {self.addr: cost}]
        # Tăng số thứ tự và phát tán
        self.seq_num += 1
        self.logger.info(f"Tăng số thứ tự lên {self.seq_num}")
        self._broadcast_link_state()
        # Cập nhật bảng chuyển tiếp
        self._compute_forwarding_table()

    def handle_remove_link(self, port):
        """Xử lý liên kết bị xóa."""
        if port in self.neighbors:
            neighbor = self.neighbors[port]
            self.logger.info(f"Xóa liên kết: cổng {port} đến {neighbor}")
            # Xóa hàng xóm và cập nhật cơ sở dữ liệu trạng thái liên kết
            del self.neighbors[port]
            if neighbor in self.neighbor_costs:
                del self.neighbor_costs[neighbor]
            if neighbor in self.ls_db[self.addr][1]:
                del self.ls_db[self.addr][1][neighbor]
            # Không xóa hàng xóm khỏi ls_db trừ khi nó không còn kết nối nào khác
            if neighbor in self.ls_db:
                del self.ls_db[neighbor][1][self.addr]
                if not self.ls_db[neighbor][1]:
                    del self.ls_db[neighbor]
            # Tăng số thứ tự và phát tán
            self.seq_num += 1
            self.logger.info(f"Tăng số thứ tự lên {self.seq_num}")
            self._broadcast_link_state()
            # Cập nhật bảng chuyển tiếp
            self._compute_forwarding_table()
        else:
            self.logger.info(f"Thử xóa liên kết không tồn tại trên cổng {port}")

    def handle_time(self, time_ms):
        """Xử lý thời gian hiện tại."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.logger.info(f"Kích hoạt heartbeat tại thời điểm {time_ms} ms")
            # Phát tán trạng thái liên kết định kỳ
            self._broadcast_link_state()

    def _broadcast_link_state(self):
        """Phát tán trạng thái liên kết hiện tại của router đến tất cả hàng xóm."""
        lsp = {
            'seq_num': self.seq_num,
            'links': self.ls_db[self.addr][1]
        }
        packet = Packet(
            kind=Packet.ROUTING,
            src_addr=self.addr,
            dst_addr=None,  # Phát tán
            content=json.dumps(lsp)
        )
        self.logger.info(f"Phát tán gói tin trạng thái liên kết với số thứ tự {self.seq_num}, liên kết: {lsp['links']}")
        for port in self.neighbors:
            self.logger.info(f"Gửi gói tin trạng thái liên kết đến cổng {port} (hàng xóm: {self.neighbors[port]})")
            self.send(port, packet)

    def _compute_forwarding_table(self):
        """Tính toán bảng chuyển tiếp bằng thuật toán Dijkstra."""
        self.logger.info(f"Tính toán bảng chuyển tiếp với ls_db: {self.ls_db}, hàng xóm: {self.neighbors}")

        # Khởi tạo khoảng cách và tiền tố cho tất cả các nút trong ls_db
        all_nodes = set(self.ls_db.keys())
        distances = {node: float('inf') for node in all_nodes}
        distances[self.addr] = 0
        predecessors = {node: None for node in all_nodes}
        pq = [(0, self.addr)]
        visited = set()

        # Thuật toán Dijkstra
        while pq:
            current_dist, current = heapq.heappop(pq)
            if current in visited:
                continue
            visited.add(current)

            # Xử lý các hàng xóm từ cơ sở dữ liệu trạng thái liên kết
            if current in self.ls_db:
                for neighbor, cost in self.ls_db[current][1].items():
                    # Đảm bảo hàng xóm nằm trong all_nodes
                    if neighbor not in all_nodes:
                        all_nodes.add(neighbor)
                        distances[neighbor] = float('inf')
                        predecessors[neighbor] = None
                    distance = current_dist + cost
                    if distance < distances[neighbor]:
                        distances[neighbor] = distance
                        predecessors[neighbor] = current
                        heapq.heappush(pq, (distance, neighbor))
                        self.logger.info(f"Cập nhật khoảng cách đến {neighbor}: {distance} qua {current}")

        # Xây dựng bảng chuyển tiếp
        self.forwarding_table = {}
        for dest in all_nodes:
            if dest == self.addr or distances[dest] == float('inf'):
                continue
            # Truy ngược để tìm bước nhảy đầu tiên
            path = []
            current = dest
            while current is not None:
                path.append(current)
                current = predecessors[current]
            if self.addr not in path:
                continue
            # Đảo ngược đường đi từ self.addr đến đích
            path = path[::-1]
            if len(path) < 2:
                continue
            next_hop = path[1]  # Bước nhảy đầu tiên sau self.addr
            self.forwarding_table[dest] = (next_hop, distances[dest])
            self.logger.info(f"Thêm tuyến đến {dest} qua bước nhảy tiếp theo {next_hop} với chi phí {distances[dest]} (đường đi: {path})")

        self.logger.info(f"Cập nhật bảng chuyển tiếp: {self.forwarding_table}")

    def __repr__(self):
        """Định dạng hiển thị để gỡ lỗi trong trình trực quan hóa mạng."""
        return (f"LSrouter(địa chỉ={self.addr}, "
                f"hàng xóm={self.neighbors}, "
                f"bảng chuyển tiếp={self.forwarding_table})")