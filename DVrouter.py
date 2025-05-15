import json  # Thư viện để mã hóa và giải mã dữ liệu JSON trong gói tin
import logging  # Thư viện để ghi log, hỗ trợ debug trạng thái router
from router import Router  # Lớp cơ sở Router cung cấp các phương thức như send, add_link
from packet import Packet  # Lớp Packet định nghĩa cấu trúc gói tin (traceroute, routing)

class DVrouter(Router):
    """Triển khai giao thức định tuyến vector khoảng cách (Distance Vector)."""

    INFINITY = 16  # Giới hạn khoảng cách tối đa để ngăn vấn đề count-to-infinity

    def __init__(self, addr, heartbeat_time):
        super().__init__(addr)  # Gọi hàm khởi tạo của lớp cha Router với địa chỉ router
        self.heartbeat_time = heartbeat_time  # Thời gian định kỳ gửi DV (milliseconds)
        self.temporary_heartbeat_time = heartbeat_time / 4  # Thời gian gửi DV tạm thời khi có thay đổi
        self.heartbeat_reduction_duration = heartbeat_time * 3  # Thời gian duy trì gửi DV tạm thời
        self.last_time = 0  # Thời điểm cuối cùng xử lý handle_time
        self.distance_vector = {addr: (0, None)}  # Bảng định tuyến: {đích: (khoảng cách, cổng)}
        self.neighbors = {}  # Danh sách hàng xóm: {cổng: (địa chỉ hàng xóm, chi phí)}
        self.neighbor_dvs = {}  # Distance vector của hàng xóm: {địa chỉ hàng xóm: DV}
        self.recent_change = False  # Cờ báo có thay đổi gần đây trong bảng định tuyến
        self.recent_change_time = 0  # Thời điểm xảy ra thay đổi gần nhất
        self.last_broadcast_dv = {}  # Lưu DV lần cuối gửi để tránh gửi trùng lặp

        # Cấu hình logging
        self.logger = logging.getLogger(f"DVrouter_{addr}")  # Tạo logger với tên router
        self.logger.setLevel(logging.INFO)  # Đặt mức log là INFO
        file_handler = logging.FileHandler(f"router_{addr}.log", mode='w')  # Tạo file log, ghi đè mỗi lần chạy
        formatter = logging.Formatter('[%(asctime)s] [DVrouter_%(name)s] %(message)s')  # Định dạng: [thời gian] [DVrouter_addr] thông điệp
        file_handler.setFormatter(formatter)  # Áp dụng định dạng
        self.logger.handlers = []  # Xóa handler cũ để tránh trùng lặp
        self.logger.addHandler(file_handler)  # Thêm handler
        self.logger.info(f"Khởi tạo router {addr}")  # Ghi log khởi tạo

    def handle_packet(self, port, packet):
        # Xử lý gói tin nhận được từ cổng port
        if packet.is_traceroute:  # Nếu là gói traceroute
            if packet.dst_addr in self.distance_vector:  # Kiểm tra đích có trong bảng định tuyến
                _, next_port = self.distance_vector[packet.dst_addr]  # Lấy cổng tiếp theo đến đích
                if next_port is not None:  # Nếu có cổng tiếp theo
                    self.logger.info(f"Chuyển tiếp traceroute đến {packet.dst_addr} qua cổng {next_port}")  # Ghi log chuyển tiếp
                    self.send(next_port, packet)  # Chuyển tiếp gói đến cổng tiếp theo
                else:  # Nếu không có cổng (đích là chính router)
                    self.logger.info(f"Không có cổng tiếp theo đến {packet.dst_addr}")  # Ghi log không có cổng tiếp theo
            else:  # Nếu đích không có trong bảng định tuyến
                self.logger.info(f"Không biết đích {packet.dst_addr}")  # Ghi log đích không xác định
            return  # Thoát hàm sau khi xử lý traceroute

        try:  # Xử lý gói định tuyến (distance vector)
            neighbor_dv = json.loads(packet.content)  # Giải mã nội dung gói thành dictionary
            neighbor_addr = packet.src_addr  # Lấy địa chỉ hàng xóm gửi gói
            # Kiểm tra hàng xóm hợp lệ
            if neighbor_addr not in [n for p, (n, c) in self.neighbors.items()]:  # Nếu nguồn không phải hàng xóm
                self.logger.info(f"Bỏ qua DV từ {neighbor_addr} vì không phải hàng xóm")  # Ghi log bỏ qua gói
                return  # Thoát hàm
            self.neighbor_dvs[neighbor_addr] = neighbor_dv  # Lưu DV của hàng xóm
            self.logger.info(f"Nhận DV từ {neighbor_addr}: {neighbor_dv}")  # Ghi log nhận DV

            # Cập nhật bảng định tuyến
            changed = self._update_distance_vector()  # Cập nhật distance_vector, kiểm tra thay đổi
            if changed:  # Nếu bảng định tuyến thay đổi
                self.recent_change = True  # Đặt cờ báo có thay đổi
                self.recent_change_time = self.last_time  # Cập nhật thời điểm thay đổi
                self._broadcast_distance_vector()  # Gửi DV mới đến hàng xóm
        except json.JSONDecodeError:  # Nếu nội dung gói không phải JSON hợp lệ
            self.logger.info(f"Gói tin từ cổng {port} không đúng định dạng")  # Ghi log gói lỗi

    def handle_new_link(self, port, endpoint, cost):
        # Xử lý liên kết mới được thêm
        self.neighbors[port] = (endpoint, cost)  # Thêm hàng xóm vào danh sách: cổng -> (địa chỉ, chi phí)
        self.distance_vector[endpoint] = (cost, port)  # Cập nhật khoảng cách đến hàng xóm mới
        self.logger.info(f"Thêm liên kết đến {endpoint} tại cổng {port} với chi phí {cost}")  # Ghi log liên kết mới
        self.recent_change = True  # Đặt cờ báo có thay đổi
        self.recent_change_time = self.last_time  # Cập nhật thời điểm thay đổi

        # Cập nhật bảng định tuyến và gửi DV một lần
        changed = self._update_distance_vector()  # Cập nhật distance_vector cho các đích khác
        self._broadcast_distance_vector()  # Gửi DV vì liên kết mới luôn ảnh hưởng đến DV

    def handle_remove_link(self, port):
        # Xử lý xóa liên kết
        if port not in self.neighbors:  # Nếu cổng không có hàng xóm
            return  # Thoát hàm
        neighbor_addr = self.neighbors[port][0]  # Lấy địa chỉ hàng xóm tại cổng
        self.logger.info(f"Xóa liên kết đến {neighbor_addr} tại cổng {port}")  # Ghi log xóa liên kết
        del self.neighbors[port]  # Xóa hàng xóm khỏi danh sách
        self.neighbor_dvs.pop(neighbor_addr, None)  # Xóa DV của hàng xóm (nếu có)
        if neighbor_addr in self.distance_vector:  # Nếu hàng xóm là đích trong distance_vector
            self.distance_vector.pop(neighbor_addr)  # Xóa đích hàng xóm
        self.recent_change = True  # Đặt cờ báo có thay đổi
        self.recent_change_time = self.last_time  # Cập nhật thời điểm thay đổi

        # Cập nhật bảng định tuyến và gửi DV một lần
        changed = self._update_distance_vector()  # Cập nhật distance_vector cho các đích khác
        self._broadcast_distance_vector()  # Gửi DV vì xóa liên kết luôn ảnh hưởng đến DV

    def handle_time(self, time_ms):
        # Xử lý sự kiện thời gian để gửi DV định kỳ
        if self.recent_change and (time_ms - self.recent_change_time) < self.heartbeat_reduction_duration:
            current_heartbeat = self.temporary_heartbeat_time  # Dùng chu kỳ ngắn nếu có thay đổi gần đây
        else:
            current_heartbeat = self.heartbeat_time  # Dùng chu kỳ bình thường
            self.recent_change = False  # Xóa cờ thay đổi nếu ngoài khoảng thời gian

        if time_ms - self.last_time >= current_heartbeat:  # Nếu đến thời điểm gửi DV định kỳ
            self.last_time = time_ms  # Cập nhật thời điểm xử lý cuối
            # Cập nhật bảng định tuyến
            changed = self._update_distance_vector()  # Cập nhật distance_vector, kiểm tra thay đổi
            # Gửi DV định kỳ nếu cần
            current_dv = {dst: dist for dst, (dist, _) in self.distance_vector.items() if dist < self.INFINITY}  # Tạo DV hiện tại
            if changed or current_dv != self.last_broadcast_dv or self.recent_change:  # Nếu DV thay đổi, khác lần trước, hoặc có thay đổi gần đây
                self._broadcast_distance_vector()  # Gửi DV đến hàng xóm

    def _update_distance_vector(self):
        """Cập nhật distance vector và trả về True nếu có thay đổi."""
        changed = False  # Cờ báo bảng định tuyến có thay đổi
        all_dsts = set(self.distance_vector.keys()) | {dst for dv in self.neighbor_dvs.values() for dst in dv}  # Tập hợp tất cả đích
        for dst in all_dsts:  # Duyệt qua từng đích
            if dst == self.addr:  # Bỏ qua chính router
                continue  # Chuyển sang đích tiếp theo
            new_dist, new_port = self._calculate_min_distance(dst)  # Tính khoảng cách tối thiểu đến đích
            old_dist, old_port = self.distance_vector.get(dst, (self.INFINITY, None))  # Lấy khoảng cách hiện tại
            if new_dist != old_dist or new_port != old_port:  # Nếu khoảng cách hoặc cổng thay đổi
                if new_dist >= self.INFINITY:  # Nếu khoảng cách quá lớn (không thể đến)
                    self.distance_vector.pop(dst, None)  # Xóa đích khỏi bảng định tuyến
                else:  # Nếu khoảng cách hợp lệ
                    self.distance_vector[dst] = (new_dist, new_port)  # Cập nhật bảng định tuyến
                changed = True  # Đánh dấu bảng định tuyến đã thay đổi
        return changed  # Trả về True nếu có thay đổi

    def _calculate_min_distance(self, dst):
        # Tính khoảng cách tối thiểu đến đích dst
        min_dist = self.INFINITY  # Khởi tạo khoảng cách nhỏ nhất là vô cực
        best_port = None  # Cổng tốt nhất để đến đích
        for port, (neighbor, cost) in self.neighbors.items():  # Duyệt qua các hàng xóm
            if neighbor == dst:  # Nếu hàng xóm chính là đích
                return (cost, port)  # Trả về chi phí và cổng trực tiếp
            neighbor_dv = self.neighbor_dvs.get(neighbor, {})  # Lấy DV của hàng xóm
            neighbor_cost = neighbor_dv.get(dst, self.INFINITY)  # Lấy khoảng cách từ hàng xóm đến đích
            total_cost = cost + neighbor_cost  # Tính tổng chi phí qua hàng xóm
            if total_cost < min_dist and total_cost < self.INFINITY:  # Nếu chi phí nhỏ hơn và hợp lệ
                min_dist = total_cost  # Cập nhật khoảng cách nhỏ nhất
                best_port = port  # Cập nhật cổng tốt nhất
        return (min_dist, best_port)  # Trả về khoảng cách và cổng tốt nhất

    def _broadcast_distance_vector(self):
        # Gửi distance vector đến tất cả hàng xóm
        dv_payload = {dst: dist for dst, (dist, _) in self.distance_vector.items() if dist < self.INFINITY}  # Tạo DV để gửi
        packet = Packet(Packet.ROUTING, self.addr, None, content=json.dumps(dv_payload))  # Tạo gói định tuyến
        for port in self.neighbors:  # Duyệt qua các cổng hàng xóm
            self.send(port, packet)  # Gửi gói đến hàng xóm
        self.logger.info(f"Gửi DV: {dv_payload}")  # Ghi log gửi DV
        self.last_broadcast_dv = dv_payload  # Lưu DV để so sánh lần sau

    def __repr__(self):
        # Trả về chuỗi biểu diễn trạng thái router để debug
        dv_str = ", ".join(f"{dst}: {dist} qua cổng {port}" for dst, (dist, port) in self.distance_vector.items())  # Chuỗi distance vector
        neighbors_str = ", ".join(f"{n}: chi phí {c} qua cổng {p}" for p, (n, c) in self.neighbors.items())  # Chuỗi hàng xóm
        return f"DVrouter(địa chỉ={self.addr}, distance_vector={{{dv_str}}}, hàng xóm={{{neighbors_str}}})"  # Chuỗi trạng thái