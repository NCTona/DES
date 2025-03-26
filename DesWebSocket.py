import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import os
import time
import threading
import hashlib
import json
import websockets


class DESFileTransferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DES File Transfer (WebSocket Version)")
        self.root.geometry("1000x800")

        # Biến cấu hình
        self.key = "183457799B3CDFF2"  # Khóa DES mặc định
        self.host = "localhost"
        self.port = 8080
        self.buffer_size = 4096
        self.server_thread = None
        self.ws_server = None
        self.running = False
        self.shared_files = {}
        self.current_connections = set()

        # Tạo giao diện
        self.create_widgets()

    def create_widgets(self):
        # Frame chính
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Phần cấu hình
        config_frame = ttk.LabelFrame(main_frame, text="Cấu hình", padding="10")
        config_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))

        # Key
        ttk.Label(config_frame, text="Khóa DES (8 ký tự):").grid(row=0, column=0, sticky="w")
        self.key_entry = ttk.Entry(config_frame, width=30)
        self.key_entry.grid(row=0, column=1, sticky="ew", padx=5)
        self.key_entry.insert(0, self.key)

        # Host và Port
        ttk.Label(config_frame, text="Host:").grid(row=1, column=0, sticky="w")
        self.host_entry = ttk.Entry(config_frame, width=30)
        self.host_entry.grid(row=1, column=1, sticky="ew", padx=5)
        self.host_entry.insert(0, self.host)

        ttk.Label(config_frame, text="Port:").grid(row=2, column=0, sticky="w")
        self.port_entry = ttk.Entry(config_frame, width=30)
        self.port_entry.grid(row=2, column=1, sticky="ew", padx=5)
        self.port_entry.insert(0, str(self.port))

        # Thêm phần Ngrok/Public Domain
        self.public_domain_var = tk.BooleanVar()
        self.public_domain_cb = ttk.Checkbutton(config_frame, text="Public Domain",
                                                variable=self.public_domain_var,
                                                command=self.toggle_public_domain)
        self.public_domain_cb.grid(row=3, column=0, sticky="w", padx=5)

        ttk.Label(config_frame, text="Ngrok URL:").grid(row=4, column=0, sticky="w")
        self.ngrok_entry = ttk.Entry(config_frame, width=30)
        self.ngrok_entry.grid(row=4, column=1, sticky="ew", padx=5)
        self.ngrok_entry.insert(0, "your-ngrok-url.ngrok-free.app")
        self.ngrok_entry.config(state='disabled')

        # Phần file
        file_frame = ttk.LabelFrame(main_frame, text="File", padding="10")
        file_frame.grid(row=1, column=0, sticky="ew", pady=(0, 15))

        ttk.Label(file_frame, text="File nguồn:").grid(row=0, column=0, sticky="w")
        self.file_path_entry = ttk.Entry(file_frame, width=70)
        self.file_path_entry.grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(file_frame, text="Chọn file", command=self.select_file).grid(row=0, column=2, padx=5)

        # Phần thao tác
        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=2, column=0, sticky="ew", pady=(0, 15))

        ttk.Button(action_frame, text="Mã hóa File", command=self.encrypt_file).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Gửi File", command=self.send_file).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Nhận File", command=self.start_server).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Giải mã File", command=self.decrypt_file).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Danh sách File", command=self.list_files).pack(side="left", padx=5)

        # Console log
        log_frame = ttk.LabelFrame(main_frame, text="Nhật ký hoạt động", padding="10")
        log_frame.grid(row=3, column=0, sticky="nsew")

        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, wrap=tk.WORD, font=('Consolas', 10))
        self.log_text.pack(fill="both", expand=True)

        # Cấu hình grid weights
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)

        self.IP = [
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        ]

        self.FP = [
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        ]

        self.PC1 = [
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        ]

        self.PC2 = [
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        ]

        self.E = [
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        ]

        self.S_BOX = [
            # S1
            [
                [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
            ],
            # S2
            [
                [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
            ],
            # S3
            [
                [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
            ],
            # S4
            [
                [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
            ],
            # S5
            [
                [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
            ],
            # S6
            [
                [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
            ],
            # S7
            [
                [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
            ],
            # S8
            [
                [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
            ]
        ]

        self.P = [
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
        ]

        self.SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    def toggle_public_domain(self):
        """Bật/tắt chế độ public domain (ngrok)"""
        if self.public_domain_var.get():
            self.ngrok_entry.config(state='normal')
            self.host_entry.config(state='disabled')
            self.port_entry.config(state='disabled')
        else:
            self.ngrok_entry.config(state='disabled')
            self.host_entry.config(state='normal')
            self.port_entry.config(state='normal')

    def log_message(self, message):
        """Thêm message vào log với timestamp"""
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update()

    def select_file(self):
        """Chọn file để mã hóa"""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, file_path)
            self.log_message(f"Đã chọn file: {file_path}")

    # =============================================
    # CÁC HÀM MÃ HÓA/GIẢI MÃ DES
    # =============================================

    def hex_to_bin(self, hex_str, pad=64):
        """Chuyển hex sang binary (mặc định 64-bit)"""
        return bin(int(hex_str, 16))[2:].zfill(pad)

    def bin_to_hex(self, bin_str):
        """Chuyển binary sang hex (tự động căn độ dài chẵn)"""
        hex_len = (len(bin_str) + 3) // 4
        return hex(int(bin_str, 2))[2:].upper().zfill(hex_len)

    def permute(self, bits, table):
        """Hoán vị các bit theo bảng hoán vị"""
        return ''.join([bits[i - 1] for i in table])

    def left_shift(self, bits, n):
        """Dịch vòng trái n bit"""
        return bits[n:] + bits[:n]

    def xor(self, a, b):
        """Phép XOR giữa hai chuỗi bit"""
        return ''.join(str(int(x) ^ int(y)) for x, y in zip(a, b))

    def generate_subkeys(self, key):
        """Tạo 16 subkey từ khóa chính"""
        key_bin = self.hex_to_bin(key)
        key_pc1 = self.permute(key_bin, self.PC1)

        left = key_pc1[:28]
        right = key_pc1[28:]

        subkeys = []
        for shift in self.SHIFT_SCHEDULE:
            left = self.left_shift(left, shift)
            right = self.left_shift(right, shift)
            subkey = self.permute(left + right, self.PC2)
            subkeys.append(subkey)

        return subkeys

    def s_box_substitution(self, bits):
        """Thay thế 48-bit qua 8 S-box thành 32-bit"""
        result = []
        for i in range(8):
            block = bits[i * 6:(i + 1) * 6]
            row = int(block[0] + block[5], 2)
            col = int(block[1:5], 2)
            val = self.S_BOX[i][row][col]
            result.append(bin(val)[2:].zfill(4))
        return ''.join(result)

    def des_round(self, left, right, subkey):
        """Một vòng Feistel của DES"""
        right_expanded = self.permute(right, self.E)
        xor_result = self.xor(right_expanded, subkey)
        sbox_result = self.s_box_substitution(xor_result)
        p_result = self.permute(sbox_result, self.P)
        new_right = self.xor(left, p_result)
        return right, new_right

    def des_encrypt_block(self, block_hex, subkeys):
        """Mã hóa 1 block 64-bit (dạng hex)"""
        block_bin = self.hex_to_bin(block_hex)
        block_ip = self.permute(block_bin, self.IP)

        left = block_ip[:32]
        right = block_ip[32:]

        for i in range(16):
            left, right = self.des_round(left, right, subkeys[i])

        ciphertext = self.permute(right + left, self.FP)
        return self.bin_to_hex(ciphertext)

    def des_decrypt_block(self, block_hex, subkeys):
        """Giải mã 1 block 64-bit (dạng hex)"""
        block_bin = self.hex_to_bin(block_hex)
        block_ip = self.permute(block_bin, self.IP)

        left = block_ip[:32]
        right = block_ip[32:]

        for i in range(15, -1, -1):
            left, right = self.des_round(left, right, subkeys[i])

        plaintext = self.permute(right + left, self.FP)
        return self.bin_to_hex(plaintext)

    def pad_data(self, data):
        """Padding dữ liệu cho đủ bội số của 8 bytes"""
        pad_len = 8 - (len(data) % 8)
        return data + bytes([pad_len] * pad_len)

    def unpad_data(self, data):
        """Gỡ padding"""
        pad_len = data[-1]
        return data[:-pad_len]

    def calculate_file_hash(self, file_path):
        """Tính toán hash của file để làm ID duy nhất"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def start_server(self):
        """Khởi động WebSocket server"""
        if self.server_thread and self.server_thread.is_alive():
            messagebox.showinfo("Thông báo", "Server đã được khởi động trước đó")
            return

        try:
            port = int(self.port_entry.get())
            self.running = True
            self.server_thread = threading.Thread(
                target=self.run_websocket_server,
                args=(port,),
                daemon=True
            )
            self.server_thread.start()

            host = self.host_entry.get()
            self.log_message(f"WebSocket Server đang chạy tại ws://{host}:{port}")
            messagebox.showinfo("Thành công", f"Server đã khởi động tại port {port}")
        except Exception as e:
            self.log_message(f"Lỗi khi khởi động server: {str(e)}")
            messagebox.showerror("Lỗi", f"Không thể khởi động server: {str(e)}")

    def run_websocket_server(self, port):
        """Chạy WebSocket server"""
        with websockets.serve(self.handle_client, "0.0.0.0", port) as server:
            self.ws_server = server
            self.log_message("WebSocket server đã sẵn sàng")
            server.serve_forever()

    def handle_client(self, websocket):
        """Xử lý kết nối từ client"""
        self.current_connections.add(websocket)
        client_address = websocket.remote_address[0]
        self.log_message(f"Client kết nối từ {client_address}")

        try:
            while self.running:
                message = websocket.recv()
                if isinstance(message, str):
                    data = json.loads(message)

                    if data.get('type') == 'list_request':
                        # Gửi danh sách file
                        response = {
                            'type': 'list_response',
                            'files': {k: {
                                'name': v['name'],
                                'size': v['size'],
                                'time': v['time']
                            } for k, v in self.shared_files.items()}
                        }
                        websocket.send(json.dumps(response))

                    elif data.get('type') == 'download_request':
                        # Xử lý yêu cầu tải file
                        file_hash = data.get('file_hash')
                        if file_hash in self.shared_files:
                            file_info = self.shared_files[file_hash]
                            self.send_file_via_websocket(websocket, file_info)
                        else:
                            websocket.send(json.dumps({
                                'type': 'error',
                                'message': 'File not found'
                            }))

        except websockets.ConnectionClosed:
            self.log_message(f"Client {client_address} đã ngắt kết nối")
        except Exception as e:
            self.log_message(f"Lỗi với client {client_address}: {str(e)}")
        finally:
            self.current_connections.remove(websocket)

    def send_file_via_websocket(self, websocket, file_info):
        """Gửi file qua WebSocket"""
        try:
            # Gửi thông tin file trước
            websocket.send(json.dumps({
                'type': 'file_info',
                'name': file_info['name'],
                'size': file_info['size']
            }))

            # Gửi dữ liệu file
            with open(file_info['path'], 'rb') as f:
                total_sent = 0
                start_time = time.time()

                while True:
                    chunk = f.read(self.buffer_size)
                    if not chunk:
                        break

                    websocket.send(chunk)
                    total_sent += len(chunk)

                    # Cập nhật tiến trình
                    progress = total_sent / file_info['size'] * 100
                    self.log_message(f"Đã gửi {total_sent}/{file_info['size']} bytes ({progress:.1f}%)")

                elapsed = time.time() - start_time
                speed = file_info['size'] / (1024 * elapsed) if elapsed > 0 else 0
                self.log_message(f"Đã gửi xong file {file_info['name']}")
                self.log_message(f"Thời gian: {elapsed:.2f} giây ({speed:.2f} KB/s)")

        except Exception as e:
            self.log_message(f"Lỗi khi gửi file: {str(e)}")

    def send_file(self):
        """Gửi file qua WebSocket"""
        input_file = self.file_path_entry.get()
        if not input_file:
            messagebox.showerror("Lỗi", "Vui lòng chọn file trước khi gửi")
            return

        # Xác định URL đích
        if self.public_domain_var.get():
            ws_url = f"wss://{self.ngrok_entry.get()}"
        else:
            host = self.host_entry.get()
            port = self.port_entry.get()
            ws_url = f"ws://{host}:{port}"

        try:
            with websockets.connect(ws_url) as websocket:
                # Đọc file và tính hash
                file_hash = self.calculate_file_hash(input_file)
                file_name = os.path.basename(input_file)
                file_size = os.path.getsize(input_file)

                # Lưu thông tin file
                self.shared_files[file_hash] = {
                    'name': file_name,
                    'path': input_file,
                    'size': file_size,
                    'time': time.time()
                }

                # Gửi thông báo có file mới
                websocket.send(json.dumps({
                    'type': 'new_file',
                    'file_hash': file_hash,
                    'name': file_name,
                    'size': file_size
                }))

                self.log_message(f"Đã gửi thông tin file {file_name} tới server")
                messagebox.showinfo("Thành công", "Đã gửi thông tin file tới server")

        except Exception as e:
            self.log_message(f"Lỗi khi gửi file: {str(e)}")
            messagebox.showerror("Lỗi", f"Không thể gửi file: {str(e)}")

    def list_files(self):
        """Lấy danh sách file từ server"""
        if self.public_domain_var.get():
            ws_url = f"wss://{self.ngrok_entry.get()}"
        else:
            host = self.host_entry.get()
            port = self.port_entry.get()
            ws_url = f"ws://{host}:{port}"

        try:
            with websockets.connect(ws_url) as websocket:
                # Gửi yêu cầu danh sách file
                websocket.send(json.dumps({'type': 'list_request'}))

                # Nhận phản hồi
                response = json.loads(websocket.recv())
                if response.get('type') == 'list_response':
                    files = response.get('files', {})

                    # Hiển thị danh sách file trong popup
                    popup = tk.Toplevel(self.root)
                    popup.title("Danh sách file trên server")

                    tree = ttk.Treeview(popup, columns=('Name', 'Size', 'Time'), show='headings')
                    tree.heading('Name', text='Tên file')
                    tree.heading('Size', text='Kích thước (bytes)')
                    tree.heading('Time', text='Thời gian upload')

                    for file_hash, file_info in files.items():
                        tree.insert('', 'end', values=(
                            file_info['name'],
                            file_info['size'],
                            time.strftime("%H:%M:%S", time.localtime(file_info['time']))
                        ))

                    tree.pack(fill='both', expand=True)

                    # Nút tải file
                    def download_selected():
                        selected = tree.focus()
                        if not selected:
                            messagebox.showwarning("Cảnh báo", "Vui lòng chọn file để tải")
                            return

                        item = tree.item(selected)
                        file_hash = list(files.keys())[int(selected[1:]) - 1]
                        self.download_file(ws_url, file_hash, files[file_hash]['name'])

                    ttk.Button(popup, text="Tải file đã chọn", command=download_selected).pack(pady=5)
                else:
                    error = response.get('message', 'Unknown error')
                    self.log_message(f"Lỗi khi lấy danh sách file: {error}")
                    messagebox.showerror("Lỗi", f"Không thể lấy danh sách file: {error}")

        except Exception as e:
            self.log_message(f"Lỗi khi lấy danh sách file: {str(e)}")
            messagebox.showerror("Lỗi", f"Không thể kết nối tới server: {str(e)}")

    def download_file(self, ws_url, file_hash, file_name):
        """Tải file từ server"""
        save_path = filedialog.asksaveasfilename(initialfile=file_name)
        if not save_path:
            return

        try:
            with websockets.connect(ws_url) as websocket:
                # Gửi yêu cầu tải file
                websocket.send(json.dumps({
                    'type': 'download_request',
                    'file_hash': file_hash
                }))

                # Nhận thông tin file
                file_info = json.loads(websocket.recv())
                if file_info.get('type') != 'file_info':
                    raise Exception("Invalid response from server")

                file_size = file_info['size']
                self.log_message(f"Bắt đầu tải file {file_name} ({file_size} bytes)...")
                start_time = time.time()

                # Nhận dữ liệu file
                with open(save_path, 'wb') as f:
                    received = 0
                    while received < file_size:
                        chunk = websocket.recv()
                        if isinstance(chunk, str):
                            error = json.loads(chunk)
                            raise Exception(error.get('message', 'Unknown error'))

                        f.write(chunk)
                        received += len(chunk)

                        # Hiển thị tiến độ
                        progress = received / file_size * 100
                        self.log_message(f"\rĐã nhận {received}/{file_size} bytes ({progress:.1f}%)")

                elapsed = time.time() - start_time
                speed = file_size / (1024 * elapsed) if elapsed > 0 else 0

                self.log_message(f"Đã tải file thành công: {save_path}")
                self.log_message(f"Thời gian: {elapsed:.2f} giây ({speed:.2f} KB/s)")

                # Cập nhật đường dẫn file
                self.file_path_entry.delete(0, tk.END)
                self.file_path_entry.insert(0, save_path)

                messagebox.showinfo("Thành công", "Tải file thành công!")

        except Exception as e:
            self.log_message(f"Lỗi khi tải file: {str(e)}")
            messagebox.showerror("Lỗi", f"Không thể tải file: {str(e)}")

    def encrypt_file(self):
        """Mã hóa file bằng DES tự triển khai"""
        input_file = self.file_path_entry.get()
        if not input_file:
            messagebox.showerror("Lỗi", "Vui lòng chọn file trước khi mã hóa")
            return

        # Cập nhật khóa từ giao diện
        self.key = self.key_entry.get()[:8]  # Đảm bảo khóa 8 ký tự
        if len(self.key) < 8:
            self.key = self.key.ljust(8, ' ')  # Padding nếu khóa ngắn hơn 8 ký tự

        output_file = input_file + ".enc"

        try:
            # Tạo subkeys
            key_hex = self.key.encode('utf-8').hex()
            subkeys = self.generate_subkeys(key_hex)

            with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
                self.log_message(f"Bắt đầu mã hóa file: {input_file}")
                start_time = time.time()
                bytes_processed = 0

                while True:
                    chunk = f_in.read(8)  # Đọc 8 bytes (64-bit) mỗi lần
                    if not chunk:
                        break

                    # Padding nếu cần
                    if len(chunk) < 8:
                        chunk = self.pad_data(chunk)

                    # Chuyển sang hex để xử lý
                    chunk_hex = chunk.hex()

                    # Mã hóa
                    encrypted_hex = self.des_encrypt_block(chunk_hex, subkeys)
                    encrypted_bytes = bytes.fromhex(encrypted_hex)

                    f_out.write(encrypted_bytes)
                    bytes_processed += len(chunk)

                elapsed = time.time() - start_time
                speed = bytes_processed / (1024 * elapsed) if elapsed > 0 else 0
                self.log_message(f"Đã mã hóa xong: {input_file} -> {output_file}")
                self.log_message(f"Tổng kích thước: {bytes_processed} bytes")
                self.log_message(f"Thời gian: {elapsed:.2f} giây ({speed:.2f} KB/s)")

            messagebox.showinfo("Thành công", "Mã hóa file thành công!")
        except Exception as e:
            self.log_message(f"Lỗi khi mã hóa: {str(e)}")
            messagebox.showerror("Lỗi", f"Không thể mã hóa file: {str(e)}")

    def decrypt_file(self):
        """Giải mã file được mã hóa bằng DES tự triển khai"""
        input_file = self.file_path_entry.get()
        if not input_file:
            messagebox.showerror("Lỗi", "Vui lòng chọn file trước khi giải mã")
            return

        # Kiểm tra xem file có phải là file mã hóa không
        if not input_file.endswith('.enc'):
            messagebox.showwarning("Cảnh báo", "File này không có phần mở rộng .enc, có thể không phải file mã hóa")

        # Cập nhật khóa từ giao diện
        self.key = self.key_entry.get()[:8]  # Đảm bảo khóa 8 ký tự
        if len(self.key) < 8:
            self.key = self.key.ljust(8, ' ')  # Padding nếu khóa ngắn hơn 8 ký tự

        output_file = input_file[:-4] if input_file.endswith('.enc') else input_file + ".dec"

        try:
            # Tạo subkeys
            key_hex = self.key.encode('utf-8').hex()
            subkeys = self.generate_subkeys(key_hex)

            with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
                self.log_message(f"Bắt đầu giải mã file: {input_file}")
                start_time = time.time()
                bytes_processed = 0

                while True:
                    chunk = f_in.read(8)  # Đọc 8 bytes (64-bit) mỗi lần
                    if not chunk:
                        break

                    # Chuyển sang hex để xử lý
                    chunk_hex = chunk.hex()

                    # Giải mã
                    decrypted_hex = self.des_decrypt_block(chunk_hex, subkeys)
                    decrypted_bytes = bytes.fromhex(decrypted_hex)

                    # Gỡ padding nếu là block cuối
                    if f_in.tell() == os.fstat(f_in.fileno()).st_size:
                        decrypted_bytes = self.unpad_data(decrypted_bytes)

                    f_out.write(decrypted_bytes)
                    bytes_processed += len(chunk)

                elapsed = time.time() - start_time
                speed = bytes_processed / (1024 * elapsed) if elapsed > 0 else 0
                self.log_message(f"Đã giải mã xong: {input_file} -> {output_file}")
                self.log_message(f"Tổng kích thước: {bytes_processed} bytes")
                self.log_message(f"Thời gian: {elapsed:.2f} giây ({speed:.2f} KB/s)")

            messagebox.showinfo("Thành công", "Giải mã file thành công!")
        except Exception as e:
            self.log_message(f"Lỗi khi giải mã: {str(e)}")
            messagebox.showerror("Lỗi", f"Không thể giải mã file: {str(e)}")

    def on_close(self):
        """Xử lý khi đóng ứng dụng"""
        self.running = False
        if self.ws_server:
            self.ws_server.shutdown()
        if self.server_thread:
            self.server_thread.join()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = DESFileTransferApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()