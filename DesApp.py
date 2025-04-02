import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import os
import time
import shutil
from flask import Flask, request, send_file, abort
import requests
import random

class DESFileTransferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DES File Encryption/Transfer/Decryption with RSA")
        self.root.geometry("1000x800")

        # Biến cấu hình
        self.key = "183457799B3CDFF2"
        self.send_host = ""
        self.port = 5000
        self.receive_host = f"http://localhost:{self.port}"
        self.buffer_size = 4096
        self.public_key = None
        self.private_key = None

        # Khởi tạo Flask app
        self.flask_app = Flask(__name__)
        self.setup_flask_routes()

        # Tạo giao diện
        self.create_widgets()

        # Tạo cặp khóa RSA
        self.generate_rsa_keys()

        # Khởi động server Flask
        self.start_server()

    def setup_flask_routes(self):
        @self.flask_app.route('/upload', methods=['POST'])
        def upload_file():
            if 'file' not in request.files:
                return abort(400, "No file part")
            file = request.files['file']
            if file.filename == '':
                return abort(400, "No selected file")
            save_path = os.path.join("received_files", file.filename)
            os.makedirs("received_files", exist_ok=True)
            file.save(save_path)
            self.root.after(0, self.notify_file_received, file.filename, save_path)
            return {"message": f"File {file.filename} uploaded successfully"}, 200

        @self.flask_app.route('/download/<filename>', methods=['GET'])
        def download_file(filename):
            file_path = os.path.join("received_files", filename)
            if os.path.exists(file_path):
                return send_file(file_path, as_attachment=True)
            return abort(404, "File not found")

        @self.flask_app.route('/public_key', methods=['GET'])
        def get_public_key():
            e, n = self.public_key
            return {"public_key": f"{e},{n}"}, 200

        @self.flask_app.route('/key', methods=['POST'])
        def receive_key():
            encrypted_key = int(request.json.get("encrypted_key"))
            try:
                des_key = self.decrypt(self.private_key, encrypted_key)
                self.log_message(f"Đã nhận và giải mã khóa DES: {des_key}")
                return {"message": "Key received"}, 200
            except Exception as e:
                return {"error": str(e)}, 400

    def notify_file_received(self, filename, temp_path):
        dialog = tk.Toplevel(self.root)
        dialog.title("File Received")
        dialog.geometry("400x200")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text=f"Đã nhận được file: {filename}").pack(pady=10)
        ttk.Label(dialog, text="Bạn muốn làm gì với file này?").pack(pady=5)

        def save_file():
            output_file = filedialog.asksaveasfilename(
                initialfile=filename,
                title="Lưu file nhận được"
            )
            if output_file:
                try:
                    shutil.move(temp_path, output_file)
                    self.log_message(f"Đã lưu file: {output_file}")
                    self.file_path_entry.delete(0, tk.END)
                    self.file_path_entry.insert(0, output_file)
                except Exception as e:
                    self.log_message(f"Lỗi khi lưu file: {str(e)}")
                    messagebox.showerror("Lỗi", f"Không thể lưu file: {str(e)}")
            dialog.destroy()

        def decrypt_and_save():
            output_file = filedialog.asksaveasfilename(
                initialfile=filename[:-4] if filename.endswith('.des') else filename,
                title="Lưu file giải mã"
            )
            if output_file:
                try:
                    key_hex = self.key_entry.get().upper()
                    if len(key_hex) != 16 or not all(c in '0123456789ABCDEF' for c in key_hex):
                        raise ValueError("Khóa phải là chuỗi hex 16 ký tự")
                    subkeys = self.generate_subkeys(key_hex)
                    with open(temp_path, 'rb') as f_in, open(output_file, 'wb') as f_out:
                        file_data = f_in.read()
                        if len(file_data) % 8 != 0:
                            raise ValueError("File mã hóa không hợp lệ")
                        for i in range(0, len(file_data), 8):
                            chunk = file_data[i:i+8]
                            chunk_hex = chunk.hex().upper()
                            decrypted_hex = self.des_decrypt_block(chunk_hex, subkeys)
                            decrypted_bytes = bytes.fromhex(decrypted_hex)
                            if i + 8 == len(file_data):
                                decrypted_bytes = self.unpad_data(decrypted_bytes)
                            f_out.write(decrypted_bytes)
                    self.log_message(f"Đã giải mã và lưu file: {output_file}")
                    self.file_path_entry.delete(0, tk.END)
                    self.file_path_entry.insert(0, output_file)
                    os.remove(temp_path)
                except Exception as e:
                    self.log_message(f"Lỗi khi giải mã: {str(e)}")
                    messagebox.showerror("Lỗi", f"Không thể giải mã file: {str(e)}")
            dialog.destroy()

        def discard_file():
            if os.path.exists(temp_path):
                os.remove(temp_path)
            self.log_message(f"Đã từ chối lưu file: {filename}")
            dialog.destroy()

        ttk.Button(dialog, text="Lưu", command=save_file).pack(side="left", padx=10, pady=10)
        ttk.Button(dialog, text="Nhận và Giải mã", command=decrypt_and_save).pack(side="left", padx=10, pady=10)
        ttk.Button(dialog, text="Hủy", command=discard_file).pack(side="left", padx=10, pady=10)

    def start_server(self):
        def run_flask():
            self.flask_app.run(host='0.0.0.0', port=self.port, debug=False, use_reloader=False)
        flask_thread = threading.Thread(target=run_flask, daemon=True)
        flask_thread.start()
        self.log_message(f"Flask server started at {self.receive_host}")

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        config_frame = ttk.LabelFrame(main_frame, text="Cấu hình", padding="10")
        config_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))

        ttk.Label(config_frame, text="Khóa DES (hex, 16 ký tự):").grid(row=0, column=0, sticky="w")
        self.key_entry = ttk.Entry(config_frame, width=30)
        self.key_entry.grid(row=0, column=1, sticky="ew", padx=5)
        self.key_entry.insert(0, self.key)

        ttk.Label(config_frame, text="Send URL:").grid(row=1, column=0, sticky="w")
        self.send_host_entry = ttk.Entry(config_frame, width=50)
        self.send_host_entry.grid(row=1, column=1, sticky="ew", padx=5)
        self.send_host_entry.insert(0, self.send_host)

        ttk.Label(config_frame, text="Receive Port (Local):").grid(row=2, column=0, sticky="w")
        self.port_entry = ttk.Entry(config_frame, width=30)
        self.port_entry.grid(row=2, column=1, sticky="ew", padx=5)
        self.port_entry.insert(0, str(self.port))
        self.port_entry.bind("<KeyRelease>", self.update_receive_host)

        file_frame = ttk.LabelFrame(main_frame, text="File", padding="10")
        file_frame.grid(row=1, column=0, sticky="ew", pady=(0, 15))

        ttk.Label(file_frame, text="File nguồn:").grid(row=0, column=0, sticky="w")
        self.file_path_entry = ttk.Entry(file_frame, width=70)
        self.file_path_entry.grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(file_frame, text="Chọn file", command=self.select_file).grid(row=0, column=2, padx=5)
        ttk.Button(file_frame, text="Mở file", command=self.open_file).grid(row=0, column=3, padx=5)

        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=2, column=0, sticky="ew", pady=(0, 15))

        ttk.Button(action_frame, text="Mã hóa File", command=self.encrypt_file).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Gửi File", command=self.send_file).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Giải mã File", command=self.decrypt_file).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Mã hóa và Gửi", command=self.encrypt_and_send_file).pack(side="left", padx=5)

        log_frame = ttk.LabelFrame(main_frame, text="Nhật ký hoạt động", padding="10")
        log_frame.grid(row=3, column=0, sticky="nsew")

        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, wrap=tk.WORD, font=('Consolas', 10))
        self.log_text.pack(fill="both", expand=True)

        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)

        # DES permutation tables (giữ nguyên)
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
            [
                [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
            ],
            [
                [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
            ],
            [
                [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
            ],
            [
                [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
            ],
            [
                [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
            ],
            [
                [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
            ],
            [
                [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
            ],
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

        self.SHIFT_SCHEDULE = [
            1, 1, 2, 2,
            2, 2, 2, 2,
            1, 2, 2, 2,
            2, 2, 2, 1
        ]

    def log_message(self, message, replace_last=False):
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        if replace_last:
            self.log_text.delete("end-2l", "end-1l")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update()

    def update_receive_host(self, event):
        try:
            new_port = int(self.port_entry.get())
            self.port = new_port
            self.receive_host = f"http://localhost:{self.port}"
            self.log_message(f"Receive URL updated to: {self.receive_host}")
        except ValueError:
            self.log_message("Lỗi: Port phải là số nguyên")

    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, file_path)
            self.log_message(f"Đã chọn file: {file_path}")

    def open_file(self):
        file_path = self.file_path_entry.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Lỗi", "Vui lòng chọn file hợp lệ trước khi mở")
            return
        try:
            if file_path.lower().endswith('.des'):
                key_hex = self.key_entry.get().upper()
                if len(key_hex) != 16 or not all(c in '0123456789ABCDEF' for c in key_hex):
                    raise ValueError("Khóa phải là chuỗi hex 16 ký tự")
                subkeys = self.generate_subkeys(key_hex)
                with open(file_path, 'rb') as f_in:
                    file_data = f_in.read()
                    if len(file_data) % 8 != 0:
                        raise ValueError("File mã hóa không hợp lệ")
                    hex_content = file_data.hex().upper()
                    self.log_message(f"Mã hex của file {file_path} trước khi giải mã:")
                    self.log_message(hex_content)
                    decrypted_content = b""
                    for i in range(0, len(file_data), 8):
                        chunk = file_data[i:i + 8]
                        chunk_hex = chunk.hex().upper()
                        decrypted_hex = self.des_decrypt_block(chunk_hex, subkeys)
                        decrypted_bytes = bytes.fromhex(decrypted_hex)
                        if i + 8 == len(file_data):
                            decrypted_bytes = self.unpad_data(decrypted_bytes)
                        decrypted_content += decrypted_bytes
                    text_content = decrypted_content.decode('utf-8')
                    self.log_message(f"Nội dung file {file_path} sau khi giải mã DES (text): {text_content}")
            else:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    self.log_message(f"Nội dung file {file_path} (text): {content}")
                except UnicodeDecodeError:
                    with open(file_path, 'rb') as f:
                        binary_content = f.read()
                    hex_content = binary_content.hex().upper()
                    self.log_message(f"Nội dung file {file_path} (hex):")
                    self.log_message(hex_content)
                    try:
                        text_content = bytes.fromhex(hex_content).decode('utf-8')
                        self.log_message(f"Nội dung file {file_path} sau khi giải mã hex (text):")
                        self.log_message(text_content)
                    except (ValueError, UnicodeDecodeError):
                        self.log_message("Không thể giải mã hex thành text.")
            self.log_message(f"Đã xử lý file: {file_path}")
        except Exception as e:
            self.log_message(f"Lỗi khi xử lý file: {str(e)}")
            messagebox.showerror("Lỗi", f"Không thể xử lý file: {str(e)}")

    # DES Implementation
    def hex_to_bin(self, hex_str, pad=64):
        return bin(int(hex_str, 16))[2:].zfill(pad)

    def bin_to_hex(self, bin_str):
        hex_len = (len(bin_str) + 3) // 4
        return hex(int(bin_str, 2))[2:].upper().zfill(hex_len)

    def permute(self, bits, table):
        return ''.join(bits[i - 1] for i in table)

    def left_shift(self, bits, n):
        return bits[n:] + bits[:n]

    def xor(self, a, b):
        return ''.join(str(int(x) ^ int(y)) for x, y in zip(a, b))

    def generate_subkeys(self, key_hex):
        if len(key_hex) != 16 or not all(c in '0123456789ABCDEF' for c in key_hex.upper()):
            raise ValueError("Khóa phải là chuỗi hex 16 ký tự")
        key_bin = self.hex_to_bin(key_hex)
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
        result = []
        for i in range(8):
            block = bits[i * 6:(i + 1) * 6]
            row = int(block[0] + block[5], 2)
            col = int(block[1:5], 2)
            val = self.S_BOX[i][row][col]
            result.append(bin(val)[2:].zfill(4))
        return ''.join(result)

    def des_round(self, left, right, subkey):
        right_expanded = self.permute(right, self.E)
        xor_result = self.xor(right_expanded, subkey)
        sbox_result = self.s_box_substitution(xor_result)
        p_result = self.permute(sbox_result, self.P)
        new_right = self.xor(left, p_result)
        return right, new_right

    def des_encrypt_block(self, block_hex, subkeys):
        block_bin = self.hex_to_bin(block_hex)
        block_ip = self.permute(block_bin, self.IP)
        left = block_ip[:32]
        right = block_ip[32:]
        for i in range(16):
            left, right = self.des_round(left, right, subkeys[i])
        ciphertext = self.permute(right + left, self.FP)
        return self.bin_to_hex(ciphertext)

    def des_decrypt_block(self, block_hex, subkeys):
        block_bin = self.hex_to_bin(block_hex)
        block_ip = self.permute(block_bin, self.IP)
        left = block_ip[:32]
        right = block_ip[32:]
        for i in range(15, -1, -1):
            left, right = self.des_round(left, right, subkeys[i])
        plaintext = self.permute(right + left, self.FP)
        return self.bin_to_hex(plaintext)

    def pad_data(self, data):
        pad_len = 8 - (len(data) % 8) if len(data) % 8 != 0 else 0
        return data + bytes([pad_len] * pad_len) if pad_len else data

    def unpad_data(self, data):
        if not data or len(data) % 8 != 0:
            return data
        pad_len = data[-1]
        if pad_len > 8 or pad_len == 0:
            return data
        return data[:-pad_len]

    # RSA Implementation
    def is_prime(self, n):
        if n < 2:
            return False
        if n == 2:
            return True
        if n % 2 == 0:
            return False
        for _ in range(5):
            a = random.randrange(2, n - 1)
            if pow(a, n - 1, n) != 1:
                return False
        return True

    def generate_prime(self, min_value, max_value):
        prime = random.randrange(min_value, max_value)
        while not self.is_prime(prime):
            prime = random.randrange(min_value, max_value)
        return prime

    def mod_inverse(self, e, phi):
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        gcd, x, _ = extended_gcd(e, phi)
        if gcd != 1:
            raise ValueError("Không tồn tại nghịch đảo modulo")
        return x % phi

    def generate_rsa_keys(self):
        # Tăng kích thước p và q để n đủ lớn (2^63 đến 2^64)
        p = self.generate_prime(2**63, 2**64 - 1)
        q = self.generate_prime(2**63, 2**64 - 1)
        while p == q:
            q = self.generate_prime(2**63, 2**64 - 1)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        while phi % e == 0 or not self.is_prime(e):
            e += 2
        d = self.mod_inverse(e, phi)
        self.public_key = (e, n)
        self.private_key = (d, n)
        self.log_message(f"Public Key: (e={e}, n={n})")
        self.log_message(f"Private Key: (d={d}, n={n})")

    def encrypt(self, public_key, message):
        e, n = public_key
        # Chuyển chuỗi hex trực tiếp thành số thay vì encode UTF-8
        m = int(message, 16)  # Giả sử message là chuỗi hex như "183457799B3CDFF2"
        if m >= n:
            raise ValueError(f"Dữ liệu {m} quá lớn so với modulus n={n}")
        c = pow(m, e, n)
        return c

    def decrypt(self, private_key, ciphertext):
        d, n = private_key
        m = pow(ciphertext, d, n)
        # Chuyển số về chuỗi hex 16 ký tự
        hex_str = hex(m)[2:].upper().zfill(16)
        return hex_str

    def fetch_public_key_from_receiver(self):
        try:
            response = requests.get(f"{self.send_host}/public_key")
            if response.status_code == 200:
                e, n = map(int, response.json().get("public_key").split(","))
                self.public_key = (e, n)
                self.log_message(f"Đã nhận khóa công khai từ bên nhận: {self.public_key}")
        except Exception as e:
            self.log_message(f"Lỗi khi lấy khóa công khai: {str(e)}")
            messagebox.showerror("Lỗi", "Không thể lấy khóa công khai")

    def send_encrypted_key(self):
        des_key = self.key_entry.get().upper()
        if not self.public_key:
            self.fetch_public_key_from_receiver()
        if self.public_key:
            try:
                encrypted_key = self.encrypt(self.public_key, des_key)
                response = requests.post(
                    f"{self.send_host}/key",
                    json={"encrypted_key": str(encrypted_key)}
                )
                if response.status_code == 200:
                    self.log_message("Đã gửi khóa DES mã hóa thành công")
                else:
                    self.log_message(f"Lỗi khi gửi khóa: {response.status_code}")
            except Exception as e:
                self.log_message(f"Lỗi khi gửi khóa: {str(e)}")
                messagebox.showerror("Lỗi", f"Không thể gửi khóa: {str(e)}")

    def encrypt_file(self):
        input_file = self.file_path_entry.get()
        if not input_file:
            messagebox.showerror("Lỗi", "Vui lòng chọn file trước khi mã hóa")
            return
        key_hex = self.key_entry.get().upper()
        if len(key_hex) != 16 or not all(c in '0123456789ABCDEF' for c in key_hex):
            messagebox.showerror("Lỗi", "Khóa phải là chuỗi hex 16 ký tự")
            return
        output_file = input_file + ".des"
        try:
            subkeys = self.generate_subkeys(key_hex)
            with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
                self.log_message(f"Bắt đầu mã hóa file: {input_file}")
                start_time = time.time()
                bytes_processed = 0
                while True:
                    chunk = f_in.read(8)
                    if not chunk:
                        break
                    chunk = self.pad_data(chunk)
                    chunk_hex = chunk.hex().upper()
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
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, output_file)
        except Exception as e:
            self.log_message(f"Lỗi khi mã hóa: {str(e)}")
            messagebox.showerror("Lỗi", f"Không thể mã hóa file: {str(e)}")

    def decrypt_file(self):
        input_file = self.file_path_entry.get()
        if not input_file:
            messagebox.showerror("Lỗi", "Vui lòng chọn file trước khi giải mã")
            return
        if not input_file.endswith('.des'):
            messagebox.showwarning("Cảnh báo", "File này không có phần mở rộng .des")
        key_hex = self.key_entry.get().upper()
        if len(key_hex) != 16 or not all(c in '0123456789ABCDEF' for c in key_hex):
            messagebox.showerror("Lỗi", "Khóa phải là chuỗi hex 16 ký tự")
            return
        output_file = input_file[:-4] if input_file.endswith('.des') else input_file + ".dec"
        try:
            subkeys = self.generate_subkeys(key_hex)
            with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
                self.log_message(f"Bắt đầu giải mã file: {input_file}")
                start_time = time.time()
                bytes_processed = 0
                file_data = f_in.read()
                if len(file_data) % 8 != 0:
                    raise ValueError("File mã hóa không có kích thước là bội của 8 byte")
                for i in range(0, len(file_data), 8):
                    chunk = file_data[i:i+8]
                    chunk_hex = chunk.hex().upper()
                    decrypted_hex = self.des_decrypt_block(chunk_hex, subkeys)
                    decrypted_bytes = bytes.fromhex(decrypted_hex)
                    if i + 8 == len(file_data):
                        decrypted_bytes = self.unpad_data(decrypted_bytes)
                    f_out.write(decrypted_bytes)
                    bytes_processed += len(chunk)
                elapsed = time.time() - start_time
                speed = bytes_processed / (1024 * elapsed) if elapsed > 0 else 0
                self.log_message(f"Đã giải mã xong: {input_file} -> {output_file}")
                self.log_message(f"Tổng kích thước: {bytes_processed} bytes")
                self.log_message(f"Thời gian: {elapsed:.2f} giây ({speed:.2f} KB/s)")
            messagebox.showinfo("Thành công", "Giải mã file thành công!")
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, output_file)
        except Exception as e:
            self.log_message(f"Lỗi khi giải mã: {str(e)}")
            messagebox.showerror("Lỗi", f"Không thể giải mã file: {str(e)}")

    def send_file(self):
        input_file = self.file_path_entry.get()
        if not input_file:
            messagebox.showerror("Lỗi", "Vui lòng chọn file trước khi gửi")
            return
        self.send_host = self.send_host_entry.get()
        if not self.send_host or not self.send_host.startswith("http"):
            messagebox.showerror("Lỗi", "Send URL phải là URL hợp lệ (http:// hoặc https://)")
            return
        try:
            upload_url = f"{self.send_host}/upload"
            file_name = os.path.basename(input_file)
            file_size = os.path.getsize(input_file)
            self.log_message(f"Bắt đầu gửi file tới {upload_url}")
            start_time = time.time()
            with open(input_file, 'rb') as f:
                files = {'file': (file_name, f, 'application/octet-stream')}
                response = requests.post(upload_url, files=files, timeout=30)
            if response.status_code == 200:
                elapsed = time.time() - start_time
                speed = file_size / (1024 * elapsed) if elapsed > 0 else 0
                self.log_message(f"Đã gửi xong file {file_name} ({file_size} bytes)")
                self.log_message(f"Thời gian: {elapsed:.2f} giây ({speed:.2f} KB/s)")
                messagebox.showinfo("Thành công", "Gửi file thành công!")
            else:
                self.log_message(f"Lỗi từ server: {response.status_code}")
                messagebox.showerror("Lỗi", f"Không thể gửi file: {response.status_code}")
        except requests.exceptions.Timeout:
            self.log_message("Lỗi: Quá thời gian gửi file")
            messagebox.showerror("Lỗi", "Quá thời gian gửi file")
        except requests.exceptions.RequestException as e:
            self.log_message(f"Lỗi khi gửi file: {str(e)}")
            messagebox.showerror("Lỗi", f"Không thể gửi file: {str(e)}")

    def encrypt_and_send_file(self):
        input_file = self.file_path_entry.get()
        if not input_file:
            messagebox.showerror("Lỗi", "Vui lòng chọn file trước khi mã hóa và gửi")
            return
        key_hex = self.key_entry.get().upper()
        if len(key_hex) != 16 or not all(c in '0123456789ABCDEF' for c in key_hex):
            messagebox.showerror("Lỗi", "Khóa phải là chuỗi hex 16 ký tự")
            return
        self.send_host = self.send_host_entry.get()
        if not self.send_host or not self.send_host.startswith("http"):
            messagebox.showerror("Lỗi", "Send URL phải là URL hợp lệ (http:// hoặc https://)")
            return

        temp_output_file = input_file + ".des"
        try:
            subkeys = self.generate_subkeys(key_hex)
            with open(input_file, 'rb') as f_in, open(temp_output_file, 'wb') as f_out:
                self.log_message(f"Bắt đầu mã hóa file: {input_file}")
                start_time = time.time()
                bytes_processed = 0
                while True:
                    chunk = f_in.read(8)
                    if not chunk:
                        break
                    chunk = self.pad_data(chunk)
                    chunk_hex = chunk.hex().upper()
                    encrypted_hex = self.des_encrypt_block(chunk_hex, subkeys)
                    encrypted_bytes = bytes.fromhex(encrypted_hex)
                    f_out.write(encrypted_bytes)
                    bytes_processed += len(chunk)
                elapsed = time.time() - start_time
                self.log_message(f"Đã mã hóa xong: {input_file} -> {temp_output_file}")

            upload_url = f"{self.send_host}/upload"
            file_name = os.path.basename(temp_output_file)
            file_size = os.path.getsize(temp_output_file)
            self.log_message(f"Bắt đầu gửi file tới {upload_url}")
            start_time = time.time()
            with open(temp_output_file, 'rb') as f:
                files = {'file': (file_name, f, 'application/octet-stream')}
                response = requests.post(upload_url, files=files, timeout=30)
            if response.status_code == 200:
                elapsed = time.time() - start_time
                speed = file_size / (1024 * elapsed) if elapsed > 0 else 0
                self.log_message(f"Đã gửi xong file {file_name} ({file_size} bytes)")
                self.log_message(f"Thời gian: {elapsed:.2f} giây ({speed:.2f} KB/s)")
                self.send_encrypted_key()
                messagebox.showinfo("Thành công", "Mã hóa và gửi file thành công!")
            else:
                self.log_message(f"Lỗi từ server: {response.status_code}")
                messagebox.showerror("Lỗi", f"Không thể gửi file: {response.status_code}")
            os.remove(temp_output_file)
        except Exception as e:
            self.log_message(f"Lỗi khi mã hóa và gửi: {str(e)}")
            messagebox.showerror("Lỗi", f"Không thể mã hóa và gửi file: {str(e)}")
            if os.path.exists(temp_output_file):
                os.remove(temp_output_file)

if __name__ == "__main__":
    root = tk.Tk()
    app = DESFileTransferApp(root)
    root.mainloop()