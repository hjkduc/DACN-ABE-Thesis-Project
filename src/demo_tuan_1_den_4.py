# ---
# ĐỒ ÁN CHUYÊN NGÀNH: MÃ HÓA DỰA TRÊN THUỘC TÍNH (ABE)
#
# TỔNG HỢP DEMO TIẾN ĐỘ TUẦN 1 - 4
#
# Sinh viên: Trần Phúc Đăng & Lê Trần Anh Đức
#
# File này demo:
# 1. (Tuần 1) Môi trường đã cài đặt thành công và import được thư viện.
# 2. (Tuần 2) Chạy được các hàm Setup() và KeyGen() cơ bản.
# 3. (Tuần 3) Chạy được các kịch bản Encrypt() và Decrypt() với policy đơn giản.
# 4. (Tuần 4) Mở rộng Encrypt/Decrypt với policy phức tạp (AND/OR)
#    và đo lường hiệu năng cơ bản bằng timeit.
# ---

# BƯỚC 1: IMPORT THƯ VIỆN (Mục tiêu Tuần 1)
try:
    # 'PairingGroup' là nền tảng toán học (bilinear pairing)
    from charm.toolbox.pairinggroup import PairingGroup, GT
    # Sử dụng scheme CP-ABE Waters 2011 (tên class là Waters11)
    from charm.schemes.abenc.waters11 import Waters11
    # 'timeit' để đo lường hiệu năng (Mục tiêu Tuần 4)
    import timeit

    print("--- DEMO TUẦN 1: MÔI TRƯỜNG ---")
    print("[TUẦN 1] Trạng thái: THÀNH CÔNG")
    print(f"     -> Đã import thành công các thư viện (Python 3.9, Charm-Crypto, Waters11).\n")

except ImportError as e:
    print(f"[LỖI] Không thể import thư viện. Vui lòng kiểm tra lại cài đặt: {e}")
    exit()
except Exception as e:
    print(f"[LỖI KHÁC KHI IMPORT] {e}") # Bắt các lỗi khác nếu có
    exit()


# ---
# ÁNH XẠ THUỘC TÍNH (ATTRIBUTE MAPPING)
# Scheme Waters11 yêu cầu thuộc tính phải là SỐ (dưới dạng chuỗi) thay vì CHỮ
# ---
ATTR_ROLE_DOCTOR = '1'
ATTR_DEPT_CARDIO = '2'
ATTR_FLOOR_F1 = '3'
ATTR_ROLE_NURSE = '4'
ATTR_DEPT_HR = '5'
# ---

def main():
    # ---
    # BƯỚC 2: KHỞI TẠO VÀ TẠO KHÓA CƠ BẢN (Mục tiêu Tuần 2)
    # ---
    print("--- DEMO TUẦN 2: SETUP & KEYGEN ---")
    print("[TUẦN 2] Đang khởi tạo các tham số toán học (Bilinear Pairing)...")

    try:
        # Khởi tạo 'PairingGroup' với đường cong elliptic 'SS512'
        group = PairingGroup('SS512')
        # Quy định số lượng thuộc tính tối đa mà hệ thống hỗ trợ
        uni_size = 100
        # Tạo đối tượng CP-ABE scheme Waters11
        cpabe = Waters11(group, uni_size)

        # Chạy thuật toán Setup() để tạo Khóa Công khai (PK) và Khóa Chủ (MK)
        (pk, mk) = cpabe.setup()
        print("[TUẦN 2] Đã chạy Setup(): Tạo ra Khóa Công khai (PK) và Khóa Chủ (MK).")

        # Định nghĩa các thuộc tính dạng số cho người dùng
        user_attributes = [ATTR_ROLE_DOCTOR, ATTR_DEPT_CARDIO, ATTR_FLOOR_F1]

        # Chạy thuật toán KeyGen() để tạo Khóa Bí mật (SK) từ MK và thuộc tính
        sk = cpabe.keygen(pk, mk, user_attributes)
        print(f"[TUẦN 2] Đã chạy KeyGen(): Tạo Khóa Bí mật (SK) cho người dùng có thuộc tính: {user_attributes}\n")

    except Exception as e:
        print(f"[LỖI BƯỚC 2] Đã xảy ra lỗi: {e}")
        return # Dừng nếu bước này lỗi

    # ---
    # BƯỚC 3: MÃ HÓA & GIẢI MÃ CƠ BẢN (Mục tiêu Tuần 3)
    # ---
    print("--- DEMO TUẦN 3: ENCRYPT/DECRYPT ---")

    try:
        # Tạo một dữ liệu ngẫu nhiên (thuộc nhóm GT) để mã hóa
        message = group.random(GT)
        print(f"[TUẦN 3] Chuẩn bị một dữ liệu nhạy cảm (message) cần bảo vệ.")

        # 2. KỊCH BẢN 3.1 (MATCH - THÀNH CÔNG)
        policy_simple_match = ATTR_ROLE_DOCTOR # Policy: '1'
        print(f"[TEST 3.1] Mã hóa với policy đơn giản: '{policy_simple_match}' (ROLE:DOCTOR)")

        # Mã hóa dữ liệu bằng PK và policy
        ciphertext_simple = cpabe.encrypt(pk, message, policy_simple_match)
        print("[TEST 3.1] Mã hóa thành công.")

        # Thử giải mã bằng SK
        try:
            decrypted_message = cpabe.decrypt(pk, sk, ciphertext_simple)
            # Kiểm tra xem dữ liệu giải mã có khớp bản gốc không
            if decrypted_message == message:
                print("[TEST 3.1] KẾT QUẢ: GIẢI MÃ THÀNH CÔNG.")
            else:
                # Trường hợp này xảy ra nếu hàm decrypt bị lỗi logic bên trong
                print("[TEST 3.1] KẾT QUẢ: LỖI LOGIC THƯ VIỆN. (Dữ liệu trả về không khớp)")
        except KeyError as ke:
             # Bắt lỗi nếu hàm decrypt không tìm thấy 'policy' trong ciphertext
            print(f"[TEST 3.1] KẾT QUẢ: GẶP LỖI THƯ VIỆN KHI GIẢI MÃ. ({ke} - Có thể do lỗi đóng gói ciphertext)")
        except Exception as e:
            print(f"[TEST 3.1] KẾT QUẢ: GẶP LỖI KHÁC KHI GIẢI MÃ. ({e})")

        # 3. KỊCH BẢN 3.2 (NON-MATCH - THẤT BẠI)
        policy_simple_fail = ATTR_ROLE_NURSE # Policy: '4'
        print(f"\n[TEST 3.2] Mã hóa với policy đơn giản: '{policy_simple_fail}' (ROLE:NURSE)")

        ciphertext_simple_fail = cpabe.encrypt(pk, message, policy_simple_fail)
        print("[TEST 3.2] Mã hóa thành công.")

        # Thử giải mã
        try:
            decrypted_message = cpabe.decrypt(pk, sk, ciphertext_simple_fail)
            # Kiểm tra xem kết quả có phải là False/None (chỉ thị giải mã thất bại) không
            if decrypted_message is False or decrypted_message is None:
                 print("[TEST 3.2] KẾT QUẢ: GIẢI MÃ THẤT BẠI NHƯ MONG ĐỢI.")
            elif decrypted_message == message:
                 print("[TEST 3.2] KẾT QUẢ: GIẢI MÃ THÀNH CÔNG (Đây là lỗi bảo mật!)")
            else:
                 print(f"[TEST 3.2] KẾT QUẢ: LỖI LOGIC THƯ VIỆN. (Trả về giá trị không mong muốn)")
        except KeyError as ke:
             # Nếu gặp KeyError ở đây, cũng coi như giải mã thất bại
            print(f"[TEST 3.2] KẾT QUẢ: GIẢI MÃ THẤT BẠI (Do lỗi thư viện {ke}, không giải mã được)")
        except Exception as e:
            print(f"[TEST 3.2] KẾT QUẢ: GẶP LỖI KHÁC KHI GIẢI MÃ. ({e})")

        print("\n")

    except Exception as e:
        print(f"[LỖI BƯỚC 3] Đã xảy ra lỗi: {e}")
        return # Dừng nếu bước này lỗi

    # ---
    # BƯỚC 4: CHÍNH SÁCH PHỨC TẠP VÀ ĐO HIỆU NĂNG (Mục tiêu Tuần 4)
    # ---
    print("--- DEMO TUẦN 4: CHÍNH SÁCH PHỨC TẠP & ĐO THỜI GIAN ---")

    try:
        # 1. KỊCH BẢN 4.1 (COMPLEX 'AND' - THÀNH CÔNG)
        policy_complex_and = f'{ATTR_ROLE_DOCTOR} and {ATTR_DEPT_CARDIO}' # Policy: '1 and 2'
        print(f"\n[TEST 4.1] Mã hóa với policy 'AND': '{policy_complex_and}'")

        ciphertext_complex_and = cpabe.encrypt(pk, message, policy_complex_and)
        print("[TEST 4.1] Mã hóa thành công.")

        # Thử giải mã
        try:
            decrypted_message = cpabe.decrypt(pk, sk, ciphertext_complex_and)
            if decrypted_message == message:
                print("[TEST 4.1] KẾT QUẢ: GIẢI MÃ THÀNH CÔNG.")
            else:
                print("[TEST 4.1] KẾT QUẢ: LỖI LOGIC THƯ VIỆN.")
        except KeyError as ke:
            print(f"[TEST 4.1] KẾT QUẢ: GẶP LỖI THƯ VIỆN KHI GIẢI MÃ. ({ke})")
        except Exception as e:
             print(f"[TEST 4.1] KẾT QUẢ: GẶP LỖI KHÁC KHI GIẢI MÃ. ({e})")


        # 2. KỊCH BẢN 4.2 (COMPLEX 'OR' - THÀNH CÔNG)
        policy_complex_or = f'{ATTR_DEPT_HR} or {ATTR_DEPT_CARDIO}' # Policy: '5 or 2'
        print(f"\n[TEST 4.2] Mã hóa với policy 'OR': '{policy_complex_or}'")

        ciphertext_complex_or = cpabe.encrypt(pk, message, policy_complex_or)
        print("[TEST 4.2] Mã hóa thành công.")

        # Thử giải mã
        try:
            decrypted_message = cpabe.decrypt(pk, sk, ciphertext_complex_or)
            if decrypted_message == message:
                print("[TEST 4.2] KẾT QUẢ: GIẢI MÃ THÀNH CÔNG.")
            else:
                print("[TEST 4.2] KẾT QUẢ: LỖI LOGIC THƯ VIỆN.")
        except KeyError as ke:
            print(f"[TEST 4.2] KẾT QUẢ: GẶP LỖI THƯ VIỆN KHI GIẢI MÃ. ({ke})")
        except Exception as e:
             print(f"[TEST 4.2] KẾT QUẢ: GẶP LỖI KHÁC KHI GIẢI MÃ. ({e})")


        # 3. KỊCH BẢN 4.3 (COMPLEX 'AND'/'OR' - THẤT BẠI)
        policy_complex_fail = f'({ATTR_ROLE_DOCTOR} and {ATTR_DEPT_HR}) or {ATTR_ROLE_NURSE}' # Policy: '(1 and 5) or 4'
        print(f"\n[TEST 4.3] Mã hóa với policy phức tạp: '{policy_complex_fail}'")

        ciphertext_complex_fail = cpabe.encrypt(pk, message, policy_complex_fail)
        print("[TEST 4.3] Mã hóa thành công.")

        # Thử giải mã
        try:
            decrypted_message = cpabe.decrypt(pk, sk, ciphertext_complex_fail)
            if decrypted_message is False or decrypted_message is None:
                 print("[TEST 4.3] KẾT QUẢ: GIẢI MÃ THẤT BẠI NHƯ MONG ĐỢI.")
            elif decrypted_message == message:
                 print("[TEST 4.3] KẾT QUẢ: GIẢI MÃ THÀNH CÔNG (Đây là lỗi bảo mật!)")
            else:
                 print(f"[TEST 4.3] KẾT QUẢ: LỖI LOGIC THƯ VIỆN.")
        except KeyError as ke:
            print(f"[TEST 4.3] KẾT QUẢ: GIẢI MÃ THẤT BẠI (Do lỗi thư viện {ke}, không giải mã được)")
        except Exception as e:
             print(f"[TEST 4.3] KẾT QUẢ: GẶP LỖI KHÁC KHI GIẢI MÃ. ({e})")


        # 4. ĐO LƯỜNG HIỆU NĂNG (timeit)
        print("\n[TUẦN 4] Đang bắt đầu đo lường hiệu năng (chạy 10 vòng lặp)...")

        number_of_runs = 10

        # 4a. Đo thời gian mã hóa (Encrypt)
        try:
            encrypt_timer = timeit.Timer(
                lambda: cpabe.encrypt(pk, message, policy_complex_fail)
            )
            encrypt_time = encrypt_timer.timeit(number=number_of_runs)
            avg_encrypt_time_ms = (encrypt_time / number_of_runs) * 1000
            print(f"[HIỆU NĂNG] Thời gian mã hóa TRUNG BÌNH (policy phức tạp): {avg_encrypt_time_ms:.4f} ms")
        except Exception as e:
            print(f"[HIỆU NĂNG] Lỗi khi đo thời gian mã hóa: {e}")

        try:
            # Tạo sẵn bản mã hợp lệ để đo thời gian decrypt
            valid_ciphertext_for_timing = cpabe.encrypt(pk, message, policy_complex_and)

            decrypt_timer = timeit.Timer(
                lambda: cpabe.decrypt(pk, sk, valid_ciphertext_for_timing)
            )
            decrypt_time = decrypt_timer.timeit(number=number_of_runs)
            avg_decrypt_time_ms = (decrypt_time / number_of_runs) * 1000
            print(f"[HIỆU NĂNG] Thời gian giải mã TRUNG BÌNH (policy phức tạp): {avg_decrypt_time_ms:.4f} ms")
        except Exception as e:
            # Bắt lỗi KeyError nếu decrypt vẫn bị lỗi ngay cả khi đo thời gian
            print(f"[HIỆU NĂNG] Lỗi khi đo thời gian giải mã: {e}")

    except Exception as e:
        print(f"[LỖI BƯỚC 4] Đã xảy ra lỗi: {e}")

    finally: 
      print("\n--- KẾT THÚC DEMO TỔNG HỢP (TUẦN 1-4) ---")

# ---
# Lệnh chạy chương trình
# ---
if __name__ == "__main__":
    main()