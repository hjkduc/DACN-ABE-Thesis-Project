# ---
# ĐỒ ÁN CHUYÊN NGÀNH: MÃ HÓA DỰA TRÊN THUỘC TÍNH (ABE)
#
# TỔNG HỢP DEMO TIẾN ĐỘ TUẦN 1 - 4
#
# Sinh viên: Trần Phúc Đăng & Lê Trần Anh Đức
#
# ---

# BƯỚC 1: IMPORT THƯ VIỆN (Mục tiêu Tuần 1)

# Việc import thành công các thư viện này chứng tỏ
# Tuần 1 (Cài đặt môi trường) đã hoàn tất.
try:
    # 'PairingGroup' là nền tảng toán học (bilinear pairing) 
    from charm.toolbox.pairinggroup import PairingGroup, GT
    
    # 'cpabe_bsw07' là scheme CP-ABE (Bethencourt-Sahai-Waters 2007)
    from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
    
    # 'timeit' để đo lường hiệu năng (Mục tiêu Tuần 4) 
    import timeit
    
    print("--- DEMO TUẦN 1: MÔI TRƯỜNG ---")
    print("[TUẦN 1] Trạng thái: THÀNH CÔNG")
    print("     -> Đã import thành công các thư viện (Python 3.10+, Charm-Crypto).\n")

except ImportError as e:
    print(f"[LỖI] Không thể import thư viện. Vui lòng kiểm tra lại cài đặt: {e}")
    exit()


def main():
    # ---
    # BƯỚC 2: KHỞI TẠO VÀ TẠO KHÓA CƠ BẢN (Mục tiêu Tuần 2)
    #
    # Mục tiêu: "Nghiên cứu toán học", "Code base setup/keygen chạy được" 
    # ---
    print("--- DEMO TUẦN 2: SETUP & KEYGEN ---")
    print("[TUẦN 2] Đang khởi tạo các tham số toán học (Bilinear Pairing)...")

    # 1. Khởi tạo 'PairingGroup' với đường cong elliptic 'SS512'
    group = PairingGroup('SS512')

    # 2. Tạo một đối tượng CP-ABE
    cpabe = CPabe_BSW07(group)

    # 3. Chạy thuật toán Setup()
    # Authority (Người quản lý) chạy 1 lần duy nhất để tạo ra:
    # (pk) Khóa Công khai: Dùng để mã hóa
    # (mk) Khóa Chủ: Dùng để tạo khóa cho người dùng
    (pk, mk) = cpabe.setup()
    print("[TUẦN 2] Đã chạy Setup(): Tạo ra Khóa Công khai (PK) và Khóa Chủ (MK).")

    # 4. Định nghĩa các thuộc tính cho một người dùng cụ thể
    # Ví dụ: Một bác sĩ tên "Anh"
    user_attributes = ['ROLE:DOCTOR', 'DEPT:CARDIO', 'FLOOR:F1']
    
    # 5. Chạy thuật toán KeyGen()
    # Authority dùng (mk) và (attributes) để tạo Khóa Bí mật (sk)
    sk = cpabe.keygen(pk, mk, user_attributes)
    print(f"[TUẦN 2] Đã chạy KeyGen(): Tạo Khóa Bí mật (SK) cho người dùng có thuộc tính: {user_attributes}\n")

    # ---
    # BƯỚC 3: MÃ HÓA & GIẢI MÃ CƠ BẢN (Mục tiêu Tuần 3)
    #
    # Mục tiêu: "Implement encrypt/decrypt cơ bản", "Test 5 cases đơn giản (match/non-match)" 
    # ---
    print("--- DEMO TUẦN 3: ENCRYPT/DECRYPT CƠ BẢN ---")

    # 1. Chuẩn bị dữ liệu (message) cần mã hóa
    # Dữ liệu phải là một phần tử thuộc nhóm GT
    message = group.random(GT)
    print(f"[TUẦN 3] Chuẩn bị một dữ liệu nhạy cảm (message) cần bảo vệ.")

    # 2. KỊCH BẢN 3.1 (MATCH - THÀNH CÔNG)
    policy_simple_match = 'ROLE:DOCTOR'
    print(f"[TEST 3.1] Mã hóa với policy đơn giản: '{policy_simple_match}'")
    
    # Mã hóa dữ liệu với (pk) và chính sách
    ciphertext_simple = cpabe.encrypt(pk, message, policy_simple_match)
    
    # Giải mã với (sk)
    try:
        decrypted_message = cpabe.decrypt(pk, sk, ciphertext_simple)
        # Kiểm tra dữ liệu sau giải mã có khớp bản gốc không
        if decrypted_message == message:
            print("[TEST 3.1] KẾT QUẢ: GIẢI MÃ THÀNH CÔNG. (Vì 'ROLE:DOCTOR' có trong bộ thuộc tính)")
        else:
            print("[TEST 3.1] KẾT QUẢ: LỖI LOGIC. (Dữ liệu không khớp)")
    except Exception as e:
        print(f"[TEST 3.1] KẾT QUẢ: LỖI - {e}")

    # 3. KỊCH BẢN 3.2 (NON-MATCH - THẤT BẠI)
    policy_simple_fail = 'ROLE:NURSE'
    print(f"\n[TEST 3.2] Mã hóa với policy đơn giản: '{policy_simple_fail}'")
    
    # Mã hóa
    ciphertext_simple_fail = cpabe.encrypt(pk, message, policy_simple_fail)
    
    # Giải mã
    try:
        decrypted_message = cpabe.decrypt(pk, sk, ciphertext_simple_fail)
        print("[TEST 3.2] KẾT QUẢ: GIẢI MÃ THÀNH CÔNG (Đây là lỗi bảo mật!)")
    except Exception as e:
        print("[TEST 3.2] KẾT QUẢ: GIẢI MÃ THẤT BẠI. (Mong đợi: Đúng. Vì 'ROLE:NURSE' không có trong bộ thuộc tính)\n")


    # ---
    # BƯỚC 4: CHÍNH SÁCH PHỨC TẠP VÀ ĐO HIỆU NĂNG (Mục tiêu Tuần 4)
    #
    # Mục tiêu: "Mở rộng policy phức tạp (AND/OR)", "Đo thời gian ban đầu (timeit)" 
    # ---
    print("--- DEMO TUẦN 4: CHÍNH SÁCH PHỨC TẠP & ĐO THỜI GIAN ---")

    # 1. KỊCH BẢN 4.1 (COMPLEX 'AND' - THÀNH CÔNG)
    policy_complex_and = 'ROLE:DOCTOR and DEPT:CARDIO'
    print(f"\n[TEST 4.1] Mã hóa với policy 'AND': '{policy_complex_and}'")
    
    ciphertext_complex_and = cpabe.encrypt(pk, message, policy_complex_and)
    
    try:
        decrypted_message = cpabe.decrypt(pk, sk, ciphertext_complex_and)
        if decrypted_message == message:
            print("[TEST 4.1] KẾT QUẢ: GIẢI MÃ THÀNH CÔNG. (Vì người dùng thỏa mãn cả 2 điều kiện)")
    except Exception as e:
        print(f"[TEST 4.1] KẾT QUẢ: GIẢI MÃ THẤT BẠI. (Lỗi: {e})")

    # 2. KỊCH BẢN 4.2 (COMPLEX 'OR' - THÀNH CÔNG)
    policy_complex_or = 'DEPT:HR or DEPT:CARDIO'
    print(f"\n[TEST 4.2] Mã hóa với policy 'OR': '{policy_complex_or}'")
    
    ciphertext_complex_or = cpabe.encrypt(pk, message, policy_complex_or)
    
    try:
        decrypted_message = cpabe.decrypt(pk, sk, ciphertext_complex_or)
        if decrypted_message == message:
            print("[TEST 4.2] KẾT QUẢ: GIẢI MÃ THÀNH CÔNG. (Vì người dùng thỏa mãn 1 trong 2 điều kiện)")
    except Exception as e:
        print(f"[TEST 4.2] KẾT QUẢ: GIẢI MÃ THẤT BẠI. (Lỗi: {e})")

    # 3. KỊCH BẢN 4.3 (COMPLEX 'AND'/'OR' - THẤT BẠI)
    policy_complex_fail = '(ROLE:DOCTOR and DEPT:HR) or ROLE:NURSE'
    print(f"\n[TEST 4.3] Mã hóa với policy phức tạp: '{policy_complex_fail}'")
    
    ciphertext_complex_fail = cpabe.encrypt(pk, message, policy_complex_fail)
    
    try:
        decrypted_message = cpabe.decrypt(pk, sk, ciphertext_complex_fail)
        print("[TEST 4.3] KẾT QUẢ: GIẢI MÃ THÀNH CÔNG (Đây là lỗi bảo mật!)")
    except Exception as e:
        print("[TEST 4.3] KẾT QUẢ: GIẢI MÃ THẤT BẠI. (Mong đợi: Đúng. Vì người dùng không thỏa mãn vế 'AND' và cũng không thỏa mãn vế 'OR')")

    # 4. ĐO LƯỜNG HIỆU NĂNG (timeit) 
    print("\n[TUẦN 4] Đang bắt đầu đo lường hiệu năng (chạy 100 vòng lặp)...")
    
    number_of_runs = 100
    
    # 4a. Đo thời gian mã hóa (Encrypt)
    # Ta dùng chính sách phức tạp nhất (TEST 4.3) để đo
    encrypt_timer = timeit.Timer(
        lambda: cpabe.encrypt(pk, message, policy_complex_fail)
    )
    encrypt_time = encrypt_timer.timeit(number=number_of_runs)
    avg_encrypt_time_ms = (encrypt_time / number_of_runs) * 1000 # Đổi sang mili-giây
    
    print(f"[HIỆU NĂNG] Thời gian mã hóa TRUNG BÌNH (policy phức tạp): {avg_encrypt_time_ms:.4f} ms")

    # 4b. Đo thời gian giải mã (Decrypt)
    # Ta dùng bản mã của kịch bản thành công (TEST 4.1) để đo
    decrypt_timer = timeit.Timer(
        lambda: cpabe.decrypt(pk, sk, ciphertext_complex_and)
    )
    decrypt_time = decrypt_timer.timeit(number=number_of_runs)
    avg_decrypt_time_ms = (decrypt_time / number_of_runs) * 1000 # Đổi sang mili-giây
    
    print(f"[HIỆU NĂNG] Thời gian giải mã TRUNG BÌNH (policy phức tạp): {avg_decrypt_time_ms:.4f} ms")
    
    print("\n--- KẾT THÚC DEMO TỔNG HỢP (TUẦN 1-4) ---")

# ---
# Lệnh chạy chương trình
# ---
if __name__ == "__main__":
    main()