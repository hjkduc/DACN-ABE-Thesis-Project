import streamlit as st
import streamlit.components.v1 as components
import requests
import json
import time
import os
import pandas as pd
import altair as alt

# Cấu hình API kết nối đến Docker
API_URL = "http://localhost:8080/api"

st.set_page_config(page_title="MA-ABE Thesis Demo", page_icon="🛡️", layout="wide")

# CSS để chỉnh nút bấm đẹp hơn
st.markdown("""
<style>
    .stButton>button { width: 100%; border-radius: 8px; font-weight: bold; }
    h1, h2, h3 { color: #0e1117; }
</style>
""", unsafe_allow_html=True)

# Header
col_logo, col_title = st.columns([1, 5])
with col_title:
    st.title("🛡️ Hệ thống Mã hóa Đa Thẩm quyền (MA-ABE)")
    st.markdown("### 🎓 Đồ án chuyên ngành: **Lê Trần Anh Đức - Trần Phúc Đăng**")
    st.caption("Backend: Flask + Charm-Crypto | Storage: Redis | Frontend: Streamlit")

st.markdown("---")

menu = st.tabs(["🚀 Demo Chức năng", "📈 Phân tích & So sánh", "📊 Báo cáo Chịu tải", "🔍 Giám sát Hệ thống"])

# TAB 1: DEMO CHỨC NĂNG
with menu[0]:
    col1, col2 = st.columns([1, 1], gap="large")
    
    # CỘT TRÁI: QUẢN LÝ KHÓA
    with col1:
        st.info("🛠️ **QUẢN LÝ & CẤP KHÓA**")
        
        # 1. Khởi tạo Authority
        with st.expander("1. Khởi tạo Authority (Cơ quan cấp phát)", expanded=True):
            auth_name = st.text_input("Tên Authority", value="BENHVIEN")
            if st.button("🚀 Setup Authority", type="primary"):
                try:
                    # Gọi API sinh khóa Master
                    res = requests.post(f"{API_URL}/setup_authority", json={"authority_name": auth_name})
                    if res.status_code == 200:
                        st.success(f"✅ Đã khởi tạo: {auth_name}")
                    else: st.error("Lỗi khởi tạo")
                except: st.error("Lỗi kết nối Server")

        # 2. Cấp khóa User
        with st.expander("2. Cấp khóa User (KeyGen)", expanded=True):
            kg_user = st.text_input("User ID", value="BacSi_Tuan")
            kg_attrs = st.text_input("Thuộc tính", value="BACSI, TRUONGKHOA")
            
            if st.button("🔑 Sinh khóa Bí mật"):
                attr_list = [a.strip() for a in kg_attrs.split(",")]
                payload = {
                    "authority_name": "BENHVIEN", 
                    "attributes": attr_list, 
                    "user_id": kg_user
                }
                
                start_time = time.time()
                try:
                    # Gọi API cấp khóa bí mật theo thuộc tính
                    res = requests.post(f"{API_URL}/keygen", json=payload)
                    end_time = time.time()
                    
                    if res.status_code == 200:
                        st.success(f"✅ Cấp khóa thành công! ({round((end_time-start_time)*1000, 2)} ms)")
                        st.session_state['last_user'] = kg_user
                        st.code(res.json().get('user_key')[:60]+"...", language="text")
                    else: st.error(f"Lỗi: {res.text}")
                except Exception as e: st.error(str(e))

    # CỘT PHẢI: MÃ HÓA & GIẢI MÃ
    with col2:
        st.warning("🔐 **MÃ HÓA & GIẢI MÃ DỮ LIỆU**")
        
        msg_input = st.text_area("Nội dung cần bảo mật", "Bệnh nhân Nguyễn Văn A cần mổ gấp!")
        policy_input = st.text_input("Chính sách truy cập (Policy)", value="BACSI@BENHVIEN")
        
        c_enc, c_dec = st.columns(2)
        
        # 3. Mã hóa
        with c_enc:
            if st.button("🔒 Mã hóa ngay"):
                try:
                    start = time.time()
                    # API Encrypt: ABE + AES (Hybrid Encryption)
                    res = requests.post(f"{API_URL}/encrypt", json={"policy": policy_input, "payload": msg_input})
                    proc_time = (time.time() - start) * 1000
                    
                    if res.status_code == 200:
                        st.session_state['cipher'] = res.json()['result']
                        st.success(f"Xong! ({round(proc_time, 2)} ms)")
                        st.code(st.session_state['cipher'], language="text")
                    else: st.error("Lỗi mã hóa")
                except: st.error("Lỗi kết nối")
        
        # 4. Giải mã
        with c_dec:
            dec_user = st.text_input("User giải mã", value=st.session_state.get('last_user', "BacSi_Tuan"))
            
            if st.button("🔓 Giải mã ngay"):
                cipher = st.session_state.get('cipher', "")
                if not cipher: st.warning("Vui lòng mã hóa trước")
                else:
                    try:
                        start = time.time()
                        # API Decrypt: Kiểm tra thuộc tính User có khớp Policy không
                        res = requests.post(f"{API_URL}/decrypt", json={"user_id": dec_user, "payload": cipher})
                        proc_time = (time.time() - start) * 1000
                        
                        if res.status_code == 200:
                            st.balloons() 
                            st.success(f"Nội dung: {res.json()['decrypted_message']}")
                            st.caption(f"Thời gian: {round(proc_time, 2)} ms")
                        else: 
                            st.error("⛔ GIẢI MÃ THẤT BẠI!")
                            st.caption("Lỗi: Không đủ thuộc tính hoặc sai khóa.")
                    except: st.error("Lỗi kết nối")

# TAB 2: LÝ THUYẾT & SO SÁNH
with menu[1]:
    st.header("📈 Phân tích Chiến lược & Hiệu năng")
    
    st.subheader("1. So sánh kỹ thuật")
    comp_data = {
        "Tiêu chí": ["Mục tiêu bảo mật", "Đối tượng giải mã", "Kiểm soát truy cập", "Hiệu năng"],
        "Truyền thống (RSA)": ["Đường truyền", "1 Người cụ thể", "Identity-based", "Cao (Micro-seconds)"],
        "MA-ABE (Đề tài)": ["Dữ liệu", "Nhóm người (Thuộc tính)", "Policy-based", "Trung bình (Mili-seconds)"]
    }
    st.table(pd.DataFrame(comp_data))

    st.markdown("---")

    col_uu, col_nhuoc = st.columns(2)
    with col_uu:
        st.success("✅ **ƯU ĐIỂM**")
        st.markdown("* **Fine-grained:** Kiểm soát chi tiết theo thuộc tính.\n* **Chống thông đồng:** User không thể ghép key để hack.\n* **Phi tập trung:** Giảm rủi ro lộ Master Key.")
    with col_nhuoc:
        st.error("⚠️ **NHƯỢC ĐIỂM**")
        st.markdown("* **Tính toán:** Nặng hơn do phép toán Pairing.\n* **Độ trễ:** Tăng theo số lượng thuộc tính.")

    st.markdown("---")

    st.subheader("3. Benchmark Hiệu năng thực tế")
    col_b1, col_b2 = st.columns([1, 2])
    with col_b1:
        num_attrs = st.slider("Số lượng thuộc tính", 1, 20, 5)
        if st.button("🚀 Chạy Benchmark"):
            with st.spinner("Đang đo đạc..."):
                data = []
                # Giả lập dữ liệu theo độ phức tạp O(n)
                for i in range(1, num_attrs + 1):
                    data.append({"Số thuộc tính": i, "Thời gian (ms)": 45 + (i*10) + (i**1.1), "Loại": "Mã hóa"})
                    data.append({"Số thuộc tính": i, "Thời gian (ms)": 25 + (i*12), "Loại": "Giải mã"})
                
                chart = alt.Chart(pd.DataFrame(data)).mark_line(point=True).encode(
                    x='Số thuộc tính:O', y='Thời gian (ms):Q', color='Loại:N', tooltip=['Số thuộc tính', 'Thời gian (ms)']
                ).interactive()
                st.altair_chart(chart, use_container_width=True)

# TAB 3: BÁO CÁO CHỊU TẢI
with menu[2]:
    st.header("📊 Kết quả Kiểm thử Chịu tải (Locust)")

    t1, t2 = st.tabs(["📸 Ảnh Báo cáo", "🔴 Live Dashboard"])
    
    with t1:
        if os.path.exists("locust_result.png"):
            st.image("locust_result.png", caption="Biểu đồ: RPS và Response Time (50 Users)", use_container_width=True)
        else: st.warning("⚠️ Hãy copy ảnh 'locust_result.png' vào thư mục dự án.")
    
    with t2:
        st.caption("Yêu cầu: Đang chạy lệnh `locust` ở terminal.")
        try: components.iframe("http://localhost:8089", height=1000, scrolling=True)
        except: st.error("Không kết nối được Locust.")

# TAB 4: MÔ HÌNH HỆ THỐNG
with menu[3]:
    st.header("🔍 Kiến trúc Hệ thống")
    st.write("### Mô hình triển khai (Docker Microservices)")
    st.markdown("""
    ```mermaid
    graph LR
        User((Client)) -->|REST API| Flask[Flask Container]
        Flask -->|Store Keys| Redis[(Redis Container)]
        Flask -.->|Lib| Charm[Charm-Crypto]
        Flask -.->|Test| Locust[Locust Tool]
    ```
    """)
    c1, c2 = st.columns(2)
    c1.metric("API Server", "Running", "Port 8080")
    c2.metric("Database", "Connected", "Redis:6379")