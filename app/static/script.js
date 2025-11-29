function log(msg, type='info') {
    const box = document.getElementById('system_log');
    const time = new Date().toLocaleTimeString();
    let color = 'white';
    if(type==='error') color = '#ff5555';
    if(type==='success') color = '#55ff55';
    if(type==='warning') color = 'yellow';
    
    box.innerHTML += `<div style="color:${color}">[${time}] ${msg}</div>`;
    box.scrollTop = box.scrollHeight;
}

// 1. KHỞI TẠO
document.getElementById('btn_init').onclick = async () => {
    log("⏳ Đang khởi tạo hệ thống...", 'warning');
    try {
        await fetch('/api/setup_authority', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ authority_name: "BENHVIEN" })
        });
        await fetch('/api/setup_authority', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ authority_name: "CONGTY_BAOHIEM" })
        });
        log("✅ Đã khởi tạo Cơ Quan: Bệnh Viện & Bảo Hiểm", 'success');
    } catch (e) { log("❌ Lỗi khởi tạo: " + e, 'error'); }
};

// 2. CẤP THẺ (KEYGEN)
async function createUser(user, auth, attr) {
    log(`⏳ Đang cấp thẻ cho ${user}...`, 'warning');
    try {
        const res = await fetch('/api/keygen', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ authority_name: auth, attributes: [attr], user_id: user })
        });
        if(res.ok) log(`✅ Đã cấp quyền ${attr} cho ${user}`, 'success');
        else log(`❌ Lỗi cấp thẻ: ${await res.text()}`, 'error');
    } catch (e) { log("❌ Lỗi mạng: " + e, 'error'); }
}

// 3. MÃ HÓA
document.getElementById('btn_encrypt').onclick = async () => {
    const policy = document.getElementById('access_policy').value;
    const content = document.getElementById('record_content').value;
    log(`🔒 Đang mã hóa hồ sơ với chính sách: ${policy}`, 'warning');
    
    try {
        const res = await fetch('/api/encrypt', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ policy: policy, payload: content })
        });
        const data = await res.json();
        if(res.ok) {
            document.getElementById('hidden_ciphertext').value = data.result;
            log("✅ Mã hóa thành công! Dữ liệu đã được bảo vệ.", 'success');
        } else {
            log("❌ Mã hóa thất bại: " + data.error, 'error');
        }
    } catch (e) { log("❌ Lỗi: " + e, 'error'); }
};

// 4. GIẢI MÃ
document.getElementById('btn_decrypt').onclick = async () => {
    const user = document.getElementById('current_user').value;
    const ciphertext = document.getElementById('hidden_ciphertext').value;
    const resultArea = document.getElementById('result_area');
    const finalResult = document.getElementById('final_result');

    if(!ciphertext) { alert("Chưa có hồ sơ nào được tạo!"); return; }

    log(`🔓 ${user} đang cố gắng mở hồ sơ...`, 'warning');
    resultArea.style.display = 'none';

    try {
        const res = await fetch('/api/decrypt', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ user_id: user, payload: ciphertext })
        });
        const data = await res.json();

        resultArea.style.display = 'block';
        if(res.ok) {
            finalResult.style.color = 'green';
            finalResult.textContent = data.decrypted_message;
            log(`✅ ${user} truy cập THÀNH CÔNG!`, 'success');
        } else {
            finalResult.style.color = 'red';
            finalResult.textContent = "TỪ CHỐI TRUY CẬP";
            log(`⛔ ${user} bị từ chối: Chính sách không khớp!`, 'error');
        }
    } catch (e) { log("❌ Lỗi: " + e, 'error'); }
};