 function showTool(toolName) {
            const sections = document.querySelectorAll('.tool-section');
            const buttons = document.querySelectorAll('.nav-btn');
            
            sections.forEach(section => section.classList.remove('active'));
            buttons.forEach(btn => btn.classList.remove('active'));
            
            document.getElementById(toolName).classList.add('active');
            event.target.classList.add('active');
        }

        // ==================== 1. HASH FUNCTIONS ====================
        function generateHash() {
            const input = document.getElementById('hashInput').value;
            const algo = document.getElementById('hashAlgo').value;
            
            if (!input) {
                document.getElementById('hashOutput').innerHTML = '<span class="error"> Vui lòng nhập dữ liệu!</span>';
                return;
            }
            
            let hash;
            switch(algo) {
                case 'MD5': hash = CryptoJS.MD5(input); break;
                case 'SHA1': hash = CryptoJS.SHA1(input); break;
                case 'SHA256': hash = CryptoJS.SHA256(input); break;
                case 'SHA512': hash = CryptoJS.SHA512(input); break;
            }
            
            document.getElementById('hashOutput').innerHTML = `
                <strong>Thuật toán:</strong> ${algo}<br>
                <strong>Hash:</strong> <span class="success">${hash}</span>
            `;
        }

        // ==================== 2. AES ENCRYPTION ====================
        let aesEncrypted = '';
        
        function aesEncrypt() {
            const plaintext = document.getElementById('aesPlaintext').value;
            const key = document.getElementById('aesKey').value;
            
            if (!plaintext || !key) {
                document.getElementById('aesOutput').innerHTML = '<span class="error">Vui lòng nhập đầy đủ dữ liệu và khóa!</span>';
                return;
            }
            
            aesEncrypted = CryptoJS.AES.encrypt(plaintext, key).toString();
            document.getElementById('aesOutput').innerHTML = `
                <strong>Ciphertext (AES):</strong><br>
                <span class="success">${aesEncrypted}</span>
            `;
        }
        
        function aesDecrypt() {
            const key = document.getElementById('aesKey').value;
            
            if (!aesEncrypted || !key) {
                document.getElementById('aesOutput').innerHTML = '<span class="error">Vui lòng mã hóa trước hoặc nhập khóa đúng!</span>';
                return;
            }
            
            try {
                const decrypted = CryptoJS.AES.decrypt(aesEncrypted, key).toString(CryptoJS.enc.Utf8);
                if (!decrypted) throw new Error('Khóa sai');
                
                document.getElementById('aesOutput').innerHTML = `
                    <strong>Plaintext (Giải mã):</strong><br>
                    <span class="info">${decrypted}</span>
                `;
            } catch(e) {
                document.getElementById('aesOutput').innerHTML = '<span class="error"> Giải mã thất bại! Khóa không đúng.</span>';
            }
        }

        // ==================== 3. RSA ENCRYPTION ====================
        let rsaEncrypt_obj = new JSEncrypt({default_key_size: 2048});
        let rsaDecrypt_obj = new JSEncrypt({default_key_size: 2048});
        let rsaCiphertext = '';
        
        function generateRSAKeys() {
            rsaEncrypt_obj = new JSEncrypt({default_key_size: 2048});
            const publicKey = rsaEncrypt_obj.getPublicKey();
            const privateKey = rsaEncrypt_obj.getPrivateKey();
            
            document.getElementById('rsaPublicKey').value = publicKey;
            document.getElementById('rsaPrivateKey').value = privateKey;
            
            rsaDecrypt_obj.setPrivateKey(privateKey);
        }
        
        function rsaEncrypt() {
            const plaintext = document.getElementById('rsaPlaintext').value;
            const publicKey = document.getElementById('rsaPublicKey').value;
            
            if (!plaintext || !publicKey) {
                document.getElementById('rsaOutput').innerHTML = '<span class="error"> Vui lòng tạo khóa và nhập dữ liệu!</span>';
                return;
            }
            
            rsaEncrypt_obj.setPublicKey(publicKey);
            rsaCiphertext = rsaEncrypt_obj.encrypt(plaintext);
            
            document.getElementById('rsaOutput').innerHTML = `
                <strong>Ciphertext (RSA):</strong><br>
                <span class="success">${rsaCiphertext}</span>
            `;
        }
        
        function rsaDecrypt() {
            const privateKey = document.getElementById('rsaPrivateKey').value;
            
            if (!rsaCiphertext || !privateKey) {
                document.getElementById('rsaOutput').innerHTML = '<span class="error">Vui lòng mã hóa trước!</span>';
                return;
            }
            
            rsaDecrypt_obj.setPrivateKey(privateKey);
            const decrypted = rsaDecrypt_obj.decrypt(rsaCiphertext);
            
            document.getElementById('rsaOutput').innerHTML = `
                <strong>Plaintext (Giải mã):</strong><br>
                <span class="info">${decrypted}</span>
            `;
        }

        // ==================== 4. DIGITAL SIGNATURE ====================
        let signKey = new JSEncrypt({default_key_size: 2048});
        let currentSignature = '';
        let currentData = '';
        
        function generateSignKeys() {
            signKey = new JSEncrypt({default_key_size: 2048});
            document.getElementById('signOutput').innerHTML = `
                <span class="success">✅ Đã tạo cặp khóa mới!</span><br>
                <small>Public Key (64 ký tự đầu): ${signKey.getPublicKey().substring(0, 64)}...</small>
            `;
        }
        
        function signData() {
            currentData = document.getElementById('signData').value;
            if (!currentData) {
                document.getElementById('signOutput').innerHTML = '<span class="error"> Vui lòng nhập dữ liệu!</span>';
                return;
            }
            
            // Hash data trước khi ký
            const hash = CryptoJS.SHA256(currentData).toString();
            currentSignature = signKey.sign(hash, CryptoJS.SHA256, "sha256");
            
            document.getElementById('signOutput').innerHTML = `
                <strong>Chữ ký số:</strong><br>
                <span class="success">${currentSignature}</span><br>
                <small>Hash (SHA-256): ${hash}</small>
            `;
        }
        
        function verifySignature() {
            const data = document.getElementById('signData').value;
            
            if (!currentSignature || data !== currentData) {
                document.getElementById('signOutput').innerHTML = '<span class="error"> Dữ liệu đã thay đổi hoặc chưa ký!</span>';
                return;
            }
            
            const hash = CryptoJS.SHA256(data).toString();
            const verified = signKey.verify(hash, currentSignature, CryptoJS.SHA256);
            
            if (verified) {
                document.getElementById('signOutput').innerHTML = '<span class="success">✅ Chữ ký HỢP LỆ! Dữ liệu nguyên vẹn.</span>';
            } else {
                document.getElementById('signOutput').innerHTML = '<span class="error">❌ Chữ ký KHÔNG HỢP LỆ! Dữ liệu có thể bị giả mạo.</span>';
            }
        }

        // ==================== 5. OTP/2FA ====================
        let otpSecretKey = '';
        let lastOTP = '';
        
        function generateOTP() {
            let secret = document.getElementById('otpSecret').value;
            if (!secret) {
                secret = CryptoJS.lib.WordArray.random(16).toString();
                document.getElementById('otpSecret').value = secret;
            }
            otpSecretKey = secret;
            
            // Simple TOTP-like (giả lập, thực tế dùng thư viện TOTP)
            const timestamp = Math.floor(Date.now() / 30000); // 30s window
            const hash = CryptoJS.HmacSHA1(timestamp.toString(), secret).toString();
            lastOTP = (parseInt(hash.substring(0, 6), 16) % 1000000).toString().padStart(6, '0');
            
            document.getElementById('otpOutput').innerHTML = `
                <strong>Secret Key:</strong> <span class="info">${secret}</span><br>
                <strong>OTP Code:</strong> <span class="success" style="font-size: 2rem;">${lastOTP}</span><br>
                <small>Hết hạn sau 30 giây</small>
            `;
        }
        
        function verifyOTP() {
            const inputOTP = document.getElementById('otpVerify').value;
            
            if (inputOTP === lastOTP) {
                document.getElementById('otpVerifyOutput').innerHTML = '<span class="success">✅ OTP CHÍNH XÁC!</span>';
            } else {
                document.getElementById('otpVerifyOutput').innerHTML = '<span class="error">❌ OTP SAI!</span>';
            }
        }

       
       
      
        
   
