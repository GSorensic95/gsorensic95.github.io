<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>RRPS Student Password Checker</title>
  <link rel="shortcut icon" href="https://aadcdn.msauth.net/shared/1.0/content/images/favicon_a_eupayfgghqiai7k9sol6lg2.ico" />
  <style>
    body {
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      background-image: url('https://cmsv2-assets.apptegy.net/uploads/5968/file/1201345/px1280_632d44df-b671-46f8-9d39-bde94ffd677d.png');
      background-size: cover;
      background-position: center;
      background-repeat: no-repeat;
      background-attachment: fixed;
      position: relative;
    }

    body::before {
      content: "";
      position: absolute;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.4); /* dark overlay */
      z-index: 0;
    }

    .container {
      position: relative;
      z-index: 1;
      background: #fff;
      width: 420px;
      padding: 40px;
      border-radius: 12px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 20px;
    }

    .logo img {
      height: 28px;
    }

    .logo span {
      font-size: 16px;
      font-weight: bold;
      color: #000;
    }

    h2 {
      font-size: 24px;
      font-weight: 400;
      margin-bottom: 20px;
      color: #000;
    }

    .input-group {
      width: 100%;
      margin-bottom: 15px;
    }

    .input-group div {
      position: relative;
      width: 100%;
    }

    .input-group input {
      width: 100%;
      padding: 12px 45px 12px 10px;
      border: none;
      border-bottom: 2px solid #666;
      font-size: 16px;
      outline: none;
      box-sizing: border-box;
    }

    .input-group input:focus {
      border-bottom: 2px solid #0067b8;
    }

    .show-password {
      position: absolute;
      right: 12px;
      top: 50%;
      transform: translateY(-50%);
      font-size: 13px;
      font-weight: 600;
      color: #0067b8;
      cursor: pointer;
      user-select: none;
    }

    .progress-bar {
      width: 100%;
      height: 12px;
      background: #ddd;
      border-radius: 6px;
      overflow: hidden;
      margin-top: 8px;
    }

    .progress-fill {
      height: 100%;
      width: 0;
      background: red;
      border-radius: 6px;
      transition: width 0.3s ease, background 0.3s ease;
    }

    .char-count {
      font-size: 14px;
      margin-top: 6px;
      text-align: center;
      color: #555;
    }

    .buttons {
      margin-top: 25px;
      display: flex;
      justify-content: flex-end;
    }

    .btn {
      padding: 10px 20px;
      border: none;
      font-size: 15px;
      cursor: pointer;
      border-radius: 6px;
    }

    .btn.back {
      background: #e6e6e6;
      margin-right: 10px;
    }

    .btn.next {
      background: #0067b8;
      color: #fff;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">
      <img src="https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg" alt="Microsoft Logo" />
      <span>RRPS Student Password Checker</span>
    </div>
    <h2>Check Your Password</h2>

    <div class="input-group">
      <div>
        <input type="password" id="password" placeholder="Password" aria-label="Password" />
        <span class="show-password" id="toggle-password">Show</span>
      </div>
      <div class="progress-bar">
        <div id="progress-fill" class="progress-fill"></div>
      </div>
      <div class="char-count" id="char-count">0 / 15 characters</div>
    </div>

    <div class="buttons">
      <button class="btn back">Back</button>
      <button class="btn next" onclick="goToMicrosoft()">Next</button>
    </div>
  </div>

  <script>
    const passwordInput = document.getElementById("password");
    const progressFill = document.getElementById("progress-fill");
    const charCount = document.getElementById("char-count");
    const togglePassword = document.getElementById("toggle-password");

    passwordInput.addEventListener("input", () => {
      const length = passwordInput.value.length;
      const percentage = Math.min((length / 15) * 100, 100);

      progressFill.style.width = percentage + "%";

      if (length < 5) {
        progressFill.style.background = "red";
      } else if (length < 10) {
        progressFill.style.background = "orange";
      } else if (length < 15) {
        progressFill.style.background = "gold";
      } else {
        progressFill.style.background = "green";
      }

      charCount.textContent = `${length} / 15 characters`;
    });

    togglePassword.addEventListener("click", () => {
      if (passwordInput.type === "password") {
        passwordInput.type = "text";
        togglePassword.textContent = "Hide";
      } else {
        passwordInput.type = "password";
        togglePassword.textContent = "Show";
      }
    });

    function goToMicrosoft() {
      window.location.href = "https://login.microsoftonline.com/";
    }
  </script>
</body>
</html>
