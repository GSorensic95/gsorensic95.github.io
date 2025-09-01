<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>RRPS Student Password Checker</title>
  <link rel="shortcut icon" href="https://aadcdn.msauth.net/shared/1.0/content/images/favicon_a_eupayfgghqiai7k9sol6lg2.ico" />
  <style>
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: "Segoe UI", Roboto, Arial, sans-serif;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh; /* fixed viewport for Chromebooks */
      background: url("https://cmsv2-assets.apptegy.net/uploads/5968/file/1201345/px1280_632d44df-b671-46f8-9d39-bde94ffd677d.png") 
                  no-repeat center center;
      background-size: cover;
      position: relative;
    }

    body::before {
      content: "";
      position: absolute;
      inset: 0;
      background: rgba(0, 0, 0, 0.4); /* overlay */
      z-index: 0;
    }

    .container {
      position: relative;
      z-index: 1;
      background: #fff;
      width: 420px; /* fixed Chromebook width */
      padding: 35px;
      border-radius: 10px;
      box-shadow: 0 4px 18px rgba(0, 0, 0, 0.3);
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 18px;
    }

    .logo img {
      height: 26px;
    }

    .logo span {
      font-size: 15px;
      font-weight: bold;
      color: #000;
    }

    h2 {
      font-size: 21px;
      margin-bottom: 18px;
      color: #000;
      font-weight: 500;
    }

    .input-group {
      margin-bottom: 18px;
    }

    .input-group div {
      position: relative;
    }

    .input-group input {
      width: 100%;
      padding: 12px 50px 12px 12px;
      border: none;
      border-bottom: 2px solid #666;
      font-size: 16px;
      outline: none;
      background: transparent;
    }

    .input-group input:focus {
      border-bottom: 2px solid #0067b8;
    }

    .show-password {
      position: absolute;
      right: 10px;
      top: 50%;
      transform: translateY(-50%);
      font-size: 13px;
      font-weight: 600;
      color: #0067b8;
      cursor: pointer;
    }

    .progress-bar {
      width: 100%;
      height: 10px;
      background: #e0e0e0;
      border-radius: 5px;
      overflow: hidden;
      margin-top: 8px;
    }

    .progress-fill {
      height: 100%;
      width: 0;
      background: red;
      transition: width 0.25s ease, background 0.25s ease;
    }

    .char-count {
      font-size: 13px;
      margin-top: 5px;
      text-align: center;
      color: #444;
    }

    .buttons {
      margin-top: 25px;
      display: flex;
      justify-content: flex-end;
    }

    .btn {
      padding: 9px 18px;
      border: none;
      font-size: 14px;
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

    .btn.back:hover { background: #d6d6d6; }
    .btn.next:hover { background: #005499; }
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

      if (length < 5) progressFill.style.background = "red";
      else if (length < 10) progressFill.style.background = "orange";
      else if (length < 15) progressFill.style.background = "gold";
      else progressFill.style.background = "green";

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
