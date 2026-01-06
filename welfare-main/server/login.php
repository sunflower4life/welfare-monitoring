<?php
session_start();
header("Content-Type: application/json");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");

include_once 'dbconnect.php';
include_once 'security_functions.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // 1. CSRF TOKEN VERIFICATION (XSS/CSRF prevention)
        $csrfToken = $_POST['csrf_token'] ?? null;
        if (!verifyCSRFToken($csrfToken)) {
            throw new Exception("CSRF token validation failed");
        }
        
        // 2. INPUT VALIDATION WITH ESCAPING
        $username = $_POST['username'] ?? null;
        $password = $_POST['password'] ?? null;

        if (!$username || !$password) {
            throw new Exception("Username and password are required");
        }

        // 3. VALIDATE INPUT - Calls validateInput() which escapes XSS
        $username = validateInput($username, 'string', 50);
        // This function uses: htmlspecialchars($input, ENT_QUOTES, 'UTF-8')
        // Converts: <script> becomes &lt;script&gt;
        
        if (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username)) {
            throw new Exception("Invalid username format");
        }

        // Continue with database query...
        $sql = "SELECT user_id, username, email, password, full_name, ic_number, phone, 
                       household_size, household_income, district, 
                       sub_district, privilege, created_at 
                FROM tbl_user 
                WHERE username = :username 
                LIMIT 1";
        
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['user_id'];
            $_SESSION['username'] = $user['username'];
            unset($user['password']);

            echo json_encode([
                "status" => "success",
                "message" => "Login successful",
                "data" => $user
            ]);
        } else {
            throw new Exception("Invalid username or password");
        }

    } catch (Exception $e) {
        echo json_encode(["status" => "error", "message" => $e->getMessage()]);
    }
}
?>