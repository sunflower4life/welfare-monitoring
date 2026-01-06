<?php
header("Content-Type: application/json");
header("X-Content-Type-Options: nosniff");

include_once 'dbconnect.php';
include_once 'security_functions.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // 1. GET INPUTS
        $username = $_POST['username'] ?? null;
        $email = $_POST['email'] ?? null;
        $password = $_POST['password'] ?? null;
        $confirmPassword = $_POST['confirm_password'] ?? null;

        if (!$username || !$email || !$password) {
            throw new Exception("Required fields are missing");
        }

        // DEBUG: Log original input
        error_log("DEBUG 1 - Original username: " . $username);

        // 2. VALIDATE & ESCAPE USERNAME
        $username = validateInput($username, 'string', 50);
        
        // DEBUG: Log escaped input
        error_log("DEBUG 2 - After validateInput: " . $username);
        error_log("DEBUG 2 - Username is null? " . ($username === null ? 'YES' : 'NO'));
        
        // Then apply format validation
        if (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username)) {
            error_log("DEBUG 3 - Regex FAILED - throwing exception");
            throw new Exception("Invalid username format");
        }

        error_log("DEBUG 3 - Regex PASSED (this should NOT happen for XSS payload)");

        // 3. VALIDATE & ESCAPE EMAIL
        $email = validateInput($email, 'email', 100);

        // 4. VALIDATE PASSWORD STRENGTH
        if (strlen($password) < 8) {
            throw new Exception("Password must be at least 8 characters");
        }
        if (!preg_match('/[A-Z]/', $password)) {
            throw new Exception("Password must contain uppercase");
        }
        if (!preg_match('/[0-9]/', $password)) {
            throw new Exception("Password must contain number");
        }
        if (!preg_match('/[!@#$%^&*]/', $password)) {
            throw new Exception("Password must contain special character");
        }

        if ($password !== $confirmPassword) {
            throw new Exception("Passwords do not match");
        }

        // 5. HASH PASSWORD
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

        error_log("DEBUG 4 - About to insert username: " . $username);

        // 6. INSERT INTO DATABASE
        $sql = "INSERT INTO tbl_user (username, email, password) 
                VALUES (:username, :email, :password)";
        $stmt = $conn->prepare($sql);
        
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $hashedPassword);

        if ($stmt->execute()) {
            error_log("DEBUG 5 - INSERT SUCCESSFUL");
            $userId = $conn->lastInsertId();

            $query = "SELECT user_id, username, email, full_name, ic_number, phone, 
                             household_size, household_income, district, 
                             sub_district, privilege, created_at 
                      FROM tbl_user WHERE user_id = :user_id";
            
            $getUser = $conn->prepare($query);
            $getUser->bindParam(':user_id', $userId);
            $getUser->execute();
            $userData = $getUser->fetch();

            echo json_encode([
                "status" => "success",
                "message" => "Registration successful",
                "data" => $userData
            ]);
        }
    } catch (PDOException $e) {
        error_log("PDOException: " . $e->getMessage());
        if ($e->getCode() == 23000) {
            echo json_encode(["status" => "error", "message" => "Username or Email already exists"]);
        } else {
            echo json_encode(["status" => "error", "message" => "Database error"]);
        }
    } catch (Exception $e) {
        error_log("Exception: " . $e->getMessage());
        echo json_encode(["status" => "error", "message" => $e->getMessage()]);
    }
}
?>